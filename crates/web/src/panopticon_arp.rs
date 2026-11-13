//! Passive ARP sniffing -- raw `AF_PACKET` capture via `pnet_datalink`,
//! the one piece of Panopticon that genuinely needs elevated privileges
//! (`CAP_NET_RAW`; see the Dockerfile's `setcap` and docker-compose.yml's
//! `cap_add`), a real deviation from every other arsenal in this
//! workspace running as an ordinary unprivileged process. `promiscuous:
//! false` deliberately -- ARP requests are link-layer broadcast and
//! replies go straight to whichever host asked, so this container
//! receives them on an ordinary bridge port without needing promiscuous
//! mode, which would additionally require `CAP_NET_ADMIN`. Behind
//! Docker's default bridge network this only ever sees the Docker
//! bridge's own ARP traffic, not a physical LAN's -- the same caveat the
//! manual discovery scan's own page already states; host networking (or
//! running the binary directly) is required to see real LAN traffic.
//!
//! `pnet_datalink::DataLinkReceiver::next()` is a blocking call (no async
//! variant exists), so the capture loop runs on a blocking task and hands
//! parsed `(mac, ip)` pairs to an ordinary async task over a channel --
//! keeping the blocking I/O and the async DB writes on separate sides of
//! that boundary rather than blocking a tokio worker thread on socket
//! reads.
//!
//! The same capture also reads **DHCP client packets** (0.2.7 N3): a
//! DISCOVER, REQUEST or INFORM carries the client's MAC, its parameter
//! request list (option 55), vendor class (option 60) and hostname (option
//! 12) -- the fingerprint `abyssal_core::classify` suggests a device type
//! from. It sees DHCP broadcast on the captured segment, and any DHCP relayed
//! to this server: add the control plane as an extra `ip helper-address`
//! (and, behind Docker's bridge network, publish UDP 67 to the container).

use std::net::Ipv4Addr;
use std::time::Duration;

use std::sync::Arc;

use abyssal_database::{DbPool, repo};
use abyssal_notifications::NotificationDispatcher;
use pnet_datalink::{Channel, Config, MacAddr};
use tokio::sync::mpsc;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;

struct ArpSighting {
    mac: MacAddr,
    ip: Ipv4Addr,
}

/// A DHCP client's fingerprint, from one DISCOVER/REQUEST/INFORM.
#[derive(Debug, PartialEq, Eq)]
struct DhcpSighting {
    /// Lowercase colon form, from the BOOTP `chaddr` (the client's own MAC,
    /// even when a relay forwarded the packet).
    mac: String,
    /// Option 55 as comma-separated decimal codes.
    prl: Option<String>,
    vendor_class: Option<String>,
    hostname: Option<String>,
    /// A REQUEST's server identifier (option 54): the server this client
    /// chose (0.2.9 Q4, rogue DHCP detection).
    server_id: Option<Ipv4Addr>,
}

/// A DHCP server's reply (OFFER/ACK/NAK) to a client (0.2.9 Q4).
#[derive(Debug, PartialEq, Eq)]
struct DhcpServerSighting {
    /// Option 54, else the packet's source address.
    server_ip: Ipv4Addr,
    /// The Ethernet source, for an unrelayed reply only: a relayed reply
    /// comes from the relay, not the server.
    server_mac: Option<String>,
    /// The client it answered (`chaddr`).
    client_mac: String,
}

/// What the capture loop hands to the async side.
enum Sighting {
    Arp(ArpSighting),
    Dhcp(DhcpSighting),
    DhcpServer(DhcpServerSighting),
}

/// The Ethernet payload and its ethertype, through at most one 802.1Q tag.
fn ethernet_payload(frame: &[u8]) -> Option<(u16, &[u8])> {
    let mut ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    let mut offset = 14;
    if ethertype == ETHERTYPE_VLAN {
        ethertype = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
        offset += 4;
    }
    Some((ethertype, frame.get(offset..)?))
}

/// A whole (unfragmented) IPv4 UDP datagram in a frame: its IP source,
/// source and destination ports, and the UDP payload. Untrusted input from
/// any device on the segment: every offset is checked.
fn udp_datagram(frame: &[u8]) -> Option<(Ipv4Addr, u16, u16, &[u8])> {
    let (ethertype, ip) = ethernet_payload(frame)?;
    if ethertype != ETHERTYPE_IPV4 || ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    // More-fragments flag or a fragment offset: not a whole datagram.
    let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff;
    if ihl < 20 || ip[9] != IPPROTO_UDP || fragment != 0 {
        return None;
    }
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let udp = ip.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    Some((src, sport, dport, &udp[8..]))
}

/// Parses one captured frame for a DHCP server's reply to a client: UDP
/// from port 67 to port 68, an OFFER, ACK or NAK (0.2.9 Q4). Replies a
/// server sends to a relay (port 67 to 67) aren't on a client segment, so
/// they aren't looked for.
fn parse_dhcp_server_reply(frame: &[u8]) -> Option<DhcpServerSighting> {
    let (src, sport, dport, payload) = udp_datagram(frame)?;
    if sport != DHCP_SERVER_PORT || dport != DHCP_CLIENT_PORT {
        return None;
    }
    let reply = abyssal_portal_net::dhcp::parse_server_reply(payload)?;
    let server_ip = reply.server_id.unwrap_or(src);
    if server_ip.is_unspecified() || server_ip.is_broadcast() {
        return None;
    }
    let relayed = !reply.giaddr.is_unspecified();
    let eth_src: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    Some(DhcpServerSighting {
        server_ip,
        server_mac: (!relayed).then(|| abyssal_portal_net::dhcp::mac_string(&eth_src)),
        client_mac: abyssal_portal_net::dhcp::mac_string(&reply.chaddr),
    })
}

/// Parses one captured frame for a DHCP client fingerprint: IPv4, UDP to
/// port 67, an unfragmented BOOTREQUEST with the DHCP magic cookie and a
/// DISCOVER (1), REQUEST (3) or INFORM (8) message type. Everything else --
/// server replies, plain BOOTP, truncated or malformed packets -- is `None`.
/// Untrusted input from any device on the segment: every offset is checked.
fn parse_dhcp_request(frame: &[u8]) -> Option<DhcpSighting> {
    let (_, _, dport, payload) = udp_datagram(frame)?;
    if dport != DHCP_SERVER_PORT {
        return None;
    }
    // The BOOTP/DHCP parsing itself is the registration DHCP server's
    // (abyssal_portal_net): one bounds-checked parser for both.
    let req = abyssal_portal_net::dhcp::parse_request(payload)?;
    if !matches!(
        req.message_type,
        abyssal_portal_net::dhcp::DISCOVER
            | abyssal_portal_net::dhcp::REQUEST
            | abyssal_portal_net::dhcp::INFORM
    ) {
        return None;
    }
    Some(DhcpSighting {
        mac: abyssal_portal_net::dhcp::mac_string(&req.chaddr),
        prl: req.prl,
        vendor_class: req.vendor_class,
        hostname: req.hostname,
        server_id: req
            .server_id
            .filter(|_| req.message_type == abyssal_portal_net::dhcp::REQUEST)
            .filter(|ip| !ip.is_unspecified()),
    })
}

/// Parses one captured Ethernet frame for an ARP sender mapping (the
/// `SHA`/`SPA` fields -- valid on both requests and replies, since either
/// one means a real, live device just spoke). Returns `None` for anything
/// that isn't a well-formed Ethernet+IPv4 ARP frame: a different
/// ethertype, a truncated capture, an ARP variant using non-6-byte MACs
/// or non-4-byte IPs (e.g. IPv6 or non-Ethernet hardware, vanishingly
/// rare on a LAN this listens on). Handles at most one 802.1Q VLAN tag;
/// this reads untrusted network input from any device on the segment, so
/// every offset is bounds-checked rather than assumed.
fn parse_arp_sender(frame: &[u8]) -> Option<ArpSighting> {
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14;
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    if ethertype != ETHERTYPE_ARP {
        return None;
    }

    let arp = frame.get(offset..)?;
    if arp.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return None;
    }

    let sha = &arp[8..14];
    let spa = &arp[14..18];
    Some(ArpSighting {
        mac: MacAddr::new(sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]),
        ip: Ipv4Addr::new(spa[0], spa[1], spa[2], spa[3]),
    })
}

async fn ingest_dhcp(pool: &DbPool, notifications: &NotificationDispatcher, s: DhcpSighting) {
    if let Some(server) = s.server_id {
        crate::panopticon_rogue_dhcp::observe(
            pool,
            notifications,
            &server.to_string(),
            None,
            Some(&s.mac),
            repo::panopticon_dhcp_servers::Seen::Chosen,
        )
        .await;
    }
    if let Err(e) = repo::panopticon_fingerprints::upsert(
        pool,
        &s.mac,
        s.prl.as_deref(),
        s.vendor_class.as_deref(),
        s.hostname.as_deref(),
    )
    .await
    {
        tracing::warn!(error = %e, mac = %s.mac, "DHCP fingerprint ingest failed");
    }
}

async fn ingest(pool: &DbPool, notifications: &NotificationDispatcher, sighting: ArpSighting) {
    // 0.0.0.0 is ARP "probe" traffic (duplicate address detection) --
    // it's not the sender's real address, so there's nothing useful to
    // record.
    if sighting.ip.is_unspecified() {
        return;
    }
    let ip = sighting.ip.to_string();
    let mac = sighting.mac.to_string();

    let prior = match repo::network_devices::find_by_ip(pool, &ip).await {
        Ok(prior) => prior,
        Err(e) => {
            tracing::warn!(error = %e, ip = %ip, "ARP ingest failed to look up prior device state");
            return;
        }
    };
    if let Err(e) = repo::network_devices::touch(pool, &ip, &mac).await {
        tracing::warn!(error = %e, ip = %ip, "ARP ingest failed to record sighting");
        return;
    }
    if let Err(e) =
        crate::panopticon_ops::audit_sighting(pool, Some(notifications), &ip, prior).await
    {
        tracing::warn!(error = %e, ip = %ip, "ARP ingest failed to record audit event");
    }
}

/// Starts the ARP capture loop on `interface_name`, if it can open the
/// interface at all -- a missing interface, a permissions failure
/// (`CAP_NET_RAW` not actually granted despite the setting being on), or
/// an interface pnet's Linux backend doesn't support are all logged and
/// the task exits, same best-effort posture as every other background
/// listener here. Like the mDNS listener and the syslog receiver this
/// codebase's own reference material describes, this is a real socket
/// bind (`CAP_NET_RAW`-gated, not just settings-gated), so enabling this
/// or changing the interface (`panopticon.arp_enabled`/
/// `panopticon.arp_interface`) takes a server restart.
pub fn spawn_panopticon_arp_listener(
    pool: DbPool,
    interface_name: String,
    notifications: Arc<NotificationDispatcher>,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Sighting>();

    tokio::task::spawn_blocking(move || {
        let interfaces = pnet_datalink::interfaces();
        let Some(interface) = interfaces.into_iter().find(|i| i.name == interface_name) else {
            tracing::error!(interface = %interface_name, "Panopticon ARP listener: interface not found");
            return;
        };

        let config = Config {
            promiscuous: false,
            read_timeout: Some(Duration::from_secs(1)),
            ..Config::default()
        };
        let mut receiver = match pnet_datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(_tx, rx)) => rx,
            Ok(_) => {
                tracing::error!(interface = %interface_name, "Panopticon ARP listener: unsupported channel type");
                return;
            }
            Err(e) => {
                tracing::error!(interface = %interface_name, error = %e, "Panopticon ARP listener failed to open interface -- CAP_NET_RAW missing?");
                return;
            }
        };

        tracing::info!(interface = %interface_name, "Panopticon ARP listener started");
        loop {
            match receiver.next() {
                Ok(frame) => {
                    let sighting = parse_arp_sender(frame)
                        .map(Sighting::Arp)
                        .or_else(|| parse_dhcp_request(frame).map(Sighting::Dhcp))
                        .or_else(|| parse_dhcp_server_reply(frame).map(Sighting::DhcpServer));
                    if let Some(sighting) = sighting
                        && tx.send(sighting).is_err()
                    {
                        break; // receiving end dropped, control plane shutting down
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {} // read_timeout, just loop
                Err(e) => {
                    tracing::warn!(interface = %interface_name, error = %e, "Panopticon ARP capture read error");
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some(sighting) = rx.recv().await {
            match sighting {
                Sighting::Arp(s) => ingest(&pool, &notifications, s).await,
                Sighting::Dhcp(s) => ingest_dhcp(&pool, &notifications, s).await,
                Sighting::DhcpServer(s) => {
                    crate::panopticon_rogue_dhcp::observe(
                        &pool,
                        &notifications,
                        &s.server_ip.to_string(),
                        s.server_mac.as_deref(),
                        Some(&s.client_mac),
                        repo::panopticon_dhcp_servers::Seen::Reply,
                    )
                    .await
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOTREQUEST: u8 = 1;
    const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

    fn build_arp_request(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // dst: broadcast
        frame.extend_from_slice(&sender_mac); // src
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
        frame.push(6); // hlen
        frame.push(4); // plen
        frame.extend_from_slice(&1u16.to_be_bytes()); // opcode: request
        frame.extend_from_slice(&sender_mac); // SHA
        frame.extend_from_slice(&sender_ip); // SPA
        frame.extend_from_slice(&[0; 6]); // THA (unknown, target's own)
        frame.extend_from_slice(&[192, 168, 1, 1]); // TPA
        frame
    }

    #[test]
    fn parses_sender_from_arp_request() {
        let frame = build_arp_request([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], [10, 0, 0, 42]);
        let sighting = parse_arp_sender(&frame).expect("should parse");
        assert_eq!(sighting.ip, Ipv4Addr::new(10, 0, 0, 42));
        assert_eq!(
            sighting.mac,
            MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55)
        );
    }

    #[test]
    fn parses_sender_through_vlan_tag() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        frame.extend_from_slice(&100u16.to_be_bytes()); // TCI (VLAN 100)
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&2u16.to_be_bytes()); // reply
        frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame.extend_from_slice(&[10, 0, 0, 99]);
        frame.extend_from_slice(&[0xaa; 6]);
        frame.extend_from_slice(&[10, 0, 0, 1]);

        let sighting = parse_arp_sender(&frame).expect("should parse through VLAN tag");
        assert_eq!(sighting.ip, Ipv4Addr::new(10, 0, 0, 99));
    }

    #[test]
    fn ignores_non_arp_ethertype() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4, not ARP
        assert!(parse_arp_sender(&frame).is_none());
    }

    /// An Ethernet/IPv4/UDP frame carrying a DHCP BOOTREQUEST with `options`
    /// (after the magic cookie), from `mac`, to port 67.
    fn dhcp_frame(mac: [u8; 6], options: &[u8]) -> Vec<u8> {
        let mut bootp = vec![0u8; 236];
        bootp[0] = BOOTREQUEST;
        bootp[1] = 1;
        bootp[2] = 6;
        bootp[28..34].copy_from_slice(&mac);
        bootp.extend_from_slice(&DHCP_MAGIC_COOKIE);
        bootp.extend_from_slice(options);
        let mut udp = Vec::new();
        udp.extend_from_slice(&68u16.to_be_bytes());
        udp.extend_from_slice(&67u16.to_be_bytes());
        udp.extend_from_slice(&((8 + bootp.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&bootp);
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, IPPROTO_UDP, 0, 0];
        ip.extend_from_slice(&[0, 0, 0, 0, 255, 255, 255, 255]);
        let total = (ip.len() + udp.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&udp);
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ip);
        frame
    }

    const MAC: [u8; 6] = [0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03];

    #[test]
    fn parses_a_windows_dhcp_discover() {
        let mut opts = vec![53, 1, 1]; // DISCOVER
        opts.extend_from_slice(&[55, 4, 1, 3, 6, 252]);
        opts.extend_from_slice(&[60, 8]);
        opts.extend_from_slice(b"MSFT 5.0");
        opts.extend_from_slice(&[12, 15]);
        opts.extend_from_slice(b"DESKTOP-4F2K9QZ");
        opts.push(255);
        let s = parse_dhcp_request(&dhcp_frame(MAC, &opts)).expect("a DHCP discover");
        assert_eq!(s.mac, "3c:22:fb:01:02:03");
        assert_eq!(s.prl.as_deref(), Some("1,3,6,252"));
        assert_eq!(s.vendor_class.as_deref(), Some("MSFT 5.0"));
        assert_eq!(s.hostname.as_deref(), Some("DESKTOP-4F2K9QZ"));
    }

    #[test]
    fn ignores_replies_plain_bootp_and_other_traffic() {
        // DHCP ACK (5) isn't a client fingerprint.
        assert!(parse_dhcp_request(&dhcp_frame(MAC, &[53, 1, 5, 255])).is_none());
        // No message type: plain BOOTP.
        assert!(parse_dhcp_request(&dhcp_frame(MAC, &[55, 1, 1, 255])).is_none());
        // A server-to-client packet (op 2).
        let mut f = dhcp_frame(MAC, &[53, 1, 1, 255]);
        f[14 + 20 + 8] = 2;
        assert!(parse_dhcp_request(&f).is_none());
        // A fragment.
        let mut f = dhcp_frame(MAC, &[53, 1, 1, 255]);
        f[14 + 6] = 0x20;
        assert!(parse_dhcp_request(&f).is_none());
        // An all-zero client MAC.
        assert!(parse_dhcp_request(&dhcp_frame([0; 6], &[53, 1, 1, 255])).is_none());
        // ARP isn't DHCP.
        assert!(parse_dhcp_request(&build_arp_request(MAC, [10, 0, 0, 1])).is_none());
    }

    #[test]
    fn control_characters_in_dhcp_text_are_dropped() {
        // A hostname with a BEL and a newline in it.
        let mut opts = vec![53, 1, 3, 12, 6, b'p', b'c', 0x07, b'\n', b'0', b'1', 255];
        let s = parse_dhcp_request(&dhcp_frame(MAC, &opts)).unwrap();
        assert_eq!(s.hostname.as_deref(), Some("pc01"));
        // An option running past the packet ends parsing without a panic.
        opts = vec![53, 1, 3, 60, 200, b'x'];
        assert!(parse_dhcp_request(&dhcp_frame(MAC, &opts)).is_none());
    }

    #[test]
    fn a_request_names_the_server_its_client_chose() {
        // REQUEST with option 54 = 10.0.0.1.
        let s = parse_dhcp_request(&dhcp_frame(MAC, &[53, 1, 3, 54, 4, 10, 0, 0, 1, 255])).unwrap();
        assert_eq!(s.server_id, Some(Ipv4Addr::new(10, 0, 0, 1)));
        // A DISCOVER has no chosen server, whatever it carries.
        let s = parse_dhcp_request(&dhcp_frame(MAC, &[53, 1, 1, 54, 4, 10, 0, 0, 1, 255])).unwrap();
        assert_eq!(s.server_id, None);
    }

    /// A DHCP server's reply (BOOTREPLY) from `server_mac`/`src` to the
    /// client `client`, through a relay when `giaddr` isn't zero.
    fn reply_frame(
        server_mac: [u8; 6],
        src: [u8; 4],
        client: [u8; 6],
        giaddr: [u8; 4],
        options: &[u8],
    ) -> Vec<u8> {
        let mut f = dhcp_frame(client, options);
        let eth = 14;
        let ip = eth;
        let udp = ip + 20;
        let bootp = udp + 8;
        f[6..12].copy_from_slice(&server_mac);
        f[ip + 12..ip + 16].copy_from_slice(&src);
        f[udp..udp + 2].copy_from_slice(&67u16.to_be_bytes());
        f[udp + 2..udp + 4].copy_from_slice(&68u16.to_be_bytes());
        f[bootp] = 2; // BOOTREPLY
        f[bootp + 24..bootp + 28].copy_from_slice(&giaddr);
        f
    }

    const SERVER_MAC: [u8; 6] = [0x02, 0xde, 0xad, 0xbe, 0xef, 0x01];

    #[test]
    fn server_replies_name_the_server() {
        // An OFFER from 192.168.1.1, option 54 = 192.168.1.1, unrelayed.
        let f = reply_frame(
            SERVER_MAC,
            [192, 168, 1, 1],
            MAC,
            [0; 4],
            &[53, 1, 2, 54, 4, 192, 168, 1, 1, 255],
        );
        let s = parse_dhcp_server_reply(&f).expect("an OFFER");
        assert_eq!(s.server_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(s.server_mac.as_deref(), Some("02:de:ad:be:ef:01"));
        assert_eq!(s.client_mac, "3c:22:fb:01:02:03");
        // No option 54: the packet's source.
        let f = reply_frame(SERVER_MAC, [192, 168, 1, 2], MAC, [0; 4], &[53, 1, 5, 255]);
        assert_eq!(
            parse_dhcp_server_reply(&f).unwrap().server_ip,
            Ipv4Addr::new(192, 168, 1, 2)
        );
        // Relayed: the Ethernet source is the relay, so no server MAC.
        let f = reply_frame(
            SERVER_MAC,
            [10, 0, 0, 254],
            MAC,
            [10, 0, 0, 254],
            &[53, 1, 2, 54, 4, 10, 1, 1, 1, 255],
        );
        let s = parse_dhcp_server_reply(&f).unwrap();
        assert_eq!(s.server_ip, Ipv4Addr::new(10, 1, 1, 1));
        assert_eq!(s.server_mac, None);
        // A client's request isn't a server reply, and the reverse.
        assert!(parse_dhcp_server_reply(&dhcp_frame(MAC, &[53, 1, 1, 255])).is_none());
        let offer = reply_frame(SERVER_MAC, [192, 168, 1, 1], MAC, [0; 4], &[53, 1, 2, 255]);
        assert!(parse_dhcp_request(&offer).is_none());
        // Truncated anywhere: nothing, never a panic.
        for cut in 0..offer.len() {
            let _ = parse_dhcp_server_reply(&offer[..cut]);
        }
    }

    #[test]
    fn truncated_dhcp_never_panics() {
        let frame = dhcp_frame(MAC, &[53, 1, 1, 55, 2, 1, 3, 60, 3, b'a', b'b', b'c', 255]);
        assert!(parse_dhcp_request(&frame).is_some());
        for cut in 0..frame.len() {
            let _ = parse_dhcp_request(&frame[..cut]);
        }
    }

    #[test]
    fn truncated_frame_yields_none_not_panic() {
        let frame = build_arp_request([1, 2, 3, 4, 5, 6], [10, 0, 0, 1]);
        for cut in 0..frame.len() {
            assert!(parse_arp_sender(&frame[..cut]).is_none() || cut == frame.len());
        }
    }
}
