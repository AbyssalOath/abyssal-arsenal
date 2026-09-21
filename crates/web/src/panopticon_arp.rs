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

use std::net::Ipv4Addr;
use std::time::Duration;

use abyssal_database::{DbPool, repo};
use pnet_datalink::{Channel, Config, MacAddr};
use tokio::sync::mpsc;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;

struct ArpSighting {
    mac: MacAddr,
    ip: Ipv4Addr,
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

async fn ingest(pool: &DbPool, sighting: ArpSighting) {
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
    if let Err(e) = crate::panopticon_ops::audit_sighting(pool, &ip, prior).await {
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
pub fn spawn_panopticon_arp_listener(pool: DbPool, interface_name: String) {
    let (tx, mut rx) = mpsc::unbounded_channel::<ArpSighting>();

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
                    if let Some(sighting) = parse_arp_sender(frame)
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
            ingest(&pool, sighting).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn truncated_frame_yields_none_not_panic() {
        let frame = build_arp_request([1, 2, 3, 4, 5, 6], [10, 0, 0, 1]);
        for cut in 0..frame.len() {
            assert!(parse_arp_sender(&frame[..cut]).is_none() || cut == frame.len());
        }
    }
}
