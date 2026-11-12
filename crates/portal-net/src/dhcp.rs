//! A small DHCP server (RFC 2131/2132) for the registration VLAN: just what
//! a captive network needs. One address pool, short leases, Panopticon as
//! router and DNS server, and the portal's URL as the captive-portal option
//! (RFC 8910, option 114). Leases live in memory: they're short, and a
//! client whose lease is forgotten by a restart simply gets a new one.
//!
//! Everything here reads untrusted packets from unregistered devices, so
//! parsing is bounds-checked throughout and the pool is capped by its range.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const CLIENT_PORT: u16 = 68;
/// BOOTP's minimum message size; some clients drop shorter replies.
const MIN_REPLY_LEN: usize = 300;
/// How long an offered address is held for the client that was offered it.
const OFFER_HOLD: Duration = Duration::from_secs(30);
/// How long a declined address (in use by someone else) stays out of the pool.
const DECLINE_HOLD: Duration = Duration::from_secs(600);

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const DECLINE: u8 = 4;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;
pub const RELEASE: u8 = 7;
pub const INFORM: u8 = 8;

/// The server's settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Panopticon's own address on the registration VLAN: the server
    /// identifier, router and DNS server handed out.
    pub server_ip: Ipv4Addr,
    pub prefix_len: u8,
    /// The pool, inclusive.
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub lease: Duration,
    /// The captive-portal URL (RFC 8910), e.g. `http://10.99.0.1/`.
    pub portal_url: String,
}

impl Config {
    pub fn netmask(&self) -> Ipv4Addr {
        let bits = u32::MAX
            .checked_shl(32 - u32::from(self.prefix_len))
            .unwrap_or(0);
        Ipv4Addr::from(bits)
    }

    fn in_range(&self, ip: Ipv4Addr) -> bool {
        (u32::from(self.range_start)..=u32::from(self.range_end)).contains(&u32::from(ip))
            && ip != self.server_ip
    }

    /// Checks the settings make sense: a range inside the server's subnet,
    /// in order, not containing the server, and not absurdly large.
    pub fn validate(&self) -> Result<(), String> {
        if !(8..=30).contains(&self.prefix_len) {
            return Err("the prefix length must be 8 to 30".into());
        }
        let mask = u32::from(self.netmask());
        let net = u32::from(self.server_ip) & mask;
        let (start, end) = (u32::from(self.range_start), u32::from(self.range_end));
        if start & mask != net || end & mask != net {
            return Err("the DHCP range must be inside the portal's subnet".into());
        }
        if start > end {
            return Err("the DHCP range's start is after its end".into());
        }
        if (start..=end).contains(&u32::from(self.server_ip)) {
            return Err("the DHCP range must not contain the portal's own address".into());
        }
        let broadcast = net | !mask;
        if start == net || end == broadcast {
            return Err("the DHCP range must not contain the network or broadcast address".into());
        }
        if end - start > 16_384 {
            return Err("the DHCP range is larger than 16384 addresses".into());
        }
        if self.lease < Duration::from_secs(30) || self.lease > Duration::from_secs(86_400) {
            return Err("the lease time must be 30 seconds to 1 day".into());
        }
        Ok(())
    }
}

pub type Mac = [u8; 6];

pub fn mac_string(mac: &Mac) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What a client's DHCP request says that the server (and fingerprinting)
/// cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub message_type: u8,
    pub xid: [u8; 4],
    pub flags: [u8; 2],
    pub ciaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: Mac,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    /// Option 55 as comma-separated decimal codes.
    pub prl: Option<String>,
    pub vendor_class: Option<String>,
    pub hostname: Option<String>,
}

fn ipv4(b: &[u8]) -> Option<Ipv4Addr> {
    let a: [u8; 4] = b.try_into().ok()?;
    Some(Ipv4Addr::from(a))
}

/// Printable ASCII only, trimmed and capped: client-controlled text that
/// ends up on web pages.
pub fn sanitize_text(raw: &[u8]) -> Option<String> {
    let s: String = raw
        .iter()
        .filter(|b| (0x20..0x7f).contains(*b))
        .map(|b| *b as char)
        .take(255)
        .collect();
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Parses a BOOTP payload (the UDP data) as a client DHCP request. `None`
/// for anything else: replies, plain BOOTP, non-Ethernet, malformed.
pub fn parse_request(bootp: &[u8]) -> Option<Request> {
    if bootp.len() < 240
        || bootp[0] != BOOTREQUEST
        || bootp[1] != 1
        || bootp[2] != 6
        || bootp[236..240] != MAGIC_COOKIE
    {
        return None;
    }
    let chaddr: Mac = bootp[28..34].try_into().ok()?;
    // All-zero, or a group (multicast/broadcast) address: not a client.
    if chaddr == [0; 6] || chaddr[0] & 1 == 1 {
        return None;
    }
    let mut req = Request {
        message_type: 0,
        xid: bootp[4..8].try_into().ok()?,
        flags: bootp[10..12].try_into().ok()?,
        ciaddr: ipv4(&bootp[12..16])?,
        giaddr: ipv4(&bootp[24..28])?,
        chaddr,
        requested_ip: None,
        server_id: None,
        prl: None,
        vendor_class: None,
        hostname: None,
    };
    let mut i = 240;
    while i < bootp.len() {
        let code = bootp[i];
        if code == 0 {
            i += 1;
            continue;
        }
        if code == 255 {
            break;
        }
        let len = usize::from(*bootp.get(i + 1)?);
        let value = bootp.get(i + 2..i + 2 + len)?;
        match code {
            53 if len == 1 => req.message_type = value[0],
            50 => req.requested_ip = ipv4(value),
            54 => req.server_id = ipv4(value),
            55 if len > 0 => {
                req.prl = Some(
                    value
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                )
            }
            60 => req.vendor_class = sanitize_text(value),
            12 => req.hostname = sanitize_text(value),
            _ => {}
        }
        i += 2 + len;
    }
    (1..=8).contains(&req.message_type).then_some(req)
}

#[derive(Debug, Clone, Copy)]
struct Lease {
    ip: Ipv4Addr,
    expires: Instant,
    /// Acknowledged (in use), rather than only offered.
    bound: bool,
}

/// The address pool: one lease per client MAC.
#[derive(Debug)]
pub struct LeasePool {
    cfg: Config,
    leases: HashMap<Mac, Lease>,
    declined: HashMap<Ipv4Addr, Instant>,
}

impl LeasePool {
    pub fn new(cfg: Config) -> Self {
        LeasePool {
            cfg,
            leases: HashMap::new(),
            declined: HashMap::new(),
        }
    }

    fn holder(&self, ip: Ipv4Addr, now: Instant) -> Option<Mac> {
        self.leases
            .iter()
            .find(|(_, l)| l.ip == ip && l.expires > now)
            .map(|(m, _)| *m)
    }

    fn usable_for(&self, mac: &Mac, ip: Ipv4Addr, now: Instant) -> bool {
        self.cfg.in_range(ip)
            && self.declined.get(&ip).is_none_or(|until| *until <= now)
            && self.holder(ip, now).is_none_or(|m| m == *mac)
    }

    /// The address to offer `mac`: its current one, the one it asked for if
    /// free, or the first free one. `None` when the pool is exhausted.
    pub fn offer(
        &mut self,
        mac: Mac,
        requested: Option<Ipv4Addr>,
        now: Instant,
    ) -> Option<Ipv4Addr> {
        let current = self.leases.get(&mac).map(|l| l.ip);
        let ip = current
            .filter(|ip| self.usable_for(&mac, *ip, now))
            .or_else(|| requested.filter(|ip| self.usable_for(&mac, *ip, now)))
            .or_else(|| {
                (u32::from(self.cfg.range_start)..=u32::from(self.cfg.range_end))
                    .map(Ipv4Addr::from)
                    .find(|ip| self.usable_for(&mac, *ip, now))
            })?;
        let bound = self.leases.get(&mac).is_some_and(|l| l.bound && l.ip == ip);
        let expires = if bound {
            self.leases[&mac].expires
        } else {
            now + OFFER_HOLD
        };
        self.leases.insert(mac, Lease { ip, expires, bound });
        Some(ip)
    }

    /// Binds `ip` to `mac` for a full lease, if it may have it.
    pub fn request(&mut self, mac: Mac, ip: Ipv4Addr, now: Instant) -> bool {
        if !self.usable_for(&mac, ip, now) {
            return false;
        }
        self.leases.insert(
            mac,
            Lease {
                ip,
                expires: now + self.cfg.lease,
                bound: true,
            },
        );
        true
    }

    pub fn release(&mut self, mac: &Mac) {
        self.leases.remove(mac);
    }

    /// The client found `ip` already in use (ARP): keep it out for a while.
    pub fn decline(&mut self, mac: &Mac, ip: Ipv4Addr, now: Instant) {
        if self.leases.get(mac).is_some_and(|l| l.ip == ip) {
            self.leases.remove(mac);
        }
        self.declined.insert(ip, now + DECLINE_HOLD);
    }

    /// Which client holds a bound lease on `ip` -- how the portal knows who
    /// is registering.
    pub fn mac_for_ip(&self, ip: Ipv4Addr, now: Instant) -> Option<Mac> {
        self.leases
            .iter()
            .find(|(_, l)| l.bound && l.ip == ip && l.expires > now)
            .map(|(m, _)| *m)
    }

    pub fn active_leases(&self, now: Instant) -> usize {
        self.leases
            .values()
            .filter(|l| l.bound && l.expires > now)
            .count()
    }

    /// Drops expired leases and declines (the pool sweeps itself as it serves).
    fn prune(&mut self, now: Instant) {
        self.leases.retain(|_, l| l.expires > now);
        self.declined.retain(|_, until| *until > now);
    }
}

/// A reply to send, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub bytes: Vec<u8>,
    pub to: SocketAddr,
}

fn push_opt(out: &mut Vec<u8>, code: u8, value: &[u8]) {
    let value = &value[..value.len().min(255)];
    out.push(code);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// Builds a BOOTREPLY. `yiaddr` is the address given (zero for INFORM and
/// NAK); `lease` adds the lease options; `config` adds the network ones.
fn build(
    cfg: &Config,
    req: &Request,
    kind: u8,
    yiaddr: Ipv4Addr,
    lease: bool,
    config: bool,
) -> Vec<u8> {
    let mut out = vec![0u8; 236];
    out[0] = BOOTREPLY;
    out[1] = 1;
    out[2] = 6;
    out[4..8].copy_from_slice(&req.xid);
    out[10..12].copy_from_slice(&req.flags);
    if kind == ACK {
        out[12..16].copy_from_slice(&req.ciaddr.octets());
    }
    out[16..20].copy_from_slice(&yiaddr.octets());
    out[28..34].copy_from_slice(&req.chaddr);
    out.extend_from_slice(&MAGIC_COOKIE);
    push_opt(&mut out, 53, &[kind]);
    push_opt(&mut out, 54, &cfg.server_ip.octets());
    if lease {
        let secs = cfg.lease.as_secs().min(u64::from(u32::MAX)) as u32;
        push_opt(&mut out, 51, &secs.to_be_bytes());
        push_opt(&mut out, 58, &(secs / 2).to_be_bytes());
        push_opt(&mut out, 59, &(secs / 8 * 7).to_be_bytes());
    }
    if config {
        push_opt(&mut out, 1, &cfg.netmask().octets());
        push_opt(&mut out, 3, &cfg.server_ip.octets());
        push_opt(&mut out, 6, &cfg.server_ip.octets());
        push_opt(&mut out, 114, cfg.portal_url.as_bytes());
    }
    out.push(255);
    if out.len() < MIN_REPLY_LEN {
        out.resize(MIN_REPLY_LEN, 0);
    }
    out
}

fn broadcast() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT))
}

/// What to answer a request with, updating the pool. `None` = stay silent.
pub fn handle(cfg: &Config, pool: &mut LeasePool, req: &Request, now: Instant) -> Option<Reply> {
    pool.prune(now);
    // Relayed requests come from other networks: never ours to answer.
    if req.giaddr != Ipv4Addr::UNSPECIFIED {
        return None;
    }
    let mac = req.chaddr;
    // A client with an address gets a unicast answer; one without, broadcast.
    let to = if req.ciaddr.is_unspecified() {
        broadcast()
    } else {
        SocketAddr::V4(SocketAddrV4::new(req.ciaddr, CLIENT_PORT))
    };
    let nak = || Reply {
        bytes: build(cfg, req, NAK, Ipv4Addr::UNSPECIFIED, false, false),
        to: broadcast(),
    };
    match req.message_type {
        DISCOVER => {
            let ip = pool.offer(mac, req.requested_ip, now)?;
            Some(Reply {
                bytes: build(cfg, req, OFFER, ip, true, true),
                to,
            })
        }
        REQUEST => {
            // SELECTING: answering someone's offer -- if not ours, step aside.
            if let Some(server) = req.server_id
                && server != cfg.server_ip
            {
                pool.release(&mac);
                return None;
            }
            // SELECTING / INIT-REBOOT name the address in option 50;
            // RENEWING / REBINDING use ciaddr.
            let ip = req
                .requested_ip
                .or(Some(req.ciaddr).filter(|ip| !ip.is_unspecified()))?;
            if pool.request(mac, ip, now) {
                Some(Reply {
                    bytes: build(cfg, req, ACK, ip, true, true),
                    to,
                })
            } else {
                Some(nak())
            }
        }
        RELEASE => {
            if req.server_id.is_none_or(|s| s == cfg.server_ip) {
                pool.release(&mac);
            }
            None
        }
        DECLINE => {
            if let Some(ip) = req.requested_ip {
                pool.decline(&mac, ip, now);
            }
            None
        }
        INFORM if !req.ciaddr.is_unspecified() => Some(Reply {
            bytes: build(cfg, req, ACK, Ipv4Addr::UNSPECIFIED, false, true),
            to,
        }),
        _ => None,
    }
}

/// A client's DHCP fingerprint, for Panopticon's device classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub mac: String,
    pub prl: Option<String>,
    pub vendor_class: Option<String>,
    pub hostname: Option<String>,
}

/// Serves DHCP on `socket` (from [`crate::bound_udp`] on port 67) until the
/// socket fails. Every request's fingerprint goes to `fingerprints`, if given.
pub async fn serve(
    socket: tokio::net::UdpSocket,
    cfg: Config,
    pool: Arc<Mutex<LeasePool>>,
    fingerprints: Option<mpsc::UnboundedSender<Fingerprint>>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, _) = socket.recv_from(&mut buf).await?;
        let Some(req) = parse_request(&buf[..n]) else {
            continue;
        };
        if let Some(tx) = &fingerprints {
            let _ = tx.send(Fingerprint {
                mac: mac_string(&req.chaddr),
                prl: req.prl.clone(),
                vendor_class: req.vendor_class.clone(),
                hostname: req.hostname.clone(),
            });
        }
        let reply = {
            let mut pool = pool.lock().unwrap_or_else(|p| p.into_inner());
            handle(&cfg, &mut pool, &req, Instant::now())
        };
        if let Some(reply) = reply
            && let Err(e) = socket.send_to(&reply.bytes, reply.to).await
        {
            tracing::warn!(error = %e, to = %reply.to, "registration DHCP: send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            server_ip: Ipv4Addr::new(10, 99, 0, 1),
            prefix_len: 24,
            range_start: Ipv4Addr::new(10, 99, 0, 100),
            range_end: Ipv4Addr::new(10, 99, 0, 102),
            lease: Duration::from_secs(60),
            portal_url: "http://10.99.0.1/".into(),
        }
    }

    const A: Mac = [0x02, 0, 0, 0, 0, 0xaa];
    const B: Mac = [0x02, 0, 0, 0, 0, 0xbb];

    /// A client request as it appears on the wire.
    fn packet(mac: Mac, kind: u8, ciaddr: [u8; 4], opts: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 236];
        p[0] = BOOTREQUEST;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&[1, 2, 3, 4]);
        p[12..16].copy_from_slice(&ciaddr);
        p[28..34].copy_from_slice(&mac);
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[53, 1, kind]);
        p.extend_from_slice(opts);
        p.push(255);
        p
    }

    fn req(mac: Mac, kind: u8, opts: &[u8]) -> Request {
        parse_request(&packet(mac, kind, [0; 4], opts)).unwrap()
    }

    /// Reads a reply's message type, yiaddr and options.
    fn read(reply: &Reply) -> (u8, Ipv4Addr, HashMap<u8, Vec<u8>>) {
        let b = &reply.bytes;
        assert_eq!(b[0], BOOTREPLY);
        assert_eq!(&b[236..240], &MAGIC_COOKIE);
        assert!(b.len() >= MIN_REPLY_LEN);
        let mut opts = HashMap::new();
        let mut i = 240;
        while b[i] != 255 {
            let len = b[i + 1] as usize;
            opts.insert(b[i], b[i + 2..i + 2 + len].to_vec());
            i += 2 + len;
        }
        (opts[&53][0], ipv4(&b[16..20]).unwrap(), opts)
    }

    #[test]
    fn discover_request_ack_with_the_captive_options() {
        let c = cfg();
        let mut pool = LeasePool::new(c.clone());
        let now = Instant::now();
        let offer = handle(&c, &mut pool, &req(A, DISCOVER, &[]), now).unwrap();
        let (kind, ip, opts) = read(&offer);
        assert_eq!((kind, ip), (OFFER, Ipv4Addr::new(10, 99, 0, 100)));
        assert_eq!(offer.to, broadcast());
        assert_eq!(opts[&1], vec![255, 255, 255, 0]);
        assert_eq!(opts[&3], vec![10, 99, 0, 1]);
        assert_eq!(opts[&6], vec![10, 99, 0, 1]);
        assert_eq!(opts[&114], b"http://10.99.0.1/".to_vec());
        assert_eq!(opts[&51], 60u32.to_be_bytes().to_vec());

        let r = req(A, REQUEST, &[50, 4, 10, 99, 0, 100, 54, 4, 10, 99, 0, 1]);
        let (kind, ip, _) = read(&handle(&c, &mut pool, &r, now).unwrap());
        assert_eq!((kind, ip), (ACK, Ipv4Addr::new(10, 99, 0, 100)));
        assert_eq!(pool.mac_for_ip(ip, now), Some(A));
        // The same client asking again gets the same address.
        let (_, again, _) = read(&handle(&c, &mut pool, &req(A, DISCOVER, &[]), now).unwrap());
        assert_eq!(again, ip);
    }

    #[test]
    fn clients_never_share_an_address_and_the_pool_runs_out() {
        let c = cfg();
        let mut pool = LeasePool::new(c.clone());
        let now = Instant::now();
        let mut seen = Vec::new();
        for i in 0..3u8 {
            let mac = [0x02, 0, 0, 0, 1, i];
            let ip = pool.offer(mac, None, now).unwrap();
            assert!(pool.request(mac, ip, now));
            seen.push(ip);
        }
        seen.dedup();
        assert_eq!(seen.len(), 3);
        // Range of 3 is full: a fourth client is silently not offered.
        assert!(handle(&c, &mut pool, &req(B, DISCOVER, &[]), now).is_none());
        // B can't take A's address either.
        assert!(!pool.request(B, seen[0], now));
        // Once leases expire, addresses come back.
        let later = now + Duration::from_secs(61);
        assert!(handle(&c, &mut pool, &req(B, DISCOVER, &[]), later).is_some());
    }

    #[test]
    fn requests_for_foreign_or_taken_addresses_are_nakked() {
        let c = cfg();
        let mut pool = LeasePool::new(c.clone());
        let now = Instant::now();
        // INIT-REBOOT with an address from another network.
        let r = req(A, REQUEST, &[50, 4, 192, 168, 1, 50]);
        let reply = handle(&c, &mut pool, &r, now).unwrap();
        assert_eq!(read(&reply).0, NAK);
        assert_eq!(reply.to, broadcast());
        // Asking for the server's own address.
        let r = req(A, REQUEST, &[50, 4, 10, 99, 0, 1]);
        assert_eq!(read(&handle(&c, &mut pool, &r, now).unwrap()).0, NAK);
    }

    #[test]
    fn another_servers_offer_and_relayed_requests_are_ignored() {
        let c = cfg();
        let mut pool = LeasePool::new(c.clone());
        let now = Instant::now();
        handle(&c, &mut pool, &req(A, DISCOVER, &[]), now).unwrap();
        // The client chose another server's offer: we let ours go.
        let r = req(A, REQUEST, &[50, 4, 10, 99, 0, 100, 54, 4, 10, 99, 0, 9]);
        assert!(handle(&c, &mut pool, &r, now).is_none());
        assert_eq!(
            pool.offer(B, None, now),
            Some(Ipv4Addr::new(10, 99, 0, 100))
        );
        // A relayed request.
        let mut p = packet(A, DISCOVER, [0; 4], &[]);
        p[24..28].copy_from_slice(&[10, 0, 0, 1]);
        assert!(handle(&c, &mut pool, &parse_request(&p).unwrap(), now).is_none());
    }

    #[test]
    fn renewals_are_unicast_and_release_and_decline_free_addresses() {
        let c = cfg();
        let mut pool = LeasePool::new(c.clone());
        let now = Instant::now();
        let ip = pool.offer(A, None, now).unwrap();
        assert!(pool.request(A, ip, now));
        let renew = parse_request(&packet(A, REQUEST, ip.octets(), &[])).unwrap();
        let reply = handle(&c, &mut pool, &renew, now).unwrap();
        assert_eq!(read(&reply).0, ACK);
        assert_eq!(reply.to, SocketAddr::V4(SocketAddrV4::new(ip, 68)));
        // INFORM: options only, no address.
        let inform = parse_request(&packet(A, INFORM, ip.octets(), &[])).unwrap();
        let (kind, yi, opts) = read(&handle(&c, &mut pool, &inform, now).unwrap());
        assert_eq!((kind, yi), (ACK, Ipv4Addr::UNSPECIFIED));
        assert!(!opts.contains_key(&51));
        // RELEASE frees it.
        let rel = parse_request(&packet(A, RELEASE, ip.octets(), &[])).unwrap();
        assert!(handle(&c, &mut pool, &rel, now).is_none());
        assert_eq!(pool.mac_for_ip(ip, now), None);
        // DECLINE keeps an address out of the pool.
        let dec = req(B, DECLINE, &[50, 4, 10, 99, 0, 100]);
        assert!(handle(&c, &mut pool, &dec, now).is_none());
        assert_ne!(
            pool.offer(A, None, now),
            Some(Ipv4Addr::new(10, 99, 0, 100))
        );
    }

    #[test]
    fn parsing_is_strict_and_never_panics() {
        let p = packet(
            A,
            DISCOVER,
            [0; 4],
            &[
                55, 3, 1, 3, 6, 60, 4, b'M', b'S', 7, b'X', 12, 2, b'p', b'c',
            ],
        );
        let r = parse_request(&p).unwrap();
        assert_eq!(r.prl.as_deref(), Some("1,3,6"));
        assert_eq!(r.vendor_class.as_deref(), Some("MSX"));
        assert_eq!(r.hostname.as_deref(), Some("pc"));
        for cut in 0..p.len() {
            let _ = parse_request(&p[..cut]);
        }
        let mut reply = p.clone();
        reply[0] = BOOTREPLY;
        assert!(parse_request(&reply).is_none());
        assert!(parse_request(&packet([0xff; 6], DISCOVER, [0; 4], &[])).is_none());
        assert!(parse_request(&packet(A, 0, [0; 4], &[])).is_none());
        // An option running past the end.
        let mut long = packet(A, DISCOVER, [0; 4], &[]);
        long.pop();
        long.extend_from_slice(&[60, 200, b'x']);
        assert!(parse_request(&long).is_none());
    }

    #[test]
    fn config_validation() {
        assert!(cfg().validate().is_ok());
        let mut c = cfg();
        c.range_end = Ipv4Addr::new(10, 99, 1, 5);
        assert!(c.validate().is_err(), "outside the subnet");
        let mut c = cfg();
        c.range_start = Ipv4Addr::new(10, 99, 0, 1);
        assert!(c.validate().is_err(), "contains the server");
        let mut c = cfg();
        c.range_end = Ipv4Addr::new(10, 99, 0, 255);
        assert!(c.validate().is_err(), "broadcast");
        let mut c = cfg();
        c.lease = Duration::from_secs(5);
        assert!(c.validate().is_err());
        assert_eq!(cfg().netmask(), Ipv4Addr::new(255, 255, 255, 0));
    }
}
