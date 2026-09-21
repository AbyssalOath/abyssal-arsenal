//! Passive mDNS listening -- an ordinary UDP multicast socket join (no
//! elevated privileges needed, unlike ARP sniffing, see
//! `panopticon_arp.rs`), following the same receiver shape a raw
//! UDP/TCP syslog listener would: bind once at startup, loop, parse each
//! datagram, spawn a task to ingest it so the receive loop never blocks on
//! a DB write. Devices that self-announce over mDNS (`*.local` A records
//! -- most consumer IoT, printers, Macs, Chromecasts) show up here even if
//! they never respond to an active probe and never send enough ordinary
//! traffic for `ip neigh` to learn them passively either.
//!
//! Deliberately doesn't look up a MAC address per packet (that would mean
//! spawning `ip neigh show` on every mDNS datagram, and consumer devices
//! chatter over mDNS often) -- the passive refresh loop
//! (`panopticon_ops.rs`, every 60s) independently keeps MAC addresses
//! fresh for anything on the local subnet; `note_sighting`'s `COALESCE`
//! semantics mean neither loop clobbers what the other already knows.

use std::net::Ipv4Addr;
use std::time::Duration;

use abyssal_database::{DbPool, repo};
use tokio::net::UdpSocket;

const MDNS_PORT: u16 = 5353;
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MAX_PACKET: usize = 65_535;
/// Bound on compression-pointer jumps while decoding one DNS name --
/// RFC 1035 names are already length-bounded; this just refuses to follow
/// a maliciously (or corruptly) circular pointer chain forever.
const MAX_NAME_POINTER_JUMPS: u8 = 8;

struct AnnouncedHost {
    /// Full name from the record, e.g. `"MacBook-Pro.local"`.
    name: String,
    ip: Ipv4Addr,
}

/// Decodes one DNS name starting at `offset`, following RFC 1035
/// compression pointers. Returns the dotted name and the offset in the
/// *original* stream immediately after the name as it appeared there
/// (i.e. after a pointer, not after wherever the pointer led) -- that's
/// the offset the caller needs to continue parsing subsequent records.
fn parse_name(buf: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut resume_at: Option<usize> = None;
    let mut jumps = 0u8;

    loop {
        let len = *buf.get(cursor)?;
        if len == 0 {
            let end = cursor + 1;
            return Some((labels.join("."), resume_at.unwrap_or(end)));
        }
        if len & 0xC0 == 0xC0 {
            let lo = *buf.get(cursor + 1)?;
            if resume_at.is_none() {
                resume_at = Some(cursor + 2);
            }
            jumps += 1;
            if jumps > MAX_NAME_POINTER_JUMPS {
                return None;
            }
            cursor = ((usize::from(len) & 0x3F) << 8) | usize::from(lo);
            continue;
        }
        let len = usize::from(len);
        let label_start = cursor + 1;
        let label = buf.get(label_start..label_start + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        cursor = label_start + len;
    }
}

/// Pulls every `*.local` A record out of an mDNS message's answer
/// section -- the self-announcement shape a device uses to say "this
/// hostname is me, at this address" (`Nmap scan report for ...`'s mDNS
/// equivalent). Anything else in the message (PTR/SRV/TXT service
/// records, AAAA, queries with no answers) is ignored; a malformed or
/// truncated packet just yields fewer records, never an error, since this
/// reads untrusted network input from any device on the multicast group.
fn parse_mdns_a_records(buf: &[u8]) -> Vec<AnnouncedHost> {
    let mut out = Vec::new();
    if buf.len() < 12 {
        return out;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        let Some((_, next)) = parse_name(buf, offset) else {
            return out;
        };
        offset = next + 4; // QTYPE + QCLASS
        if offset > buf.len() {
            return out;
        }
    }

    for _ in 0..ancount {
        let Some((name, next)) = parse_name(buf, offset) else {
            return out;
        };
        offset = next;
        if offset + 10 > buf.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > buf.len() {
            return out;
        }
        if rtype == 1 && rdlength == 4 && name.to_ascii_lowercase().ends_with(".local") {
            out.push(AnnouncedHost {
                ip: Ipv4Addr::new(
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ),
                name,
            });
        }
        offset += rdlength;
    }
    out
}

async fn ingest(pool: &DbPool, host: AnnouncedHost) {
    let ip = host.ip.to_string();
    let hostname = host.name.strip_suffix(".local").unwrap_or(&host.name);

    let prior = match repo::network_devices::find_by_ip(pool, &ip).await {
        Ok(prior) => prior,
        Err(e) => {
            tracing::warn!(error = %e, ip = %ip, "mDNS ingest failed to look up prior device state");
            return;
        }
    };
    if let Err(e) = repo::network_devices::note_sighting(pool, &ip, None, Some(hostname)).await {
        tracing::warn!(error = %e, ip = %ip, "mDNS ingest failed to record sighting");
        return;
    }
    if let Err(e) = crate::panopticon_ops::audit_sighting(pool, &ip, prior).await {
        tracing::warn!(error = %e, ip = %ip, "mDNS ingest failed to record audit event");
    }
}

/// Binds the mDNS multicast listener once at startup -- like the syslog
/// receiver this codebase's own reference material describes, this is a
/// real socket bind, so enabling/disabling it (`panopticon.mdns_enabled`)
/// takes a server restart, not just a settings save. A bind failure
/// (port already in use, no multicast-capable interface) is logged and
/// the task simply exits -- best-effort, same as every other background
/// listener here, never fatal to the rest of the control plane.
pub fn spawn_panopticon_mdns_listener(pool: DbPool) {
    tokio::spawn(async move {
        let socket = match UdpSocket::bind(("0.0.0.0", MDNS_PORT)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, port = MDNS_PORT, "Panopticon mDNS listener failed to bind");
                return;
            }
        };
        if let Err(e) = socket.join_multicast_v4(MDNS_GROUP, Ipv4Addr::UNSPECIFIED) {
            tracing::error!(error = %e, "Panopticon mDNS listener failed to join multicast group");
            return;
        }
        tracing::info!(port = MDNS_PORT, group = %MDNS_GROUP, "Panopticon mDNS listener started");

        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            let (n, _src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "Panopticon mDNS recv error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let hosts = parse_mdns_a_records(&buf[..n]);
            if hosts.is_empty() {
                continue;
            }
            let pool = pool.clone();
            tokio::spawn(async move {
                for host in hosts {
                    ingest(&pool, host).await;
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built mDNS response: one question (ignored) and one A record
    /// answer for `"host.local"` -> `10.0.0.5`, with the answer's NAME
    /// using a compression pointer back into the question section rather
    /// than repeating the labels -- real mDNS responders do exactly this,
    /// so the fixture is only realistic if it exercises the pointer path.
    fn build_packet() -> Vec<u8> {
        let mut buf = vec![
            0x00, 0x00, // ID
            0x84, 0x00, // flags: response, authoritative
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        // Question: "host.local" starts at offset 12, immediately after
        // the 12-byte header -- the answer's NAME below points back here.
        for label in ["host", "local"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // root
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

        // Answer: pointer to offset 12 (where "host.local" starts), TYPE=A(1),
        // CLASS=IN(1) with cache-flush bit set (0x8001, as real mDNS does),
        // TTL, RDLENGTH=4, RDATA=10.0.0.5.
        buf.push(0xC0);
        buf.push(12);
        buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        buf.extend_from_slice(&0x8001u16.to_be_bytes()); // CLASS IN | flush
        buf.extend_from_slice(&120u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        buf.extend_from_slice(&[10, 0, 0, 5]);
        buf
    }

    #[test]
    fn parses_a_record_with_compressed_name() {
        let packet = build_packet();
        let records = parse_mdns_a_records(&packet);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "host.local");
        assert_eq!(records[0].ip, Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn ignores_non_local_names() {
        let mut buf = vec![
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in ["example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        assert!(parse_mdns_a_records(&buf).is_empty());
    }

    #[test]
    fn truncated_packet_yields_no_panic_and_no_records() {
        let packet = build_packet();
        for cut in 0..packet.len() {
            let _ = parse_mdns_a_records(&packet[..cut]);
        }
    }

    #[test]
    fn rejects_pointer_loop_without_hanging() {
        // A name whose pointer points at itself -- must terminate via the
        // jump-count guard, not spin forever.
        let buf = vec![0xC0, 0x00];
        assert!(parse_name(&buf, 0).is_none());
    }
}
