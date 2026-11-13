//! SNMP traps from the switches Panopticon polls (0.2.9 Q5,
//! `docs/roadmap/0.2.9.md`).
//!
//! Discovery and port location come from SNMP polls, so a device plugged in
//! between polls was invisible until the next one (five minutes), and so
//! were policies like "new unknown device". A switch can say so at once: a
//! linkUp/linkDown trap, or a Cisco MAC-notification trap naming the MAC
//! and port. A trap schedules an immediate poll of that switch, then a
//! policy pass.
//!
//! What's believed: only a packet from the address of an enabled switch
//! Panopticon already polls over v1/v2c, carrying that switch's own
//! community (compared in constant time) -- checked in that order, the
//! source before the packet is even parsed, so traps from anywhere else
//! cost a lookup in a cached list. SNMPv3 traps (USM, the switch's engine
//! ID) aren't handled: a v3 switch keeps being polled as before. A trap
//! only ever causes a *read* (a poll) and a policy pass, whose own rules
//! and guards decide anything else; a forged one can't do more than that.
//!
//! Load: at most one trap-triggered poll per switch per
//! `panopticon.snmp_trap_min_interval_seconds`; traps inside the window are
//! folded into one more poll at its end, so a flapping port can't make a
//! poll storm.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use abyssal_core::settings::{
    PANOPTICON_SNMP_TRAP_MIN_INTERVAL_SECONDS, PANOPTICON_SNMP_TRAP_MIN_INTERVAL_SECONDS_DEFAULT,
    PANOPTICON_SNMP_TRAP_PORT, PANOPTICON_SNMP_TRAP_PORT_DEFAULT, PANOPTICON_SNMP_TRAPS_ENABLED,
};
use abyssal_core::{EncryptionKey, PanopticonSwitch, SnmpVersion};
use abyssal_database::{DbPool, repo};
use snmp2::{MessageType, Oid, Pdu, Value};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use uuid::Uuid;

/// snmpTrapOID.0: a v2c trap's identity.
const SNMP_TRAP_OID: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
/// linkDown / linkUp (RFC 3418 / IF-MIB).
const LINK_DOWN: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 5, 3];
const LINK_UP: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 5, 4];
/// ifIndex (IF-MIB), the column a link trap carries.
const IF_INDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 1];
/// CISCO-MAC-NOTIFICATION-MIB: cmnMacChangedNotification, its v1
/// enterprise, and cmnHistMacChangedMsg (the changes, packed).
const CISCO_MAC_CHANGED: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 215, 2, 0, 1];
const CISCO_MAC_NOTIFICATION_ENTERPRISE: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 215, 2];
const CISCO_MAC_CHANGED_MSG: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 215, 1, 1, 8, 1, 2];

/// How long the cached list of switches is used before it's read again.
const SWITCH_CACHE: Duration = Duration::from_secs(30);

/// One MAC change from a Cisco MAC-notification trap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacChange {
    pub added: bool,
    pub vlan: u16,
    pub mac: String,
    /// dot1dBasePort (the bridge port, not the ifIndex).
    pub bridge_port: u16,
}

/// What a trap says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrapKind {
    LinkUp(Option<u32>),
    LinkDown(Option<u32>),
    MacChanges(Vec<MacChange>),
    /// Any other trap, by its OID: recorded, but no poll.
    Other(String),
}

impl TrapKind {
    /// Whether this trap means devices may have come or gone: a poll.
    pub(crate) fn wants_poll(&self) -> bool {
        !matches!(self, TrapKind::Other(_))
    }

    pub(crate) fn summary(&self) -> String {
        let port = |i: &Option<u32>| i.map_or(String::new(), |i| format!(" ifIndex {i}"));
        match self {
            TrapKind::LinkUp(i) => format!("linkUp{}", port(i)),
            TrapKind::LinkDown(i) => format!("linkDown{}", port(i)),
            TrapKind::MacChanges(changes) => {
                let list: Vec<String> = changes
                    .iter()
                    .take(4)
                    .map(|c| {
                        format!(
                            "{} {} VLAN {} port {}",
                            if c.added { "+" } else { "-" },
                            c.mac,
                            c.vlan,
                            c.bridge_port
                        )
                    })
                    .collect();
                let more = changes.len().saturating_sub(4);
                format!(
                    "MAC notification: {}{}",
                    list.join(", "),
                    if more > 0 {
                        format!(" (+{more})")
                    } else {
                        String::new()
                    }
                )
            }
            TrapKind::Other(oid) => format!("trap {oid}"),
        }
    }
}

/// A parsed trap: its community, and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Trap {
    pub community: Vec<u8>,
    pub kind: TrapKind,
}

fn components(oid: &Oid<'_>) -> Option<Vec<u64>> {
    Some(oid.iter()?.collect())
}

fn dotted(parts: &[u64]) -> String {
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The ifIndex a link trap carries (`ifIndex.N = N`), if any.
fn if_index(varbinds: &[(Vec<u64>, Option<i64>)]) -> Option<u32> {
    varbinds
        .iter()
        .find(|(oid, _)| oid.len() == IF_INDEX.len() + 1 && oid.starts_with(IF_INDEX))
        .and_then(|(oid, v)| v.or(oid.last().map(|n| *n as i64)))
        .and_then(|n| u32::try_from(n).ok())
}

/// Unpacks cmnHistMacChangedMsg: 11-byte records (operation: 1 learnt,
/// 2 removed; VLAN; MAC; bridge port), ending at a 0 operation or the end.
pub(crate) fn parse_mac_changes(msg: &[u8]) -> Vec<MacChange> {
    msg.as_chunks::<11>()
        .0
        .iter()
        .take_while(|r| r[0] != 0)
        .filter(|r| matches!(r[0], 1 | 2))
        .map(|r| MacChange {
            added: r[0] == 1,
            vlan: u16::from_be_bytes([r[1], r[2]]),
            mac: r[3..9]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
            bridge_port: u16::from_be_bytes([r[9], r[10]]),
        })
        .collect()
}

/// Parses a v1 or v2c trap. `None` for anything else (requests, informs,
/// v3, malformed). Untrusted input: `snmp2`'s reader checks every length.
pub(crate) fn parse_trap(bytes: &[u8]) -> Option<Trap> {
    let pdu = Pdu::from_bytes(bytes).ok()?;
    let community = pdu.community.to_vec();
    let mut binds: Vec<(Vec<u64>, Option<i64>)> = Vec::new();
    let mut trap_oid: Option<Vec<u64>> = None;
    let mut mac_msgs: Vec<u8> = Vec::new();
    for (oid, value) in pdu.varbinds.clone() {
        let Some(oid) = components(&oid) else {
            continue;
        };
        match value {
            Value::ObjectIdentifier(v) if oid == SNMP_TRAP_OID => trap_oid = components(&v),
            Value::Integer(n) => binds.push((oid, Some(n))),
            Value::OctetString(s)
                if oid.len() > CISCO_MAC_CHANGED_MSG.len()
                    && oid.starts_with(CISCO_MAC_CHANGED_MSG) =>
            {
                mac_msgs.extend_from_slice(s)
            }
            _ => binds.push((oid, None)),
        }
    }
    let kind = match pdu.message_type {
        MessageType::TrapV1 => {
            let info = pdu.v1_trap_info.as_ref()?;
            let enterprise = components(&info.enterprise).unwrap_or_default();
            match (info.generic_trap, info.specific_trap) {
                (2, _) => TrapKind::LinkDown(if_index(&binds)),
                (3, _) => TrapKind::LinkUp(if_index(&binds)),
                (6, 1) if enterprise == CISCO_MAC_NOTIFICATION_ENTERPRISE => {
                    TrapKind::MacChanges(parse_mac_changes(&mac_msgs))
                }
                (g, s) => {
                    TrapKind::Other(format!("{} generic {g} specific {s}", dotted(&enterprise)))
                }
            }
        }
        MessageType::Trap => {
            let oid = trap_oid?;
            if oid == LINK_DOWN {
                TrapKind::LinkDown(if_index(&binds))
            } else if oid == LINK_UP {
                TrapKind::LinkUp(if_index(&binds))
            } else if oid == CISCO_MAC_CHANGED {
                TrapKind::MacChanges(parse_mac_changes(&mac_msgs))
            } else {
                TrapKind::Other(dotted(&oid))
            }
        }
        _ => return None,
    };
    Some(Trap { community, kind })
}

/// Equal bytes, in time that doesn't depend on where they differ.
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The enabled v1/v2c switch at `ip`, from a list read at most every
/// `SWITCH_CACHE`.
struct Switches {
    list: Vec<PanopticonSwitch>,
    read_at: Option<Instant>,
}

impl Switches {
    async fn at(&mut self, pool: &DbPool, ip: IpAddr) -> Option<PanopticonSwitch> {
        if self.read_at.is_none_or(|t| t.elapsed() > SWITCH_CACHE) {
            match repo::panopticon_switches::list_enabled(pool).await {
                Ok(list) => self.list = list,
                Err(e) => tracing::warn!(error = %e, "SNMP traps: couldn't list switches"),
            }
            self.read_at = Some(Instant::now());
        }
        self.list
            .iter()
            .find(|s| {
                s.enabled
                    && matches!(s.snmp_version, SnmpVersion::V1 | SnmpVersion::V2c)
                    && s.ip_address.trim().parse::<IpAddr>().ok() == Some(ip)
            })
            .cloned()
    }
}

/// Per switch: when its last trap-triggered poll started, and whether one
/// more is already scheduled for the end of the window.
#[derive(Default)]
struct Debounce {
    last: Option<Instant>,
    pending: bool,
}

/// What [`debounce`] decided for one trap.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PollWhen {
    Now,
    /// One more poll after this long (the end of the window).
    After(Duration),
    /// Already scheduled: folded into it.
    Folded,
}

fn debounce(d: &mut Debounce, now: Instant, min: Duration) -> PollWhen {
    match d.last {
        Some(last) if now.duration_since(last) < min => {
            if d.pending {
                PollWhen::Folded
            } else {
                d.pending = true;
                PollWhen::After(min - now.duration_since(last))
            }
        }
        _ => {
            d.last = Some(now);
            PollWhen::Now
        }
    }
}

/// Starts the trap listener when it's enabled. Needs the encryption key
/// (the switches' communities are stored encrypted).
pub async fn spawn_snmp_trap_listener(pool: DbPool, key: Option<Arc<EncryptionKey>>) {
    if !repo::settings::get_bool(&pool, PANOPTICON_SNMP_TRAPS_ENABLED, false)
        .await
        .unwrap_or(false)
    {
        return;
    }
    let Some(key) = key else {
        tracing::warn!("SNMP traps are enabled but ENCRYPTION_KEY isn't set; not listening");
        return;
    };
    let get = |k: &'static str, d: u32| {
        let pool = pool.clone();
        async move { repo::settings::get_u32(&pool, k, d).await.unwrap_or(d) }
    };
    let port = get(PANOPTICON_SNMP_TRAP_PORT, PANOPTICON_SNMP_TRAP_PORT_DEFAULT).await;
    let min = Duration::from_secs(u64::from(
        get(
            PANOPTICON_SNMP_TRAP_MIN_INTERVAL_SECONDS,
            PANOPTICON_SNMP_TRAP_MIN_INTERVAL_SECONDS_DEFAULT,
        )
        .await
        .clamp(1, 3600),
    ));
    let Ok(port) = u16::try_from(port) else {
        tracing::error!(port, "SNMP traps: not a port");
        return;
    };
    let socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(port, error = %e, "SNMP traps: can't listen (port in use, or below 1024 without CAP_NET_BIND_SERVICE?)");
            return;
        }
    };
    tracing::info!(port, "Panopticon SNMP trap listener started");
    tokio::spawn(async move {
        let debounces: Arc<Mutex<HashMap<Uuid, Debounce>>> = Arc::default();
        let mut switches = Switches {
            list: Vec::new(),
            read_at: None,
        };
        let mut buf = vec![0u8; 8192];
        loop {
            let (n, from) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "SNMP traps: receive failed");
                    continue;
                }
            };
            // The source first: anything not from a polled switch is
            // dropped before it's parsed.
            let Some(switch) = switches.at(&pool, from.ip()).await else {
                tracing::debug!(from = %from, "SNMP trap from an address that isn't a polled v1/v2c switch; dropped");
                continue;
            };
            let Some(trap) = parse_trap(&buf[..n]) else {
                tracing::debug!(switch = %switch.name, "SNMP trap: not a v1/v2c trap; dropped");
                continue;
            };
            let community = switch
                .community_encrypted
                .as_deref()
                .and_then(|c| key.decrypt(c).ok());
            if !community.is_some_and(|c| same_secret(c.as_bytes(), &trap.community)) {
                tracing::warn!(switch = %switch.name, "SNMP trap with the wrong community; dropped");
                continue;
            }
            let summary = trap.kind.summary();
            if let Err(e) = repo::panopticon_switches::record_trap(&pool, switch.id, &summary).await
            {
                tracing::warn!(error = %e, "SNMP traps: couldn't record a trap");
            }
            if !trap.kind.wants_poll() {
                tracing::debug!(switch = %switch.name, trap = %summary, "SNMP trap recorded");
                continue;
            }
            let when = debounce(
                debounces.lock().await.entry(switch.id).or_default(),
                Instant::now(),
                min,
            );
            tracing::info!(switch = %switch.name, trap = %summary, when = ?when, "SNMP trap");
            let (pool, key, debounces) = (pool.clone(), key.clone(), debounces.clone());
            match when {
                PollWhen::Folded => {}
                PollWhen::Now => {
                    tokio::spawn(async move { poll_after_trap(&pool, &key, &switch).await });
                }
                PollWhen::After(wait) => {
                    tokio::spawn(async move {
                        tokio::time::sleep(wait).await;
                        if let Some(d) = debounces.lock().await.get_mut(&switch.id) {
                            d.pending = false;
                            d.last = Some(Instant::now());
                        }
                        poll_after_trap(&pool, &key, &switch).await;
                    });
                }
            }
        }
    });
}

/// The poll a trap asked for, then a policy pass for whatever it found.
async fn poll_after_trap(pool: &DbPool, key: &Arc<EncryptionKey>, switch: &PanopticonSwitch) {
    match crate::panopticon_snmp::poll_and_record(pool, switch, key).await {
        Ok(matched) => {
            tracing::info!(switch = %switch.name, matched, "SNMP trap: polled the switch")
        }
        Err(e) => {
            tracing::warn!(switch = %switch.name, error = %e, "SNMP trap: polled the switch, which failed")
        }
    }
    match crate::panopticon_policy::run_policy_pass_now(pool, Some(key)).await {
        Ok(()) => tracing::info!(switch = %switch.name, "SNMP trap: policy pass run"),
        Err(e) => tracing::error!(error = %e, "SNMP trap: the policy pass failed"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // ---- A minimal BER encoder for building test traps ----

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = body.len();
        if len < 128 {
            out.push(len as u8);
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend(bytes);
        }
        out.extend_from_slice(body);
        out
    }

    fn int(n: i64) -> Vec<u8> {
        let bytes = n.to_be_bytes();
        let mut i = 0;
        while i < 7
            && ((bytes[i] == 0 && bytes[i + 1] & 0x80 == 0)
                || (bytes[i] == 0xff && bytes[i + 1] & 0x80 != 0))
        {
            i += 1;
        }
        tlv(0x02, &bytes[i..])
    }

    fn oid(parts: &[u64]) -> Vec<u8> {
        let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
        for &p in &parts[2..] {
            let mut stack = vec![(p & 0x7f) as u8];
            let mut v = p >> 7;
            while v > 0 {
                stack.push(0x80 | (v & 0x7f) as u8);
                v >>= 7;
            }
            stack.reverse();
            body.extend(stack);
        }
        tlv(0x06, &body)
    }

    fn varbind(name: &[u64], value: Vec<u8>) -> Vec<u8> {
        tlv(0x30, &[oid(name), value].concat())
    }

    /// A v2c trap: `trap_oid` plus `binds`.
    pub(crate) fn v2c_trap(community: &[u8], trap_oid: &[u64], binds: Vec<Vec<u8>>) -> Vec<u8> {
        let mut vbs = vec![
            varbind(&[1, 3, 6, 1, 2, 1, 1, 3, 0], tlv(0x43, &[0x01, 0x00])),
            varbind(SNMP_TRAP_OID, oid(trap_oid)),
        ];
        vbs.extend(binds);
        let pdu = tlv(
            0xa7,
            &[int(1), int(0), int(0), tlv(0x30, &vbs.concat())].concat(),
        );
        tlv(0x30, &[int(1), tlv(0x04, community), pdu].concat())
    }

    /// A v1 trap.
    fn v1_trap(
        community: &[u8],
        enterprise: &[u64],
        generic: i64,
        specific: i64,
        binds: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let pdu = tlv(
            0xa4,
            &[
                oid(enterprise),
                tlv(0x40, &[10, 0, 0, 2]),
                int(generic),
                int(specific),
                tlv(0x43, &[0x01]),
                tlv(0x30, &binds.concat()),
            ]
            .concat(),
        );
        tlv(0x30, &[int(0), tlv(0x04, community), pdu].concat())
    }

    fn if_index_bind(i: u64) -> Vec<u8> {
        varbind(&[IF_INDEX, &[i]].concat(), int(i as i64))
    }

    #[test]
    fn link_traps_v2c_and_v1() {
        let t = parse_trap(&v2c_trap(b"public", LINK_DOWN, vec![if_index_bind(7)])).unwrap();
        assert_eq!(t.community, b"public");
        assert_eq!(t.kind, TrapKind::LinkDown(Some(7)));
        assert_eq!(t.kind.summary(), "linkDown ifIndex 7");
        let t = parse_trap(&v2c_trap(b"public", LINK_UP, vec![])).unwrap();
        assert_eq!(t.kind, TrapKind::LinkUp(None));
        let t = parse_trap(&v1_trap(
            b"c1",
            &[1, 3, 6, 1, 4, 1, 9],
            3,
            0,
            vec![if_index_bind(12)],
        ))
        .unwrap();
        assert_eq!(t.kind, TrapKind::LinkUp(Some(12)));
        assert!(t.kind.wants_poll());
    }

    #[test]
    fn cisco_mac_notifications() {
        let mut msg = vec![1, 0, 10, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01, 0, 5];
        msg.extend([2, 0, 20, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02, 0, 6]);
        msg.push(0);
        let bind = varbind(&[CISCO_MAC_CHANGED_MSG, &[1]].concat(), tlv(0x04, &msg));
        let t = parse_trap(&v2c_trap(b"public", CISCO_MAC_CHANGED, vec![bind.clone()])).unwrap();
        let TrapKind::MacChanges(changes) = &t.kind else {
            panic!("{:?}", t.kind)
        };
        assert_eq!(changes.len(), 2);
        assert_eq!(
            changes[0],
            MacChange {
                added: true,
                vlan: 10,
                mac: "aa:bb:cc:00:00:01".into(),
                bridge_port: 5
            }
        );
        assert!(!changes[1].added);
        assert_eq!(
            t.kind.summary(),
            "MAC notification: + aa:bb:cc:00:00:01 VLAN 10 port 5, - aa:bb:cc:00:00:02 VLAN 20 port 6"
        );
        // The v1 form.
        let t = parse_trap(&v1_trap(
            b"c1",
            CISCO_MAC_NOTIFICATION_ENTERPRISE,
            6,
            1,
            vec![bind],
        ))
        .unwrap();
        assert!(matches!(t.kind, TrapKind::MacChanges(ref c) if c.len() == 2));
    }

    #[test]
    fn other_traps_are_recorded_without_a_poll_and_junk_is_nothing() {
        let t = parse_trap(&v2c_trap(
            b"public",
            &[1, 3, 6, 1, 6, 3, 1, 1, 5, 1],
            vec![],
        ))
        .unwrap();
        assert_eq!(t.kind, TrapKind::Other("1.3.6.1.6.3.1.1.5.1".into()));
        assert!(!t.kind.wants_poll());
        assert!(parse_trap(b"").is_none());
        assert!(parse_trap(b"\x30\x03\x02\x01\x01").is_none());
        let good = v2c_trap(b"public", LINK_DOWN, vec![if_index_bind(7)]);
        for cut in 0..good.len() {
            let _ = parse_trap(&good[..cut]);
        }
        // Truncated records in a MAC message are ignored, not misread.
        assert!(parse_mac_changes(&[1, 0, 10, 0xaa]).is_empty());
    }

    #[test]
    fn communities_compare_exactly() {
        assert!(same_secret(b"public", b"public"));
        assert!(!same_secret(b"public", b"publiC"));
        assert!(!same_secret(b"public", b"public2"));
        assert!(!same_secret(b"", b"x"));
    }

    #[test]
    fn a_burst_of_traps_makes_two_polls() {
        let min = Duration::from_secs(10);
        let mut d = Debounce::default();
        let t0 = Instant::now();
        assert_eq!(debounce(&mut d, t0, min), PollWhen::Now);
        assert_eq!(
            debounce(&mut d, t0 + Duration::from_secs(2), min),
            PollWhen::After(Duration::from_secs(8))
        );
        assert_eq!(
            debounce(&mut d, t0 + Duration::from_secs(3), min),
            PollWhen::Folded
        );
        assert_eq!(
            debounce(&mut d, t0 + Duration::from_secs(9), min),
            PollWhen::Folded
        );
        // After the window (the deferred poll cleared `pending`): at once again.
        d.pending = false;
        assert_eq!(
            debounce(&mut d, t0 + Duration::from_secs(11), min),
            PollWhen::Now
        );
    }
}
