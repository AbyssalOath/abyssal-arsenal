//! Switch neighbors -- the links between switches, APs, phones and servers
//! that LLDP (IEEE 802.1AB, every vendor) and CDP (Cisco) advertise -- read
//! in the same SNMP poll as the forwarding table (`panopticon_snmp`), and
//! shown on the Topology page.
//!
//! Parsing is pure and works on the poll's `(index suffix, value)` rows, so
//! it's tested without a switch.

use std::collections::{BTreeMap, HashMap};

use crate::panopticon_snmp::OwnedValue;

/// LLDP-MIB `lldpRemTable` (remote systems, per local port).
pub const LLDP_REM_TABLE: &[u64] = &[1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
/// LLDP-MIB `lldpLocPortTable` (what the switch calls its own LLDP ports).
pub const LLDP_LOC_PORT_TABLE: &[u64] = &[1, 0, 8802, 1, 1, 2, 1, 3, 7, 1];
/// LLDP-MIB `lldpRemManAddrIfSubtype`: walked only for its index, which
/// carries each neighbor's management address.
pub const LLDP_REM_MAN_ADDR_IF_SUBTYPE: &[u64] = &[1, 0, 8802, 1, 1, 2, 1, 4, 2, 1, 3];
/// CISCO-CDP-MIB `cdpCacheTable`.
pub const CDP_CACHE_TABLE: &[u64] = &[1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// `lldp` or `cdp`.
    pub protocol: &'static str,
    /// The local port's label, as the rest of Panopticon labels ports.
    pub local_port: String,
    pub local_if_index: Option<u32>,
    pub remote_name: String,
    pub remote_port: String,
    pub remote_address: Option<String>,
    /// LLDP's system description or CDP's platform.
    pub remote_platform: String,
    pub chassis_id: String,
}

type Rows = [(Vec<u64>, OwnedValue)];

fn text(value: &OwnedValue) -> Option<String> {
    match value {
        OwnedValue::OctetString(bytes) => Some(String::from_utf8_lossy(bytes).trim().to_string()),
        _ => None,
    }
}

fn int(value: &OwnedValue) -> Option<i64> {
    match value {
        OwnedValue::Integer(n) => Some(*n),
        OwnedValue::Counter(n) => i64::try_from(*n).ok(),
        _ => None,
    }
}

fn hex_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// An LLDP ID: a MAC for subtype `mac_subtype`, else text when printable,
/// else hex.
fn lldp_id(subtype: Option<i64>, value: Option<&OwnedValue>, mac_subtype: i64) -> String {
    let Some(OwnedValue::OctetString(bytes)) = value else {
        return String::new();
    };
    let printable = bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    if subtype == Some(mac_subtype) && bytes.len() == 6 || !printable {
        hex_mac(bytes)
    } else {
        String::from_utf8_lossy(bytes).trim().to_string()
    }
}

/// The local port's label: the poll's own label for the interface LLDP's
/// port description or ID names (matched against `ifDescr`), else the
/// interface the LLDP port number is, else LLDP's own description.
fn local_port(
    port_num: u64,
    loc_desc: Option<&str>,
    loc_id: Option<&str>,
    labels: &HashMap<i64, String>,
    hw_descr: &HashMap<i64, String>,
) -> (String, Option<u32>) {
    for candidate in [loc_desc, loc_id].into_iter().flatten() {
        if candidate.is_empty() {
            continue;
        }
        if let Some((if_index, _)) = hw_descr
            .iter()
            .find(|(_, hw)| hw.eq_ignore_ascii_case(candidate))
            && let Some(label) = labels.get(if_index)
        {
            return (label.clone(), u32::try_from(*if_index).ok());
        }
    }
    if loc_desc.is_none()
        && loc_id.is_none()
        && let Ok(idx) = i64::try_from(port_num)
        && let Some(label) = labels.get(&idx)
    {
        return (label.clone(), u32::try_from(idx).ok());
    }
    let label = [loc_desc, loc_id]
        .into_iter()
        .flatten()
        .find(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("port {port_num}"));
    (label, None)
}

/// Neighbors from `lldpRemTable`, its management addresses and the local
/// port table. `labels` is the poll's ifIndex -> label map (names first),
/// `hw_descr` its ifIndex -> raw `ifDescr`.
pub fn lldp_neighbors(
    rem: &Rows,
    loc_ports: &Rows,
    man_addrs: &Rows,
    labels: &HashMap<i64, String>,
    hw_descr: &HashMap<i64, String>,
) -> Vec<Neighbor> {
    // (localPortNum, remIndex) -> column -> value
    let mut remote: BTreeMap<(u64, u64), HashMap<u64, &OwnedValue>> = BTreeMap::new();
    for (suffix, value) in rem {
        if let [column, _time_mark, port, index] = suffix.as_slice() {
            remote
                .entry((*port, *index))
                .or_default()
                .insert(*column, value);
        }
    }
    let mut loc: HashMap<u64, HashMap<u64, String>> = HashMap::new();
    for (suffix, value) in loc_ports {
        if let ([column, port], Some(t)) = (suffix.as_slice(), text(value)) {
            loc.entry(*port).or_default().insert(*column, t);
        }
    }
    let mut addresses: HashMap<(u64, u64), String> = HashMap::new();
    for (suffix, _) in man_addrs {
        // timeMark.localPortNum.remIndex.addrSubtype.addrLen.addr...
        if let [_time, port, index, 1, 4, a, b, c, d] = suffix.as_slice() {
            addresses
                .entry((*port, *index))
                .or_insert_with(|| format!("{a}.{b}.{c}.{d}"));
        }
    }

    remote
        .into_iter()
        .map(|((port, index), cols)| {
            let loc_cols = loc.get(&port);
            let (local, local_if_index) = local_port(
                port,
                loc_cols.and_then(|c| c.get(&4)).map(String::as_str),
                loc_cols.and_then(|c| c.get(&3)).map(String::as_str),
                labels,
                hw_descr,
            );
            let get_text = |col| cols.get(&col).and_then(|v| text(v)).unwrap_or_default();
            let port_desc = get_text(8);
            let port_id = lldp_id(cols.get(&6).and_then(|v| int(v)), cols.get(&7).copied(), 3);
            Neighbor {
                protocol: "lldp",
                local_port: local,
                local_if_index,
                remote_name: get_text(9),
                remote_port: if port_desc.is_empty() {
                    port_id
                } else {
                    port_desc
                },
                remote_address: addresses.get(&(port, index)).cloned(),
                remote_platform: get_text(10),
                chassis_id: lldp_id(cols.get(&4).and_then(|v| int(v)), cols.get(&5).copied(), 4),
            }
        })
        .collect()
}

/// Neighbors from Cisco's `cdpCacheTable`, indexed by the local ifIndex.
pub fn cdp_neighbors(cache: &Rows, labels: &HashMap<i64, String>) -> Vec<Neighbor> {
    let mut rows: BTreeMap<(u64, u64), HashMap<u64, &OwnedValue>> = BTreeMap::new();
    for (suffix, value) in cache {
        if let [column, if_index, device] = suffix.as_slice() {
            rows.entry((*if_index, *device))
                .or_default()
                .insert(*column, value);
        }
    }
    rows.into_iter()
        .map(|((if_index, _), cols)| {
            let get_text = |col| cols.get(&col).and_then(|v| text(v)).unwrap_or_default();
            let address = match (cols.get(&3).and_then(|v| int(v)), cols.get(&4)) {
                (Some(1), Some(OwnedValue::OctetString(b))) if b.len() == 4 => {
                    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
                }
                _ => None,
            };
            let idx = i64::try_from(if_index).unwrap_or(-1);
            Neighbor {
                protocol: "cdp",
                local_port: labels
                    .get(&idx)
                    .cloned()
                    .unwrap_or_else(|| format!("if{if_index}")),
                local_if_index: u32::try_from(if_index).ok(),
                remote_name: get_text(6),
                remote_port: get_text(7),
                remote_address: address,
                remote_platform: get_text(8),
                chassis_id: String::new(),
            }
        })
        .collect()
}

/// The same neighbor advertised over both protocols (common on Cisco gear
/// running LLDP too) is shown once, preferring LLDP.
pub fn merge(lldp: Vec<Neighbor>, cdp: Vec<Neighbor>) -> Vec<Neighbor> {
    let mut out = lldp;
    for n in cdp {
        let same = out.iter_mut().find(|l| {
            l.local_port == n.local_port
                && (l.remote_name.eq_ignore_ascii_case(&n.remote_name)
                    || (l.remote_address.is_some() && l.remote_address == n.remote_address))
        });
        match same {
            // Keep the LLDP entry, but take what only CDP said (phones often
            // advertise their address over CDP alone).
            Some(l) => {
                if l.remote_address.is_none() {
                    l.remote_address = n.remote_address;
                }
                if l.remote_platform.is_empty() {
                    l.remote_platform = n.remote_platform;
                }
            }
            None => out.push(n),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> OwnedValue {
        OwnedValue::OctetString(v.as_bytes().to_vec())
    }
    fn i(n: i64) -> OwnedValue {
        OwnedValue::Integer(n)
    }

    fn labels() -> (HashMap<i64, String>, HashMap<i64, String>) {
        let labels = HashMap::from([
            (1, "Uplink-Core".to_string()),
            (2, "Slot: 0 Port: 2 Gigabit - Level".to_string()),
        ]);
        let hw = HashMap::from([
            (1, "Slot: 0 Port: 1 Gigabit - Level".to_string()),
            (2, "Slot: 0 Port: 2 Gigabit - Level".to_string()),
        ]);
        (labels, hw)
    }

    #[test]
    fn lldp_neighbors_with_local_ports_and_management_addresses() {
        let (labels, hw) = labels();
        // Two neighbors: a core switch on local LLDP port 49 (which the
        // switch describes as port 1), and a phone on port 50 (port 2).
        let rem = vec![
            (vec![4, 0, 49, 1], i(4)),
            (
                vec![5, 0, 49, 1],
                OwnedValue::OctetString(vec![0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]),
            ),
            (vec![6, 0, 49, 1], i(5)),
            (vec![7, 0, 49, 1], s("Gi1/0/24")),
            (vec![8, 0, 49, 1], s("GigabitEthernet1/0/24")),
            (vec![9, 0, 49, 1], s("core-sw1")),
            (vec![10, 0, 49, 1], s("Cisco IOS Software, C9300")),
            (vec![9, 0, 50, 3], s("SEP001122334455")),
            (vec![7, 0, 50, 3], s("Port 1")),
        ];
        let loc = vec![
            (vec![3, 49], s("1")),
            (vec![4, 49], s("Slot: 0 Port: 1 Gigabit - Level")),
            (vec![4, 50], s("Slot: 0 Port: 2 Gigabit - Level")),
        ];
        let man = vec![(vec![0, 49, 1, 1, 4, 10, 0, 0, 2], i(2))];
        let n = lldp_neighbors(&rem, &loc, &man, &labels, &hw);
        assert_eq!(n.len(), 2);
        assert_eq!(
            n[0].local_port, "Uplink-Core",
            "matched through ifDescr to its name"
        );
        assert_eq!(n[0].local_if_index, Some(1));
        assert_eq!(n[0].remote_name, "core-sw1");
        assert_eq!(
            n[0].remote_port, "GigabitEthernet1/0/24",
            "port description preferred"
        );
        assert_eq!(n[0].remote_address.as_deref(), Some("10.0.0.2"));
        assert_eq!(n[0].chassis_id, "00:1b:21:aa:bb:cc");
        assert_eq!(n[0].remote_platform, "Cisco IOS Software, C9300");
        assert_eq!(n[1].local_port, "Slot: 0 Port: 2 Gigabit - Level");
        assert_eq!(n[1].remote_name, "SEP001122334455");
        assert_eq!(n[1].remote_port, "Port 1", "falls back to the port ID");
        assert_eq!(n[1].remote_address, None);
    }

    #[test]
    fn lldp_local_ports_without_a_local_table() {
        let (labels, hw) = labels();
        let rem = vec![
            (vec![9, 0, 2, 1], s("ap-lobby")),
            (vec![9, 0, 77, 1], s("mystery")),
        ];
        let n = lldp_neighbors(&rem, &[], &[], &labels, &hw);
        assert_eq!(
            n[0].local_port, "Slot: 0 Port: 2 Gigabit - Level",
            "the port number is the ifIndex"
        );
        assert_eq!(n[1].local_port, "port 77");
    }

    #[test]
    fn cdp_neighbors_by_if_index() {
        let (labels, _) = labels();
        let cache = vec![
            (vec![3, 1, 7], i(1)),
            (vec![4, 1, 7], OwnedValue::OctetString(vec![10, 0, 0, 2])),
            (vec![6, 1, 7], s("core-sw1.corp.local")),
            (vec![7, 1, 7], s("GigabitEthernet1/0/24")),
            (vec![8, 1, 7], s("cisco C9300-48P")),
            (vec![6, 9, 1], s("phone")),
        ];
        let n = cdp_neighbors(&cache, &labels);
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].local_port, "Uplink-Core");
        assert_eq!(n[0].remote_address.as_deref(), Some("10.0.0.2"));
        assert_eq!(n[0].remote_platform, "cisco C9300-48P");
        assert_eq!(n[1].local_port, "if9");
    }

    #[test]
    fn a_neighbor_on_both_protocols_shows_once() {
        let lldp = Neighbor {
            protocol: "lldp",
            local_port: "Uplink-Core".into(),
            local_if_index: Some(1),
            remote_name: "core-sw1".into(),
            remote_port: "Gi1/0/24".into(),
            remote_address: Some("10.0.0.2".into()),
            remote_platform: String::new(),
            chassis_id: String::new(),
        };
        let cdp_same = Neighbor {
            protocol: "cdp",
            remote_name: "core-sw1.corp.local".into(),
            ..lldp.clone()
        };
        let lldp_phone = Neighbor {
            protocol: "lldp",
            local_port: "Slot: 0 Port: 2".into(),
            remote_name: "SEP001122334455".into(),
            remote_address: None,
            remote_platform: String::new(),
            ..lldp.clone()
        };
        let cdp_phone = Neighbor {
            protocol: "cdp",
            remote_address: Some("172.31.0.9".into()),
            remote_platform: "Cisco IP Phone 8845".into(),
            ..lldp_phone.clone()
        };
        let cdp_other = Neighbor {
            protocol: "cdp",
            local_port: "Slot: 0 Port: 9".into(),
            remote_name: "phone".into(),
            remote_address: None,
            ..lldp.clone()
        };
        let merged = merge(vec![lldp, lldp_phone], vec![cdp_same, cdp_other, cdp_phone]);
        assert_eq!(
            merged.len(),
            3,
            "same address or name on the same port = same neighbor"
        );
        assert_eq!(merged[0].protocol, "lldp");
        assert_eq!(
            merged[1].protocol, "lldp",
            "the phone is kept as its LLDP entry..."
        );
        assert_eq!(
            merged[1].remote_address.as_deref(),
            Some("172.31.0.9"),
            "...with CDP's address"
        );
        assert_eq!(merged[1].remote_platform, "Cisco IP Phone 8845");
        assert_eq!(merged[2].remote_name, "phone");
    }
}
