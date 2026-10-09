//! MAC addresses (and so vendors) for Panopticon, from agents.
//!
//! Discovery's nmap runs inside the control plane's container, behind
//! Docker's NAT, so the container's own neighbor table never holds a LAN
//! device's MAC. The hosts around those devices do: the control plane's own
//! server (whose ARP cache the scan's traffic just filled), and every agent
//! for its own subnet. `AgentOperation::NeighborTable` reports a host's ARP
//! table and its own interfaces; this merges them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_database::{DbPool, repo};
use abyssal_hosts::HostConnectionRegistry;

const QUERY_TIMEOUT: Duration = Duration::from_secs(20);
/// Agents asked at once.
const BATCH: usize = 32;

/// What the agents know, keyed by IPv4 address.
#[derive(Debug, Default)]
pub struct AgentNeighbors {
    /// MAC for every address any agent knows; an agent's own interface wins
    /// over another host's ARP entry for it.
    pub macs: HashMap<String, String>,
    /// Addresses that belong to a managed host, with that host's name.
    pub own: HashMap<String, String>,
}

/// `aa:bb:cc:dd:ee:ff` lowercase from either `aa:bb..` or Windows'
/// `AA-BB-..`. `None` for anything that isn't a single device's address:
/// all zeros, broadcast or multicast.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let mac = raw.trim().replace('-', ":").to_ascii_lowercase();
    let octets: Vec<u8> = mac
        .split(':')
        .map(|o| u8::from_str_radix(o, 16).ok())
        .collect::<Option<_>>()?;
    if octets.len() != 6 || mac.split(':').any(|o| o.len() != 2) {
        return None;
    }
    // The low bit of the first octet marks group (multicast/broadcast).
    if octets.iter().all(|&o| o == 0) || octets[0] & 1 == 1 {
        return None;
    }
    Some(mac)
}

/// Bridges, veths and tunnels on a Linux host: their neighbors are
/// containers and VMs on that host, not devices on the network.
pub(crate) fn is_virtual_interface(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "docker", "br-", "veth", "virbr", "vnet", "cni", "flannel", "cali", "podman", "lxc", "lxd",
        "tun", "tap", "kube", "weave", "cilium", "vxlan",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

#[derive(Debug, PartialEq)]
pub struct Entry {
    pub ip: String,
    pub mac: String,
    pub own: bool,
}

/// Parses one agent's `NeighborTable` output, dropping virtual interfaces
/// and anything that isn't a plain IPv4 address with a device MAC.
pub fn parse_neighbor_table(stdout: &str) -> Vec<Entry> {
    stdout
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.trim_end_matches('\r').split('\t').collect();
            let own = match *fields.first()? {
                "neighbor" => false,
                "self" => true,
                _ => return None,
            };
            let ip = fields.get(1)?.trim();
            ip.parse::<std::net::Ipv4Addr>().ok()?;
            let mac = normalize_mac(fields.get(2)?)?;
            if fields
                .get(3)
                .is_some_and(|i| is_virtual_interface(i.trim()))
            {
                return None;
            }
            Some(Entry {
                ip: ip.to_string(),
                mac,
                own,
            })
        })
        .collect()
}

/// Merges one host's entries into `into`.
fn merge(into: &mut AgentNeighbors, host_name: &str, entries: Vec<Entry>) {
    for entry in entries {
        if entry.own {
            into.own.insert(entry.ip.clone(), host_name.to_string());
            into.macs.insert(entry.ip, entry.mac);
        } else if !into.own.contains_key(&entry.ip) {
            into.macs.entry(entry.ip).or_insert(entry.mac);
        }
    }
}

/// Asks connected agents (0.2.2+) for their neighbor tables -- every one
/// after a scan, or only the control plane's own server for the frequent
/// passive refresh. Hosts that don't answer are skipped.
pub async fn collect(
    pool: &DbPool,
    hosts: &Arc<HostConnectionRegistry>,
    only_control_plane: bool,
) -> AgentNeighbors {
    let mut out = AgentNeighbors::default();
    let candidates: Vec<(uuid::Uuid, String)> = match repo::hosts::list(pool).await {
        Ok(list) => list
            .into_iter()
            .filter(|h| {
                h.is_active()
                    && !h.pending_approval
                    && (!only_control_plane || h.is_control_plane)
                    && hosts.supports(h.id, &AgentOperation::NeighborTable)
            })
            .map(|h| (h.id, h.name))
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "panopticon: couldn't list hosts for neighbor tables");
            return out;
        }
    };

    for batch in candidates.chunks(BATCH) {
        let mut set = tokio::task::JoinSet::new();
        for (id, name) in batch.iter().cloned() {
            let hosts = hosts.clone();
            set.spawn(async move {
                let outcome = hosts
                    .dispatch(id, AgentOperation::NeighborTable, QUERY_TIMEOUT)
                    .await;
                (name, outcome)
            });
        }
        while let Some(Ok((name, outcome))) = set.join_next().await {
            match outcome {
                Ok(CommandOutcome::Ok(output)) => {
                    merge(&mut out, &name, parse_neighbor_table(&output.stdout));
                }
                Ok(CommandOutcome::Err(e)) => {
                    tracing::debug!(host = %name, error = %e, "panopticon: neighbor table failed");
                }
                Err(e) => {
                    tracing::debug!(host = %name, error = %e, "panopticon: neighbor table failed");
                }
            }
        }
    }
    out
}

/// When an agent connects: fills in the MAC (and a missing hostname) of
/// inventory devices that are this host's own addresses. Runs once per
/// connection, so a newly installed agent's device gets its MAC without
/// waiting for the next scan.
pub async fn enrich_from_host(
    pool: &DbPool,
    hosts: &HostConnectionRegistry,
    host_id: uuid::Uuid,
    host_name: &str,
) {
    if !hosts.supports(host_id, &AgentOperation::NeighborTable) {
        return;
    }
    let Ok(CommandOutcome::Ok(output)) = hosts
        .dispatch(host_id, AgentOperation::NeighborTable, QUERY_TIMEOUT)
        .await
    else {
        return;
    };
    for entry in parse_neighbor_table(&output.stdout)
        .into_iter()
        .filter(|e| e.own)
    {
        if let Err(e) =
            repo::network_devices::enrich_from_agent(pool, &entry.ip, &entry.mac, host_name).await
        {
            tracing::warn!(error = %e, ip = %entry.ip, "panopticon: failed to record an agent's own MAC");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_are_normalized_and_group_addresses_rejected() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-0F").as_deref(),
            Some("aa:bb:cc:dd:ee:0f")
        );
        assert_eq!(
            normalize_mac("00:15:5d:01:02:03").as_deref(),
            Some("00:15:5d:01:02:03")
        );
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
        assert_eq!(normalize_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize_mac("01:00:5e:00:00:fb"), None, "IPv4 multicast");
        assert_eq!(normalize_mac("33-33-00-00-00-01"), None, "IPv6 multicast");
        assert_eq!(normalize_mac("<unknown>"), None);
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(normalize_mac("aabb:cc:dd:ee:ff:0"), None);
    }

    #[test]
    fn parses_linux_and_windows_tables_and_drops_virtual_interfaces() {
        let linux = "neighbor\t192.168.1.1\taa:bb:cc:dd:ee:01\teth0\n\
                     neighbor\t172.18.0.3\t02:42:ac:12:00:03\tbr-1a2b3c\n\
                     neighbor\t172.17.0.2\t02:42:ac:11:00:02\tdocker0\n\
                     self\t192.168.1.5\t10:22:33:44:55:66\teth0\n\
                     self\t172.17.0.1\t02:42:00:00:00:01\tdocker0\n";
        assert_eq!(
            parse_neighbor_table(linux),
            vec![
                Entry {
                    ip: "192.168.1.1".into(),
                    mac: "aa:bb:cc:dd:ee:01".into(),
                    own: false
                },
                Entry {
                    ip: "192.168.1.5".into(),
                    mac: "10:22:33:44:55:66".into(),
                    own: true
                },
            ]
        );
        let windows = "neighbor\t10.0.0.1\tAA-BB-CC-00-00-01\tEthernet\r\n\
                       neighbor\t10.0.0.255\tFF-FF-FF-FF-FF-FF\tEthernet\r\n\
                       neighbor\t224.0.0.22\t01-00-5E-00-00-16\tEthernet\r\n\
                       self\t10.0.0.7\t00-15-5D-AA-BB-CC\tEthernet\r\n\
                       garbage line\r\n";
        let parsed = parse_neighbor_table(windows);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].mac, "aa:bb:cc:00:00:01");
        assert!(parsed[1].own);
    }

    #[test]
    fn a_hosts_own_interface_beats_another_hosts_arp_entry() {
        let mut n = AgentNeighbors::default();
        merge(
            &mut n,
            "router-watcher",
            vec![Entry {
                ip: "10.0.0.7".into(),
                mac: "aa:aa:aa:aa:aa:aa".into(),
                own: false,
            }],
        );
        merge(
            &mut n,
            "win-07",
            vec![Entry {
                ip: "10.0.0.7".into(),
                mac: "00:15:5d:aa:bb:cc".into(),
                own: true,
            }],
        );
        merge(
            &mut n,
            "late-arp",
            vec![Entry {
                ip: "10.0.0.7".into(),
                mac: "bb:bb:bb:bb:bb:bb".into(),
                own: false,
            }],
        );
        assert_eq!(n.macs["10.0.0.7"], "00:15:5d:aa:bb:cc");
        assert_eq!(n.own["10.0.0.7"], "win-07");
    }
}
