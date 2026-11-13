//! DHCP servers seen on the network, and which of them are allowed (0.2.9
//! Q4, `docs/roadmap/0.2.9.md`): a server that isn't is a rogue.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{network_of, parse_cidr};

/// One DHCP server the capture has seen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpServer {
    pub server_ip: String,
    /// Only from an unrelayed reply (a relayed one's source is the relay).
    pub server_mac: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// Replies (OFFER/ACK/NAK) seen from it.
    pub replies: u32,
    /// Client REQUESTs that chose it (option 54).
    pub chosen: u32,
    pub last_client_mac: Option<String>,
    pub alerted_at: Option<DateTime<Utc>>,
}

/// One entry of the allowed list: an address, or a CIDR block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedServer {
    Address(IpAddr),
    Network(IpAddr, u8),
}

impl AllowedServer {
    fn contains(&self, ip: IpAddr) -> bool {
        match *self {
            AllowedServer::Address(a) => a == ip,
            AllowedServer::Network(net, prefix) => {
                let p = |a: IpAddr| network_of(&a.to_string(), prefix, prefix);
                net.is_ipv4() == ip.is_ipv4() && p(ip).is_some() && p(ip) == p(net)
            }
        }
    }
}

/// Parses the allowed list: addresses and CIDR blocks separated by commas,
/// spaces or newlines. An entry that's neither is an error naming it.
pub fn parse_allowed_dhcp_servers(raw: &str) -> Result<Vec<AllowedServer>, String> {
    raw.split([',', ' ', '\n', '\r', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            if let Some((net, prefix)) = parse_cidr(entry) {
                Ok(AllowedServer::Network(net, prefix))
            } else {
                entry
                    .parse()
                    .map(AllowedServer::Address)
                    .map_err(|_| format!("\"{entry}\" isn't an address or a CIDR block"))
            }
        })
        .collect()
}

/// Whether a DHCP server is a rogue: detection is on (the allowed list
/// isn't empty), and the server is neither on it nor one of `always`
/// (Panopticon's own registration DHCP server). An address that doesn't
/// parse can't be on the list, so it's a rogue too.
pub fn is_rogue_dhcp_server(server_ip: &str, allowed: &[AllowedServer], always: &[IpAddr]) -> bool {
    if allowed.is_empty() {
        return false;
    }
    let Ok(ip) = server_ip.trim().parse::<IpAddr>() else {
        return true;
    };
    !always.contains(&ip) && !allowed.iter().any(|a| a.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowed_list_takes_addresses_and_blocks() {
        let allowed = parse_allowed_dhcp_servers("10.0.0.1, 10.0.1.0/24\n192.0.2.7").unwrap();
        assert_eq!(allowed.len(), 3);
        assert!(parse_allowed_dhcp_servers("10.0.0.1, dhcp.example").is_err());
        assert!(parse_allowed_dhcp_servers("10.0.0.0/33").is_err());
        assert!(parse_allowed_dhcp_servers("  ").unwrap().is_empty());
    }

    #[test]
    fn a_server_off_the_list_is_a_rogue() {
        let allowed = parse_allowed_dhcp_servers("10.0.0.1, 10.0.1.0/24").unwrap();
        let portal: IpAddr = "10.99.0.1".parse().unwrap();
        assert!(!is_rogue_dhcp_server("10.0.0.1", &allowed, &[portal]));
        assert!(!is_rogue_dhcp_server("10.0.1.200", &allowed, &[portal]));
        assert!(is_rogue_dhcp_server("10.0.2.1", &allowed, &[portal]));
        assert!(is_rogue_dhcp_server("192.168.1.1", &allowed, &[portal]));
        // Panopticon's own registration DHCP server is always allowed.
        assert!(!is_rogue_dhcp_server("10.99.0.1", &allowed, &[portal]));
        assert!(is_rogue_dhcp_server("not-an-ip", &allowed, &[portal]));
        // An empty list: detection off, nothing is a rogue.
        assert!(!is_rogue_dhcp_server("192.168.1.1", &[], &[]));
    }
}
