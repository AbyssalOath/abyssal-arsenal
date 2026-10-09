//! `NeighborTable`: this host's IPv4 neighbor (ARP) table plus its own
//! interfaces' addresses, for Panopticon. Its scanner runs inside the control
//! plane's container, behind Docker's NAT, so it never sees a MAC address;
//! the hosts around those devices do. One tab-separated line per entry:
//!
//! ```text
//! neighbor<TAB>192.168.1.20<TAB>aa:bb:cc:dd:ee:ff<TAB>eth0
//! self<TAB>192.168.1.5<TAB>11:22:33:44:55:66<TAB>eth0
//! ```
//!
//! Read-only, and needs no privileges on either OS.

use abyssal_agent_protocol::CommandOutcome;
#[cfg(unix)]
use abyssal_agent_protocol::OperationOutput;

#[cfg(unix)]
fn ok(lines: Vec<String>) -> CommandOutcome {
    CommandOutcome::Ok(OperationOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

#[cfg(unix)]
pub async fn neighbor_table() -> CommandOutcome {
    use crate::process::run_command;

    let neigh = match run_command("ip", &["-4", "neigh", "show"]).await {
        Ok(output) => output.stdout,
        Err(e) => return CommandOutcome::Err(format!("ip neigh failed: {e}")),
    };
    let mut lines = parse_ip_neigh(&neigh);

    if let Ok(addrs) = run_command("ip", &["-o", "-4", "addr", "show"]).await {
        for (ip, interface) in parse_ip_addr(&addrs.stdout) {
            let path = format!("/sys/class/net/{interface}/address");
            if let Ok(mac) = tokio::fs::read_to_string(&path).await {
                let mac = mac.trim();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    lines.push(format!("self\t{ip}\t{mac}\t{interface}"));
                }
            }
        }
    }
    ok(lines)
}

/// `ip -4 neigh show`: `192.168.1.1 dev eth0 lladdr aa:bb:.. REACHABLE`.
/// Entries without a link-layer address (`FAILED`, `INCOMPLETE`) are
/// skipped.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_ip_neigh(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let ip = tokens.first()?;
            let pos = tokens.iter().position(|&t| t == "lladdr")?;
            let mac = tokens.get(pos + 1)?;
            let dev = tokens
                .iter()
                .position(|&t| t == "dev")
                .and_then(|p| tokens.get(p + 1))
                .copied()
                .unwrap_or("");
            Some(format!("neighbor\t{ip}\t{mac}\t{dev}"))
        })
        .collect()
}

/// `ip -o -4 addr show`: `2: eth0    inet 192.168.1.5/24 brd ...`. Loopback
/// is skipped.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_ip_addr(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let interface = tokens.get(1)?.trim_end_matches(':');
            // "eth0.10@eth0" for a VLAN interface: /sys uses the first part.
            let interface = interface.split('@').next()?;
            let pos = tokens.iter().position(|&t| t == "inet")?;
            let ip = tokens.get(pos + 1)?.split('/').next()?;
            (interface != "lo" && !ip.starts_with("127."))
                .then(|| (ip.to_string(), interface.to_string()))
        })
        .collect()
}

#[cfg(windows)]
pub async fn neighbor_table() -> CommandOutcome {
    // Unreachable/Incomplete entries have no usable address; broadcast and
    // multicast entries are filtered by the control plane.
    let script = r#"$ErrorActionPreference = 'SilentlyContinue'
Get-NetNeighbor -AddressFamily IPv4 |
  Where-Object { $_.LinkLayerAddress -and $_.State -notin @('Unreachable','Incomplete') } |
  ForEach-Object { "neighbor`t$($_.IPAddress)`t$($_.LinkLayerAddress)`t$($_.InterfaceAlias)" }
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike '127.*' } |
  ForEach-Object {
    $a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex
    if ($a -and $a.MacAddress) { "self`t$($_.IPAddress)`t$($a.MacAddress)`t$($a.Name)" }
  }
"#;
    match crate::process::run_powershell(script).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(not(any(unix, windows)))]
pub async fn neighbor_table() -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_neighbors_and_skips_ones_without_a_mac() {
        let out = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n\
                   192.168.1.9 dev eth0  FAILED\n\
                   192.168.1.20 dev eth0 lladdr aa:bb:cc:dd:ee:20 STALE\n\
                   172.17.0.2 dev docker0 lladdr 02:42:ac:11:00:02 DELAY\n";
        assert_eq!(
            parse_ip_neigh(out),
            vec![
                "neighbor\t192.168.1.1\taa:bb:cc:dd:ee:01\teth0",
                "neighbor\t192.168.1.20\taa:bb:cc:dd:ee:20\teth0",
                "neighbor\t172.17.0.2\t02:42:ac:11:00:02\tdocker0",
            ]
        );
    }

    #[test]
    fn parses_own_addresses_without_loopback() {
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
                   2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\\ ...\n\
                   5: eth0.10@eth0    inet 10.10.0.2/24 scope global eth0.10\\ ...\n";
        assert_eq!(
            parse_ip_addr(out),
            vec![
                ("192.168.1.5".to_string(), "eth0".to_string()),
                ("10.10.0.2".to_string(), "eth0.10".to_string()),
            ]
        );
    }
}
