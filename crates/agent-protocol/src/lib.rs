//! Wire format shared between the control plane and `abyssal-agent`. This
//! crate is pure data — no I/O — so both sides link the exact same
//! definitions instead of hand-keeping two copies in sync.
//!
//! `AgentOperation` is the actual security boundary for remote execution: an
//! agent will only ever run one of these fixed, named operations, never an
//! arbitrary command string sent over the wire. Adding a capability means
//! adding a variant here (and implementing it in the agent) — the protocol
//! itself can't be used to smuggle in anything else.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOperation {
    /// Pure connectivity/liveness check — no work performed.
    Ping,
    /// Hostname, kernel version, and uptime, read locally on the agent's host.
    SystemInfo,
    /// Memory and disk usage, read locally on the agent's host.
    ResourceUsage,
    /// Currently logged-in users/sessions on the agent's host.
    LoggedInUsers,
    /// Sets the agent's host's persistent hostname. Write -- a real mutation,
    /// but not destructive/irreversible, so it doesn't require the explicit
    /// confirmation a `Destructive` operation does.
    SetHostname { hostname: String },
    /// Immediately reboots the agent's host. Destructive -- the control
    /// plane requires explicit confirmation before ever dispatching this.
    Reboot,
    /// Listening TCP/UDP sockets on the agent's host (`ss -tulpn`).
    ListeningPorts,
    /// The last ~30 sshd journal entries (login attempts, failures).
    RecentAuthLog,
    /// Current firewall status, from whichever of firewalld/ufw/nftables/
    /// iptables the agent detects on its host.
    FirewallStatus,
    /// Allows a port through the detected firewall backend. Write -- a real
    /// mutation, but additive/non-destructive, so no confirmation required.
    FirewallAllowPort { port: u16, protocol: String },
    /// Enables the detected firewall backend (firewalld/ufw only -- raw
    /// nftables/iptables have no single well-defined "enable"). Destructive:
    /// can cut off remote access if the current management port isn't
    /// already allowed, so the control plane requires explicit confirmation.
    FirewallEnable,
    /// Validates a sudo password via `sudo -S -v` and starts/refreshes a
    /// time-boxed elevation window on the agent ("Apotheosis"). Write --
    /// the password prompt itself is the meaningful confirmation step, so
    /// this doesn't additionally require the `Destructive` confirmation
    /// gate. `idle_timeout_secs` is the control plane's admin-configured
    /// window (Settings); the agent has no DB access of its own, so it has
    /// to be told the value on every elevation rather than reading it
    /// locally.
    Elevate {
        password: String,
        idle_timeout_secs: u64,
    },
    /// Clears the elevation window early and drops sudo's own cache too.
    Deescalate,
    /// Human-readable elevation status (elevated or not, remaining time).
    ElevationStatus,
    /// Network interfaces and their addresses (`ip addr show`).
    NetworkInterfaces,
    /// The routing table (`ip route show`).
    NetworkRoutes,
    /// DNS resolver configuration, from whichever of systemd-resolved or
    /// plain `/etc/resolv.conf` the agent detects on its host.
    DnsConfig,
    /// All active TCP/UDP sockets, not just listening ones -- complements
    /// Cadavault's `ListeningPorts` (attack-surface focus) with a
    /// diagnostics-focused view of what's actually connected right now.
    ActiveConnections,
    /// Ping + DNS lookup against a target the operator supplies. Read --
    /// sends network traffic, but only ICMP echo/DNS query, not the kind
    /// of thing that needs a confirmation gate.
    ConnectivityCheck { target: String },
    /// Brings a network interface up or down (`ip link set <iface> up|down`).
    /// The control plane treats `up: true` as Write (additive, safe) and
    /// `up: false` as Destructive (can cut off remote access to the host if
    /// it's the interface currently in use) -- same command either way, the
    /// risk categorization lives on the control-plane side of the dispatch,
    /// same as every other op here.
    InterfaceSetState { interface: String, up: bool },
    /// Active network scan ("Necrolink" -- network visibility) via nmap, if
    /// present on the host. Destructive: sends real traffic to a
    /// third-party target and can trip IDS/IPS elsewhere on the network, so
    /// the control plane requires explicit confirmation and gates this
    /// behind its own dedicated `network.scan` permission (Super Admin
    /// only by default), independent of the general `network.manage`
    /// permission the rest of this arsenal's write operations use.
    /// `ports` is an optional nmap `-p` spec (e.g. `"22,80,443"` or
    /// `"1-1024"`); omitted means nmap's own default port set. Uses a TCP
    /// connect scan (`-sT`), which doesn't need root -- unlike a SYN scan,
    /// so this isn't entangled with Apotheosis elevation.
    NetworkScan {
        target: String,
        ports: Option<String>,
    },
}

/// Hand-written rather than derived so a value carrying a real sudo password
/// (`Elevate`) can never have that password land in a log line just because
/// something somewhere formatted an operation with `{:?}` -- this is a
/// backstop, not the primary control (the primary control is that nothing
/// logs an `AgentOperation` at all), but it means that stays true even if a
/// future change accidentally would have.
impl fmt::Debug for AgentOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentOperation::Ping => write!(f, "Ping"),
            AgentOperation::SystemInfo => write!(f, "SystemInfo"),
            AgentOperation::ResourceUsage => write!(f, "ResourceUsage"),
            AgentOperation::LoggedInUsers => write!(f, "LoggedInUsers"),
            AgentOperation::SetHostname { hostname } => f
                .debug_struct("SetHostname")
                .field("hostname", hostname)
                .finish(),
            AgentOperation::Reboot => write!(f, "Reboot"),
            AgentOperation::ListeningPorts => write!(f, "ListeningPorts"),
            AgentOperation::RecentAuthLog => write!(f, "RecentAuthLog"),
            AgentOperation::FirewallStatus => write!(f, "FirewallStatus"),
            AgentOperation::FirewallAllowPort { port, protocol } => f
                .debug_struct("FirewallAllowPort")
                .field("port", port)
                .field("protocol", protocol)
                .finish(),
            AgentOperation::FirewallEnable => write!(f, "FirewallEnable"),
            AgentOperation::Elevate {
                idle_timeout_secs, ..
            } => f
                .debug_struct("Elevate")
                .field("password", &"[REDACTED]")
                .field("idle_timeout_secs", idle_timeout_secs)
                .finish(),
            AgentOperation::Deescalate => write!(f, "Deescalate"),
            AgentOperation::ElevationStatus => write!(f, "ElevationStatus"),
            AgentOperation::NetworkInterfaces => write!(f, "NetworkInterfaces"),
            AgentOperation::NetworkRoutes => write!(f, "NetworkRoutes"),
            AgentOperation::DnsConfig => write!(f, "DnsConfig"),
            AgentOperation::ActiveConnections => write!(f, "ActiveConnections"),
            AgentOperation::ConnectivityCheck { target } => f
                .debug_struct("ConnectivityCheck")
                .field("target", target)
                .finish(),
            AgentOperation::InterfaceSetState { interface, up } => f
                .debug_struct("InterfaceSetState")
                .field("interface", interface)
                .field("up", up)
                .finish(),
            AgentOperation::NetworkScan { target, ports } => f
                .debug_struct("NetworkScan")
                .field("target", target)
                .field("ports", ports)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandOutcome {
    Ok(OperationOutput),
    Err(String),
}

/// Sent from the control plane down an established agent connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    Command {
        request_id: Uuid,
        operation: AgentOperation,
    },
    Ping,
}

/// Sent from the agent back up to the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    Response {
        request_id: Uuid,
        outcome: CommandOutcome,
    },
    Pong,
}

/// Shared by both the control plane (for a useful validation error before
/// ever dispatching) and the agent (the actual execution boundary, which
/// never trusts a wire value just because the control plane already checked
/// it) -- RFC 1123 hostname/label rules.
pub fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Shared the same way `is_valid_hostname` is: both the control plane (for a
/// clean validation error) and the agent (the real execution boundary) check
/// this independently before a `FirewallAllowPort` dispatch is honored.
pub fn is_valid_port_protocol(port: u16, protocol: &str) -> bool {
    port != 0 && (protocol == "tcp" || protocol == "udp")
}

/// A target for `ConnectivityCheck` or `NetworkScan`: an IPv4 address, an
/// IPv4 CIDR range (e.g. `192.168.1.0/24`), or a hostname. Explicitly
/// rejects anything starting with `-` even though the character classes
/// below already couldn't produce one -- belt and suspenders against the
/// value ever being misread as a flag by whatever it's eventually passed
/// to as an argv entry (`ping`, `nmap`, ...).
pub fn is_valid_network_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 253 || target.starts_with('-') {
        return false;
    }

    if let Some((addr, prefix)) = target.split_once('/') {
        return addr.parse::<std::net::Ipv4Addr>().is_ok()
            && prefix.parse::<u8>().is_ok_and(|p| p <= 32);
    }

    target.parse::<std::net::Ipv4Addr>().is_ok() || is_valid_hostname(target)
}

/// A Linux network interface name: up to `IFNAMSIZ - 1` (15) characters,
/// no spaces or path separators.
pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// An nmap `-p` port spec: digits, commas, and hyphens only (e.g.
/// `"22,80,443"` or `"1-1024"`). The restricted character set is itself
/// the argument-injection defense: no letters or spaces means this value
/// can never spell out a different flag, even though a literal `-` is
/// allowed for ranges.
pub fn is_valid_port_spec(spec: &str) -> bool {
    !spec.is_empty()
        && spec.len() <= 256
        && spec
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ',' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reasonable_hostnames() {
        assert!(is_valid_hostname("web-01"));
        assert!(is_valid_hostname("db1"));
        assert!(is_valid_hostname("host.example.com"));
    }

    #[test]
    fn rejects_malformed_hostnames() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-leading-hyphen"));
        assert!(!is_valid_hostname("trailing-hyphen-"));
        assert!(!is_valid_hostname("has a space"));
        assert!(!is_valid_hostname("has_underscore"));
        assert!(!is_valid_hostname("semi;colon"));
        assert!(!is_valid_hostname(&"a".repeat(254)));
    }

    #[test]
    fn validates_port_and_protocol() {
        assert!(is_valid_port_protocol(22, "tcp"));
        assert!(is_valid_port_protocol(53, "udp"));
        assert!(!is_valid_port_protocol(0, "tcp"));
        assert!(!is_valid_port_protocol(22, "icmp"));
        assert!(!is_valid_port_protocol(22, "TCP"));
    }

    #[test]
    fn accepts_reasonable_network_targets() {
        assert!(is_valid_network_target("192.168.1.1"));
        assert!(is_valid_network_target("192.168.1.0/24"));
        assert!(is_valid_network_target("host.example.com"));
        assert!(is_valid_network_target("web-01"));
    }

    #[test]
    fn rejects_malformed_network_targets() {
        assert!(!is_valid_network_target(""));
        assert!(!is_valid_network_target("-oN /etc/passwd"));
        assert!(!is_valid_network_target("192.168.1.0/33"));
        assert!(!is_valid_network_target("192.168.1.0/"));
        assert!(!is_valid_network_target("not a hostname"));
        assert!(!is_valid_network_target("2001:db8::1"));
    }

    #[test]
    fn accepts_reasonable_interface_names() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("wlan0"));
        assert!(is_valid_interface_name("enp0s3"));
        assert!(is_valid_interface_name("br-abc123"));
    }

    #[test]
    fn rejects_malformed_interface_names() {
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name("-eth0"));
        assert!(!is_valid_interface_name("eth0; rm -rf /"));
        assert!(!is_valid_interface_name(&"a".repeat(16)));
    }

    #[test]
    fn accepts_reasonable_port_specs() {
        assert!(is_valid_port_spec("22"));
        assert!(is_valid_port_spec("22,80,443"));
        assert!(is_valid_port_spec("1-1024"));
    }

    #[test]
    fn rejects_malformed_port_specs() {
        assert!(!is_valid_port_spec(""));
        assert!(!is_valid_port_spec("22,80,--script=vuln"));
        assert!(!is_valid_port_spec("22 80"));
        assert!(!is_valid_port_spec(&"1".repeat(257)));
    }
}
