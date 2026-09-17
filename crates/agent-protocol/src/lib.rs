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
    /// gate.
    Elevate { password: String },
    /// Clears the elevation window early and drops sudo's own cache too.
    Deescalate,
    /// Human-readable elevation status (elevated or not, remaining time).
    ElevationStatus,
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
            AgentOperation::Elevate { .. } => f
                .debug_struct("Elevate")
                .field("password", &"[REDACTED]")
                .finish(),
            AgentOperation::Deescalate => write!(f, "Deescalate"),
            AgentOperation::ElevationStatus => write!(f, "ElevationStatus"),
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
}
