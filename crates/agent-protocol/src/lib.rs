//! Wire format shared between the control plane and `abyssal-agent`. This
//! crate is pure data — no I/O — so both sides link the exact same
//! definitions instead of hand-keeping two copies in sync.
//!
//! `AgentOperation` is the actual security boundary for remote execution: an
//! agent will only ever run one of these fixed, named operations, never an
//! arbitrary command string sent over the wire. Adding a capability means
//! adding a variant here (and implementing it in the agent) — the protocol
//! itself can't be used to smuggle in anything else.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOperation {
    /// Pure connectivity/liveness check — no work performed.
    Ping,
    /// Hostname, kernel version, and uptime, read locally on the agent's host.
    SystemInfo,
    /// Memory and disk usage, read locally on the agent's host.
    ResourceUsage,
    /// Currently logged-in users/sessions on the agent's host.
    LoggedInUsers,
    /// Immediately reboots the agent's host. Destructive -- the control
    /// plane requires explicit confirmation before ever dispatching this.
    Reboot,
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
