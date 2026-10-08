//! Panopticon NAC enforcement (phase 3) model -- the record of an SNMP SET
//! actually written to a live switch to take a port out of service, and
//! enough snapshotted prior state to put it back exactly as it was.
//!
//! This type is pure data; the SNMP I/O that applies/reverts an action lives
//! in `abyssal_web::panopticon_snmp`, and the orchestration (snapshot ->
//! persist -> SET -> schedule revert) in `abyssal_web::panopticon_enforcement`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What an enforcement action does to a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementKind {
    /// SNMP SET `ifAdminStatus` = down(2). The port goes dark; whatever is
    /// plugged into it loses link entirely. Revert restores the port's
    /// previously-recorded admin status (normally up).
    Disable,
    /// SNMP SET `dot1qPvid` to the quarantine VLAN and add the port to that
    /// VLAN's static untagged/egress maps. The device keeps link but is
    /// isolated on the quarantine VLAN. Revert restores the port's previous
    /// PVID and removes it from the quarantine VLAN's maps. Vendor-dependent
    /// -- some switches don't honor Q-BRIDGE writes over SNMP.
    Quarantine,
}

impl EnforcementKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EnforcementKind::Disable => "disable",
            EnforcementKind::Quarantine => "quarantine",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            EnforcementKind::Disable => "Disable port",
            EnforcementKind::Quarantine => "Quarantine (VLAN)",
        }
    }
}

impl std::str::FromStr for EnforcementKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disable" => Ok(EnforcementKind::Disable),
            "quarantine" => Ok(EnforcementKind::Quarantine),
            _ => Err(()),
        }
    }
}

/// Lifecycle of an enforcement action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementState {
    /// The SET succeeded and the action is currently in effect.
    Active,
    /// The port has been restored (operator released it, or the auto-revert
    /// sweep expired it) and the restoring SET succeeded.
    Reverted,
    /// The apply-time SET failed (switch unreachable, read-only community,
    /// rejected value). The port was *not* changed; the row is kept as an
    /// audit trail of the attempt. Terminal.
    ApplyFailed,
    /// The action was applied, but the later revert SET failed -- the port may
    /// still be enforced on the switch. Surfaced loudly so an operator can
    /// intervene by hand; the revert sweep keeps retrying these.
    RevertFailed,
}

impl EnforcementState {
    pub const fn as_str(self) -> &'static str {
        match self {
            EnforcementState::Active => "active",
            EnforcementState::Reverted => "reverted",
            EnforcementState::ApplyFailed => "apply_failed",
            EnforcementState::RevertFailed => "revert_failed",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            EnforcementState::Active => "Active",
            EnforcementState::Reverted => "Reverted",
            EnforcementState::ApplyFailed => "Apply failed",
            EnforcementState::RevertFailed => "Revert failed",
        }
    }

    /// Whether this action is still in effect on the switch (or believed to
    /// be, in the `RevertFailed` case) -- i.e. the port is not known-good.
    pub const fn is_in_effect(self) -> bool {
        matches!(
            self,
            EnforcementState::Active | EnforcementState::RevertFailed
        )
    }
}

impl std::str::FromStr for EnforcementState {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(EnforcementState::Active),
            "reverted" => Ok(EnforcementState::Reverted),
            "apply_failed" => Ok(EnforcementState::ApplyFailed),
            "revert_failed" => Ok(EnforcementState::RevertFailed),
            _ => Err(()),
        }
    }
}

/// One enforcement action against one switch port. `original_admin_status`
/// (for `Disable`) and `original_pvid` (for `Quarantine`) are the snapshot the
/// revert path restores to -- captured by reading the switch immediately
/// before the enforcing SET, so a revert returns the port to exactly the
/// state it was in rather than a guessed default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementAction {
    pub id: Uuid,
    pub switch_id: Uuid,
    /// Snapshot of the switch's name at apply time, so history stays readable
    /// even if the switch is later renamed or removed.
    pub switch_name: String,
    /// IF-MIB ifIndex of the enforced port.
    pub if_index: u32,
    /// Human-readable port label (`ifDescr`) snapshot at apply time.
    pub port_label: String,
    pub kind: EnforcementKind,
    pub state: EnforcementState,
    /// Prior `ifAdminStatus` code for a `Disable` action, restored on revert.
    pub original_admin_status: Option<i64>,
    /// Prior `dot1qPvid` for a `Quarantine` action, restored on revert.
    pub original_pvid: Option<i64>,
    /// The quarantine VLAN a `Quarantine` action moved the port into.
    pub quarantine_vlan: Option<i64>,
    /// Operator-supplied reason, shown in history and the audit log.
    pub reason: Option<String>,
    /// Who applied it (user id), or `None` if somehow system-initiated.
    pub created_by: Option<Uuid>,
    pub created_by_username: Option<String>,
    pub created_at: DateTime<Utc>,
    /// When the auto-revert sweep should restore this action, or `None` for a
    /// permanent action (no timeout). Ignored once `state` is terminal.
    pub expires_at: Option<DateTime<Utc>>,
    pub reverted_at: Option<DateTime<Utc>>,
    /// Last error from a failed apply or revert, for the UI/audit trail.
    pub last_error: Option<String>,
}

impl EnforcementAction {
    /// Whether a timed action is due for auto-revert as of `now`.
    pub fn is_due_for_revert(&self, now: DateTime<Utc>) -> bool {
        self.state.is_in_effect() && self.expires_at.is_some_and(|exp| exp <= now)
    }
}
