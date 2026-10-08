//! Panopticon NAC auto-enforcement policy (phase 4) model -- the ordered rules
//! that let enforcement fire without a human in the loop. A rule pairs a
//! *trigger* (why: a device is untrusted, or newly-appeared and unclassified)
//! with an *action* (disable / quarantine, reusing `EnforcementKind`) and
//! optional *scope* filters (subnet / switch / device type) that narrow which
//! devices it applies to.
//!
//! Pure data; the matching + the actual (gated) enforcement live in
//! `abyssal_web::panopticon_policy`, which evaluates enabled rules in `priority`
//! order and acts on the first match.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DeviceType, EnforcementKind};

/// Why a policy rule fires against a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyTrigger {
    /// The device is classified `Untrusted` (an admin marked it so). A stateful
    /// condition -- it keeps matching for as long as the device stays untrusted
    /// and present, which is exactly the desired "keep this device contained"
    /// behaviour.
    Untrusted,
    /// The device is newly-appeared and still unclassified (`Unknown` trust) --
    /// a rogue-device condition, bounded to a recent-first-seen window so a rule
    /// catches genuinely new arrivals rather than mass-enforcing every
    /// never-classified device on the network. See
    /// `abyssal_web::panopticon_policy` for the window.
    NewUnknown,
}

impl PolicyTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyTrigger::Untrusted => "untrusted",
            PolicyTrigger::NewUnknown => "new_unknown",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            PolicyTrigger::Untrusted => "Untrusted device",
            PolicyTrigger::NewUnknown => "New / unclassified device",
        }
    }

    pub const ALL: &'static [PolicyTrigger] =
        &[PolicyTrigger::Untrusted, PolicyTrigger::NewUnknown];
}

impl std::str::FromStr for PolicyTrigger {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "untrusted" => Ok(PolicyTrigger::Untrusted),
            "new_unknown" => Ok(PolicyTrigger::NewUnknown),
            _ => Err(()),
        }
    }
}

/// What mode the whole policy engine runs in. `Off` disables it entirely;
/// `Simulate` evaluates rules and records what it *would* do (audit log +
/// tracing) without writing to any switch -- the recommended way to watch a
/// new policy before arming it; `Active` actually applies the matched action
/// (still subject to every M3 gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyMode {
    #[default]
    Off,
    Simulate,
    Active,
}

impl PolicyMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyMode::Off => "off",
            PolicyMode::Simulate => "simulate",
            PolicyMode::Active => "active",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            PolicyMode::Off => "Off",
            PolicyMode::Simulate => "Simulate (log only, no writes)",
            PolicyMode::Active => "Active (enforce for real)",
        }
    }

    pub const ALL: &'static [PolicyMode] =
        &[PolicyMode::Off, PolicyMode::Simulate, PolicyMode::Active];
}

impl std::str::FromStr for PolicyMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(PolicyMode::Off),
            "simulate" => Ok(PolicyMode::Simulate),
            "active" => Ok(PolicyMode::Active),
            _ => Err(()),
        }
    }
}

/// One auto-enforcement rule. Evaluated in ascending `priority` order; the
/// first enabled rule whose `trigger` and all set scope filters match a device
/// decides the action for that device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: Uuid,
    /// Lower runs first. Unique-ish ordering key maintained by the CRUD layer.
    pub priority: i32,
    pub name: String,
    pub enabled: bool,
    pub trigger: PolicyTrigger,
    pub action: EnforcementKind,
    /// Scope filters -- all optional, AND-combined. `None` means "any".
    /// Matched against the device's normalized `network` (e.g. "10.0.9.0/24").
    pub subnet: Option<String>,
    pub switch_id: Option<Uuid>,
    pub device_type: Option<DeviceType>,
    /// Auto-revert timeout for actions this rule applies: `None` = use the
    /// global default, `Some(0)` = permanent, `Some(n)` = n minutes.
    pub timeout_minutes: Option<u32>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
