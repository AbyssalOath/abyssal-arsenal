//! Panopticon NAC auto-enforcement policy (phase 4) model -- the ordered rules
//! that let enforcement fire without a human in the loop. A rule pairs a
//! *trigger* (why: a device is untrusted, newly-appeared and unclassified, or
//! -- 0.2.7 N1 -- flagged by Scourge, Thanatos or Cadavault) with an *action*
//! (disable / quarantine, reusing `EnforcementKind`) and optional *scope*
//! filters (subnet / switch / device type) that narrow which devices it
//! applies to.
//!
//! Pure data; the matching + the actual (gated) enforcement live in
//! `abyssal_web::panopticon_policy`, which evaluates enabled rules in `priority`
//! order and acts on the first match.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DeviceType, EnforcementKind, Severity};

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
    /// Scourge (Suricata) raised an alert at or above the rule's minimum
    /// severity with this device as the flow's *source*, within the signal
    /// window. Never the destination: that's the victim of an inbound attack.
    IdsAlert,
    /// Thanatos has an *open* security event at or above the rule's minimum
    /// severity, within the signal window, on the managed host this device
    /// belongs to. Acknowledging or resolving the event stands the rule down.
    SecurityEvent,
    /// The latest Cadavault posture run on the managed host this device
    /// belongs to scored below the rule's threshold.
    PostureFailing,
    /// The device answered DHCP as a server that isn't on the allowed list
    /// (0.2.9 Q4), within the signal window: by the source MAC of an
    /// unrelayed reply it sent, never by an address a packet names (which
    /// any device can forge).
    RogueDhcp,
}

/// The minimum severity a signal trigger uses when the rule doesn't set one.
pub const DEFAULT_SIGNAL_MIN_SEVERITY: Severity = Severity::High;
/// The posture score `PostureFailing` compares against when the rule doesn't
/// set one: below this fails.
pub const DEFAULT_POSTURE_BELOW: u8 = 60;

impl PolicyTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyTrigger::Untrusted => "untrusted",
            PolicyTrigger::NewUnknown => "new_unknown",
            PolicyTrigger::IdsAlert => "ids_alert",
            PolicyTrigger::SecurityEvent => "security_event",
            PolicyTrigger::PostureFailing => "posture_failing",
            PolicyTrigger::RogueDhcp => "rogue_dhcp",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            PolicyTrigger::Untrusted => "Untrusted device",
            PolicyTrigger::NewUnknown => "New / unclassified device",
            PolicyTrigger::IdsAlert => "IDS alert from the device (Scourge)",
            PolicyTrigger::SecurityEvent => "Open security event on the host (Thanatos)",
            PolicyTrigger::PostureFailing => "Failing posture (Cadavault)",
            PolicyTrigger::RogueDhcp => "Rogue DHCP server (not on the allowed list)",
        }
    }

    /// Whether the rule's `min_severity` applies to this trigger.
    pub const fn uses_severity(self) -> bool {
        matches!(self, PolicyTrigger::IdsAlert | PolicyTrigger::SecurityEvent)
    }

    /// Whether this trigger needs the device linked to a managed host.
    pub const fn needs_managed_host(self) -> bool {
        matches!(
            self,
            PolicyTrigger::SecurityEvent | PolicyTrigger::PostureFailing
        )
    }

    pub const ALL: &'static [PolicyTrigger] = &[
        PolicyTrigger::Untrusted,
        PolicyTrigger::NewUnknown,
        PolicyTrigger::IdsAlert,
        PolicyTrigger::SecurityEvent,
        PolicyTrigger::PostureFailing,
        PolicyTrigger::RogueDhcp,
    ];
}

impl std::str::FromStr for PolicyTrigger {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "untrusted" => Ok(PolicyTrigger::Untrusted),
            "new_unknown" => Ok(PolicyTrigger::NewUnknown),
            "ids_alert" => Ok(PolicyTrigger::IdsAlert),
            "security_event" => Ok(PolicyTrigger::SecurityEvent),
            "posture_failing" => Ok(PolicyTrigger::PostureFailing),
            "rogue_dhcp" => Ok(PolicyTrigger::RogueDhcp),
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
    /// `IdsAlert` / `SecurityEvent`: the lowest severity that fires the rule.
    /// `None` = [`DEFAULT_SIGNAL_MIN_SEVERITY`]. Ignored by other triggers.
    pub min_severity: Option<Severity>,
    /// `PostureFailing`: fires when the latest score is below this. `None` =
    /// [`DEFAULT_POSTURE_BELOW`]. Ignored by other triggers.
    pub posture_below: Option<u8>,
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

impl PolicyRule {
    pub fn effective_min_severity(&self) -> Severity {
        self.min_severity.unwrap_or(DEFAULT_SIGNAL_MIN_SEVERITY)
    }

    pub fn effective_posture_below(&self) -> u8 {
        self.posture_below.unwrap_or(DEFAULT_POSTURE_BELOW)
    }

    /// The trigger with its threshold, for the rule table, e.g. "IDS alert
    /// from the device (Scourge): high or worse".
    pub fn condition_label(&self) -> String {
        match self.trigger {
            t if t.uses_severity() => {
                format!("{}: {} or worse", t.label(), self.effective_min_severity())
            }
            PolicyTrigger::PostureFailing => format!(
                "{}: score below {}",
                self.trigger.label(),
                self.effective_posture_below()
            ),
            t => t.label().to_string(),
        }
    }
}

/// What a policy rule would have done to a device, recorded while the
/// policy runs in Simulate mode (0.2.9 Q2, roadmap B6): one row per rule and
/// device, updated each sweep it still matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySimulation {
    pub rule_id: Uuid,
    pub device_id: Uuid,
    pub rule_name: String,
    pub device_ip: String,
    pub mac_address: Option<String>,
    pub action: EnforcementKind,
    /// `port` (SNMP), `radius`, or `skipped`.
    pub path: String,
    /// The port, or why it wouldn't be enforced; and the signal.
    pub detail: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub times_seen: u32,
}
