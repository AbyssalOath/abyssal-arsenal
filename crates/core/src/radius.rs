//! Panopticon NAC phase 5 (embedded RADIUS server) model types -- the network
//! access servers (switches/APs) allowed to talk to the RADIUS listener, and
//! the authenticated sessions it has accounted. The wire protocol and the
//! server itself live in `abyssal_web::radius` / `abyssal_web::panopticon_radius`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A RADIUS client (a "NAS": a switch or AP) permitted to send Access/Accounting
/// requests. Matched by source address, keyed to a shared secret. The secret is
/// stored encrypted at rest (`abyssal_core::crypto::EncryptionKey`); callers
/// decrypt it only at the point of verifying/signing a packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusClient {
    pub id: Uuid,
    pub name: String,
    /// The NAS source address this client matches: either a bare IP
    /// ("10.0.0.2") or a CIDR ("10.0.0.0/24") covering a range of NAS devices.
    pub nas_address: String,
    pub shared_secret_encrypted: String,
    pub enabled: bool,
    /// How to push a re-authorization to this NAS (RFC 5176), 0.2.7 N2.
    pub coa_mode: CoaMode,
    /// UDP port the NAS listens on for CoA/Disconnect (RFC 5176 default 3799).
    pub coa_port: u16,
    pub created_at: DateTime<Utc>,
}

/// How Panopticon asks a NAS to re-authorize a session after a device's trust
/// or quarantine changes (RFC 5176 Dynamic Authorization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CoaMode {
    /// Never: changes take effect at the device's next authentication.
    #[default]
    Off,
    /// Disconnect-Request: the NAS ends the session and the device
    /// re-authenticates, getting the new decision. Works on most switches and
    /// controllers; the device briefly loses access.
    Disconnect,
    /// CoA-Request carrying Cisco's `subscriber:command=reauthenticate`: the
    /// switch re-runs authorization without dropping the link. Cisco IOS/IOS-XE
    /// (and some others that copy it).
    CiscoReauth,
}

impl CoaMode {
    pub const ALL: &'static [CoaMode] = &[CoaMode::Off, CoaMode::Disconnect, CoaMode::CiscoReauth];

    pub const fn as_str(self) -> &'static str {
        match self {
            CoaMode::Off => "off",
            CoaMode::Disconnect => "disconnect",
            CoaMode::CiscoReauth => "cisco_reauth",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            CoaMode::Off => "Off",
            CoaMode::Disconnect => "Disconnect (RFC 5176)",
            CoaMode::CiscoReauth => "Reauthenticate (Cisco CoA)",
        }
    }
}

impl std::str::FromStr for CoaMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CoaMode::ALL
            .iter()
            .copied()
            .find(|m| m.as_str() == s)
            .ok_or(())
    }
}

/// One accounted RADIUS session, from the NAS's accounting stream -- the
/// "richer identity" record tying an authenticated user/MAC to where and when
/// it was on the network. Keyed uniquely by (`nas_ip`, `acct_session_id`);
/// Interim-Update refreshes `last_seen_at`, Stop sets `stopped_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusSession {
    pub id: Uuid,
    /// The authenticated identity: a real username for an EAP session, or the
    /// MAC for a MAB session.
    pub username: Option<String>,
    /// Device MAC (from Calling-Station-Id), normalized lower-colon where
    /// possible -- what ties a session back to an inventory device.
    pub mac_address: Option<String>,
    pub nas_ip: Option<String>,
    /// Switch port the session is on (Called-Station-Id / NAS-Port-Id).
    pub nas_port: Option<String>,
    pub framed_ip: Option<String>,
    pub acct_session_id: Option<String>,
    /// How Panopticon authorized it: "mab", "pap", or "accounting" (a session
    /// first seen via an accounting packet we didn't authorize ourselves).
    pub auth_method: Option<String>,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub terminate_cause: Option<String>,
    /// The latest CoA/Disconnect sent for this session and the NAS's answer.
    pub last_coa_at: Option<DateTime<Utc>>,
    pub last_coa_result: Option<String>,
}

impl RadiusSession {
    /// Whether this session is still open (no Stop recorded).
    pub fn is_active(&self) -> bool {
        self.stopped_at.is_none()
    }
}
