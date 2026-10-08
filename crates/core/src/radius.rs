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
    pub created_at: DateTime<Utc>,
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
}

impl RadiusSession {
    /// Whether this session is still open (no Stop recorded).
    pub fn is_active(&self) -> bool {
        self.stopped_at.is_none()
    }
}
