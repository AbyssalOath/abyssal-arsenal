use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A managed Linux host enrolled with the control plane. Its own OS is what
/// arsenals like `necropsy`/`ossuary`/`cadavault` actually operate on — never
/// the control-plane container itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing)]
    pub credential_hash: String,
    pub enrolled_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    /// The remote address the agent's WebSocket connected from, captured
    /// once at `ws_upgrade` time (not refreshed on every heartbeat/pong --
    /// see `crates/web/src/routes/agent.rs`). Best-effort: behind a reverse
    /// proxy this is the proxy's address, not the host's real one, same
    /// caveat every other `ConnectInfo`-derived IP in this app already has.
    /// Used by Panopticon to correlate a discovered network device against
    /// a known managed host.
    pub last_seen_ip: Option<String>,
    /// The coarse platform family the agent reported at its most recent
    /// connect (`std::env::consts::OS` on the agent binary -- `"linux"`,
    /// `"windows"`, `"macos"`, ...), or `None` for a host that has never
    /// connected under an agent build new enough to report it. Lets
    /// Thanatos (and anything else that needs to) route to the right
    /// detection logic per host instead of assuming Linux.
    pub os: Option<String>,
    /// The agent binary's own version at its most recent connect, or
    /// `None` for the same reason as `os`.
    pub agent_version: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Host {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}
