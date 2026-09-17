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
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Host {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}
