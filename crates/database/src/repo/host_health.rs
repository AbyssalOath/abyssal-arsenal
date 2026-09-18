use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct HostHealthRow {
    host_id: String,
    failed_unit_count: i32,
    error: Option<String>,
    checked_at: NaiveDateTime,
}

/// One host's most recent health-sweep result. `needs_attention` is the
/// dashboard's single "is this host okay" signal: either the sweep itself
/// couldn't complete (`error` set -- host unreachable, no systemd, ...) or
/// it completed and found failed units.
pub struct HostHealth {
    pub host_id: Uuid,
    pub failed_unit_count: i32,
    pub error: Option<String>,
    pub checked_at: DateTime<Utc>,
}

impl HostHealth {
    pub fn needs_attention(&self) -> bool {
        self.error.is_some() || self.failed_unit_count > 0
    }
}

impl From<HostHealthRow> for HostHealth {
    fn from(row: HostHealthRow) -> Self {
        HostHealth {
            host_id: Uuid::parse_str(&row.host_id).unwrap_or_default(),
            failed_unit_count: row.failed_unit_count,
            error: row.error,
            checked_at: DateTime::from_naive_utc_and_offset(row.checked_at, Utc),
        }
    }
}

/// Records (or replaces) the latest sweep result for one host -- always
/// exactly one row per host, never a history.
pub async fn upsert(
    pool: &DbPool,
    host_id: Uuid,
    failed_unit_count: i32,
    error: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO host_health_snapshots (host_id, failed_unit_count, error, checked_at) \
         VALUES (?, ?, ?, CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE \
             failed_unit_count = VALUES(failed_unit_count), \
             error = VALUES(error), \
             checked_at = VALUES(checked_at)",
    )
    .bind(host_id.to_string())
    .bind(failed_unit_count)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every host whose latest sweep result needs a look -- failed units or a
/// sweep error -- most recently checked first.
pub async fn needing_attention(pool: &DbPool) -> anyhow::Result<Vec<HostHealth>> {
    let rows: Vec<HostHealthRow> = sqlx::query_as(
        "SELECT * FROM host_health_snapshots \
         WHERE failed_unit_count > 0 OR error IS NOT NULL \
         ORDER BY checked_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}
