use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct BackupRecordRow {
    id: String,
    host_id: String,
    name: String,
    #[allow(dead_code)]
    source_path: String,
    created_at: NaiveDateTime,
}

pub struct BackupRecord {
    pub id: Uuid,
    pub host_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

impl From<BackupRecordRow> for BackupRecord {
    fn from(row: BackupRecordRow) -> Self {
        BackupRecord {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            host_id: Uuid::parse_str(&row.host_id).unwrap_or_default(),
            name: row.name,
            created_at: DateTime::from_naive_utc_and_offset(row.created_at, Utc),
        }
    }
}

/// Records that Reliquary created a backup -- purely a control-plane-side
/// history for the dashboard; the backup archive itself lives only on the
/// host, this never mirrors its contents.
pub async fn record(
    pool: &DbPool,
    host_id: Uuid,
    name: &str,
    source_path: &str,
    created_by: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO backup_records (id, host_id, name, source_path, created_by) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(host_id.to_string())
    .bind(name)
    .bind(source_path)
    .bind(created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(())
}

/// The single most recent backup across the whole fleet, for the
/// dashboard's "last backup" line -- `None` means no backup has ever been
/// recorded.
pub async fn most_recent(pool: &DbPool) -> anyhow::Result<Option<BackupRecord>> {
    let row: Option<BackupRecordRow> =
        sqlx::query_as("SELECT * FROM backup_records ORDER BY created_at DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(Into::into))
}
