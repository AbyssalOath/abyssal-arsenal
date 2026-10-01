//! Per-host, per-channel Windows Event Log high-water marks for Thanatos (see
//! `web::thanatos_ops` and `agent::thanatos`). The control plane hands these
//! back to each `ScanSecurityEvents` so the Windows agent reads only events
//! newer than it last saw.

use uuid::Uuid;

use crate::DbPool;

/// Every `(channel, record_id)` high-water mark recorded for a host -- passed
/// into the host's next scan.
pub async fn offsets_for_host(pool: &DbPool, host_id: Uuid) -> anyhow::Result<Vec<(String, u64)>> {
    let rows: Vec<(String, u64)> = sqlx::query_as(
        "SELECT channel, record_id FROM thanatos_windows_log_offsets WHERE host_id = ?",
    )
    .bind(host_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Advances a channel's high-water mark. Only ever moves forward (`GREATEST`),
/// so an out-of-order or stale report can never rewind a host past events it has
/// already ingested.
pub async fn record_offset(
    pool: &DbPool,
    host_id: Uuid,
    channel: &str,
    record_id: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO thanatos_windows_log_offsets (host_id, channel, record_id) \
         VALUES (?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             record_id = GREATEST(record_id, VALUES(record_id)), \
             updated_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(host_id.to_string())
    .bind(channel)
    .bind(record_id)
    .execute(pool)
    .await?;
    Ok(())
}
