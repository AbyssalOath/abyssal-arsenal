use abyssal_core::security_event::hash_event_line;
use abyssal_core::{SecurityEvent, Severity};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct SecurityEventRow {
    id: String,
    host_id: String,
    source: String,
    severity: String,
    label: String,
    raw_line: String,
    occurred_at: NaiveDateTime,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<SecurityEventRow> for SecurityEvent {
    fn from(row: SecurityEventRow) -> Self {
        SecurityEvent {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            host_id: Uuid::parse_str(&row.host_id).unwrap_or_default(),
            source: row.source,
            // A row with a severity key this build doesn't recognize
            // (e.g. rolled back to an older binary after a newer one
            // wrote data) falls back to `Low` rather than failing the
            // whole query -- one mislabeled row is far better than the
            // entire event log becoming unreadable.
            severity: Severity::from_key(&row.severity).unwrap_or(Severity::Low),
            label: row.label,
            raw_line: row.raw_line,
            occurred_at: utc(row.occurred_at),
        }
    }
}

/// Inserts one classified event, deduplicating on content hash --
/// re-scanning the same log tail window on every sweep produces the same
/// hash and is silently ignored, not a duplicate row. Returns whether this
/// call actually inserted a new row (`rows_affected() == 1` for a real
/// insert, `0` when `INSERT IGNORE` skipped a duplicate).
pub async fn insert_if_new(
    pool: &DbPool,
    host_id: Uuid,
    source: &str,
    severity: Severity,
    label: &str,
    raw_line: &str,
) -> anyhow::Result<bool> {
    let hash = hash_event_line(host_id, source, raw_line);
    let result = sqlx::query(
        "INSERT IGNORE INTO thanatos_events (id, host_id, line_hash, source, severity, label, raw_line) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(host_id.to_string())
    .bind(hash)
    .bind(source)
    .bind(severity.as_key())
    .bind(label)
    .bind(raw_line)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_recent_for_host(
    pool: &DbPool,
    host_id: Uuid,
    limit: i64,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let rows: Vec<SecurityEventRow> = sqlx::query_as(
        "SELECT * FROM thanatos_events WHERE host_id = ? ORDER BY occurred_at DESC LIMIT ?",
    )
    .bind(host_id.to_string())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Correlation-raised findings across every host, most recent first --
/// the "alerts" view.
pub async fn list_recent_alerts(pool: &DbPool, limit: i64) -> anyhow::Result<Vec<SecurityEvent>> {
    let rows: Vec<SecurityEventRow> = sqlx::query_as(
        "SELECT * FROM thanatos_events WHERE source = 'correlation' \
         ORDER BY occurred_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// How many `high`/`critical` events a host has logged (excluding its own
/// past correlation findings, which shouldn't feed back into triggering
/// new ones) in the last `minutes` -- the threshold check a correlation
/// sweep runs per host.
pub async fn count_high_severity_since(
    pool: &DbPool,
    host_id: Uuid,
    minutes: i64,
) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM thanatos_events \
         WHERE host_id = ? AND source != 'correlation' \
           AND severity IN ('high', 'critical') \
           AND occurred_at > (NOW() - INTERVAL ? MINUTE)",
    )
    .bind(host_id.to_string())
    .bind(minutes)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// The correlation sweep's own cooldown check: has this host already had
/// a correlation finding raised in the last `minutes`? Prevents one
/// ongoing burst from generating a fresh alert on every sweep tick.
pub async fn has_recent_correlation_event(
    pool: &DbPool,
    host_id: Uuid,
    minutes: i64,
) -> anyhow::Result<bool> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM thanatos_events \
         WHERE host_id = ? AND source = 'correlation' \
           AND occurred_at > (NOW() - INTERVAL ? MINUTE)",
    )
    .bind(host_id.to_string())
    .bind(minutes)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// Fleet-wide event counts by severity in the last `hours` -- the
/// landing page's summary row.
pub async fn count_by_severity_since(
    pool: &DbPool,
    hours: i64,
) -> anyhow::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*) FROM thanatos_events \
         WHERE occurred_at > (NOW() - INTERVAL ? HOUR) \
         GROUP BY severity",
    )
    .bind(hours)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
