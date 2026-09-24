//! Sepulchre: `validation_runs` -- see `migrations/0019_sepulchre_storage.sql`.

use abyssal_core::{ValidationCheckResult, ValidationMode, ValidationRun, ValidationStatus};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(FromRow)]
struct ValidationRunRow {
    id: String,
    connection_id: String,
    mode: String,
    checks: serde_json::Value,
    overall_status: String,
    started_at: NaiveDateTime,
    finished_at: Option<NaiveDateTime>,
    triggered_by: Option<String>,
}

impl TryFrom<ValidationRunRow> for ValidationRun {
    type Error = anyhow::Error;
    fn try_from(row: ValidationRunRow) -> Result<Self, Self::Error> {
        Ok(ValidationRun {
            id: Uuid::parse_str(&row.id)?,
            connection_id: Uuid::parse_str(&row.connection_id)?,
            mode: row
                .mode
                .parse()
                .map_err(|_| anyhow::anyhow!("unknown validation mode: {}", row.mode))?,
            checks: serde_json::from_value(row.checks)?,
            overall_status: row.overall_status.parse().map_err(|_| {
                anyhow::anyhow!("unknown validation status: {}", row.overall_status)
            })?,
            started_at: utc(row.started_at),
            finished_at: row.finished_at.map(utc),
            triggered_by: row
                .triggered_by
                .map(|id| Uuid::parse_str(&id))
                .transpose()?,
        })
    }
}

/// Starts a run row before any checks execute, so a crash mid-validation
/// leaves a visibly `Failed`/unfinished row rather than nothing at all.
pub async fn start(
    pool: &DbPool,
    connection_id: Uuid,
    mode: ValidationMode,
    triggered_by: Option<Uuid>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO validation_runs (id, connection_id, mode, checks, overall_status, triggered_by) \
         VALUES (?, ?, ?, JSON_ARRAY(), ?, ?)",
    )
    .bind(id.to_string())
    .bind(connection_id.to_string())
    .bind(mode.as_str())
    .bind("failed")
    .bind(triggered_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn finish(
    pool: &DbPool,
    id: Uuid,
    checks: &[ValidationCheckResult],
    overall_status: ValidationStatus,
) -> anyhow::Result<()> {
    let checks_json = serde_json::to_value(checks)?;
    sqlx::query(
        "UPDATE validation_runs SET checks = ?, overall_status = ?, \
         finished_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(checks_json)
    .bind(overall_status.as_str())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<ValidationRun>> {
    let row: Option<ValidationRunRow> =
        sqlx::query_as("SELECT * FROM validation_runs WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    row.map(TryFrom::try_from).transpose()
}

pub async fn history_for_connection(
    pool: &DbPool,
    connection_id: Uuid,
    limit: i64,
) -> anyhow::Result<Vec<ValidationRun>> {
    let rows: Vec<ValidationRunRow> = sqlx::query_as(
        "SELECT * FROM validation_runs WHERE connection_id = ? ORDER BY started_at DESC LIMIT ?",
    )
    .bind(connection_id.to_string())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(TryFrom::try_from).collect()
}

pub async fn most_recent(
    pool: &DbPool,
    connection_id: Uuid,
) -> anyhow::Result<Option<ValidationRun>> {
    let row: Option<ValidationRunRow> = sqlx::query_as(
        "SELECT * FROM validation_runs WHERE connection_id = ? AND finished_at IS NOT NULL \
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(connection_id.to_string())
    .fetch_optional(pool)
    .await?;
    row.map(TryFrom::try_from).transpose()
}
