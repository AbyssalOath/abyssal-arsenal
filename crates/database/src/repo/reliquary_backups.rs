use abyssal_core::{
    BackupComponent, BackupJob, BackupJobType, BackupManifest, BackupStatus, BackupTrigger,
    VerificationStatus,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct BackupRow {
    id: String,
    job_type: String,
    status: String,
    trigger_source: String,
    components: Value,
    encrypted: bool,
    includes_encryption_keys: bool,
    destination_path: String,
    destination_connection_id: Option<String>,
    file_name: Option<String>,
    size_bytes: Option<u64>,
    sha256: Option<String>,
    manifest_json: Option<Value>,
    error_message: Option<String>,
    verification_status: Option<String>,
    verification_at: Option<NaiveDateTime>,
    verification_details: Option<String>,
    started_at: Option<NaiveDateTime>,
    finished_at: Option<NaiveDateTime>,
    created_by: Option<String>,
    created_at: NaiveDateTime,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

fn parse_components(value: &Value) -> Vec<BackupComponent> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| s.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

impl From<BackupRow> for BackupJob {
    fn from(row: BackupRow) -> Self {
        BackupJob {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            job_type: row.job_type.parse().unwrap_or(BackupJobType::Native),
            status: row.status.parse().unwrap_or(BackupStatus::Failed),
            trigger_source: row.trigger_source.parse().unwrap_or(BackupTrigger::Manual),
            components: parse_components(&row.components),
            encrypted: row.encrypted,
            includes_encryption_keys: row.includes_encryption_keys,
            destination_path: row.destination_path,
            destination_connection_id: row
                .destination_connection_id
                .and_then(|id| Uuid::parse_str(&id).ok()),
            file_name: row.file_name,
            size_bytes: row.size_bytes,
            sha256: row.sha256,
            manifest: row
                .manifest_json
                .and_then(|v| serde_json::from_value::<BackupManifest>(v).ok()),
            error_message: row.error_message,
            verification_status: row
                .verification_status
                .and_then(|s| s.parse::<VerificationStatus>().ok()),
            verification_at: row.verification_at.map(utc),
            verification_details: row.verification_details,
            started_at: row.started_at.map(utc),
            finished_at: row.finished_at.map(utc),
            created_by: row
                .created_by
                .map(|id| Uuid::parse_str(&id).unwrap_or_default()),
            created_at: utc(row.created_at),
        }
    }
}

pub struct NewBackupJob<'a> {
    pub trigger_source: BackupTrigger,
    pub components: &'a [BackupComponent],
    pub encrypted: bool,
    pub includes_encryption_keys: bool,
    pub destination_path: &'a str,
    pub destination_connection_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
}

/// Creates a job row in `Queued` status. The orchestrator transitions it
/// to `Running` (`mark_running`) immediately after, in a separate step,
/// so "a job exists" and "a job is actually executing" are always
/// distinguishable even if the process crashes between the two.
pub async fn create(pool: &DbPool, job: NewBackupJob<'_>) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    let components_json = serde_json::to_value(
        job.components
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>(),
    )?;
    sqlx::query(
        "INSERT INTO reliquary_backups \
         (id, job_type, status, trigger_source, components, encrypted, includes_encryption_keys, \
          destination_path, destination_connection_id, created_by) \
         VALUES (?, 'native', ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(BackupStatus::Queued.as_str())
    .bind(job.trigger_source.as_str())
    .bind(components_json)
    .bind(job.encrypted)
    .bind(job.includes_encryption_keys)
    .bind(job.destination_path)
    .bind(job.destination_connection_id.map(|c| c.to_string()))
    .bind(job.created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<BackupJob>> {
    let row: Option<BackupRow> = sqlx::query_as("SELECT * FROM reliquary_backups WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<BackupJob>> {
    let rows: Vec<BackupRow> =
        sqlx::query_as("SELECT * FROM reliquary_backups ORDER BY created_at DESC")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn mark_running(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE reliquary_backups SET status = ?, started_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(BackupStatus::Running.as_str())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn mark_succeeded(
    pool: &DbPool,
    id: Uuid,
    file_name: &str,
    size_bytes: u64,
    sha256: &str,
    manifest: &BackupManifest,
) -> anyhow::Result<()> {
    let manifest_json = serde_json::to_value(manifest)?;
    sqlx::query(
        "UPDATE reliquary_backups SET status = ?, file_name = ?, size_bytes = ?, sha256 = ?, \
         manifest_json = ?, finished_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(BackupStatus::Succeeded.as_str())
    .bind(file_name)
    .bind(size_bytes)
    .bind(sha256)
    .bind(manifest_json)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_failed(pool: &DbPool, id: Uuid, error_message: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE reliquary_backups SET status = ?, error_message = ?, \
         finished_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(BackupStatus::Failed.as_str())
    .bind(error_message)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_cancelled(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE reliquary_backups SET status = ?, finished_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(BackupStatus::Cancelled.as_str())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn record_verification(
    pool: &DbPool,
    id: Uuid,
    status: VerificationStatus,
    details: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE reliquary_backups SET verification_status = ?, verification_details = ?, \
         verification_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(status.as_str())
    .bind(details)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM reliquary_backups WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Every job still `Queued`/`Running` -- if this is non-empty at startup,
/// the previous process crashed mid-backup (a clean shutdown never leaves
/// one of these, see `reliquary_backup::recover_interrupted_jobs`).
pub async fn list_unterminated(pool: &DbPool) -> anyhow::Result<Vec<BackupJob>> {
    let rows: Vec<BackupRow> = sqlx::query_as(
        "SELECT * FROM reliquary_backups WHERE status IN ('queued', 'running', 'verifying')",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn most_recent_backup_time(pool: &DbPool) -> anyhow::Result<Option<DateTime<Utc>>> {
    let row: Option<(Option<NaiveDateTime>,)> = sqlx::query_as(
        "SELECT MAX(created_at) FROM reliquary_backups WHERE status IN ('succeeded', 'verified')",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(t,)| t).map(utc))
}
