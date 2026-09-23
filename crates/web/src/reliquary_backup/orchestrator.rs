//! Job lifecycle, scheduling, and retention -- GitHub issue #9. Ties the
//! `BackupProvider`/`StorageDestination` engine to the `reliquary_backups`
//! table: creating a job row, running the provider, recording the
//! outcome, and the unattended scheduled-backup loop (same plain
//! `tokio::spawn` + `tokio::time::interval` pattern every other
//! background task in this app already uses -- `crates/app/src/main.rs`
//! -- not a new scheduler dependency).

use std::sync::Arc;
use std::time::Duration;

use abyssal_core::settings::{
    RELIQUARY_BACKUP_INCLUDE_AUDIT_LOGS, RELIQUARY_BACKUP_RETENTION_DAYS,
    RELIQUARY_BACKUP_RETENTION_DEFAULT_DAYS, RELIQUARY_BACKUP_RETENTION_DEFAULT_KEEP_LAST,
    RELIQUARY_BACKUP_RETENTION_KEEP_LAST, RELIQUARY_BACKUP_SCHEDULE_DEFAULT_INTERVAL_HOURS,
    RELIQUARY_BACKUP_SCHEDULE_ENABLED, RELIQUARY_BACKUP_SCHEDULE_INTERVAL_HOURS,
};
use abyssal_core::{BackupComponent, BackupJob, BackupTrigger};
use abyssal_database::{DbPool, repo};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::BackupError;
use super::provider::{BackupProvider, BackupRequest};

/// MariaDB named lock GET_LOCK()/RELEASE_LOCK() key -- session-scoped, so
/// it's automatically released if the connection holding it drops (a
/// crash mid-backup releases the lock on its own; it does *not* fix up
/// the job row, which is what `recover_interrupted_jobs` is for). No new
/// table needed for this the way a job-lock row would.
const LOCK_NAME: &str = "reliquary_backup";

/// Runs `f` only if the named lock can be acquired immediately
/// (`GET_LOCK(name, 0)` -- non-blocking: a `0` or `NULL` result means
/// someone else already holds it, or the lock server is unavailable,
/// either of which means "don't run a second backup/restore right now"),
/// holding one dedicated connection for the lock's whole lifetime (a
/// pooled connection would let the lock silently migrate to a different
/// session on the next query). Always releases before returning, even if
/// `f` fails.
async fn with_backup_lock<F, Fut, T>(pool: &DbPool, f: F) -> Result<Option<T>, BackupError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, BackupError>>,
{
    let mut conn = pool.acquire().await?;
    let (acquired,): (Option<i64>,) = sqlx::query_as("SELECT GET_LOCK(?, 0)")
        .bind(LOCK_NAME)
        .fetch_one(&mut *conn)
        .await?;
    if acquired != Some(1) {
        return Ok(None);
    }

    let result = f().await;

    let _: (Option<i64>,) = sqlx::query_as("SELECT RELEASE_LOCK(?)")
        .bind(LOCK_NAME)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or((None,));

    result.map(Some)
}

pub struct RunBackupOptions {
    pub trigger_source: BackupTrigger,
    pub components: Vec<BackupComponent>,
    pub encrypt: bool,
    pub passphrase: Option<Zeroizing<String>>,
    pub created_by: Option<uuid::Uuid>,
}

/// Creates the job row, runs the provider under the backup lock, and
/// records the outcome either way. Returns the job ID whether it
/// succeeded or failed -- the caller looks up the row for the actual
/// result rather than this function returning it directly, so every
/// caller (the web route, the scheduler, the CLI) sees the exact same
/// "go look at the job" shape.
pub async fn run_backup(
    pool: &DbPool,
    provider: &dyn BackupProvider,
    destination_path: &str,
    options: RunBackupOptions,
    cancel: &CancellationToken,
) -> Result<uuid::Uuid, BackupError> {
    let includes_keys = options
        .components
        .contains(&BackupComponent::EncryptionKeys);
    if includes_keys && !options.encrypt {
        return Err(BackupError::Config(
            "backups that include encryption keys must be encrypted".to_string(),
        ));
    }

    let job_id = repo::reliquary_backups::create(
        pool,
        repo::reliquary_backups::NewBackupJob {
            trigger_source: options.trigger_source,
            components: &options.components,
            encrypted: options.encrypt,
            includes_encryption_keys: includes_keys,
            destination_path,
            created_by: options.created_by,
        },
    )
    .await?;

    let outcome = with_backup_lock(pool, || async {
        repo::reliquary_backups::mark_running(pool, job_id).await?;
        let request = BackupRequest {
            components: options.components,
            encrypt: options.encrypt,
            passphrase: options.passphrase,
        };
        provider.create(request, cancel).await
    })
    .await;

    match outcome {
        Ok(Some(outcome)) => {
            repo::reliquary_backups::mark_succeeded(
                pool,
                job_id,
                &outcome.file_name,
                outcome.size_bytes,
                &outcome.sha256,
                &outcome.manifest,
            )
            .await?;
        }
        Ok(None) => {
            repo::reliquary_backups::mark_failed(
                pool,
                job_id,
                "another backup or restore was already in progress -- try again shortly",
            )
            .await?;
        }
        Err(BackupError::Cancelled) => {
            repo::reliquary_backups::mark_cancelled(pool, job_id).await?;
        }
        Err(e) => {
            repo::reliquary_backups::mark_failed(pool, job_id, &e.to_string()).await?;
        }
    }

    Ok(job_id)
}

/// At startup, any job still `Queued`/`Running`/`Verifying` means the
/// previous process crashed mid-backup (a clean shutdown never leaves one
/// of these -- there's no persistent "resume where it left off" for a
/// partially-written archive, since resuming a partial `mariadb-dump`
/// safely isn't well-defined). Swept to `Failed` with a clear message
/// rather than left looking perpetually "in progress" forever.
pub async fn recover_interrupted_jobs(pool: &DbPool) -> anyhow::Result<usize> {
    let stuck = repo::reliquary_backups::list_unterminated(pool).await?;
    for job in &stuck {
        repo::reliquary_backups::mark_failed(
            pool,
            job.id,
            "interrupted by a control-plane restart or crash before this backup finished",
        )
        .await?;
    }
    Ok(stuck.len())
}

/// Retention pruning: keep at least the most recent `keep_last`
/// (regardless of age), additionally prune anything older than
/// `retention_days` (if `> 0`) among what's left, and -- overriding both
/// -- never delete the only remaining backup whose `verification_status`
/// is passing. Every prune is logged (`tracing::info!`) with the job ID
/// and why.
pub async fn prune_retention(
    pool: &DbPool,
    storage: &dyn super::storage::StorageDestination,
) -> anyhow::Result<usize> {
    let keep_last = repo::settings::get_u32(
        pool,
        RELIQUARY_BACKUP_RETENTION_KEEP_LAST,
        RELIQUARY_BACKUP_RETENTION_DEFAULT_KEEP_LAST,
    )
    .await? as usize;
    let retention_days = repo::settings::get_u32(
        pool,
        RELIQUARY_BACKUP_RETENTION_DAYS,
        RELIQUARY_BACKUP_RETENTION_DEFAULT_DAYS,
    )
    .await?;

    let jobs: Vec<BackupJob> = repo::reliquary_backups::list(pool)
        .await?
        .into_iter()
        .filter(|j| j.status.is_terminal() && j.file_name.is_some())
        .collect();

    let to_prune = select_prune_candidates(&jobs, keep_last, retention_days, chrono::Utc::now());

    let mut pruned = 0usize;
    for job in &to_prune {
        if let Some(file_name) = &job.file_name {
            storage.delete(file_name).await?;
        }
        repo::reliquary_backups::delete(pool, job.id).await?;
        tracing::info!(job_id = %job.id, created_at = %job.created_at, "reliquary retention: pruned backup");
        pruned += 1;
    }
    Ok(pruned)
}

/// The pure selection logic behind `prune_retention`, split out so it's
/// unit-testable without a live database (no DB-integration-test harness
/// exists in this codebase -- see docs/reliquary-backups.md). `jobs` is
/// assumed pre-filtered to terminal jobs that still have a file; `now` is
/// threaded through rather than read internally so tests can fix a clock.
///
/// Keeps at least the most recent `keep_last` regardless of age,
/// additionally prunes anything older than `retention_days` (`0` disables
/// age-based pruning) among what's left, and -- overriding both -- never
/// selects the only remaining backup whose `verification_status` is
/// passing.
fn select_prune_candidates(
    jobs: &[BackupJob],
    keep_last: usize,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<BackupJob> {
    let mut jobs: Vec<BackupJob> = jobs.to_vec();
    // Newest first, so `keep_last` naturally keeps the most recent N when
    // we skip over them below.
    jobs.sort_by_key(|j| std::cmp::Reverse(j.created_at));

    let has_any_verified = jobs
        .iter()
        .any(|j| j.verification_status.is_some_and(|v| v.is_passing()));
    let mut kept_a_verified_one = !has_any_verified; // if none exist, there's nothing to protect

    let mut candidates = Vec::new();
    for (index, job) in jobs.into_iter().enumerate() {
        if index < keep_last {
            if job.verification_status.is_some_and(|v| v.is_passing()) {
                kept_a_verified_one = true;
            }
            continue;
        }

        let is_old_enough =
            retention_days > 0 && (now - job.created_at).num_days() >= retention_days as i64;
        if !is_old_enough {
            continue;
        }

        let is_verified = job.verification_status.is_some_and(|v| v.is_passing());
        if is_verified && !kept_a_verified_one {
            tracing::info!(
                job_id = %job.id,
                "reliquary retention: keeping otherwise-prunable backup -- it's the only \
                 remaining verified one"
            );
            kept_a_verified_one = true;
            continue;
        }

        if is_verified {
            kept_a_verified_one = true; // this one's pruned, but there may be others; recomputed loosely
        }
        candidates.push(job);
    }
    candidates
}

/// The unattended scheduled-backup loop -- off by default
/// (`RELIQUARY_BACKUP_SCHEDULE_ENABLED`), re-checked every tick so
/// toggling the setting takes effect on the next tick, same pattern as
/// every other opt-in sweep in this app. Runs at most one backup per
/// `interval_hours`, tracked by looking at the most recent successful
/// backup's own timestamp rather than an in-process timer, so a control-
/// plane restart doesn't cause an immediate extra backup nor lose track
/// of when the last one actually happened.
pub fn spawn_scheduled_backup_loop(
    pool: DbPool,
    provider: Arc<dyn BackupProvider>,
    storage: Arc<dyn super::storage::StorageDestination>,
    destination_path: String,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
        loop {
            interval.tick().await;

            let enabled = repo::settings::get_bool(&pool, RELIQUARY_BACKUP_SCHEDULE_ENABLED, false)
                .await
                .unwrap_or(false);
            if !enabled {
                continue;
            }
            let interval_hours = repo::settings::get_u32(
                &pool,
                RELIQUARY_BACKUP_SCHEDULE_INTERVAL_HOURS,
                RELIQUARY_BACKUP_SCHEDULE_DEFAULT_INTERVAL_HOURS,
            )
            .await
            .unwrap_or(RELIQUARY_BACKUP_SCHEDULE_DEFAULT_INTERVAL_HOURS);
            if interval_hours == 0 {
                continue;
            }

            let last = repo::reliquary_backups::most_recent_backup_time(&pool)
                .await
                .ok()
                .flatten();
            let due = match last {
                None => true,
                Some(last) => {
                    chrono::Utc::now().signed_duration_since(last)
                        >= chrono::Duration::hours(interval_hours as i64)
                }
            };
            if !due {
                continue;
            }

            let include_audit_logs =
                repo::settings::get_bool(&pool, RELIQUARY_BACKUP_INCLUDE_AUDIT_LOGS, true)
                    .await
                    .unwrap_or(true);
            let mut components = vec![BackupComponent::Database, BackupComponent::Configuration];
            if include_audit_logs {
                components.push(BackupComponent::AuditLogs);
            }

            let cancel = CancellationToken::new();
            let result = run_backup(
                &pool,
                provider.as_ref(),
                &destination_path,
                RunBackupOptions {
                    trigger_source: BackupTrigger::Scheduled,
                    components,
                    // Deliberately never encrypted: encryption needs a
                    // passphrase, and there's nobody present on an
                    // unattended run to supply one -- storing one for
                    // scheduled use is a real feature but not one this
                    // pass builds (see docs/reliquary-backups.md). A
                    // scheduled backup is exactly as sensitive as the
                    // database it dumps either way; the destination
                    // directory's own permissions (0600 files, admin-only
                    // access) are what protect it, same as an
                    // unencrypted manual backup would be.
                    encrypt: false,
                    passphrase: None,
                    created_by: None,
                },
                &cancel,
            )
            .await;
            match result {
                Ok(job_id) => tracing::info!(job_id = %job_id, "reliquary: scheduled backup ran"),
                Err(e) => {
                    tracing::error!(error = %e, "reliquary: scheduled backup failed to start")
                }
            }

            if let Err(e) = prune_retention(&pool, storage.as_ref()).await {
                tracing::error!(error = %e, "reliquary: retention pruning failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use abyssal_core::{BackupJobType, BackupStatus, VerificationStatus};
    use chrono::Duration;
    use uuid::Uuid;

    use super::*;

    fn job(days_old: i64, verified: bool, now: chrono::DateTime<chrono::Utc>) -> BackupJob {
        BackupJob {
            id: Uuid::new_v4(),
            job_type: BackupJobType::Native,
            status: BackupStatus::Succeeded,
            trigger_source: BackupTrigger::Manual,
            components: vec![BackupComponent::Database],
            encrypted: false,
            includes_encryption_keys: false,
            destination_path: "/backups".to_string(),
            file_name: Some(format!("backup-{}.tar.zst", Uuid::new_v4())),
            size_bytes: Some(1024),
            sha256: Some("deadbeef".to_string()),
            manifest: None,
            error_message: None,
            verification_status: verified.then_some(VerificationStatus::QuickPassed),
            verification_at: None,
            verification_details: None,
            started_at: None,
            finished_at: None,
            created_by: None,
            created_at: now - Duration::days(days_old),
        }
    }

    #[test]
    fn keeps_at_least_keep_last_regardless_of_age() {
        let now = chrono::Utc::now();
        let jobs: Vec<BackupJob> = (0..5).map(|d| job(d * 40, false, now)).collect();
        let pruned = select_prune_candidates(&jobs, 3, 30, now);
        // The 3 newest survive keep_last; only the 2 oldest (well past
        // retention_days, none verified) are pruned.
        assert_eq!(pruned.len(), 2);
    }

    #[test]
    fn retention_days_zero_disables_age_based_pruning() {
        let now = chrono::Utc::now();
        let jobs: Vec<BackupJob> = (0..5).map(|d| job(d * 100, false, now)).collect();
        let pruned = select_prune_candidates(&jobs, 1, 0, now);
        assert!(pruned.is_empty());
    }

    #[test]
    fn never_prunes_the_only_verified_backup() {
        let now = chrono::Utc::now();
        // One very old, verified backup; everything else unverified and
        // old enough to otherwise be pruned. keep_last = 0 so nothing is
        // protected by recency alone.
        let mut jobs = vec![job(400, true, now)];
        jobs.extend((0..3).map(|_| job(400, false, now)));
        let pruned = select_prune_candidates(&jobs, 0, 30, now);
        assert_eq!(pruned.len(), 3);
        assert!(pruned.iter().all(|j| j.verification_status.is_none()));
    }

    #[test]
    fn prunes_a_verified_backup_if_another_verified_one_survives() {
        let now = chrono::Utc::now();
        let jobs = vec![job(400, true, now), job(400, true, now)];
        let pruned = select_prune_candidates(&jobs, 0, 30, now);
        // Both are old enough and verified, but there are two -- one can
        // go, the other one's protection is what's actually being tested.
        assert_eq!(pruned.len(), 1);
    }

    #[test]
    fn nothing_pruned_when_nothing_old_enough() {
        let now = chrono::Utc::now();
        let jobs: Vec<BackupJob> = (0..3).map(|_| job(1, false, now)).collect();
        let pruned = select_prune_candidates(&jobs, 0, 30, now);
        assert!(pruned.is_empty());
    }
}
