//! Native (control-plane) backups -- GitHub issue #9. Organized as one
//! page with clearly separated sections matching the four the issue asks
//! for (Application Data, Control-Plane Configuration, Managed Systems --
//! placeholder, Verification & Recovery), rather than four separate
//! routes/pages -- a scope simplification made under this pass's time
//! budget, noted in the final summary, not a silent cut.

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, BackupComponent, Permission};
use abyssal_database::repo;
use axum::Form;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::reliquary_backup::orchestrator::{self, RunBackupOptions};
use crate::reliquary_backup::verify;
use crate::state::AppState;
use crate::templates::{
    BackupJobRow, BaseCtx, ReliquaryBackupTemplate, ReliquaryRestorePreviewTemplate,
};
use crate::theme;

fn job_row(
    job: abyssal_core::BackupJob,
    tz: &str,
    connection_names: &std::collections::HashMap<Uuid, String>,
) -> BackupJobRow {
    let destination_label = match job.destination_connection_id {
        None => "Local".to_string(),
        Some(id) => connection_names
            .get(&id)
            .map(|name| format!("Sepulchre: {name}"))
            .unwrap_or_else(|| "Sepulchre (connection deleted)".to_string()),
    };
    BackupJobRow {
        id: job.id.to_string(),
        destination_label,
        status_label: job.status.label(),
        status_key: job.status.as_str(),
        trigger_label: match job.trigger_source {
            abyssal_core::BackupTrigger::Manual => "Manual",
            abyssal_core::BackupTrigger::Scheduled => "Scheduled",
        },
        components: job
            .components
            .iter()
            .map(|c| c.label().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        encrypted: job.encrypted,
        size_display: job
            .size_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "—".to_string()),
        created_at: crate::common::format_in_tz(job.created_at, tz),
        verification_label: job
            .verification_status
            .map(|v| v.label().to_string())
            .unwrap_or_else(|| "Not verified".to_string()),
        verification_passed: job.verification_status.is_some_and(|v| v.is_passing()),
        verification_failure_detail: job
            .verification_status
            .is_some_and(|v| !v.is_passing())
            .then_some(job.verification_details)
            .flatten(),
        can_download: matches!(
            job.status,
            abyssal_core::BackupStatus::Succeeded | abyssal_core::BackupStatus::Verified
        ) && job.file_name.is_some(),
        error_message: job.error_message,
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub async fn page(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsView)?;
    render_page(&state, &jar, &ctx, None, None).await
}

async fn render_page(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    message: Option<String>,
    error: Option<String>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(jar),
    )
    .await?;

    // All connections, not just eligible ones -- a job's `destination_label`
    // needs to resolve even for a connection that's since been disabled or
    // had its role changed, not just ones currently pickable for a new
    // backup.
    let all_connections = repo::storage_connections::list(
        &state.pool,
        &repo::storage_connections::ConnectionFilter::default(),
        0,
        500,
    )
    .await?;
    let connection_names: std::collections::HashMap<Uuid, String> = all_connections
        .iter()
        .map(|c| (c.id, c.name.clone()))
        .collect();

    let jobs = repo::reliquary_backups::list(&state.pool)
        .await?
        .into_iter()
        .map(|j| job_row(j, &ctx.user.timezone, &connection_names))
        .collect();

    let default_destination_connection_id = repo::settings::get_string(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_DESTINATION_CONNECTION_ID,
        "",
    )
    .await?;

    // Only connections actually eligible as a backup destination --
    // enabled and holding the `backup_destination` role. `resolve_destination`
    // still re-checks full usability (every capability verified, validated
    // recently) at submit time; this is just what's worth offering in the
    // dropdown at all.
    let mut destination_connections = Vec::new();
    for connection in all_connections.iter().filter(|c| c.enabled) {
        let roles =
            repo::storage_connections::roles_for_connection(&state.pool, connection.id).await?;
        if roles.contains(&abyssal_core::ConnectionRole::BackupDestination) {
            let id = connection.id.to_string();
            let is_default = id == default_destination_connection_id;
            destination_connections.push((id, connection.name.clone(), is_default));
        }
    }

    let schedule_enabled = repo::settings::get_bool(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_SCHEDULE_ENABLED,
        false,
    )
    .await?;
    let schedule_interval_hours = repo::settings::get_u32(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_SCHEDULE_INTERVAL_HOURS,
        abyssal_core::settings::RELIQUARY_BACKUP_SCHEDULE_DEFAULT_INTERVAL_HOURS,
    )
    .await?;
    let retention_keep_last = repo::settings::get_u32(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_RETENTION_KEEP_LAST,
        abyssal_core::settings::RELIQUARY_BACKUP_RETENTION_DEFAULT_KEEP_LAST,
    )
    .await?;
    let retention_days = repo::settings::get_u32(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_RETENTION_DAYS,
        abyssal_core::settings::RELIQUARY_BACKUP_RETENTION_DEFAULT_DAYS,
    )
    .await?;
    let destination_path = repo::settings::get_string(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_DESTINATION_PATH,
        abyssal_core::settings::RELIQUARY_BACKUP_DEFAULT_DESTINATION_PATH,
    )
    .await?;
    let encrypt_by_default = repo::settings::get_bool(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_ENCRYPT_BY_DEFAULT,
        false,
    )
    .await?;
    let include_audit_logs_by_default = repo::settings::get_bool(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_INCLUDE_AUDIT_LOGS,
        true,
    )
    .await?;

    let tpl = ReliquaryBackupTemplate {
        base,
        can_manage: ctx.has(Permission::BackupsCreate),
        can_restore: ctx.has(Permission::BackupsRestore),
        jobs,
        message,
        error,
        schedule_enabled,
        schedule_interval_hours,
        retention_keep_last,
        retention_days,
        destination_path,
        destination_connections,
        default_destination_connection_id,
        encrypt_by_default,
        encryption_key_available: state.encryption_key.is_some(),
        include_audit_logs_by_default,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct CreateBackupForm {
    csrf_token: String,
    #[serde(default)]
    component_database: bool,
    #[serde(default)]
    component_configuration: bool,
    #[serde(default)]
    component_encryption_keys: bool,
    #[serde(default)]
    component_audit_logs: bool,
    #[serde(default)]
    encrypt: bool,
    #[serde(default)]
    passphrase: String,
    #[serde(default)]
    passphrase_confirm: String,
    /// A Sepulchre connection's UUID, or empty for the local destination
    /// -- see `orchestrator::resolve_destination`.
    #[serde(default)]
    destination_connection_id: String,
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<CreateBackupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsCreate)?;
    require_csrf(&jar, &form.csrf_token)?;

    let mut components = Vec::new();
    if form.component_database {
        components.push(BackupComponent::Database);
    }
    if form.component_configuration {
        components.push(BackupComponent::Configuration);
    }
    if form.component_encryption_keys {
        components.push(BackupComponent::EncryptionKeys);
    }
    if form.component_audit_logs {
        components.push(BackupComponent::AuditLogs);
    }
    if components.is_empty() {
        return render_page(
            &state,
            &jar,
            &ctx,
            None,
            Some("Select at least one component to back up.".to_string()),
        )
        .await;
    }

    let includes_keys = components.contains(&BackupComponent::EncryptionKeys);
    if includes_keys && !form.encrypt {
        return render_page(
            &state,
            &jar,
            &ctx,
            None,
            Some(
                "Including encryption keys requires encrypting the backup -- check \"Encrypt \
                 this backup\" too."
                    .to_string(),
            ),
        )
        .await;
    }
    let encrypt = form.encrypt;

    let passphrase = if encrypt {
        if form.passphrase.is_empty() {
            return render_page(
                &state,
                &jar,
                &ctx,
                None,
                Some("A passphrase is required to encrypt this backup.".to_string()),
            )
            .await;
        }
        if form.passphrase != form.passphrase_confirm {
            return render_page(
                &state,
                &jar,
                &ctx,
                None,
                Some("Passphrase and confirmation don't match.".to_string()),
            )
            .await;
        }
        if form.passphrase.len() < 12 {
            return render_page(
                &state,
                &jar,
                &ctx,
                None,
                Some("Passphrase must be at least 12 characters.".to_string()),
            )
            .await;
        }
        Some(Zeroizing::new(form.passphrase))
    } else {
        None
    };

    let connection_id = form.destination_connection_id.trim();
    let connection_id = if connection_id.is_empty() {
        None
    } else {
        match Uuid::parse_str(connection_id) {
            Ok(id) => Some(id),
            Err(_) => {
                return render_page(
                    &state,
                    &jar,
                    &ctx,
                    None,
                    Some("Not a valid destination.".to_string()),
                )
                .await;
            }
        }
    };
    let (storage, destination_label) =
        match orchestrator::resolve_destination(&state, connection_id).await {
            Ok(v) => v,
            Err(e) => {
                return render_page(
                    &state,
                    &jar,
                    &ctx,
                    None,
                    Some(format!("That destination isn't usable right now: {e}")),
                )
                .await;
            }
        };

    let cancel = CancellationToken::new();
    let job_id = orchestrator::run_backup(
        &state.pool,
        state.reliquary_backup_provider.as_ref(),
        storage.as_ref(),
        &destination_label,
        connection_id,
        RunBackupOptions {
            trigger_source: abyssal_core::BackupTrigger::Manual,
            components,
            encrypt,
            passphrase,
            created_by: Some(ctx.user.id),
        },
        &cancel,
    )
    .await?;

    let job = repo::reliquary_backups::find_by_id(&state.pool, job_id).await?;
    let succeeded = job
        .as_ref()
        .is_some_and(|j| j.status == abyssal_core::BackupStatus::Succeeded);

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(
            AuditAction::BackupCreated,
            if succeeded {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
        )
        .actor(Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource(&job_id.to_string()),
    )
    .await?;

    if succeeded {
        render_page(
            &state,
            &jar,
            &ctx,
            Some("Backup completed.".to_string()),
            None,
        )
        .await
    } else {
        let message = job
            .and_then(|j| j.error_message)
            .unwrap_or_else(|| "Backup failed.".to_string());
        render_page(&state, &jar, &ctx, None, Some(message)).await
    }
}

/// Download/verify/restore all read the archive back from a real local
/// path (`storage.resolve(file_name)` + direct filesystem I/O) -- true
/// for `LocalFs` but not for a Sepulchre-backed destination, whose
/// `resolve()` is a synthetic, display-only string (see
/// `sepulchre::reliquary_adapter`'s doc comment). Refused here with a
/// clear reason rather than left to fail as a confusing "file not found"
/// partway through one of those operations.
fn require_local_destination(job: &abyssal_core::BackupJob) -> Result<(), WebError> {
    if job.destination_connection_id.is_some() {
        return Err(WebError(AppError::Validation(
            "This backup was written to a Sepulchre connection -- downloading, verifying, and \
             restoring from a Sepulchre-backed destination isn't supported yet, only writing to \
             one. See docs/sepulchre.md."
                .into(),
        )));
    }
    Ok(())
}

pub async fn download(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsView)?;

    let job = repo::reliquary_backups::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_local_destination(&job)?;
    let file_name = job.file_name.ok_or(AppError::NotFound)?;
    // The file name comes from the DB row for this specific job ID, never
    // directly from the request -- there's no user-controlled path here
    // to traverse.
    let path = state.reliquary_backup_storage.resolve(&file_name);
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| AppError::NotFound)?;
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = Body::from_stream(stream);

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::BackupDownloaded, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&file_name),
    )
    .await?;

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file_name}\""),
            ),
        ],
        body,
    )
        .into_response())
}

pub async fn verify_quick(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsCreate)?;

    let job = repo::reliquary_backups::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_local_destination(&job)?;
    let Some(file_name) = &job.file_name else {
        return render_page(
            &state,
            &jar,
            &ctx,
            None,
            Some("This backup has no archive file to verify.".to_string()),
        )
        .await;
    };
    let expected_sha256 = job.sha256.clone().unwrap_or_default();

    let outcome = verify::quick_verify(
        state.reliquary_backup_storage.as_ref(),
        file_name,
        &expected_sha256,
        job.manifest.as_ref(),
    )
    .await?;

    let status = if outcome.passed {
        abyssal_core::VerificationStatus::QuickPassed
    } else {
        abyssal_core::VerificationStatus::QuickFailed
    };
    repo::reliquary_backups::record_verification(&state.pool, id, status, &outcome.details).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(
            AuditAction::BackupVerified,
            if outcome.passed {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
        )
        .actor(Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource(file_name),
    )
    .await?;

    render_page(
        &state,
        &jar,
        &ctx,
        Some(format!(
            "Verification {}: {}",
            if outcome.passed { "passed" } else { "failed" },
            outcome.details
        )),
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct DeleteBackupForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
}

pub async fn delete(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<DeleteBackupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsCreate)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Deletion was not confirmed.".into(),
        )));
    }

    let job = repo::reliquary_backups::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if let Some(file_name) = &job.file_name {
        // Best-effort: the connection this job used may since have been
        // disabled or deleted entirely (the FK is `ON DELETE SET NULL`
        // specifically so that's never blocked) -- an admin explicitly
        // asking to delete this job record should still succeed even if
        // the remote file underneath it can no longer be reached to
        // clean up, rather than getting stuck forever on an
        // unresolvable destination.
        match orchestrator::resolve_destination(&state, job.destination_connection_id).await {
            Ok((storage, _label)) => {
                if let Err(e) = storage.delete(file_name).await {
                    tracing::warn!(job_id = %id, error = %e, "could not delete the archive file for a deleted backup job");
                }
            }
            Err(e) => {
                tracing::warn!(job_id = %id, error = %e, "could not resolve this job's destination to delete its archive file");
            }
        }
    }
    repo::reliquary_backups::delete(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::BackupDeleted, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&id.to_string()),
    )
    .await?;

    Ok(Redirect::to("/arsenals/reliquary/backups").into_response())
}

#[derive(Deserialize)]
pub struct SettingsForm {
    csrf_token: String,
    #[serde(default)]
    schedule_enabled: bool,
    #[serde(default)]
    schedule_interval_hours: String,
    #[serde(default)]
    retention_keep_last: String,
    #[serde(default)]
    retention_days: String,
    #[serde(default)]
    destination_path: String,
    /// A Sepulchre connection's UUID, or empty for the local destination
    /// -- the scheduled backup loop's own fixed answer (a manual "Backup
    /// now" always lets the operator pick per-run instead).
    #[serde(default)]
    schedule_destination_connection_id: String,
    #[serde(default)]
    encrypt_by_default: bool,
    #[serde(default)]
    include_audit_logs_by_default: bool,
}

pub async fn update_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SettingsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsCreate)?;
    require_csrf(&jar, &form.csrf_token)?;

    let interval_hours: u32 = form.schedule_interval_hours.trim().parse().unwrap_or(24);
    let keep_last: u32 = form.retention_keep_last.trim().parse().unwrap_or(7);
    let retention_days: u32 = form.retention_days.trim().parse().unwrap_or(30);
    let destination_path = form.destination_path.trim();
    if destination_path.is_empty() || !destination_path.starts_with('/') {
        return render_page(
            &state,
            &jar,
            &ctx,
            None,
            Some("Destination path must be an absolute path.".to_string()),
        )
        .await;
    }
    let schedule_destination_connection_id = form.schedule_destination_connection_id.trim();
    if !schedule_destination_connection_id.is_empty()
        && Uuid::parse_str(schedule_destination_connection_id).is_err()
    {
        return render_page(
            &state,
            &jar,
            &ctx,
            None,
            Some("Not a valid scheduled-backup destination.".to_string()),
        )
        .await;
    }

    let by = Some(ctx.user.id);
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_SCHEDULE_ENABLED,
        serde_json::json!(form.schedule_enabled),
        by,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_SCHEDULE_INTERVAL_HOURS,
        serde_json::json!(interval_hours),
        by,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_RETENTION_KEEP_LAST,
        serde_json::json!(keep_last),
        by,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_RETENTION_DAYS,
        serde_json::json!(retention_days),
        by,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_DESTINATION_PATH,
        serde_json::json!(destination_path),
        by,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_DESTINATION_CONNECTION_ID,
        serde_json::json!(schedule_destination_connection_id),
        by,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_ENCRYPT_BY_DEFAULT,
        serde_json::json!(form.encrypt_by_default),
        by,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        abyssal_core::settings::RELIQUARY_BACKUP_INCLUDE_AUDIT_LOGS,
        serde_json::json!(form.include_audit_logs_by_default),
        by,
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::BackupSettingsChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("reliquary_backup_settings"),
    )
    .await?;

    render_page(
        &state,
        &jar,
        &ctx,
        Some("Settings saved.".to_string()),
        None,
    )
    .await
}

pub async fn restore_preview(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsRestore)?;

    let job = repo::reliquary_backups::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_local_destination(&job)?;
    let Some(manifest) = &job.manifest else {
        return Err(WebError(AppError::Validation(
            "This backup has no manifest -- it can't be restored.".into(),
        )));
    };

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(
        &ctx,
        &theme::current(&jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(&jar),
    )
    .await?;

    let preview = crate::reliquary_backup::restore::preview(
        state.reliquary_backup_storage.as_ref(),
        job.file_name.as_deref().unwrap_or_default(),
        manifest,
        &database_url_from_env()?,
    )
    .await?;

    let is_verified = job.verification_status.is_some_and(|v| v.is_passing());

    let tpl = ReliquaryRestorePreviewTemplate {
        base,
        job_id: id.to_string(),
        is_encrypted: manifest.encryption.is_some(),
        is_verified,
        schema_version_matches: preview.schema_version_matches,
        current_schema_version: preview.current_schema_version,
        backup_schema_version: manifest.schema_migration_version,
        mariadb_major_version_differs: preview.mariadb_major_version_differs,
        current_mariadb_version: preview.current_mariadb_version,
        backup_mariadb_version: manifest.mariadb_version.clone(),
        components: manifest
            .components
            .iter()
            .map(|c| c.label().to_string())
            .collect(),
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RestoreForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    passphrase: String,
    #[serde(default)]
    override_unverified: bool,
    #[serde(default)]
    component_database: bool,
}

pub async fn restore(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<RestoreForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsRestore)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm || form.confirm_text.trim() != "RESTORE" {
        return Err(WebError(AppError::Validation(
            "Type RESTORE to confirm this destructive action.".into(),
        )));
    }

    let job = repo::reliquary_backups::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_local_destination(&job)?;
    let Some(manifest) = job.manifest.clone() else {
        return Err(WebError(AppError::Validation(
            "This backup has no manifest -- it can't be restored.".into(),
        )));
    };
    let is_verified = job.verification_status.is_some_and(|v| v.is_passing());
    if !is_verified && !form.override_unverified {
        return Err(WebError(AppError::Validation(
            "This backup hasn't been verified. Verify it first, or explicitly override.".into(),
        )));
    }

    let mut components = Vec::new();
    if form.component_database {
        components.push(BackupComponent::Database);
    }
    if components.is_empty() {
        return Err(WebError(AppError::Validation(
            "Select at least one component to restore.".into(),
        )));
    }

    // Automatic pre-restore safety backup, unencrypted (there's no
    // passphrase collection step for this one -- it exists purely so
    // "the restore itself went wrong" has a way back). Always the local
    // destination, deliberately -- restoring is exactly the moment a
    // remote Sepulchre connection's own reachability is least trustworthy
    // to depend on, and a safety net that might itself be unreachable
    // defeats the point of having one.
    let (safety_storage, safety_label) = orchestrator::resolve_destination(&state, None).await?;
    let safety_cancel = CancellationToken::new();
    let _ = orchestrator::run_backup(
        &state.pool,
        state.reliquary_backup_provider.as_ref(),
        safety_storage.as_ref(),
        &safety_label,
        None,
        RunBackupOptions {
            trigger_source: abyssal_core::BackupTrigger::Manual,
            components: vec![BackupComponent::Database],
            encrypt: false,
            passphrase: None,
            created_by: Some(ctx.user.id),
        },
        &safety_cancel,
    )
    .await;

    let cancel = CancellationToken::new();
    let work_dir = std::env::temp_dir().join(format!("reliquary-restore-{id}"));
    let passphrase = (!form.passphrase.is_empty()).then(|| Zeroizing::new(form.passphrase.clone()));

    let result = crate::reliquary_backup::restore::restore(
        state.reliquary_backup_storage.as_ref(),
        &state.maintenance_mode,
        crate::reliquary_backup::restore::RestoreRequest {
            file_name: job.file_name.as_deref().unwrap_or_default(),
            manifest: &manifest,
            components: &components,
            passphrase,
            database_url: &database_url_from_env()?,
            work_dir: &work_dir,
        },
        &cancel,
    )
    .await;
    let _ = tokio::fs::remove_dir_all(&work_dir).await;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(
            AuditAction::BackupRestored,
            if result.is_ok() {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
        )
        .actor(Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource(&id.to_string())
        .metadata(serde_json::json!({ "components": components.iter().map(|c| c.as_str()).collect::<Vec<_>>() })),
    )
    .await?;

    match result {
        Ok(()) => Ok(Redirect::to("/arsenals/reliquary/backups").into_response()),
        Err(e) => Err(WebError(AppError::Validation(format!(
            "Restore failed: {e}"
        )))),
    }
}

fn database_url_from_env() -> Result<String, WebError> {
    std::env::var("DATABASE_URL")
        .map_err(|_| WebError(AppError::Internal(anyhow::anyhow!("DATABASE_URL not set"))))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn job(destination_connection_id: Option<Uuid>) -> abyssal_core::BackupJob {
        abyssal_core::BackupJob {
            id: Uuid::new_v4(),
            job_type: abyssal_core::BackupJobType::Native,
            status: abyssal_core::BackupStatus::Succeeded,
            trigger_source: abyssal_core::BackupTrigger::Manual,
            components: vec![BackupComponent::Database],
            encrypted: false,
            includes_encryption_keys: false,
            destination_path: "/backups".to_string(),
            destination_connection_id,
            file_name: Some("backup-test.tar.zst".to_string()),
            size_bytes: Some(1024),
            sha256: Some("deadbeef".to_string()),
            manifest: None,
            error_message: None,
            verification_status: None,
            verification_at: None,
            verification_details: None,
            started_at: None,
            finished_at: None,
            created_by: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn a_local_job_is_allowed_for_read_operations() {
        assert!(require_local_destination(&job(None)).is_ok());
    }

    #[test]
    fn a_sepulchre_backed_job_is_refused_for_read_operations() {
        assert!(require_local_destination(&job(Some(Uuid::new_v4()))).is_err());
    }

    #[test]
    fn destination_label_is_local_when_no_connection_is_set() {
        let row = job_row(job(None), "UTC", &HashMap::new());
        assert_eq!(row.destination_label, "Local");
    }

    #[test]
    fn destination_label_names_a_known_connection() {
        let id = Uuid::new_v4();
        let mut names = HashMap::new();
        names.insert(id, "my-sftp".to_string());
        let row = job_row(job(Some(id)), "UTC", &names);
        assert_eq!(row.destination_label, "Sepulchre: my-sftp");
    }

    #[test]
    fn destination_label_notes_a_deleted_connection() {
        let row = job_row(job(Some(Uuid::new_v4())), "UTC", &HashMap::new());
        assert_eq!(row.destination_label, "Sepulchre (connection deleted)");
    }
}
