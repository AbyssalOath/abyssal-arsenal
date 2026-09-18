use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, ReliquaryHostRow, ReliquaryHostTemplate, ReliquaryTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsView)?;

    if let Some(host_id) = host_context::current(&jar) {
        if state.hosts.is_connected(host_id) {
            return Ok(Redirect::to(&format!("/arsenals/reliquary/{host_id}")).into_response());
        }
    }

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

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(ReliquaryHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = ReliquaryTemplate { base, hosts };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

async fn render_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

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

    let tpl = ReliquaryHostTemplate {
        can_create: ctx.has(Permission::BackupsCreate),
        can_restore: ctx.has(Permission::BackupsRestore),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn show_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

/// Shared dispatch, same shape as every other arsenal's `run_read_op` --
/// used here by both the actual read op (List Backups) and Verify Backup,
/// which is also non-mutating (just tests archive integrity).
#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::BackupsView,
            OperationKind::Read,
            false,
            Duration::from_secs(30),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

pub async fn list_backups(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListBackups,
        "Backups",
    )
    .await
}

#[derive(Deserialize)]
pub struct VerifyBackupForm {
    csrf_token: String,
    filename: String,
}

pub async fn verify_backup(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<VerifyBackupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsView)?;
    require_csrf(&jar, &form.csrf_token)?;

    let filename = form.filename.trim().to_string();
    if !abyssal_agent_protocol::is_valid_backup_filename(&filename) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a backup filename (must end in .tar.gz, no path separators)."
                .into(),
        )));
    }

    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::VerifyBackup {
            filename: filename.clone(),
        },
        &format!("Verify Backup ({filename})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct CreateBackupForm {
    csrf_token: String,
    source_path: String,
    name: String,
}

pub async fn create_backup(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<CreateBackupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsCreate)?;
    require_csrf(&jar, &form.csrf_token)?;

    let source_path = form.source_path.trim().to_string();
    if !abyssal_agent_protocol::is_valid_absolute_path(&source_path) {
        return Err(WebError(AppError::Validation(
            "Enter an absolute path (starting with /) to back up.".into(),
        )));
    }
    let name = form.name.trim().to_string();
    if !abyssal_agent_protocol::is_valid_backup_name(&name) {
        return Err(WebError(AppError::Validation(
            "Backup names may only contain letters, digits, hyphens, and underscores.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Create Backup ({name}) -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::CreateBackup {
                source_path: source_path.clone(),
                name: name.clone(),
            },
            Permission::BackupsCreate,
            OperationKind::Write,
            false,
            Duration::from_secs(300),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            if let Err(e) = repo::backup_records::record(
                &state.pool,
                host_id,
                &name,
                &source_path,
                Some(ctx.user.id),
            )
            .await
            {
                tracing::error!(error = %e, "failed to persist backup record");
            }
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct RestoreQuery {
    filename: String,
    target_path: String,
}

pub async fn restore_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RestoreQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsRestore)?;

    let filename = q.filename.trim().to_string();
    if !abyssal_agent_protocol::is_valid_backup_filename(&filename) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a backup filename.".into(),
        )));
    }
    let target_path = q.target_path.trim().to_string();
    if !abyssal_agent_protocol::is_valid_absolute_path(&target_path) {
        return Err(WebError(AppError::Validation(
            "Enter an absolute path (starting with /) to restore into.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
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

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Restore backup".to_string(),
        message: format!(
            "This will extract \"{filename}\" into \"{target_path}\" on \"{}\", overwriting any \
             files already there with the same names. This cannot be undone.",
            host.name
        ),
        action_url: format!(
            "/arsenals/reliquary/{host_id}/restore?filename={}&target_path={}",
            urlencoding_encode(&filename),
            urlencoding_encode(&target_path)
        ),
        cancel_url: format!("/arsenals/reliquary/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected: host.name.clone(),
        }),
        extra_hidden_fields: vec![],
    };
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
}

pub async fn restore_backup(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RestoreQuery>,
    Form(form): Form<RestoreForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::BackupsRestore)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "The restore was not confirmed.".into(),
        )));
    }

    let filename = q.filename.trim().to_string();
    if !abyssal_agent_protocol::is_valid_backup_filename(&filename) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a backup filename.".into(),
        )));
    }
    let target_path = q.target_path.trim().to_string();
    if !abyssal_agent_protocol::is_valid_absolute_path(&target_path) {
        return Err(WebError(AppError::Validation(
            "Enter an absolute path (starting with /) to restore into.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
    let result_label = Some(format!(
        "Restore Backup ({filename} -> {target_path}) -- {}",
        host.name
    ));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::RestoreBackup {
                filename,
                target_path,
            },
            Permission::BackupsRestore,
            OperationKind::Destructive,
            true,
            Duration::from_secs(300),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct ElevateForm {
    csrf_token: String,
    sudo_password: String,
}

pub async fn elevate(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ElevateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsElevate)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.sudo_password.trim().is_empty() {
        return Err(WebError(AppError::Validation(
            "Enter a sudo password to elevate.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match maybe_elevate(&state, &ctx, host_id, &host.name, Some(form.sudo_password)).await {
        Ok(warning) => {
            let message = format!("{}Elevated.", warning.unwrap_or(""));
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                Some(message),
                None,
            )
            .await
        }
        Err(e) => {
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                None,
                Some(e),
            )
            .await
        }
    }
}
