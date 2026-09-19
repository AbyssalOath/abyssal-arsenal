use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{
    WorkflowContextRow, maybe_elevate, require_csrf, urlencoding_encode, workflow_context_rows,
};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, CatacombHostRow, CatacombHostTemplate, CatacombTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/catacomb/{host_id}")).into_response());
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
            hosts.push(CatacombHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = CatacombTemplate { base, hosts };
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
    render_host_with_context(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        Vec::new(),
        None,
    )
    .await
}

/// Same as `render_host`, but also shows a banner naming which
/// workflow-registry context fields (if any) arrived in the query string,
/// and pre-fills the Directory Usage Breakdown path field with
/// `prefill_path` when a suggestion carried one -- Phase 6 of Contextual
/// Arsenal Workflow Navigation: the user still has to click "run," this
/// just saves them retyping the path the suggestion already named.
#[allow(clippy::too_many_arguments)]
async fn render_host_with_context(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    context: Vec<WorkflowContextRow>,
    prefill_path: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Phase 9: a page reached via a suggestion counts as selecting this
    // host globally too, effective immediately -- including this same
    // page's own top-nav switcher, not just future navigation.
    let arrived_via_suggestion = !context.is_empty();
    let selected_host_id = if arrived_via_suggestion {
        Some(host_id)
    } else {
        host_context::current(jar)
    };

    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        selected_host_id,
    )
    .await?;

    let tpl = CatacombHostTemplate {
        can_manage: ctx.has(Permission::StorageManage),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
        context,
        prefill_path,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    let jar = match host_context::carry_forward_cookie(host_id, arrived_via_suggestion) {
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
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    let context = workflow_context_rows(&query);
    let prefill_path = query.get("mount_point").cloned();
    render_host_with_context(
        &state,
        &jar,
        &ctx,
        host_id,
        None,
        None,
        None,
        context,
        prefill_path,
    )
    .await
}

fn validate_path(path: &str) -> Result<String, WebError> {
    let path = path.trim().to_string();
    if !abyssal_agent_protocol::is_valid_mount_target(&path) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid absolute path.".into(),
        )));
    }
    Ok(path)
}

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
            Permission::StorageView,
            OperationKind::Read,
            false,
            Duration::from_secs(20),
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

#[derive(Deserialize)]
pub struct PathForm {
    csrf_token: String,
    path: String,
}

pub async fn directory_usage_breakdown(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PathForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let path = validate_path(&form.path)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::DirectoryUsageBreakdown { path: path.clone() },
        &format!("Directory Usage Breakdown ({path})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct FindLargeFilesForm {
    csrf_token: String,
    path: String,
    min_size_mb: u32,
}

pub async fn find_large_files(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<FindLargeFilesForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let path = validate_path(&form.path)?;
    if !abyssal_agent_protocol::is_valid_size_mb(form.min_size_mb) {
        return Err(WebError(AppError::Validation(
            "That size threshold isn't valid.".into(),
        )));
    }
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FindLargeFiles {
            path: path.clone(),
            min_size_mb: form.min_size_mb,
        },
        &format!("Large Files ({path}, >={}MB)", form.min_size_mb),
    )
    .await
}

#[derive(Deserialize)]
pub struct DeviceForm {
    csrf_token: String,
    device: String,
}

pub async fn filesystem_check_dry_run(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<DeviceForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let device = validate_path(&form.device)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FilesystemCheckDryRun {
            device: device.clone(),
        },
        &format!("Filesystem Check, Dry Run ({device})"),
    )
    .await
}

/// `Write`, no confirmation required -- TRIM only discards blocks a
/// filesystem already considers free.
pub async fn trim_filesystem(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PathForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let mountpoint = validate_path(&form.path)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Trim Filesystem ({mountpoint}) -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::TrimFilesystem { mountpoint },
            Permission::StorageManage,
            OperationKind::Write,
            false,
            Duration::from_secs(30),
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
pub struct DeviceQuery {
    device: String,
}

pub async fn filesystem_repair_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<DeviceQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;
    let device = validate_path(&q.device)?;

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
        title: "Repair filesystem".to_string(),
        message: format!(
            "This will run fsck's repair mode against \"{device}\" on \"{}\", auto-answering \
             yes to every fix. Refused if the device is currently mounted. This can rewrite the \
             filesystem's on-disk structures and cannot be undone.",
            host.name
        ),
        action_url: format!(
            "/arsenals/catacomb/{host_id}/repair?device={}",
            urlencoding_encode(&device)
        ),
        cancel_url: format!("/arsenals/catacomb/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "device path".to_string(),
            expected: device.clone(),
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
pub struct ConfirmForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn filesystem_repair(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<DeviceQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Filesystem repair was not confirmed.".into(),
        )));
    }

    let device = validate_path(&q.device)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &device)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Repair Filesystem ({device}) -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::FilesystemRepair { device },
            Permission::StorageManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(120),
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
