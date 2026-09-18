use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::settings::HOST_ISOLATION_ENABLED;
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
use crate::templates::{BaseCtx, InquestHostRow, InquestHostTemplate, InquestTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;

    if let Some(host_id) = host_context::current(&jar) {
        if state.hosts.is_connected(host_id) {
            return Ok(Redirect::to(&format!("/arsenals/inquest/{host_id}")).into_response());
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
            hosts.push(InquestHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = InquestTemplate { base, hosts };
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
    let host_isolation_enabled =
        repo::settings::get_bool(&state.pool, HOST_ISOLATION_ENABLED, false).await?;

    let tpl = InquestHostTemplate {
        can_manage: ctx.has(Permission::IncidentsRespond),
        host_isolation_enabled,
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
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

/// The second gate `IsolateHost` requires, on top of the normal
/// `incidents.respond` permission and type-to-confirm: checked fresh at
/// every entry point that leads to dispatching it (both the confirm-page
/// GET and the dispatch POST), never assumed from an earlier check --
/// same discipline as Ossuary's `ensure_high_risk_enabled`.
async fn ensure_host_isolation_enabled(state: &AppState) -> Result<(), WebError> {
    let enabled = repo::settings::get_bool(&state.pool, HOST_ISOLATION_ENABLED, false).await?;
    if !enabled {
        return Err(WebError(AppError::Validation(
            "Host network isolation is disabled. An admin must enable it on the Settings page \
             first."
                .into(),
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
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
            Permission::IncidentsView,
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

pub async fn list_blocked_ips(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListBlockedIps,
        "Blocked IPs",
    )
    .await
}

pub async fn isolation_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::IsolationStatus,
        "Isolation Status",
    )
    .await
}

pub async fn list_quarantined_files(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListQuarantinedFiles,
        "Quarantined Files",
    )
    .await
}

// ---------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_write_op(
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
            Permission::IncidentsRespond,
            OperationKind::Write,
            false,
            Duration::from_secs(60),
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
pub struct IpForm {
    csrf_token: String,
    ip: String,
}

fn validate_ip(ip: &str) -> Result<String, WebError> {
    let ip = ip.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ip_address(&ip) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid IP address.".into(),
        )));
    }
    Ok(ip)
}

pub async fn block_remote_ip(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<IpForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let ip = validate_ip(&form.ip)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::BlockRemoteIp { ip: ip.clone() },
        &format!("Block IP ({ip})"),
    )
    .await
}

pub async fn unblock_remote_ip(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<IpForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let ip = validate_ip(&form.ip)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::UnblockRemoteIp { ip: ip.clone() },
        &format!("Unblock IP ({ip})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct QuarantineForm {
    csrf_token: String,
    path: String,
}

pub async fn quarantine_file(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<QuarantineForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let path = form.path.trim().to_string();
    if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
        return Err(WebError(AppError::Validation(
            "Enter an absolute path (starting with /) to quarantine.".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::QuarantineFile { path: path.clone() },
        &format!("Quarantine File ({path})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct RestoreQuarantineForm {
    csrf_token: String,
    quarantine_filename: String,
}

fn validate_quarantine_filename(filename: &str) -> Result<String, WebError> {
    let filename = filename.trim().to_string();
    if !abyssal_agent_protocol::is_valid_quarantine_filename(&filename) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a quarantine filename -- copy it exactly from \"Quarantined \
             Files\" above."
                .into(),
        )));
    }
    Ok(filename)
}

pub async fn restore_quarantined_file(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RestoreQuarantineForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let quarantine_filename = validate_quarantine_filename(&form.quarantine_filename)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RestoreQuarantinedFile {
            quarantine_filename: quarantine_filename.clone(),
        },
        &format!("Restore Quarantined File ({quarantine_filename})"),
    )
    .await
}

pub async fn deisolate_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::DeisolateHost,
        "De-isolate Host",
    )
    .await
}

// ---------------------------------------------------------------------
// Shared Destructive confirm/dispatch machinery -- used by both
// `DeleteQuarantinedFile` (conservative tier) and `IsolateHost`
// (high-risk tier). `high_risk` controls whether
// `ensure_host_isolation_enabled` also gates this; every high-risk call
// site still checks it again itself right before this too -- belt and
// suspenders on the one gate this arsenal can't afford to get wrong.
#[allow(clippy::too_many_arguments)]
async fn destructive_confirm(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    title: &str,
    message: String,
    action_url: String,
    type_to_confirm_label: &str,
    type_to_confirm_expected: &str,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;

    // Fetched only to confirm the host still exists before rendering a
    // confirm page for it -- the message/expected-confirm-text are
    // already built by the caller, which fetched the host itself too.
    let _host = repo::hosts::find_by_id(&state.pool, host_id)
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
        title: title.to_string(),
        message,
        action_url,
        cancel_url: format!("/arsenals/inquest/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: type_to_confirm_label.to_string(),
            expected: type_to_confirm_expected.to_string(),
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

#[allow(clippy::too_many_arguments)]
async fn run_destructive_op(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    expected_confirm_text: &str,
    operation: AgentOperation,
    label: &str,
    form: ConfirmForm,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(format!(
            "{label} was not confirmed."
        ))));
    }
    crate::common::require_typed_confirmation(&form.confirm_text, expected_confirm_text)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::IncidentsRespond,
            OperationKind::Destructive,
            true,
            Duration::from_secs(60),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
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
                state,
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

// ---------------------------------------------------------------------
// Destructive (conservative tier): delete quarantined file
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SingleFieldQuery {
    value: String,
}

pub async fn delete_quarantined_file_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    let filename = validate_quarantine_filename(&q.value)?;
    let action_url = format!(
        "/arsenals/inquest/{host_id}/delete-quarantined?value={}",
        urlencoding_encode(&filename)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Delete quarantined file",
        format!(
            "This will permanently delete the quarantined file \"{filename}\". It cannot be \
             restored afterward. This cannot be undone."
        ),
        action_url,
        "quarantine filename",
        &filename,
    )
    .await
}

pub async fn delete_quarantined_file(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let filename = validate_quarantine_filename(&q.value)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &filename,
        AgentOperation::DeleteQuarantinedFile {
            filename: filename.clone(),
        },
        "Delete Quarantined File",
        form,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive (high-risk tier): full host isolation
// ---------------------------------------------------------------------

pub async fn isolate_host_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    ensure_host_isolation_enabled(&state).await?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let action_url = format!("/arsenals/inquest/{host_id}/isolate");
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Isolate host",
        format!(
            "This will block ALL network traffic on \"{}\" except loopback, already-established \
             connections, and the control plane's own connection back to this agent. If anything \
             about that exception is wrong for this host's network setup (NAT, a DNS-based \
             control-plane address that later re-resolves differently, a multi-homed host), this \
             can sever the agent's own connection with no remote way to undo it -- recovery would \
             then need physical or console access. Double-check this is really the host you mean \
             before confirming.",
            host.name
        ),
        action_url,
        "hostname",
        &host.name,
    )
    .await
}

pub async fn isolate_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_host_isolation_enabled(&state).await?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &host.name,
        AgentOperation::IsolateHost,
        "Isolate Host",
        form,
    )
    .await
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
