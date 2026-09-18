use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, ReanimationHostRow, ReanimationHostTemplate, ReanimationTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(ReanimationHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = ReanimationTemplate { base, hosts };
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
    let base = BaseCtx::build(ctx, &theme::current(jar), &csrf_token, &state.elevation);

    let tpl = ReanimationHostTemplate {
        can_manage: ctx.has(Permission::SystemsManage),
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
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    sudo_password: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let tls_warning = match maybe_elevate(state, ctx, host_id, &host.name, sudo_password).await {
        Ok(warning) => warning.unwrap_or(""),
        Err(e) => return render_host(state, jar, ctx, host_id, result_label, None, Some(e)).await,
    };

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::SystemsView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
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
                Some(format!("{tls_warning}{}", output.stdout)),
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

pub async fn list_processes(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListProcesses,
        "Processes",
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct PidForm {
    csrf_token: String,
    pid: u32,
    #[serde(default)]
    sudo_password: Option<String>,
}

fn validate_pid(pid: u32) -> Result<u32, WebError> {
    if !abyssal_agent_protocol::is_valid_pid(pid) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid, non-protected process ID.".into(),
        )));
    }
    Ok(pid)
}

pub async fn process_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PidForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ProcessDetail { pid },
        &format!("Process Detail ({pid})"),
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct ReniceForm {
    csrf_token: String,
    pid: u32,
    priority: i32,
    #[serde(default)]
    sudo_password: Option<String>,
}

fn validate_priority(priority: i32) -> Result<i32, WebError> {
    if !abyssal_agent_protocol::is_valid_nice_priority(priority) {
        return Err(WebError(AppError::Validation(
            "Nice priority must be between -20 and 19.".into(),
        )));
    }
    Ok(priority)
}

/// `Write`, no confirmation required -- renicing is reversible.
pub async fn renice_priority(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ReniceForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    let priority = validate_priority(form.priority)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Renice ({pid} -> {priority}) -- {}", host.name));

    let tls_warning =
        match maybe_elevate(&state, &ctx, host_id, &host.name, form.sudo_password).await {
            Ok(warning) => warning.unwrap_or(""),
            Err(e) => {
                return render_host(&state, &jar, &ctx, host_id, result_label, None, Some(e)).await
            }
        };

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::RenicePriority { pid, priority },
            Permission::SystemsManage,
            OperationKind::Write,
            false,
            Duration::from_secs(15),
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
                Some(format!("{tls_warning}{}", output.stdout)),
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
pub struct SignalQuery {
    pid: u32,
    signal: String,
}

fn validate_signal(signal: &str) -> Result<String, WebError> {
    if !abyssal_agent_protocol::is_valid_signal_name(signal) {
        return Err(WebError(AppError::Validation(
            "That isn't one of the supported signals.".into(),
        )));
    }
    Ok(signal.to_string())
}

pub async fn signal_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SignalQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;

    let pid = validate_pid(q.pid)?;
    let signal = validate_signal(&q.signal)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Send signal".to_string(),
        message: format!(
            "This will send SIG{signal} to process {pid} on \"{}\". Any signal is an \
             intentional interruption of whatever that process is doing.",
            host.name
        ),
        action_url: format!(
            "/arsenals/reanimation/{host_id}/signal?pid={pid}&signal={}",
            urlencoding_encode(&signal)
        ),
        cancel_url: format!("/arsenals/reanimation/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "process ID".to_string(),
            expected: pid.to_string(),
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
pub struct SignalForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn send_signal(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SignalQuery>,
    Form(form): Form<SignalForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Send signal was not confirmed.".into(),
        )));
    }

    let pid = validate_pid(q.pid)?;
    let signal = validate_signal(&q.signal)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &pid.to_string())?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!(
        "Send Signal (SIG{signal} -> {pid}) -- {}",
        host.name
    ));

    let tls_warning =
        match maybe_elevate(&state, &ctx, host_id, &host.name, form.sudo_password).await {
            Ok(warning) => warning.unwrap_or(""),
            Err(e) => {
                return render_host(&state, &jar, &ctx, host_id, result_label, None, Some(e)).await
            }
        };

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SendSignal { pid, signal },
            Permission::SystemsManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(15),
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
                Some(format!("{tls_warning}{}", output.stdout)),
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
