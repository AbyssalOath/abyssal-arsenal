use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, CadavaultHostRow, CadavaultTemplate};
use crate::theme;

async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(ctx, &theme::current(jar), &csrf_token);

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(CadavaultHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = CadavaultTemplate {
        base,
        hosts,
        can_manage: ctx.has(Permission::SecurityManage),
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

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    render(&state, &jar, &ctx, None, None, None).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

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

    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(10),
            None,
        )
        .await;

    let result_label = Some(format!("{label} -- {}", host.name));
    match result {
        Ok(output) => render(state, jar, ctx, result_label, Some(output.stdout), None).await,
        Err(e) => render(state, jar, ctx, result_label, None, Some(e.to_string())).await,
    }
}

pub async fn firewall_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FirewallStatus,
        "Firewall Status",
    )
    .await
}

pub async fn listening_ports(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListeningPorts,
        "Listening Ports",
    )
    .await
}

pub async fn recent_auth_log(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RecentAuthLog,
        "Recent Auth Log",
    )
    .await
}

#[derive(Deserialize)]
pub struct AllowPortForm {
    csrf_token: String,
    port: u16,
    protocol: String,
}

pub async fn allow_port(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<AllowPortForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !abyssal_agent_protocol::is_valid_port_protocol(form.port, &form.protocol) {
        return Err(WebError(AppError::Validation(
            "Enter a port between 1 and 65535 and choose tcp or udp.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::FirewallAllowPort {
                port: form.port,
                protocol: form.protocol.clone(),
            },
            Permission::SecurityManage,
            OperationKind::Write,
            false,
            Duration::from_secs(15),
            None,
        )
        .await;

    let result_label = Some(format!(
        "Allow Port ({}/{}) -- {}",
        form.port, form.protocol, host.name
    ));
    match result {
        Ok(output) => render(&state, &jar, &ctx, result_label, Some(output.stdout), None).await,
        Err(e) => render(&state, &jar, &ctx, result_label, None, Some(e.to_string())).await,
    }
}

pub async fn enable_firewall_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Enable firewall".to_string(),
        message: format!(
            "This will enable the detected firewall on \"{}\". If the port you're connecting through isn't already allowed, this can cut off remote access to that host.",
            host.name
        ),
        action_url: format!("/arsenals/cadavault/{host_id}/firewall-enable"),
        cancel_url: "/arsenals/cadavault".to_string(),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct EnableFirewallForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
}

pub async fn enable_firewall(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<EnableFirewallForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Enabling the firewall was not confirmed.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::FirewallEnable,
            Permission::SecurityManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(15),
            None,
        )
        .await;

    let result_label = Some(format!("Enable Firewall -- {}", host.name));
    match result {
        Ok(output) => render(&state, &jar, &ctx, result_label, Some(output.stdout), None).await,
        Err(e) => render(&state, &jar, &ctx, result_label, None, Some(e.to_string())).await,
    }
}
