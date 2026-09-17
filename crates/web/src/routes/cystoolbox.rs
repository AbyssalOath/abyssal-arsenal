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
use crate::templates::{BaseCtx, CystoolboxHostRow, CystoolboxTemplate};
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
            hosts.push(CystoolboxHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = CystoolboxTemplate {
        base,
        hosts,
        can_manage: ctx.has(Permission::SystemsManage),
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
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
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
            Permission::SystemsView,
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

pub async fn system_overview(
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
        AgentOperation::SystemInfo,
        "System Overview",
    )
    .await
}

pub async fn resource_usage(
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
        AgentOperation::ResourceUsage,
        "Resource Usage",
    )
    .await
}

pub async fn logged_in_users(
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
        AgentOperation::LoggedInUsers,
        "Logged-in Users",
    )
    .await
}

pub async fn reboot_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Reboot host".to_string(),
        message: format!(
            "This will immediately reboot \"{}\". Any unsaved work or active sessions on that host will be interrupted.",
            host.name
        ),
        action_url: format!("/arsenals/cystoolbox/{host_id}/reboot"),
        cancel_url: "/arsenals/cystoolbox".to_string(),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RebootForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
}

pub async fn reboot(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RebootForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Reboot was not confirmed.".into(),
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
            AgentOperation::Reboot,
            Permission::SystemsManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(10),
            None,
        )
        .await;

    let result_label = Some(format!("Reboot -- {}", host.name));
    match result {
        Ok(output) => render(&state, &jar, &ctx, result_label, Some(output.stdout), None).await,
        Err(e) => render(&state, &jar, &ctx, result_label, None, Some(e.to_string())).await,
    }
}
