use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use chrono::Duration as ChronoDuration;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, HostRow, HostsTemplate};
use crate::theme;

fn control_plane_base_url(state: &AppState, headers: &HeaderMap) -> String {
    let scheme = if state.config.cookie_secure {
        "https"
    } else {
        "http"
    };
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    format!("{scheme}://{host}")
}

async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    enrollment_command: Option<String>,
    action_result: Option<String>,
    action_error: Option<String>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(ctx, &theme::current(jar), &csrf_token);

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        hosts.push(HostRow {
            id: host.id.to_string(),
            name: host.name.clone(),
            enrolled_at: host.enrolled_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            last_seen_at: host
                .last_seen_at
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "never".to_string()),
            online: state.hosts.is_connected(host.id),
        });
    }

    let tpl = HostsTemplate {
        base,
        hosts,
        enrollment_command,
        action_result,
        action_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsView)?;
    render(&state, &jar, &ctx, None, None, None).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

pub async fn generate_enrollment_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    headers: HeaderMap,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let token = generate_token();
    let hash = hash_token(&token);
    repo::host_enrollment_tokens::create(
        &state.pool,
        &hash,
        Some(ctx.user.id),
        ChronoDuration::minutes(15),
    )
    .await?;

    let base_url = control_plane_base_url(&state, &headers);
    let command =
        format!("abyssal-agent run --control-plane-url {base_url} --enrollment-token {token}");

    render(&state, &jar, &ctx, Some(command), None, None).await
}

pub async fn run_system_info(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            id,
            &host.name,
            AgentOperation::SystemInfo,
            Permission::HostsManage,
            OperationKind::Read,
            false,
            Duration::from_secs(10),
            None,
        )
        .await;

    match result {
        Ok(output) => render(&state, &jar, &ctx, None, Some(output.stdout), None).await,
        Err(e) => render(&state, &jar, &ctx, None, None, Some(e.to_string())).await,
    }
}

pub async fn revoke_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Revoke host".to_string(),
        message: format!(
            "This will revoke \"{}\"'s credential. Its agent will no longer be able to connect until re-enrolled.",
            host.name
        ),
        action_url: format!("/admin/hosts/{id}/revoke"),
        cancel_url: "/admin/hosts".to_string(),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RevokeForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
}

pub async fn revoke(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<RevokeForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Revocation was not confirmed.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    repo::hosts::revoke(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::HostRevoked, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&host.name),
    )
    .await?;

    Ok(Redirect::to("/admin/hosts").into_response())
}
