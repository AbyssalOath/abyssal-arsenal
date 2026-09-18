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
use crate::host_context;
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

#[allow(clippy::too_many_arguments)]
async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    enrollment_command: Option<String>,
    uninstall_command: Option<String>,
    action_result: Option<String>,
    action_error: Option<String>,
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

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        let elevation_remaining = state
            .elevation
            .remaining_for(host.id)
            .map(crate::templates::format_remaining);
        hosts.push(HostRow {
            id: host.id.to_string(),
            name: host.name.clone(),
            enrolled_at: crate::common::format_in_tz(host.enrolled_at, &ctx.user.timezone),
            last_seen_at: host
                .last_seen_at
                .map(|t| crate::common::format_in_tz(t, &ctx.user.timezone))
                .unwrap_or_else(|| "never".to_string()),
            online: state.hosts.is_connected(host.id),
            revoked: host.revoked_at.is_some(),
            elevation_remaining,
            protocol_mismatch: state.hosts.agent_protocol_mismatch(host.id),
        });
    }

    let tpl = HostsTemplate {
        base,
        hosts,
        enrollment_command,
        uninstall_command,
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
    render(&state, &jar, &ctx, None, None, None, None).await
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

    render(&state, &jar, &ctx, Some(command), None, None, None).await
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

    let elevated = state.elevation.is_elevated(id);
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
            elevated,
        )
        .await;

    match result {
        Ok(output) => render(&state, &jar, &ctx, None, None, Some(output.stdout), None).await,
        Err(e) => render(&state, &jar, &ctx, None, None, None, Some(e.to_string())).await,
    }
}

pub async fn deescalate(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsElevate)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let elevated = state.elevation.is_elevated(id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            id,
            &format!("Elevate Privileges -- {}", host.name),
            AgentOperation::Deescalate,
            Permission::HostsElevate,
            OperationKind::Write,
            false,
            Duration::from_secs(10),
            None,
            elevated,
        )
        .await;

    state.elevation.mark_deescalated(id);

    match result {
        Ok(output) => render(&state, &jar, &ctx, None, None, Some(output.stdout), None).await,
        Err(e) => render(&state, &jar, &ctx, None, None, None, Some(e.to_string())).await,
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

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Revoke host".to_string(),
        message: format!(
            "This will revoke \"{}\"'s credential. Its agent will no longer be able to connect until re-enrolled.",
            host.name
        ),
        action_url: format!("/admin/hosts/{id}/revoke"),
        cancel_url: "/admin/hosts".to_string(),
        escalate_host_id: None,
        type_to_confirm: None,
        extra_hidden_fields: vec![],
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

pub async fn remove_confirm(
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

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Remove host".to_string(),
        message: format!(
            "This will permanently delete \"{}\" and its credential from Abyssal Arsenal -- \
             this cannot be undone. Its audit history is kept. The agent itself keeps running \
             on the remote machine until you uninstall it there; you'll be given the command to \
             do that after confirming.",
            host.name
        ),
        action_url: format!("/admin/hosts/{id}/remove"),
        cancel_url: "/admin/hosts".to_string(),
        escalate_host_id: None,
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
pub struct RemoveForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn remove(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<RemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;

    // Delete first, then drop any live connection -- a connection that
    // outlives the DB row can no longer be dispatched to via `/admin/hosts`
    // (its row is gone), and if it ever disconnects and tries to
    // reconnect, its credential no longer resolves to a host either.
    repo::hosts::delete(&state.pool, id).await?;
    state.hosts.unregister(id);

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::HostRemoved, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&host.name),
    )
    .await?;

    let uninstall_command = "sudo systemctl disable --now abyssal-agent\n\
         sudo rm -f /usr/local/bin/abyssal-agent\n\
         sudo rm -rf /etc/abyssal-agent\n\
         sudo rm -f /etc/systemd/system/abyssal-agent.service\n\n\
         (If you installed it with `cargo install` instead, remove \
         ~/.cargo/bin/abyssal-agent and whatever --credentials-file path you gave it.)"
        .to_string();

    render(
        &state,
        &jar,
        &ctx,
        None,
        Some(uninstall_command),
        None,
        None,
    )
    .await
}
