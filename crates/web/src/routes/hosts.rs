use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
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
use crate::templates::{BaseCtx, EnrollmentInstructions, HostRow, HostsTemplate};
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

/// Builds the per-OS enrollment guidance for a freshly generated token. All
/// four commands are fully filled in (control-plane URL, agent version, and
/// the one-time token) so the operator copies one block verbatim. The
/// version is this control plane's own (`update_check::CURRENT_VERSION`) --
/// the release whose agent artifact matches this build's protocol, same
/// version the SSH-deploy path and self-update install.
fn build_enrollment_instructions(base_url: &str, token: &str) -> EnrollmentInstructions {
    let version = crate::update_check::CURRENT_VERSION.trim();
    let linux_asset = format!("abyssal-agent-v{version}-x86_64-unknown-linux-gnu");
    let windows_asset = format!("abyssal-agent-v{version}-x86_64-pc-windows-msvc");
    let releases = "https://github.com/AbyssalOath/abyssal-arsenal/releases/download";

    let linux_oneliner =
        format!("curl -fsSL {base_url}/install.sh | sudo sh -s -- --enrollment-token {token}");

    let linux_manual = format!(
        "curl -LO {releases}/v{version}/{linux_asset}.tar.gz\n\
         tar -xzf {linux_asset}.tar.gz\n\
         sudo ./{linux_asset}/abyssal-agent install \\\n  \
         --control-plane-url {base_url} --enrollment-token {token}"
    );

    // Downloads the served script text and invokes it as a scriptblock with
    // the token as a parameter -- the reliable way to pass an argument to a
    // remotely fetched PowerShell script (plain `irm ... | iex` can't take
    // one). Must be run from an elevated ("Run as administrator") prompt.
    let windows_oneliner =
        format!("& ([scriptblock]::Create((irm {base_url}/install.ps1))) -EnrollmentToken {token}");

    let windows_manual = format!(
        "$v = \"{version}\"; $a = \"{windows_asset}\"\n\
         Invoke-WebRequest {releases}/v$v/$a.zip -OutFile \"$a.zip\"\n\
         Expand-Archive \"$a.zip\" -DestinationPath . -Force\n\
         .\\$a\\abyssal-agent.exe install `\n  \
         --control-plane-url {base_url} --enrollment-token {token}"
    );

    EnrollmentInstructions {
        token: token.to_string(),
        linux_oneliner,
        linux_manual,
        windows_oneliner,
        windows_manual,
    }
}

#[allow(clippy::too_many_arguments)]
async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    enrollment: Option<EnrollmentInstructions>,
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
            os: host.os.clone().unwrap_or_else(|| "unknown".to_string()),
            agent_version: host
                .agent_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        });
    }

    let tpl = HostsTemplate {
        base,
        hosts,
        enrollment,
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
    let instructions = build_enrollment_instructions(&base_url, &token);

    render(&state, &jar, &ctx, Some(instructions), None, None, None).await
}

/// Pushes the currently-connected agent to update itself to this control
/// plane's own version, over the existing WebSocket -- the one-click answer
/// to the "Agent out of date" badge. Only works on an agent build new
/// enough to understand `AgentOperation::SelfUpdate`; one that predates it
/// can't deserialize the message and drops the connection, which surfaces
/// here as a clear "too old to self-update" message pointing back at the
/// re-deploy path, rather than a silent failure.
pub async fn update_agent(
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

    // Whether it looked out of date *before* we dispatched -- used only to
    // phrase the failure message, since a stale agent disconnecting on the
    // unknown operation is exactly the expected outcome for a mismatch.
    let was_mismatched = state.hosts.agent_protocol_mismatch(id);

    let version = crate::update_check::CURRENT_VERSION.trim().to_string();
    let elevated = state.elevation.is_elevated(id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            id,
            &format!("Update agent -- {}", host.name),
            AgentOperation::SelfUpdate {
                version: version.clone(),
            },
            Permission::HostsManage,
            OperationKind::Write,
            false,
            // Generous: the agent downloads a ~10 MB release and unpacks it
            // before replying, all ahead of the scheduled restart.
            Duration::from_secs(180),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => render(&state, &jar, &ctx, None, None, Some(output.stdout), None).await,
        Err(e) => {
            let message = e.to_string();
            // The signature of an agent too old to know the SelfUpdate
            // operation: it fails to deserialize the command and drops the
            // connection instead of replying.
            let looks_too_old =
                was_mismatched && message.contains("disconnected before responding");
            let friendly = if looks_too_old {
                format!(
                    "This agent is too old to update itself over its connection (it doesn't \
                     understand the update command yet, so it dropped the connection). Re-deploy \
                     it to v{version} using the bootstrap one-liner (generate a token above) or \
                     the SSH quick-add from a Panopticon scan, then future updates can be done \
                     from here. Underlying error: {message}"
                )
            } else {
                message
            };
            render(&state, &jar, &ctx, None, None, None, Some(friendly)).await
        }
    }
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
