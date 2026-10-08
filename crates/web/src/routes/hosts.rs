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
use crate::deploy_commands;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, DeploymentInstructions, EnrollmentInstructions, HostRow, HostsTemplate,
};
use crate::theme;

fn control_plane_base_url(state: &AppState, headers: &HeaderMap) -> String {
    crate::common::request_base_url(state, headers)
}

/// Builds the per-OS enrollment guidance for a freshly generated token. Every
/// command is fully filled in (control-plane URL, agent version, the one-time
/// token, and -- with an internal CA -- the CA fingerprint to pin) so the
/// operator copies one block verbatim. See `crate::deploy_commands`.
fn build_enrollment_instructions(base_url: &str, token: &str) -> EnrollmentInstructions {
    let ca = crate::public_ca::load();
    let ca = ca.as_ref();
    EnrollmentInstructions {
        token: token.to_string(),
        ca_fingerprint: ca.map(|ca| ca.fingerprint_display()),
        linux_oneliner: deploy_commands::linux_oneliner(base_url, token, ca),
        linux_manual: deploy_commands::linux_manual(base_url, token, ca),
        windows_oneliner: deploy_commands::windows_oneliner(base_url, token, ca),
        windows_manual: deploy_commands::windows_manual(base_url, token, ca),
        windows_rmm: deploy_commands::windows_rmm(base_url, token, ca),
    }
}

#[allow(clippy::too_many_arguments)]
async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    enrollment: Option<EnrollmentInstructions>,
    deployment: Option<crate::templates::DeploymentInstructions>,
    uninstall_command: Option<String>,
    action_result: Option<String>,
    action_error: Option<String>,
) -> Result<Response, WebError> {
    render_full(
        state,
        jar,
        ctx,
        enrollment,
        deployment,
        uninstall_command,
        action_result,
        action_error,
        None,
    )
    .await
}

/// [`render`], plus the AAT in clear -- only ever passed by the audited
/// reveal/rotate handlers; every other render shows it masked.
#[allow(clippy::too_many_arguments)]
async fn render_full(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    enrollment: Option<EnrollmentInstructions>,
    deployment: Option<crate::templates::DeploymentInstructions>,
    uninstall_command: Option<String>,
    action_result: Option<String>,
    action_error: Option<String>,
    revealed_aat: Option<String>,
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
            pending_approval: host.pending_approval,
            os: host.os.clone().unwrap_or_else(|| "unknown".to_string()),
            agent_version: host
                .agent_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        });
    }

    let deployment_tokens = repo::host_enrollment_tokens::list_active_deployment(&state.pool)
        .await?
        .into_iter()
        .map(|t| crate::templates::DeploymentTokenView {
            id: t.id.to_string(),
            label: t.label.unwrap_or_else(|| "(unlabeled)".to_string()),
            created: crate::common::format_in_tz(t.created_at, &ctx.user.timezone),
            expires: crate::common::format_in_tz(t.expires_at, &ctx.user.timezone),
            use_count: t.use_count,
        })
        .collect();

    let aat = crate::templates::AatView {
        // PUBLIC_URL (install.sh sets it) -- this render has no request to
        // infer the address from, and the commands are for other machines.
        commands: crate::deploy_commands::aat_commands(
            state
                .config
                .public_url
                .as_deref()
                .unwrap_or("https://<control-plane-address>")
                .trim_end_matches('/'),
            revealed_aat.as_deref(),
        ),
        revealed: revealed_aat,
        require_approval: crate::aat::require_approval(&state.pool).await?,
        pending_count: hosts.iter().filter(|h| h.pending_approval).count(),
    };

    let tpl = HostsTemplate {
        base,
        can_enroll: ctx.has(Permission::HostsEnroll),
        can_manage: ctx.has(Permission::HostsManage),
        aat,
        hosts,
        enrollment,
        deployment,
        deployment_tokens,
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
    render(&state, &jar, &ctx, None, None, None, None, None).await
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
    abyssal_rbac::ensure(&ctx, Permission::HostsEnroll)?;
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

    render(
        &state,
        &jar,
        &ctx,
        Some(instructions),
        None,
        None,
        None,
        None,
    )
    .await
}

/// The install command(s) for a reusable deployment token, by OS -- what an
/// operator drops into PDQ Deploy, a GPO startup script, or Intune. Same
/// commands as a single-use token; the difference is the token is reusable,
/// so the same command provisions every machine it's pushed to. Windows gets
/// the unattended RMM script as the primary command (that's what deployment
/// tokens are for) plus the interactive one-liner for a quick manual test.
fn build_deployment_command(
    base_url: &str,
    token: &str,
    os: &str,
    ca: Option<&crate::public_ca::PublicCa>,
) -> (String, String, Option<String>) {
    if os == "linux" {
        (
            "Linux".to_string(),
            deploy_commands::linux_oneliner(base_url, token, ca),
            None,
        )
    } else {
        (
            "Windows".to_string(),
            deploy_commands::windows_rmm(base_url, token, ca),
            Some(deploy_commands::windows_oneliner(base_url, token, ca)),
        )
    }
}

#[derive(Deserialize)]
pub struct DeploymentForm {
    csrf_token: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    ttl_hours: u32,
    #[serde(default)]
    label: String,
}

/// Creates a reusable deployment token and shows the OS-specific install
/// command for mass rollout. The command (which contains the token) is shown
/// once -- the token is hashed at rest -- so save it into your deploy tool now.
pub async fn generate_deployment_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    headers: HeaderMap,
    Form(form): Form<DeploymentForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    // Default 30 days; clamp to [1 hour, 1 year] so a hand-posted value can't
    // mint an effectively-permanent key by accident.
    let ttl_hours = if form.ttl_hours == 0 {
        720
    } else {
        form.ttl_hours.clamp(1, 24 * 365)
    };
    let label = form.label.trim();
    let token = generate_token();
    let hash = hash_token(&token);
    repo::host_enrollment_tokens::create_deployment(
        &state.pool,
        &hash,
        Some(ctx.user.id),
        ChronoDuration::hours(i64::from(ttl_hours)),
        (!label.is_empty()).then_some(label),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("host.deployment_token")
            .metadata(
                serde_json::json!({ "action": "create", "label": label, "ttl_hours": ttl_hours }),
            ),
    )
    .await?;

    let base_url = control_plane_base_url(&state, &headers);
    let ca = crate::public_ca::load();
    let (os_label, command, interactive_command) =
        build_deployment_command(&base_url, &token, &form.os, ca.as_ref());
    let deployment = DeploymentInstructions {
        os_label,
        token,
        command,
        interactive_command,
        ca_fingerprint: ca.as_ref().map(|ca| ca.fingerprint_display()),
        expires: crate::common::format_in_tz(
            chrono::Utc::now() + ChronoDuration::hours(i64::from(ttl_hours)),
            &ctx.user.timezone,
        ),
    };

    render(&state, &jar, &ctx, None, Some(deployment), None, None, None).await
}

/// Revokes a reusable deployment token (it stops enrolling new hosts
/// immediately; already-enrolled hosts are unaffected).
pub async fn revoke_deployment_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::host_enrollment_tokens::revoke(&state.pool, id).await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("host.deployment_token")
            .metadata(serde_json::json!({ "action": "revoke", "id": id.to_string() })),
    )
    .await?;

    Ok(Redirect::to("/admin/hosts").into_response())
}

/// Shows the AAT in clear. A POST, not part of the page, so every view of the
/// secret is a deliberate, audit-logged action.
pub async fn reveal_aat(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let aat = match crate::aat::ensure(&state.pool, state.encryption_key.as_deref()).await {
        Ok(aat) => aat,
        Err(e) => {
            return render(
                &state,
                &jar,
                &ctx,
                None,
                None,
                None,
                None,
                Some(format!("{e:#}")),
            )
            .await;
        }
    };
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::SecretAccessed, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("host.aat"),
    )
    .await?;
    render_full(&state, &jar, &ctx, None, None, None, None, None, Some(aat)).await
}

/// Replaces the AAT. The old one stops enrolling new hosts immediately;
/// enrolled hosts are unaffected. Shows the new one, since every deploy
/// package needs updating with it.
pub async fn rotate_aat(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let aat = crate::aat::rotate(
        &state.pool,
        state.encryption_key.as_deref(),
        Some(ctx.user.id),
    )
    .await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("host.aat")
            .metadata(serde_json::json!({ "action": "rotate" })),
    )
    .await?;
    render_full(
        &state,
        &jar,
        &ctx,
        None,
        None,
        None,
        Some(
            "Install token rotated. The old one no longer enrolls hosts -- update your \
             PDQ/Intune/GPO packages with the new one below."
                .to_string(),
        ),
        None,
        Some(aat),
    )
    .await
}

#[derive(Deserialize)]
pub struct AatApprovalForm {
    csrf_token: String,
    /// A checkbox: present ("on") when checked, absent otherwise.
    #[serde(default)]
    require_approval: Option<String>,
}

pub async fn set_aat_approval(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<AatApprovalForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let required = form.require_approval.is_some();
    crate::aat::set_require_approval(&state.pool, required, Some(ctx.user.id)).await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("host.aat")
            .metadata(serde_json::json!({ "require_approval": required })),
    )
    .await?;
    Ok(Redirect::to("/admin/hosts").into_response())
}

/// Lets a host enrolled with the AAT (while approval was required) connect.
/// Its agent is already retrying, so it shows up online within a minute.
/// Rejecting one is just Remove.
pub async fn approve(
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
    if repo::hosts::approve(&state.pool, id).await? {
        abyssal_audit::record(
            &state.pool,
            AuditEvent::new(AuditAction::HostApproved, AuditOutcome::Success)
                .actor(Actor {
                    user_id: ctx.user.id,
                    username: &ctx.user.username,
                })
                .resource(&host.name),
        )
        .await?;
    }
    Ok(Redirect::to("/admin/hosts").into_response())
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
        Ok(output) => {
            render(
                &state,
                &jar,
                &ctx,
                None,
                None,
                None,
                Some(output.stdout),
                None,
            )
            .await
        }
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
            render(&state, &jar, &ctx, None, None, None, None, Some(friendly)).await
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
        Ok(output) => {
            render(
                &state,
                &jar,
                &ctx,
                None,
                None,
                None,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            render(
                &state,
                &jar,
                &ctx,
                None,
                None,
                None,
                None,
                Some(e.to_string()),
            )
            .await
        }
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
        Ok(output) => {
            render(
                &state,
                &jar,
                &ctx,
                None,
                None,
                None,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            render(
                &state,
                &jar,
                &ctx,
                None,
                None,
                None,
                None,
                Some(e.to_string()),
            )
            .await
        }
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
        None,
        Some(uninstall_command),
        None,
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_command_windows_is_the_rmm_script_plus_the_one_liner() {
        let (label, cmd, interactive) =
            build_deployment_command("https://arsenal.corp.local", "TOK123", "windows", None);
        assert_eq!(label, "Windows");
        assert!(cmd.contains("install.ps1"));
        assert!(cmd.contains("-ExitCode"));
        assert!(cmd.contains("$env:ABYSSAL_ENROLLMENT_TOKEN = 'TOK123'"));
        assert!(interactive.unwrap().contains("-EnrollmentToken 'TOK123'"));
    }

    #[test]
    fn deployment_command_linux_uses_the_sh_one_liner() {
        let (label, cmd, interactive) =
            build_deployment_command("https://arsenal.corp.local", "TOK123", "linux", None);
        assert_eq!(label, "Linux");
        assert!(cmd.contains("install.sh"));
        assert!(cmd.contains("--enrollment-token 'TOK123'"));
        assert!(interactive.is_none());
    }

    #[test]
    fn deployment_command_defaults_to_windows_for_unknown_os() {
        // Anything that isn't "linux" falls back to the Windows command.
        let (label, _, _) = build_deployment_command("https://x", "t", "", None);
        assert_eq!(label, "Windows");
    }
}
