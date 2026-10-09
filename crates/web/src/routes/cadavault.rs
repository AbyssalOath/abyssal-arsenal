use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, SshHardeningSetting};
use abyssal_agent_protocol::{SECURITY_SYSCTLS, recommended_sysctl};
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
    WorkflowContextRow, maybe_elevate, require_csrf, suggested_actions_for, workflow_context_rows,
};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, CadavaultHostRow, CadavaultHostTemplate, CadavaultPostureTemplate, CadavaultTemplate,
    PostureCategoryRow, SuggestedActionView, SysctlPostureRow,
};
use crate::theme;

/// The hardening settings offered in the UI, as `(form_value, label)` pairs.
fn ssh_hardening_options() -> Vec<(String, String)> {
    SshHardeningSetting::ALL
        .iter()
        .map(|s| (s.as_str().to_string(), s.label().to_string()))
        .collect()
}

/// Landing page for this arsenal: just a host picker, same as Cystoolbox.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/cadavault/{host_id}")).into_response());
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
            hosts.push(CadavaultHostRow {
                is_control_plane: host.is_control_plane,
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = CadavaultTemplate { base, hosts };
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
    render_host_full(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn render_host_with_suggestions(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    suggested_actions: Vec<SuggestedActionView>,
) -> Result<Response, WebError> {
    render_host_full(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        Vec::new(),
        Vec::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn render_host_full(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    suggested_actions: Vec<SuggestedActionView>,
    context: Vec<WorkflowContextRow>,
    sysctl_posture: Vec<SysctlPostureRow>,
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

    let tpl = CadavaultHostTemplate {
        can_manage: ctx.has(Permission::SecurityManage),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        control_plane: crate::control_plane::page_note(&state.hosts, host_id),
        firewall_enable_refusal: crate::control_plane::refusal(
            &state.hosts,
            host_id,
            &AgentOperation::FirewallEnable,
        ),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
        ssh_hardening_settings: ssh_hardening_options(),
        sysctl_posture,
        suggested_actions,
        context,
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
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    render_host_full(
        &state,
        &jar,
        &ctx,
        host_id,
        None,
        None,
        None,
        Vec::new(),
        workflow_context_rows(&query),
        Vec::new(),
    )
    .await
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
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(10),
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

/// Parses the agent's `SshdConfigAudit` output (one `key value` line per
/// audited directive) into the structured booleans the workflow registry
/// checks. A directive that's absent or set to anything but a plain `yes` is
/// reported `false` -- e.g. `permitrootlogin without-password` means root
/// password login is *not* enabled, so `permit_root_login` is `false`.
fn parse_sshd_audit(stdout: &str) -> serde_json::Value {
    let value_for = |key: &str| -> Option<String> {
        stdout.lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            let k = parts.next()?;
            if k.eq_ignore_ascii_case(key) {
                Some(parts.collect::<Vec<_>>().join(" "))
            } else {
                None
            }
        })
    };
    let is_yes = |key: &str| value_for(key).as_deref() == Some("yes");

    serde_json::json!({
        "permit_root_login": is_yes("permitrootlogin"),
        "password_authentication": is_yes("passwordauthentication"),
        "permit_empty_passwords": is_yes("permitemptypasswords"),
        "x11_forwarding": is_yes("x11forwarding"),
    })
}

/// Extracts the integer that follows a fixed label line in an audit report,
/// or 0 when the line is missing or its value isn't a number (e.g. `unknown`
/// where a check needed elevation) -- never claim a workflow count off a
/// value the agent couldn't actually determine.
fn count_after_label(stdout: &str, label: &str) -> i64 {
    stdout
        .lines()
        .map(str::trim_start)
        .find(|l| l.starts_with(label))
        .and_then(|l| l[label.len()..].split_whitespace().next())
        .and_then(|t| t.parse::<i64>().ok())
        .unwrap_or(0)
}

/// Reads the value after a fixed label line, trimmed, if present.
fn field_after_label(stdout: &str, label: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(label))
        .map(|l| l[label.len()..].trim().to_string())
}

/// Parses the account-policy audit report into the counts the workflow
/// registry checks.
fn parse_account_audit(stdout: &str) -> serde_json::Value {
    serde_json::json!({
        "extra_uid0_count": count_after_label(stdout, "Extra UID-0 accounts (besides root):"),
        "empty_password_count": count_after_label(stdout, "Empty-password accounts:"),
        "nopasswd_count": count_after_label(stdout, "Sudoers NOPASSWD entries:"),
    })
}

/// Parses the MAC status report: whether a MAC system is present at all, and
/// whether it's enforcing.
fn parse_mac_status(stdout: &str) -> serde_json::Value {
    let system = field_after_label(stdout, "MAC system:").unwrap_or_default();
    let present = !system.is_empty() && !system.eq_ignore_ascii_case("none");
    let enforcing = field_after_label(stdout, "MAC enforcing:").as_deref() == Some("yes");
    serde_json::json!({ "mac_present": present, "mac_enforcing": enforcing })
}

/// Parses the automatic-updates report into its `enabled|disabled|unknown`
/// state.
fn parse_auto_updates(stdout: &str) -> serde_json::Value {
    let state =
        field_after_label(stdout, "Automatic updates:").unwrap_or_else(|| "unknown".to_string());
    serde_json::json!({ "automatic_updates": state })
}

/// Shared body for Cadavault's structured read audits: runs a `SecurityView`
/// read op, parses its output into the workflow registry, and renders the host
/// page with the report and any "Suggested Next Steps".
#[allow(clippy::too_many_arguments)]
async fn run_audit_with_suggestions(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    source_action: &str,
    parse: fn(&str) -> serde_json::Value,
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
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let entry = parse(&output.stdout);
            let suggested_actions = suggested_actions_for(
                state,
                "cadavault",
                source_action,
                std::slice::from_ref(&entry),
                host_id,
            )
            .await;
            render_host_with_suggestions(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
                suggested_actions,
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

pub async fn sshd_config_audit(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_audit_with_suggestions(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::SshdConfigAudit,
        "SSH Configuration Audit",
        "sshd_config_audit",
        parse_sshd_audit,
    )
    .await
}

pub async fn account_policy_audit(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_audit_with_suggestions(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::AccountPolicyAudit,
        "Account Policy Audit",
        "account_policy_audit",
        parse_account_audit,
    )
    .await
}

pub async fn mac_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_audit_with_suggestions(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::MacStatus,
        "Mandatory Access Control Status",
        "mac_status",
        parse_mac_status,
    )
    .await
}

pub async fn automatic_updates_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_audit_with_suggestions(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::AutomaticUpdatesStatus,
        "Automatic Updates Status",
        "automatic_updates_status",
        parse_auto_updates,
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

    run_port_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FirewallAllowPort {
            port: form.port,
            protocol: form.protocol.clone(),
        },
        format!("Allow Port ({}/{})", form.port, form.protocol),
    )
    .await
}

pub async fn deny_port(
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

    run_port_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FirewallDenyPort {
            port: form.port,
            protocol: form.protocol.clone(),
        },
        format!("Deny Port ({}/{})", form.port, form.protocol),
    )
    .await
}

/// Shared body for the additive (Write) firewall port operations.
async fn run_port_write_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: String,
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
            Permission::SecurityManage,
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
pub struct PortQuery {
    port: u16,
    protocol: String,
}

/// Confirmation page for removing a previously-allowed port -- Destructive,
/// since revoking a port can cut off remote access, so it uses the same
/// type-the-hostname gate as Enable Firewall.
pub async fn remove_port_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(query): Query<PortQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;

    if !abyssal_agent_protocol::is_valid_port_protocol(query.port, &query.protocol) {
        return Err(WebError(AppError::Validation(
            "Enter a port between 1 and 65535 and choose tcp or udp.".into(),
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
        title: "Remove firewall rule".to_string(),
        message: format!(
            "This will remove the allow rule for port {}/{} on \"{}\". If you're connected through that port, this can cut off remote access to the host.",
            query.port, query.protocol, host.name
        ),
        action_url: format!("/arsenals/cadavault/{host_id}/remove-port"),
        cancel_url: format!("/arsenals/cadavault/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected: host.name.clone(),
        }),
        extra_hidden_fields: vec![
            ("port".to_string(), query.port.to_string()),
            ("protocol".to_string(), query.protocol.clone()),
        ],
        shred_option: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RemovePortForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    port: u16,
    protocol: String,
}

pub async fn remove_port(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RemovePortForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removing the firewall rule was not confirmed.".into(),
        )));
    }
    if !abyssal_agent_protocol::is_valid_port_protocol(form.port, &form.protocol) {
        return Err(WebError(AppError::Validation(
            "Enter a port between 1 and 65535 and choose tcp or udp.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
    let result_label = Some(format!(
        "Remove Port ({}/{}) -- {}",
        form.port, form.protocol, host.name
    ));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::FirewallRemovePort {
                port: form.port,
                protocol: form.protocol.clone(),
            },
            Permission::SecurityManage,
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
        title: "Enable firewall".to_string(),
        message: format!(
            "This will enable the detected firewall on \"{}\". If the port you're connecting through isn't already allowed, this can cut off remote access to that host.",
            host.name
        ),
        action_url: format!("/arsenals/cadavault/{host_id}/firewall-enable"),
        cancel_url: format!("/arsenals/cadavault/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected: host.name.clone(),
        }),
        extra_hidden_fields: vec![],
        shred_option: None,
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
    #[serde(default)]
    confirm_text: String,
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
    crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
    let result_label = Some(format!("Enable Firewall -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
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
pub struct SettingQuery {
    setting: String,
}

/// Confirmation page for applying one SSH hardening directive. Destructive:
/// tightening auth can cut off the current session, so it uses the type-the-
/// hostname gate. The chosen setting is carried through as a hidden field.
pub async fn harden_sshd_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(query): Query<SettingQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;

    let setting = SshHardeningSetting::from_wire(&query.setting).ok_or_else(|| {
        WebError(AppError::Validation(
            "Choose a valid SSH hardening setting.".into(),
        ))
    })?;

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

    let (key, value) = setting.directive();
    let lockout_note = if setting.can_lock_out() {
        " If you're currently relying on that method to reach this host, you could lock yourself out -- make sure you have another way in (such as a working SSH key) first."
    } else {
        ""
    };
    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: format!("{} on {}", setting.label(), host.name),
        message: format!(
            "This will set `{key} {value}` in a Cadavault-managed sshd drop-in on \"{}\", validate the whole config, and reload sshd.{lockout_note}",
            host.name
        ),
        action_url: format!("/arsenals/cadavault/{host_id}/harden-sshd"),
        cancel_url: format!("/arsenals/cadavault/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected: host.name.clone(),
        }),
        extra_hidden_fields: vec![("setting".to_string(), setting.as_str().to_string())],
        shred_option: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct HardenSshdForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    setting: String,
}

pub async fn harden_sshd(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<HardenSshdForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Applying the SSH hardening setting was not confirmed.".into(),
        )));
    }
    let setting = SshHardeningSetting::from_wire(&form.setting).ok_or_else(|| {
        WebError(AppError::Validation(
            "Choose a valid SSH hardening setting.".into(),
        ))
    })?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
    let result_label = Some(format!("{} -- {}", setting.label(), host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::HardenSshd { setting },
            Permission::SecurityManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(20),
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

pub async fn clear_ssh_hardening_confirm(
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
        title: "Clear SSH hardening".to_string(),
        message: format!(
            "This removes every Cadavault-managed sshd hardening directive on \"{}\", returning sshd to the host's own defaults, then validates and reloads. If a default re-opens password or root login, that changes who can reach the host.",
            host.name
        ),
        action_url: format!("/arsenals/cadavault/{host_id}/clear-ssh-hardening"),
        cancel_url: format!("/arsenals/cadavault/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected: host.name.clone(),
        }),
        extra_hidden_fields: vec![],
        shred_option: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn clear_ssh_hardening(
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
            "Clearing SSH hardening was not confirmed.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
    let result_label = Some(format!("Clear SSH Hardening -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ClearSshHardening,
            Permission::SecurityManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(20),
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

/// Turns the agent's `SysctlSecurityPosture` output (one `key\tvalue` line
/// per baseline key) into scored table rows, and the count of failing rows.
/// A key the kernel doesn't expose (`unavailable`) is reported but never
/// counted as failing -- there's nothing to fix.
fn build_sysctl_rows(stdout: &str) -> (Vec<SysctlPostureRow>, usize) {
    let current: HashMap<&str, &str> = stdout
        .lines()
        .filter_map(|line| {
            let mut it = line.splitn(2, '\t');
            let key = it.next()?;
            Some((key, it.next().unwrap_or("").trim()))
        })
        .collect();

    let mut rows = Vec::with_capacity(SECURITY_SYSCTLS.len());
    let mut failing = 0;
    for entry in SECURITY_SYSCTLS {
        let value = current.get(entry.key).copied().unwrap_or("unavailable");
        let (status_label, status_badge_class, needs_fix) = if value == "unavailable" {
            ("unavailable", "badge-muted", false)
        } else if value == entry.recommended {
            ("pass", "badge-success", false)
        } else {
            failing += 1;
            ("fail", "badge-warning", true)
        };
        rows.push(SysctlPostureRow {
            key: entry.key.to_string(),
            current: value.to_string(),
            recommended: entry.recommended.to_string(),
            description: entry.description.to_string(),
            status_label: status_label.to_string(),
            status_badge_class: status_badge_class.to_string(),
            needs_fix,
        });
    }
    (rows, failing)
}

/// Runs the posture read, scores it, wires the failing count into the
/// workflow registry, and renders the host page with the table. Shared by the
/// posture check and the apply handler (which refreshes the table afterward),
/// so `extra_label`/`extra_output` let the apply handler surface its own
/// result above the refreshed table.
async fn run_sysctl_posture(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    extra_label: Option<String>,
    extra_output: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SysctlSecurityPosture,
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let (rows, failing) = build_sysctl_rows(&output.stdout);
            let entry = serde_json::json!({ "failing_count": failing });
            let suggested_actions = suggested_actions_for(
                state,
                "cadavault",
                "sysctl_posture",
                std::slice::from_ref(&entry),
                host_id,
            )
            .await;
            let label =
                extra_label.unwrap_or_else(|| format!("Sysctl Security Posture -- {}", host.name));
            render_host_full(
                state,
                jar,
                ctx,
                host_id,
                Some(label),
                extra_output,
                None,
                suggested_actions,
                Vec::new(),
                rows,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            let label =
                extra_label.unwrap_or_else(|| format!("Sysctl Security Posture -- {}", host.name));
            render_host(
                state,
                jar,
                ctx,
                host_id,
                Some(label),
                extra_output,
                Some(e.to_string()),
            )
            .await
        }
    }
}

pub async fn sysctl_posture(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_sysctl_posture(&state, &jar, &ctx, host_id, None, None).await
}

#[derive(Deserialize)]
pub struct ApplySysctlForm {
    csrf_token: String,
    key: String,
}

pub async fn apply_sysctl(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ApplySysctlForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    // Only ever apply a baseline key, and only ever to its reviewed value --
    // the key names a row in `SECURITY_SYSCTLS` or the request is rejected, so
    // Cadavault can't be used to set an arbitrary sysctl.
    let recommended = recommended_sysctl(&form.key).ok_or_else(|| {
        WebError(AppError::Validation(
            "That kernel parameter isn't part of the security baseline.".into(),
        ))
    })?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SetPersistentSysctl {
                key: form.key.clone(),
                value: recommended.to_string(),
            },
            Permission::SecurityManage,
            OperationKind::Write,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            // Refresh the table so the applied row shows as passing.
            run_sysctl_posture(
                &state,
                &jar,
                &ctx,
                host_id,
                Some(format!(
                    "Applied {} = {recommended} -- {}",
                    form.key, host.name
                )),
                Some(output.stdout),
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
                Some(format!("Apply {} -- {}", form.key, host.name)),
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

// ---- M5: aggregate Security Posture Report -----------------------------

/// A rolled-up score across the posture categories.
struct ScoreSummary {
    percent: u8,
    label: String,
    badge_class: String,
    pass: usize,
    warn: usize,
    fail: usize,
}

fn posture_row(name: &str, status: &str, badge: &str, summary: String) -> PostureCategoryRow {
    PostureCategoryRow {
        name: name.to_string(),
        status_label: status.to_string(),
        status_badge_class: badge.to_string(),
        summary,
    }
}

/// Rolls each sub-check's raw output up into one category row, and, for the
/// checks that feed the workflow registry, the `(source_action, entry)` pair
/// to evaluate. Pure so the scoring is unit-tested without a live host. Each
/// argument is the captured stdout of a read op, or the error if it couldn't
/// run (rendered as an `unavailable` category).
fn assemble_posture(
    firewall: &Result<String, String>,
    sshd: &Result<String, String>,
    sysctl: &Result<String, String>,
    accounts: &Result<String, String>,
    mac: &Result<String, String>,
    updates: &Result<String, String>,
) -> (
    Vec<PostureCategoryRow>,
    Vec<(&'static str, serde_json::Value)>,
) {
    let mut rows = Vec::new();
    let mut entries: Vec<(&'static str, serde_json::Value)> = Vec::new();

    // Firewall -- best-effort read of the status text; raw iptables/nftables
    // has no unambiguous "active" signal, so that's reported as unavailable
    // rather than guessed. No workflow entry (firewall isn't a registry
    // source).
    rows.push(match firewall {
        Ok(out) => {
            let lower = out.to_lowercase();
            if lower.contains("status: active") || lower.contains("state: running") {
                posture_row(
                    "Firewall",
                    "pass",
                    "badge-success",
                    "Firewall is active".into(),
                )
            } else if lower.contains("status: inactive")
                || lower.contains("not running")
                || lower.contains("state: not running")
            {
                posture_row(
                    "Firewall",
                    "fail",
                    "badge-danger",
                    "Firewall is inactive".into(),
                )
            } else {
                posture_row(
                    "Firewall",
                    "unavailable",
                    "badge-muted",
                    "Could not determine firewall state".into(),
                )
            }
        }
        Err(e) => posture_row(
            "Firewall",
            "unavailable",
            "badge-muted",
            format!("Unavailable: {e}"),
        ),
    });

    // SSH hardening.
    rows.push(match sshd {
        Ok(out) => {
            let entry = parse_sshd_audit(out);
            entries.push(("sshd_config_audit", entry.clone()));
            let is = |k: &str| entry[k] == serde_json::json!(true);
            if is("permit_empty_passwords")
                || is("permit_root_login")
                || is("password_authentication")
            {
                posture_row(
                    "SSH",
                    "fail",
                    "badge-danger",
                    "Password/root login or empty passwords permitted".into(),
                )
            } else if is("x11_forwarding") {
                posture_row(
                    "SSH",
                    "warn",
                    "badge-warning",
                    "Hardened, but X11 forwarding is on".into(),
                )
            } else {
                posture_row(
                    "SSH",
                    "pass",
                    "badge-success",
                    "Key-only, root login restricted".into(),
                )
            }
        }
        Err(e) => posture_row(
            "SSH",
            "unavailable",
            "badge-muted",
            format!("Unavailable: {e}"),
        ),
    });

    // Kernel / sysctl.
    rows.push(match sysctl {
        Ok(out) => {
            let (_, failing) = build_sysctl_rows(out);
            entries.push((
                "sysctl_posture",
                serde_json::json!({ "failing_count": failing }),
            ));
            if failing == 0 {
                posture_row(
                    "Kernel/sysctl",
                    "pass",
                    "badge-success",
                    "All baseline parameters set".into(),
                )
            } else if failing <= 3 {
                posture_row(
                    "Kernel/sysctl",
                    "warn",
                    "badge-warning",
                    format!("{failing} parameters below baseline"),
                )
            } else {
                posture_row(
                    "Kernel/sysctl",
                    "fail",
                    "badge-danger",
                    format!("{failing} parameters below baseline"),
                )
            }
        }
        Err(e) => posture_row(
            "Kernel/sysctl",
            "unavailable",
            "badge-muted",
            format!("Unavailable: {e}"),
        ),
    });

    // Accounts.
    rows.push(match accounts {
        Ok(out) => {
            let entry = parse_account_audit(out);
            entries.push(("account_policy_audit", entry.clone()));
            let n = |k: &str| entry[k].as_i64().unwrap_or(0);
            if n("extra_uid0_count") >= 1 || n("empty_password_count") >= 1 {
                posture_row(
                    "Accounts",
                    "fail",
                    "badge-danger",
                    "Extra privileged or passwordless accounts".into(),
                )
            } else if n("nopasswd_count") >= 1 {
                posture_row(
                    "Accounts",
                    "warn",
                    "badge-warning",
                    "NOPASSWD sudoers present".into(),
                )
            } else {
                posture_row(
                    "Accounts",
                    "pass",
                    "badge-success",
                    "No extra UID-0 or passwordless accounts".into(),
                )
            }
        }
        Err(e) => posture_row(
            "Accounts",
            "unavailable",
            "badge-muted",
            format!("Unavailable: {e}"),
        ),
    });

    // Mandatory access control. Absent MAC is a warn, not a fail -- plenty of
    // hosts run without SELinux/AppArmor.
    rows.push(match mac {
        Ok(out) => {
            let entry = parse_mac_status(out);
            entries.push(("mac_status", entry.clone()));
            if entry["mac_enforcing"] == serde_json::json!(true) {
                posture_row(
                    "Access control",
                    "pass",
                    "badge-success",
                    "MAC enforcing".into(),
                )
            } else if entry["mac_present"] == serde_json::json!(true) {
                posture_row(
                    "Access control",
                    "warn",
                    "badge-warning",
                    "MAC present but not enforcing".into(),
                )
            } else {
                posture_row(
                    "Access control",
                    "warn",
                    "badge-warning",
                    "No SELinux/AppArmor detected".into(),
                )
            }
        }
        Err(e) => posture_row(
            "Access control",
            "unavailable",
            "badge-muted",
            format!("Unavailable: {e}"),
        ),
    });

    // Automatic updates.
    rows.push(match updates {
        Ok(out) => {
            let entry = parse_auto_updates(out);
            entries.push(("automatic_updates_status", entry.clone()));
            match entry["automatic_updates"].as_str().unwrap_or("unknown") {
                "enabled" => posture_row(
                    "Automatic updates",
                    "pass",
                    "badge-success",
                    "Automatic updates enabled".into(),
                ),
                "disabled" => posture_row(
                    "Automatic updates",
                    "warn",
                    "badge-warning",
                    "Automatic updates disabled".into(),
                ),
                _ => posture_row(
                    "Automatic updates",
                    "unavailable",
                    "badge-muted",
                    "Status unknown for this package manager".into(),
                ),
            }
        }
        Err(e) => posture_row(
            "Automatic updates",
            "unavailable",
            "badge-muted",
            format!("Unavailable: {e}"),
        ),
    });

    (rows, entries)
}

/// Weighted score: pass = 1.0, warn = 0.5, fail = 0.0; `unavailable`
/// categories are excluded from the denominator so a check that couldn't run
/// neither helps nor hurts the grade.
fn score_posture(rows: &[PostureCategoryRow]) -> ScoreSummary {
    let (mut pass, mut warn, mut fail) = (0usize, 0usize, 0usize);
    for r in rows {
        match r.status_label.as_str() {
            "pass" => pass += 1,
            "warn" => warn += 1,
            "fail" => fail += 1,
            _ => {}
        }
    }
    let applicable = pass + warn + fail;
    let percent = if applicable == 0 {
        0
    } else {
        ((pass as f64 + warn as f64 * 0.5) / applicable as f64 * 100.0).round() as u8
    };
    let (label, badge_class) = if applicable == 0 {
        ("No data", "badge-muted")
    } else if percent >= 85 {
        ("Good", "badge-success")
    } else if percent >= 60 {
        ("Fair", "badge-warning")
    } else {
        ("Poor", "badge-danger")
    };
    ScoreSummary {
        percent,
        label: label.to_string(),
        badge_class: badge_class.to_string(),
        pass,
        warn,
        fail,
    }
}

/// Runs one read op and captures its stdout, or the error string if it
/// couldn't run -- used by the posture report to gather every sub-check.
async fn run_read_capture(
    state: &AppState,
    ctx: &AuthContext,
    host_id: Uuid,
    host_name: &str,
    operation: AgentOperation,
) -> Result<String, String> {
    let elevated = state.elevation.is_elevated(host_id);
    match state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            host_name,
            operation,
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await
    {
        Ok(output) => Ok(output.stdout),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn posture_report(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Gather every sub-check. Each is independent: one failing (e.g. a check
    // that needs a tool the host lacks) becomes an `unavailable` category
    // rather than sinking the whole report.
    let firewall = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::FirewallStatus,
    )
    .await;
    let sshd = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::SshdConfigAudit,
    )
    .await;
    let sysctl = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::SysctlSecurityPosture,
    )
    .await;
    let accounts = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::AccountPolicyAudit,
    )
    .await;
    let mac = run_read_capture(&state, &ctx, host_id, &host.name, AgentOperation::MacStatus).await;
    let updates = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::AutomaticUpdatesStatus,
    )
    .await;

    // If every sub-check errored the host is almost certainly offline mid-run;
    // deescalate as the individual handlers do on failure.
    if firewall.is_err()
        && sshd.is_err()
        && sysctl.is_err()
        && accounts.is_err()
        && mac.is_err()
        && updates.is_err()
    {
        state.elevation.mark_deescalated(host_id);
    }

    let (categories, entries) =
        assemble_posture(&firewall, &sshd, &sysctl, &accounts, &mac, &updates);
    let summary = score_posture(&categories);

    // The report is the richest workflow source: it re-uses every sub-check's
    // existing registry entries, aggregating and de-duplicating their
    // suggestions instead of defining its own.
    let mut seen = std::collections::HashSet::new();
    let mut suggested_actions = Vec::new();
    for (action, entry) in &entries {
        for a in suggested_actions_for(
            &state,
            "cadavault",
            action,
            std::slice::from_ref(entry),
            host_id,
        )
        .await
        {
            if seen.insert(a.url.clone()) {
                suggested_actions.push(a);
            }
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

    let tpl = CadavaultPostureTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        control_plane: crate::control_plane::page_note(&state.hosts, host_id),
        score_percent: summary.percent,
        score_label: summary.label,
        score_badge_class: summary.badge_class,
        pass_count: summary.pass,
        warn_count: summary.warn,
        fail_count: summary.fail,
        categories,
        suggested_actions,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_audit_reads_yes_as_true_and_hardened_values_as_false() {
        let stdout = "permitrootlogin without-password\npasswordauthentication yes\npermitemptypasswords no\nx11forwarding yes\n";
        let v = parse_sshd_audit(stdout);
        assert_eq!(v["permit_root_login"], serde_json::json!(false));
        assert_eq!(v["password_authentication"], serde_json::json!(true));
        assert_eq!(v["permit_empty_passwords"], serde_json::json!(false));
        assert_eq!(v["x11_forwarding"], serde_json::json!(true));
    }

    #[test]
    fn parse_audit_treats_missing_directive_as_false() {
        let v = parse_sshd_audit("permitrootlogin no\n");
        assert_eq!(v["password_authentication"], serde_json::json!(false));
    }

    #[test]
    fn password_auth_enabled_suggests_cryptkeeper_key_review() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "password_authentication": true });
        let targets: Vec<String> = registry
            .evaluate("cadavault", "sshd_config_audit", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"cryptkeeper".to_string()));
    }

    #[test]
    fn password_auth_disabled_suggests_nothing() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "password_authentication": false });
        assert!(
            registry
                .evaluate("cadavault", "sshd_config_audit", &entry)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn sysctl_rows_score_pass_fail_and_unavailable() {
        // rp_filter recommends "1"; accept_redirects recommends "0".
        let stdout = "net.ipv4.conf.all.rp_filter\t1\nnet.ipv4.conf.all.accept_redirects\t1\nnet.ipv6.conf.all.accept_redirects\tunavailable";
        let (rows, failing) = build_sysctl_rows(stdout);
        assert_eq!(rows.len(), SECURITY_SYSCTLS.len());
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
        assert_eq!(by_key("net.ipv4.conf.all.rp_filter").status_label, "pass");
        let redirects = by_key("net.ipv4.conf.all.accept_redirects");
        assert_eq!(redirects.status_label, "fail");
        assert!(redirects.needs_fix);
        assert_eq!(
            by_key("net.ipv6.conf.all.accept_redirects").status_label,
            "unavailable"
        );
        // A key the agent didn't report at all is also "unavailable", not a fix.
        assert_eq!(by_key("kernel.dmesg_restrict").status_label, "unavailable");
        // Only the one genuinely-wrong value counts as failing.
        assert_eq!(failing, 1);
    }

    #[test]
    fn every_baseline_key_has_a_recommended_lookup() {
        for entry in SECURITY_SYSCTLS {
            assert_eq!(recommended_sysctl(entry.key), Some(entry.recommended));
        }
        assert_eq!(recommended_sysctl("kernel.not_a_real_key"), None);
    }

    #[test]
    fn failing_sysctls_suggest_grimoire() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "failing_count": 3 });
        let targets: Vec<String> = registry
            .evaluate("cadavault", "sysctl_posture", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"grimoire".to_string()));
    }

    #[test]
    fn no_failing_sysctls_suggest_nothing() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "failing_count": 0 });
        assert!(
            registry
                .evaluate("cadavault", "sysctl_posture", &entry)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn parse_account_audit_reads_counts_and_ignores_unknowns() {
        let report = "Extra UID-0 accounts (besides root): 1\nEmpty-password accounts: unknown -- needs elevation to read this host's file\nSudoers NOPASSWD entries: 2\n\nPassword aging defaults (login.defs):\n  PASS_MAX_DAYS: 99999\n";
        let v = parse_account_audit(report);
        assert_eq!(v["extra_uid0_count"], serde_json::json!(1));
        // "unknown" must parse as 0, never a false positive.
        assert_eq!(v["empty_password_count"], serde_json::json!(0));
        assert_eq!(v["nopasswd_count"], serde_json::json!(2));
    }

    #[test]
    fn account_findings_suggest_parish() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let hit = serde_json::json!({ "extra_uid0_count": 1, "empty_password_count": 0 });
        let targets: Vec<String> = registry
            .evaluate("cadavault", "account_policy_audit", &hit)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"parish".to_string()));

        let clean = serde_json::json!({ "extra_uid0_count": 0, "empty_password_count": 0, "nopasswd_count": 0 });
        assert!(
            registry
                .evaluate("cadavault", "account_policy_audit", &clean)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn parse_mac_status_detects_present_and_enforcing() {
        let selinux = "MAC system: SELinux\nMAC enforcing: yes\ngetenforce: Enforcing";
        let v = parse_mac_status(selinux);
        assert_eq!(v["mac_present"], serde_json::json!(true));
        assert_eq!(v["mac_enforcing"], serde_json::json!(true));

        let none = "MAC system: none\nMAC enforcing: no";
        let v = parse_mac_status(none);
        assert_eq!(v["mac_present"], serde_json::json!(false));
    }

    #[test]
    fn non_enforcing_mac_suggests_grimoire_but_absent_mac_does_not() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let lax = serde_json::json!({ "mac_present": true, "mac_enforcing": false });
        let targets: Vec<String> = registry
            .evaluate("cadavault", "mac_status", &lax)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"grimoire".to_string()));

        // No MAC system at all: nothing to enforce, so no suggestion.
        let none = serde_json::json!({ "mac_present": false, "mac_enforcing": false });
        assert!(
            registry
                .evaluate("cadavault", "mac_status", &none)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn disabled_auto_updates_suggest_apothecary() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let disabled =
            parse_auto_updates("Package manager: apt\nAutomatic updates: disabled\n(...)");
        let targets: Vec<String> = registry
            .evaluate("cadavault", "automatic_updates_status", &disabled)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"apothecary".to_string()));

        // "unknown" (e.g. pacman) must not trigger a suggestion.
        let unknown =
            parse_auto_updates("Package manager: pacman\nAutomatic updates: unknown\n(...)");
        assert!(
            registry
                .evaluate("cadavault", "automatic_updates_status", &unknown)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn posture_report_scores_a_clean_host_well() {
        let firewall = Ok("Status: active".to_string());
        let sshd = Ok(
            "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nx11forwarding no"
                .to_string(),
        );
        // No failing sysctls.
        let sysctl = Ok(SECURITY_SYSCTLS
            .iter()
            .map(|s| format!("{}\t{}", s.key, s.recommended))
            .collect::<Vec<_>>()
            .join("\n"));
        let accounts = Ok(
            "Extra UID-0 accounts (besides root): 0\nEmpty-password accounts: 0\nSudoers NOPASSWD entries: 0"
                .to_string(),
        );
        let mac = Ok("MAC system: SELinux\nMAC enforcing: yes".to_string());
        let updates = Ok("Package manager: apt\nAutomatic updates: enabled".to_string());

        let (rows, _entries) =
            assemble_posture(&firewall, &sshd, &sysctl, &accounts, &mac, &updates);
        let score = score_posture(&rows);
        assert_eq!(score.percent, 100);
        assert_eq!(score.label, "Good");
        assert_eq!(score.fail, 0);
    }

    #[test]
    fn posture_report_flags_and_aggregates_suggestions_for_a_weak_host() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let firewall = Ok("Status: inactive".to_string());
        let sshd = Ok("permitrootlogin yes\npasswordauthentication yes".to_string());
        let sysctl = Ok("net.ipv4.conf.all.rp_filter\t0".to_string()); // many missing -> unavailable, one fail
        let accounts = Ok(
            "Extra UID-0 accounts (besides root): 1\nEmpty-password accounts: 0\nSudoers NOPASSWD entries: 0"
                .to_string(),
        );
        let mac = Ok("MAC system: none\nMAC enforcing: no".to_string());
        let updates = Ok("Package manager: apt\nAutomatic updates: disabled".to_string());

        let (rows, entries) =
            assemble_posture(&firewall, &sshd, &sysctl, &accounts, &mac, &updates);
        let score = score_posture(&rows);
        assert!(score.fail >= 2, "firewall+ssh+accounts should fail");

        // Aggregating each entry's own registry matches should surface the
        // downstream arsenals from several different sub-checks.
        let mut targets = std::collections::HashSet::new();
        for (action, entry) in &entries {
            for m in registry.evaluate("cadavault", action, entry).matches {
                targets.insert(m.target_arsenal);
            }
        }
        assert!(targets.contains("cryptkeeper")); // password auth on
        assert!(targets.contains("parish")); // extra uid-0
        assert!(targets.contains("apothecary")); // updates disabled
    }

    #[test]
    fn posture_report_excludes_unavailable_from_the_score() {
        let unavailable = Err("host offline".to_string());
        let good_ssh = Ok(
            "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nx11forwarding no"
                .to_string(),
        );
        let (rows, _) = assemble_posture(
            &unavailable,
            &good_ssh,
            &unavailable,
            &unavailable,
            &unavailable,
            &unavailable,
        );
        let score = score_posture(&rows);
        // Only SSH is applicable and it passes -> 100%, everything else excluded.
        assert_eq!(score.percent, 100);
        assert_eq!(score.pass, 1);
    }

    #[test]
    fn failed_logins_now_also_suggest_hardening_with_cadavault() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "failed_login_count": 5 });
        let targets: Vec<String> = registry
            .evaluate("postmortem", "failed_login_attempts", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"cadavault".to_string()));
    }
}
