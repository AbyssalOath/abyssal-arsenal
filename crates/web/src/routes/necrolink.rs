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

use crate::common::{maybe_elevate, require_csrf};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, NecrolinkHostRow, NecrolinkHostTemplate, NecrolinkTemplate};
use crate::theme;

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(NecrolinkHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = NecrolinkTemplate { base, hosts };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[allow(clippy::too_many_arguments)]
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

    let tpl = NecrolinkHostTemplate {
        can_manage: ctx.has(Permission::NetworkManage),
        can_scan: ctx.has(Permission::NetworkScan),
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
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
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
            Permission::NetworkView,
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

pub async fn network_interfaces(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::NetworkInterfaces,
        "Network Interfaces",
        form.sudo_password,
    )
    .await
}

pub async fn network_routes(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::NetworkRoutes,
        "Routes",
        form.sudo_password,
    )
    .await
}

pub async fn dns_config(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::DnsConfig,
        "DNS Configuration",
        form.sudo_password,
    )
    .await
}

pub async fn active_connections(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ActiveConnections,
        "Active Connections",
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct ConnectivityCheckForm {
    csrf_token: String,
    target: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn connectivity_check(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConnectivityCheckForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    require_csrf(&jar, &form.csrf_token)?;

    let target = form.target.trim().to_string();
    if !abyssal_agent_protocol::is_valid_network_target(&target) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid IP address or hostname.".into(),
        )));
    }

    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ConnectivityCheck {
            target: target.clone(),
        },
        &format!("Connectivity Check ({target})"),
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct InterfaceUpForm {
    csrf_token: String,
    interface: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn interface_up(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<InterfaceUpForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let interface = form.interface.trim().to_string();
    if !abyssal_agent_protocol::is_valid_interface_name(&interface) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid interface name.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Interface Up ({interface}) -- {}", host.name));

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
            AgentOperation::InterfaceSetState {
                interface,
                up: true,
            },
            Permission::NetworkManage,
            OperationKind::Write,
            false,
            Duration::from_secs(10),
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
pub struct InterfaceDownQuery {
    interface: String,
}

pub async fn interface_down_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<InterfaceDownQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;

    let interface = q.interface.trim().to_string();
    if !abyssal_agent_protocol::is_valid_interface_name(&interface) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid interface name.".into(),
        )));
    }

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
        title: "Bring interface down".to_string(),
        message: format!(
            "This will bring \"{interface}\" down on \"{}\". If that's the interface currently \
             used to reach this host, it can cut off remote access.",
            host.name
        ),
        action_url: format!(
            "/arsenals/necrolink/{host_id}/interface/down?interface={}",
            urlencoding_encode(&interface)
        ),
        cancel_url: format!("/arsenals/necrolink/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "interface name".to_string(),
            expected: interface.clone(),
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
pub struct InterfaceDownForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn interface_down(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<InterfaceDownQuery>,
    Form(form): Form<InterfaceDownForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Bringing the interface down was not confirmed.".into(),
        )));
    }

    let interface = q.interface.trim().to_string();
    if !abyssal_agent_protocol::is_valid_interface_name(&interface) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid interface name.".into(),
        )));
    }
    crate::common::require_typed_confirmation(&form.confirm_text, &interface)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Interface Down ({interface}) -- {}", host.name));

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
            AgentOperation::InterfaceSetState {
                interface,
                up: false,
            },
            Permission::NetworkManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(10),
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
pub struct ScanQuery {
    target: String,
    #[serde(default)]
    ports: Option<String>,
}

pub async fn scan_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<ScanQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;

    let target = q.target.trim().to_string();
    if !abyssal_agent_protocol::is_valid_network_target(&target) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid IP address, CIDR range, or hostname.".into(),
        )));
    }
    let ports = q.ports.as_deref().map(str::trim).filter(|p| !p.is_empty());
    if let Some(p) = ports {
        if !abyssal_agent_protocol::is_valid_port_spec(p) {
            return Err(WebError(AppError::Validation(
                "That doesn't look like a valid port spec (digits, commas, and hyphens only, e.g. 22,80,443 or 1-1024).".into(),
            )));
        }
    }

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

    let mut action_url = format!(
        "/arsenals/necrolink/{host_id}/scan?target={}",
        urlencoding_encode(&target)
    );
    if let Some(p) = ports {
        action_url.push_str(&format!("&ports={}", urlencoding_encode(p)));
    }

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Scan network target".to_string(),
        message: format!(
            "This will run an nmap TCP connect scan from \"{}\" against \"{target}\"{}. This \
             sends real network traffic to that target and may trigger intrusion detection \
             there or in between -- only scan targets you're authorized to scan.",
            host.name,
            match ports {
                Some(p) => format!(" (ports: {p})"),
                None => String::new(),
            }
        ),
        action_url,
        cancel_url: format!("/arsenals/necrolink/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "scan target".to_string(),
            expected: target.clone(),
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
pub struct NetworkScanForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

pub async fn network_scan(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<ScanQuery>,
    Form(form): Form<NetworkScanForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "The scan was not confirmed.".into(),
        )));
    }

    let target = q.target.trim().to_string();
    if !abyssal_agent_protocol::is_valid_network_target(&target) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid IP address, CIDR range, or hostname.".into(),
        )));
    }
    let ports = q
        .ports
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    if let Some(p) = &ports {
        if !abyssal_agent_protocol::is_valid_port_spec(p) {
            return Err(WebError(AppError::Validation(
                "That doesn't look like a valid port spec.".into(),
            )));
        }
    }

    crate::common::require_typed_confirmation(&form.confirm_text, &target)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Network Scan ({target}) -- {}", host.name));

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
            AgentOperation::NetworkScan { target, ports },
            Permission::NetworkScan,
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

/// Minimal, dependency-free percent-encoding for the handful of characters
/// that can plausibly show up in an interface name, IP/CIDR, hostname, or
/// port spec and would otherwise break a query string (this crate doesn't
/// already depend on a URL-encoding crate for anything else).
fn urlencoding_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
