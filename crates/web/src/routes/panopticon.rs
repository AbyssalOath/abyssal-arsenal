use std::collections::HashMap;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationParams;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::common::{require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::panopticon_ops::DiscoveryScanOperation;
use crate::state::AppState;
use crate::templates::{BaseCtx, NetworkDeviceRow, PanopticonTemplate, SubnetGroup};
use crate::theme;

/// Groups a device's IPv4 address into its /24 -- the common case for a
/// LAN -- or `"other"` for anything this simple heuristic can't parse
/// (IPv6, malformed data). See `SubnetGroup`'s doc comment for why this
/// isn't real L2 topology.
fn subnet_of(ip: &str) -> String {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
    } else {
        "other".to_string()
    }
}

async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
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

    let hosts = repo::hosts::list(&state.pool).await?;
    let mut managed_by_ip: HashMap<String, String> = HashMap::new();
    for host in &hosts {
        if host.is_active() {
            if let Some(ip) = &host.last_seen_ip {
                managed_by_ip.insert(ip.clone(), host.name.clone());
            }
        }
    }

    let devices = repo::network_devices::list(&state.pool).await?;

    let mut subnet_counts: Vec<(String, usize, usize)> = Vec::new();
    for device in &devices {
        let subnet = subnet_of(&device.ip_address);
        let managed = managed_by_ip.contains_key(&device.ip_address);
        match subnet_counts.iter_mut().find(|(s, _, _)| *s == subnet) {
            Some((_, count, managed_count)) => {
                *count += 1;
                if managed {
                    *managed_count += 1;
                }
            }
            None => subnet_counts.push((subnet, 1, if managed { 1 } else { 0 })),
        }
    }
    subnet_counts.sort_by(|a, b| a.0.cmp(&b.0));
    let subnets = subnet_counts
        .into_iter()
        .map(|(subnet, device_count, managed_count)| SubnetGroup {
            subnet,
            device_count,
            managed_count,
        })
        .collect();

    let device_rows = devices
        .into_iter()
        .map(|d| NetworkDeviceRow {
            id: d.id.to_string(),
            managed_host_name: managed_by_ip.get(&d.ip_address).cloned(),
            ip_address: d.ip_address,
            mac_address: d.mac_address,
            hostname: d.hostname,
            open_ports: d.open_ports,
            first_seen_at: crate::common::format_in_tz(d.first_seen_at, &ctx.user.timezone),
            last_seen_at: crate::common::format_in_tz(d.last_seen_at, &ctx.user.timezone),
        })
        .collect();

    let tpl = PanopticonTemplate {
        can_scan: ctx.has(Permission::NetworkScan),
        can_manage: ctx.has(Permission::NetworkManage),
        base,
        devices: device_rows,
        subnets,
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
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    render(&state, &jar, &ctx, None, None, None).await
}

// ---------------------------------------------------------------------
// Discovery scan
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ScanQuery {
    target: String,
    #[serde(default)]
    ports: Option<String>,
}

fn validate_scan_query(q: &ScanQuery) -> Result<(String, Option<String>), WebError> {
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
                "That doesn't look like a valid port spec (digits, commas, and hyphens only, \
                 e.g. 22,80,443 or 1-1024)."
                    .into(),
            )));
        }
    }
    Ok((target, ports.map(str::to_string)))
}

pub async fn scan_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<ScanQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;
    let (target, ports) = validate_scan_query(&q)?;

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

    let mut action_url = format!(
        "/arsenals/panopticon/scan?target={}",
        urlencoding_encode(&target)
    );
    if let Some(p) = &ports {
        action_url.push_str(&format!("&ports={}", urlencoding_encode(p)));
    }

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Run discovery scan".to_string(),
        message: format!(
            "This will run an nmap TCP connect scan from the control plane against \"{target}\"{}. \
             This sends real network traffic to that target and may trigger intrusion detection \
             there or in between -- only scan targets you're authorized to scan. Discovered \
             devices are added to the inventory below.",
            match &ports {
                Some(p) => format!(" (ports: {p})"),
                None => String::new(),
            }
        ),
        action_url,
        cancel_url: "/arsenals/panopticon".to_string(),
        escalate_host_id: None,
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
pub struct ScanForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn scan(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<ScanQuery>,
    Form(form): Form<ScanForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "The scan was not confirmed.".into(),
        )));
    }
    let (target, ports) = validate_scan_query(&q)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &target)?;

    let result_label = Some(format!("Discovery Scan ({target})"));
    let op = DiscoveryScanOperation {
        pool: state.pool.clone(),
        target,
        ports,
    };
    let result = state
        .executor
        .execute(
            &ctx,
            &op,
            OperationParams {
                confirm: true,
                ..Default::default()
            },
            CancellationToken::new(),
            None,
        )
        .await;

    match result {
        Ok(output) => render(&state, &jar, &ctx, result_label, Some(output.stdout), None).await,
        Err(e) => render(&state, &jar, &ctx, result_label, None, Some(e.to_string())).await,
    }
}

// ---------------------------------------------------------------------
// Remove device from inventory
// ---------------------------------------------------------------------

pub async fn remove_device_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;

    let device = repo::network_devices::find_by_id(&state.pool, id)
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
        title: "Remove device from inventory".to_string(),
        message: format!(
            "This will remove \"{}\" from the network device inventory. It reappears if a \
             future scan finds it again -- this doesn't block or affect the device itself.",
            device.ip_address
        ),
        action_url: format!("/arsenals/panopticon/devices/{id}/remove"),
        cancel_url: "/arsenals/panopticon".to_string(),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "IP address".to_string(),
            expected: device.ip_address.clone(),
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
pub struct RemoveDeviceForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn remove_device(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<RemoveDeviceForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let device = repo::network_devices::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &device.ip_address)?;

    repo::network_devices::delete(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkDeviceRemoved, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&device.ip_address),
    )
    .await?;

    Ok(Redirect::to("/arsenals/panopticon").into_response())
}
