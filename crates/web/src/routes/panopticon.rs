use std::collections::HashMap;
use std::str::FromStr;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS, PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS,
    PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS, PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS,
    PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS, PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS,
};
use abyssal_core::{AppError, DeviceType, Permission, TrustState};
use abyssal_database::repo;
use abyssal_execution::OperationParams;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
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
use crate::templates::{
    BaseCtx, NetworkDeviceRow, PanopticonClassifyTemplate, PanopticonTemplate, SubnetGroup,
};
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
    port_filter: Option<u16>,
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
        if host.is_active()
            && let Some(ip) = &host.last_seen_ip
        {
            managed_by_ip.insert(ip.clone(), host.name.clone());
        }
    }

    let devices = repo::network_devices::list(&state.pool).await?;
    let switches = repo::panopticon_switches::list(&state.pool).await?;
    let switch_names: HashMap<Uuid, String> =
        switches.into_iter().map(|s| (s.id, s.name)).collect();

    // Topology counts reflect the whole inventory regardless of the port
    // filter below -- that filter narrows the device table, not the
    // subnet overview.
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
        .filter(|d| match port_filter {
            Some(port) => d.ports.iter().any(|p| p.port == port),
            None => true,
        })
        .map(|d| {
            let stale = d.is_stale();
            let vendor = d.vendor().map(str::to_string);
            let open_ports = if d.ports.is_empty() {
                None
            } else {
                Some(
                    d.ports
                        .iter()
                        .map(|p| match &p.service {
                            Some(svc) => format!("{}/{} {}", p.port, p.protocol, svc),
                            None => format!("{}/{}", p.port, p.protocol),
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            };
            let switch_location = d
                .switch_id
                .and_then(|id| switch_names.get(&id))
                .map(|name| match &d.switch_port {
                    Some(port) => format!("{name} / {port}"),
                    None => name.clone(),
                });
            NetworkDeviceRow {
                id: d.id.to_string(),
                managed_host_name: managed_by_ip.get(&d.ip_address).cloned(),
                ip_address: d.ip_address,
                mac_address: d.mac_address,
                vendor,
                hostname: d.hostname,
                open_ports,
                device_type_label: d.device_type.label().to_string(),
                device_type_value: d.device_type.as_str().to_string(),
                trust_label: d.trust_state.label().to_string(),
                trust_value: d.trust_state.as_str().to_string(),
                notes: d.notes,
                first_seen_at: crate::common::format_in_tz(d.first_seen_at, &ctx.user.timezone),
                last_seen_at: crate::common::format_in_tz(d.last_seen_at, &ctx.user.timezone),
                stale,
                switch_location,
            }
        })
        .collect();

    let tpl = PanopticonTemplate {
        can_scan: ctx.has(Permission::NetworkScan),
        can_manage: ctx.has(Permission::NetworkManage),
        base,
        devices: device_rows,
        subnets,
        port_filter: port_filter.map(|p| p.to_string()).unwrap_or_default(),
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

#[derive(Deserialize)]
pub struct ShowQuery {
    #[serde(default)]
    port: Option<String>,
}

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<ShowQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    let port_filter = q.port.as_deref().and_then(|p| p.trim().parse::<u16>().ok());
    render(&state, &jar, &ctx, port_filter, None, None, None).await
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
    if let Some(p) = ports
        && !abyssal_agent_protocol::is_valid_port_spec(p)
    {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid port spec (digits, commas, and hyphens only, \
                 e.g. 22,80,443 or 1-1024)."
                .into(),
        )));
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
        Ok(output) => {
            render(
                &state,
                &jar,
                &ctx,
                None,
                result_label,
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
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
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

// ---------------------------------------------------------------------
// Device classification (device type / trust state / notes)
// ---------------------------------------------------------------------

pub async fn classify_form(
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

    let tpl = PanopticonClassifyTemplate {
        base,
        device_id: id.to_string(),
        ip_address: device.ip_address,
        device_types: DeviceType::ALL
            .iter()
            .map(|t| (t.as_str(), t.label(), *t == device.device_type))
            .collect(),
        trust_states: TrustState::ALL
            .iter()
            .map(|t| (t.as_str(), t.label(), *t == device.trust_state))
            .collect(),
        notes: device.notes.unwrap_or_default(),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ClassifyForm {
    csrf_token: String,
    device_type: String,
    trust_state: String,
    #[serde(default)]
    notes: String,
}

pub async fn classify_device(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ClassifyForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let device_type = DeviceType::from_str(&form.device_type)
        .map_err(|()| WebError(AppError::Validation("Not a recognized device type.".into())))?;
    let trust_state = TrustState::from_str(&form.trust_state)
        .map_err(|()| WebError(AppError::Validation("Not a recognized trust state.".into())))?;
    let notes = form.notes.trim();
    let notes = if notes.is_empty() { None } else { Some(notes) };

    let device = repo::network_devices::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    repo::network_devices::classify(&state.pool, id, device_type, trust_state, notes).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkDeviceClassified, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&device.ip_address),
    )
    .await?;

    Ok(Redirect::to("/arsenals/panopticon").into_response())
}

// ---------------------------------------------------------------------
// Managed switches (SNMP polling)
// ---------------------------------------------------------------------

async fn render_switches(
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

    let switches = repo::panopticon_switches::list(&state.pool).await?;
    let switch_rows = switches
        .into_iter()
        .map(|s| crate::templates::PanopticonSwitchRow {
            id: s.id.to_string(),
            name: s.name,
            ip_address: s.ip_address,
            snmp_port: s.snmp_port,
            enabled: s.enabled,
            last_polled_at: s
                .last_polled_at
                .map(|t| crate::common::format_in_tz(t, &ctx.user.timezone)),
            last_poll_error: s.last_poll_error,
        })
        .collect();

    let tpl = crate::templates::PanopticonSwitchesTemplate {
        can_manage: ctx.has(Permission::NetworkManage),
        can_scan: ctx.has(Permission::NetworkScan),
        base,
        switches: switch_rows,
        encryption_configured: state.encryption_key.is_some(),
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

pub async fn switches_show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    render_switches(&state, &jar, &ctx, None, None, None).await
}

#[derive(Deserialize)]
pub struct SwitchAddForm {
    csrf_token: String,
    name: String,
    ip_address: String,
    #[serde(default)]
    snmp_port: String,
    community: String,
}

pub async fn switch_add(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SwitchAddForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let Some(encryption_key) = &state.encryption_key else {
        return Err(WebError(AppError::Validation(
            "Set ENCRYPTION_KEY in the environment before adding a switch -- its SNMP \
             community string can't be stored safely without it."
                .into(),
        )));
    };

    let name = form.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(WebError(AppError::Validation(
            "Switch name must be 1-128 characters.".into(),
        )));
    }
    let ip_address = form.ip_address.trim();
    if !abyssal_agent_protocol::is_valid_network_target(ip_address) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid IP address or hostname.".into(),
        )));
    }
    let snmp_port_raw = form.snmp_port.trim();
    let snmp_port: u16 = if snmp_port_raw.is_empty() {
        161
    } else {
        snmp_port_raw
            .parse()
            .map_err(|_| WebError(AppError::Validation("SNMP port must be 1-65535.".into())))?
    };
    let community = form.community.trim();
    if community.is_empty() {
        return Err(WebError(AppError::Validation(
            "Community string is required.".into(),
        )));
    }

    let community_encrypted = encryption_key
        .encrypt(community)
        .map_err(|e| WebError(AppError::Validation(format!("Encryption failed: {e}"))))?;

    repo::panopticon_switches::create(
        &state.pool,
        name,
        ip_address,
        snmp_port,
        &community_encrypted,
        true,
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkSwitchAdded, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(name),
    )
    .await?;

    Ok(Redirect::to("/arsenals/panopticon/switches").into_response())
}

#[derive(Deserialize)]
pub struct SwitchEnabledForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn switch_set_enabled(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SwitchEnabledForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::panopticon_switches::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    repo::panopticon_switches::set_enabled(&state.pool, id, form.enabled).await?;

    Ok(Redirect::to("/arsenals/panopticon/switches").into_response())
}

pub async fn switch_remove_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;

    let switch = repo::panopticon_switches::find_by_id(&state.pool, id)
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
        title: "Remove switch".to_string(),
        message: format!(
            "This will remove \"{}\" and its stored (encrypted) community string. Devices \
             this switch previously located keep their last-known port label until the next \
             poll of a switch that still knows about them.",
            switch.name
        ),
        action_url: format!("/arsenals/panopticon/switches/{id}/remove"),
        cancel_url: "/arsenals/panopticon/switches".to_string(),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "switch name".to_string(),
            expected: switch.name.clone(),
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
pub struct SwitchRemoveForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn switch_remove(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SwitchRemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let switch = repo::panopticon_switches::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &switch.name)?;

    repo::panopticon_switches::delete(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkSwitchRemoved, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&switch.name),
    )
    .await?;

    Ok(Redirect::to("/arsenals/panopticon/switches").into_response())
}

#[derive(Deserialize)]
pub struct SwitchPollForm {
    csrf_token: String,
}

pub async fn switch_poll_now(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SwitchPollForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkScan)?;
    require_csrf(&jar, &form.csrf_token)?;

    let switch = repo::panopticon_switches::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let Some(encryption_key) = state.encryption_key.clone() else {
        return Err(WebError(AppError::Validation(
            "ENCRYPTION_KEY isn't configured -- this switch's community string can't be \
             decrypted."
                .into(),
        )));
    };

    let result_label = Some(format!("SNMP Poll ({})", switch.name));
    let op = crate::panopticon_snmp::SnmpPollOperation {
        pool: state.pool.clone(),
        switch,
        encryption_key,
    };
    let result = state
        .executor
        .execute(
            &ctx,
            &op,
            OperationParams::default(),
            CancellationToken::new(),
            None,
        )
        .await;

    match result {
        Ok(output) => {
            render_switches(&state, &jar, &ctx, result_label, Some(output.stdout), None).await
        }
        Err(e) => {
            render_switches(&state, &jar, &ctx, result_label, None, Some(e.to_string())).await
        }
    }
}

// ---------------------------------------------------------------------
// Switch bandwidth (Phase 3)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SwitchTrafficQuery {
    port: Option<u32>,
    range: Option<String>,
}

pub async fn switch_traffic(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Query(q): Query<SwitchTrafficQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;

    let switch = repo::panopticon_switches::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let raw_days = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS,
    )
    .await?;
    let hourly_days = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS,
    )
    .await?;
    let daily_days = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS,
    )
    .await?;

    let ports = repo::panopticon_traffic::list_ports(&state.pool, id).await?;
    let mut port_rows = Vec::with_capacity(ports.len());
    for port in &ports {
        let latest =
            repo::panopticon_traffic::latest_raw_samples(&state.pool, id, port.if_index, 2).await?;
        let rate = crate::panopticon_traffic::rates_from_raw(&latest);
        let (current_in, current_out) = match rate.last() {
            Some(p) => (
                crate::panopticon_traffic::format_bps(p.avg_in_bps),
                crate::panopticon_traffic::format_bps(p.avg_out_bps),
            ),
            None => ("—".to_string(), "—".to_string()),
        };
        port_rows.push(crate::templates::PanopticonPortRow {
            if_index: port.if_index,
            label: port
                .if_descr
                .clone()
                .unwrap_or_else(|| format!("if{}", port.if_index)),
            last_seen_at: crate::common::format_in_tz(port.last_seen_at, &ctx.user.timezone),
            current_in,
            current_out,
        });
    }

    let available = crate::panopticon_traffic::available_ranges(raw_days, hourly_days, daily_days);
    let selected_range = q
        .range
        .as_deref()
        .and_then(crate::panopticon_traffic::TrafficRange::from_str)
        .filter(|r| available.contains(r))
        .unwrap_or(crate::panopticon_traffic::TrafficRange::Hours24);
    let ranges = available
        .iter()
        .map(|r| {
            (
                r.as_str().to_string(),
                r.label().to_string(),
                *r == selected_range,
            )
        })
        .collect();

    let mut chart_svg = None;
    let mut chart_port_label = None;
    let mut chart_current_in = None;
    let mut chart_current_out = None;
    if let Some(if_index) = q.port {
        let points = crate::panopticon_traffic::points_for_range(
            &state.pool,
            id,
            if_index,
            selected_range,
            raw_days,
            hourly_days,
            daily_days,
        )
        .await?;
        chart_svg = crate::panopticon_traffic::render_chart_svg(&points);
        chart_port_label = port_rows
            .iter()
            .find(|p| p.if_index == if_index)
            .map(|p| p.label.clone());
        if let Some(last) = points.last() {
            chart_current_in = Some(crate::panopticon_traffic::format_bps(last.avg_in_bps));
            chart_current_out = Some(crate::panopticon_traffic::format_bps(last.avg_out_bps));
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

    let tpl = crate::templates::PanopticonSwitchTrafficTemplate {
        base,
        switch_id: switch.id.to_string(),
        switch_name: switch.name,
        ports: port_rows,
        selected_port: q.port,
        selected_range: selected_range.as_str().to_string(),
        ranges,
        chart_svg,
        chart_port_label,
        chart_current_in,
        chart_current_out,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}
