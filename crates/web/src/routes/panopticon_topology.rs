//! Panopticon's Topology page (switch neighbors from LLDP / CDP) and DHCP
//! lease import -- see `crate::panopticon_topology` and
//! `crate::panopticon_dhcp`.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, DhcpHostOption, PanopticonDhcpTemplate, PanopticonTopologyTemplate, TopologyLink,
    TopologySwitch,
};
use crate::theme;

/// What a neighbor is, as far as Panopticon knows: one of the managed
/// switches (by management address or name), or an inventory device (by
/// address).
fn identify(
    neighbor: &repo::panopticon_topology::Neighbor,
    switches: &[abyssal_core::PanopticonSwitch],
    devices_by_ip: &HashMap<String, abyssal_core::NetworkDevice>,
) -> (Option<String>, String) {
    let short = |name: &str| {
        name.split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    if let Some(sw) = switches.iter().find(|sw| {
        neighbor.remote_address.as_deref() == Some(sw.ip_address.as_str())
            || (!neighbor.remote_name.is_empty() && short(&neighbor.remote_name) == short(&sw.name))
    }) {
        return (
            Some(sw.id.to_string()),
            format!("Managed switch: {}", sw.name),
        );
    }
    if let Some(device) = neighbor
        .remote_address
        .as_deref()
        .and_then(|ip| devices_by_ip.get(ip))
    {
        let name = device
            .hostname
            .clone()
            .unwrap_or_else(|| device.ip_address.clone());
        let vendor = device
            .vendor()
            .map(|v| format!(" ({v})"))
            .unwrap_or_default();
        return (None, format!("In inventory: {name}{vendor}"));
    }
    (None, String::new())
}

pub async fn topology(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    let switches = repo::panopticon_switches::list(&state.pool).await?;
    let neighbors = repo::panopticon_topology::list_neighbors(&state.pool).await?;
    let devices_by_ip: HashMap<String, abyssal_core::NetworkDevice> =
        repo::network_devices::list(&state.pool)
            .await?
            .into_iter()
            .map(|d| (d.ip_address.clone(), d))
            .collect();

    let names: HashMap<String, String> = switches
        .iter()
        .map(|s| (s.id.to_string(), s.name.clone()))
        .collect();
    let mut by_switch: HashMap<String, Vec<TopologyLink>> = HashMap::new();
    // Switch-to-switch links, each pair once.
    let mut backbone: BTreeSet<(String, String)> = BTreeSet::new();
    for n in &neighbors {
        let (peer_switch, identity) = identify(n, &switches, &devices_by_ip);
        if let (Some(peer), Some(here)) = (&peer_switch, names.get(&n.switch_id))
            && let Some(there) = names.get(peer)
            && peer != &n.switch_id
        {
            let pair = if here <= there {
                (here.clone(), there.clone())
            } else {
                (there.clone(), here.clone())
            };
            backbone.insert(pair);
        }
        by_switch
            .entry(n.switch_id.clone())
            .or_default()
            .push(TopologyLink {
                local_port: n.local_port.clone(),
                protocol: n.protocol.to_ascii_uppercase(),
                remote_name: if n.remote_name.is_empty() {
                    n.chassis_id.clone()
                } else {
                    n.remote_name.clone()
                },
                remote_port: n.remote_port.clone(),
                remote_address: n.remote_address.clone().unwrap_or_default(),
                remote_platform: n.remote_platform.chars().take(120).collect(),
                identity,
                seen_at: crate::common::format_in_tz(n.seen_at(), &ctx.user.timezone),
            });
    }
    let topo_switches = switches
        .iter()
        .map(|s| TopologySwitch {
            name: s.name.clone(),
            ip_address: s.ip_address.clone(),
            links: by_switch.remove(&s.id.to_string()).unwrap_or_default(),
        })
        .collect();

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
    let tpl = PanopticonTopologyTemplate {
        base,
        switches: topo_switches,
        backbone: backbone.into_iter().collect(),
        neighbor_count: neighbors.len(),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

async fn render_dhcp(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    result: Option<String>,
    error: Option<String>,
) -> Result<Response, WebError> {
    let probe = AgentOperation::DhcpLeases;
    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.supports(host.id, &probe) {
            hosts.push(DhcpHostOption {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }
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
    let tpl = PanopticonDhcpTemplate {
        base,
        can_manage: ctx.has(Permission::NetworkManage),
        hosts,
        lease_count: repo::panopticon_topology::lease_count(&state.pool).await?,
        result,
        error,
    };
    let jar = match new_cookie {
        Some(c) => jar.clone().add(c),
        None => jar.clone(),
    };
    Ok((jar, tpl).into_response())
}

pub async fn dhcp(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    render_dhcp(&state, &jar, &ctx, None, None).await
}

fn describe(summary: &crate::panopticon_dhcp::ImportSummary, source: &str) -> String {
    format!(
        "Imported {} current lease(s) from {source} ({} format), {} with a hostname; filled in {} \
         inventory device(s). Later scans use these names too.",
        summary.current,
        summary.format.label(),
        summary.with_hostname,
        summary.devices_updated
    )
}

async fn audit_import(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
    source: &str,
    outcome: AuditOutcome,
    detail: serde_json::Value,
) {
    let event = AuditEvent::new(AuditAction::NetworkDhcpLeasesImported, outcome)
        .actor(Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource(source)
        .metadata(detail);
    if let Err(e) = abyssal_audit::record(&state.pool, event).await {
        tracing::error!(error = %e, "failed to record a DHCP lease import");
    }
}

#[derive(Deserialize)]
pub struct PasteForm {
    csrf_token: String,
    leases: String,
}

pub async fn dhcp_import(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PasteForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let source = "a pasted lease file";
    match crate::panopticon_dhcp::import(&state.pool, source, &form.leases).await {
        Ok(summary) => {
            audit_import(
                &state,
                &ctx,
                source,
                AuditOutcome::Success,
                serde_json::json!({ "leases": summary.current, "devices_updated": summary.devices_updated }),
            )
            .await;
            render_dhcp(&state, &jar, &ctx, Some(describe(&summary, source)), None).await
        }
        Err(e) => render_dhcp(&state, &jar, &ctx, None, Some(e)).await,
    }
}

#[derive(Deserialize)]
pub struct HostForm {
    csrf_token: String,
    host_id: Uuid,
}

pub async fn dhcp_import_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<HostForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let host = repo::hosts::find_by_id(&state.pool, form.host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host.id,
            &host.name,
            AgentOperation::DhcpLeases,
            Permission::NetworkManage,
            OperationKind::Read,
            false,
            Duration::from_secs(60),
            None,
            state.elevation.is_elevated(host.id),
        )
        .await;
    let text = match result {
        Ok(output) => output.stdout,
        Err(e) => {
            return render_dhcp(
                &state,
                &jar,
                &ctx,
                None,
                Some(format!("Couldn't read {}'s leases: {e}", host.name)),
            )
            .await;
        }
    };
    // The agent's first line says which server or file it read.
    let source = text
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("# abyssal-dhcp-source: "))
        .map(|s| format!("{} ({s})", host.name))
        .unwrap_or_else(|| host.name.clone());
    match crate::panopticon_dhcp::import(&state.pool, &source, &text).await {
        Ok(summary) => {
            audit_import(
                &state,
                &ctx,
                &source,
                AuditOutcome::Success,
                serde_json::json!({ "leases": summary.current, "devices_updated": summary.devices_updated }),
            )
            .await;
            render_dhcp(&state, &jar, &ctx, Some(describe(&summary, &source)), None).await
        }
        Err(e) => render_dhcp(&state, &jar, &ctx, None, Some(e)).await,
    }
}
