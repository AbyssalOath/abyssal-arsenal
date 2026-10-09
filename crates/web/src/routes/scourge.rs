//! Scourge web routes (phase 2: read-only foundation). A host-agent arsenal:
//! the landing page is a host picker, each host gets `/arsenals/scourge/:host_id`
//! with on-demand read actions (sensor status, rule listing, pcap listing) that
//! dispatch to the agent via `Executor::execute_on_host` -- the same shape
//! Inquest's read page uses. The live-updating alert views and dashboard tile
//! (which read the control-plane cache) arrive in phase 3 with that cache; a
//! page/fragment must never dispatch to an agent on render.

use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, RawQuery, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::dashboard_prefs;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::pagination;
use crate::scourge_ops::{ScourgeCaptureJob, ScourgeCaptureState};
use crate::state::AppState;
use crate::templates::{
    BaseCtx, ConfirmTemplate, ScourgeAlertRow, ScourgeAlertsFragment, ScourgeAlertsTemplate,
    ScourgeAlertsView, ScourgeCaptureTemplate, ScourgeHostGroup, ScourgeHostTemplate,
    ScourgeTemplate, SummaryTile, TypeToConfirm,
};
use crate::theme;
use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    SCOURGE_CAPTURE_ENABLED, SCOURGE_CONFIG_CHANGES_ENABLED, SCOURGE_IPS_ENABLED,
    SCOURGE_PCAP_MAX_TOTAL_MB, SCOURGE_PCAP_MAX_TOTAL_MB_DEFAULT, SCOURGE_PCAP_RETENTION_DAYS,
    SCOURGE_PCAP_RETENTION_DAYS_DEFAULT,
};
use abyssal_database::repo::scourge::AlertFilter;
use chrono::{Duration as ChronoDuration, Utc};

/// Same per-page group count as Inquest/Panopticon/Thanatos.
const GROUPS_PER_PAGE: u32 = 25;

/// What Scourge can and can't do on this host -- shown on the per-host page so a
/// non-Linux host doesn't look broken when every action returns "unsupported".
fn platform_note(os: Option<&str>) -> &'static str {
    match os {
        Some("linux") | None => {
            "Scourge runs a Suricata sensor on this host. Read actions (status, rules, pcaps) \
             work from file permissions where possible; the collection sweep needs read access \
             to the EVE log. Install/config/capture/IPS are Linux-only and arrive in later work."
        }
        _ => {
            "Scourge is Linux-only -- there is no sensor for this host's OS. Every action here \
              returns \"not supported on this platform.\""
        }
    }
}

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    RawQuery(raw): RawQuery,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeView)?;

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/scourge/{host_id}")).into_response());
    }

    let query = pagination::parse_group_list_query(raw.as_deref());
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

    let mut connected_hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            connected_hosts.push(host);
        }
    }

    let open_set: std::collections::HashSet<&str> = query.open.iter().map(String::as_str).collect();
    let group_total = connected_hosts.len() as u64;
    let group_page_requested = query.group_page.unwrap_or(1).max(1);
    let group_page_num = if pagination::Page::<()>::page_out_of_range(
        group_page_requested,
        GROUPS_PER_PAGE,
        group_total,
    ) {
        pagination::total_pages(group_total, GROUPS_PER_PAGE)
    } else {
        group_page_requested
    };
    let group_offset = pagination::offset(group_page_num, GROUPS_PER_PAGE) as usize;
    let group_page_meta: pagination::Page<()> =
        pagination::Page::new(vec![], group_page_num, GROUPS_PER_PAGE, group_total);
    let group_list_page = Some(pagination::numbered_page_info(&group_page_meta, |p| {
        query.with_group_page(p).href("/arsenals/scourge")
    }));

    let groups = connected_hosts
        .iter()
        .skip(group_offset)
        .take(GROUPS_PER_PAGE as usize)
        .map(|host| {
            let host_id_str = host.id.to_string();
            let is_open = open_set.contains(host_id_str.as_str());
            let open_href =
                (!is_open).then(|| query.with_open(&host_id_str).href("/arsenals/scourge"));
            ScourgeHostGroup {
                host_id: host_id_str,
                host_name: host.name.clone(),
                os_label: crate::common::os_label(host.os.as_deref()),
                is_open,
                open_href,
            }
        })
        .collect();

    let tpl = ScourgeTemplate {
        base,
        groups,
        group_list_page,
    };
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

    let config_changes_enabled =
        repo::settings::get_bool(&state.pool, SCOURGE_CONFIG_CHANGES_ENABLED, false).await?;
    let capture_enabled =
        repo::settings::get_bool(&state.pool, SCOURGE_CAPTURE_ENABLED, false).await?;
    let ips_enabled = repo::settings::get_bool(&state.pool, SCOURGE_IPS_ENABLED, false).await?;
    let tpl = ScourgeHostTemplate {
        can_manage: ctx.has(Permission::ScourgeManage),
        config_changes_enabled,
        capture_enabled,
        ips_enabled,
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        os_label: crate::common::os_label(host.os.as_deref()),
        platform_note: platform_note(host.os.as_deref()),
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
    Query(_query): Query<HashMap<String, String>>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct RuleSearchForm {
    csrf_token: String,
    #[serde(default)]
    query: String,
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
            Permission::ScourgeView,
            OperationKind::Read,
            false,
            Duration::from_secs(25),
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

pub async fn sensor_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeSensorStatus,
        "Sensor Status",
    )
    .await
}

pub async fn list_pcaps(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgePcapList,
        "Packet Captures",
    )
    .await
}

pub async fn list_rules(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RuleSearchForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeListRules {
            query: form.query.trim().to_string(),
        },
        "Rules",
    )
    .await
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
            let label = Some(format!("Elevation -- {}", host.name));
            let msg = format!(
                "Host elevated.{}",
                warning.map(|w| format!(" {w}")).unwrap_or_default()
            );
            render_host(&state, &jar, &ctx, host_id, label, Some(msg), None).await
        }
        Err(e) => {
            let label = Some(format!("Elevation -- {}", host.name));
            render_host(&state, &jar, &ctx, host_id, label, None, Some(e)).await
        }
    }
}

// ---------------------------------------------------------------------
// Alert inspection (phase 3): reads ONLY the control-plane cache, never
// dispatches to an agent. Full page + live htmx fragment share one view
// builder; the fragment carries the current filters and does the same
// permission check as the page.
// ---------------------------------------------------------------------

const ALERTS_PER_PAGE: u32 = 50;
const ALERTS_BASE_PATH: &str = "/arsenals/scourge/alerts";
const ALERTS_FRAGMENT_PATH: &str = "/arsenals/scourge/alerts/fragment";

#[derive(Deserialize, Default)]
pub struct AlertsQuery {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    src_ip: Option<String>,
    #[serde(default)]
    dst_ip: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    category: Option<String>,
    /// Relative range preset: `1h` | `24h` | `7d` | `all` (default `24h`).
    #[serde(default)]
    range: Option<String>,
    #[serde(default)]
    page: Option<u32>,
}

/// Trims an optional filter to `Some(non-empty)` or `None`.
fn clean(v: &Option<String>) -> Option<String> {
    v.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Maps a range preset to a `since` cutoff (`None` = all time).
fn range_since(range: &str) -> Option<chrono::DateTime<Utc>> {
    let now = Utc::now();
    match range {
        "1h" => Some(now - ChronoDuration::hours(1)),
        "7d" => Some(now - ChronoDuration::days(7)),
        "all" => None,
        // "24h" and anything unrecognized default to 24h.
        _ => Some(now - ChronoDuration::hours(24)),
    }
}

/// Builds the page/fragment URL carrying the current filters (+ page when > 1),
/// so a poll lands on exactly the same filtered view. Omits empty filters and
/// the default first page.
fn alerts_href(base: &str, q: &AlertsQuery, page: Option<u32>) -> String {
    let mut params: Vec<(&str, String)> = Vec::new();
    let mut push = |k: &'static str, v: &Option<String>| {
        if let Some(v) = clean(v) {
            params.push((k, v));
        }
    };
    push("host", &q.host);
    push("severity", &q.severity);
    push("signature", &q.signature);
    push("src_ip", &q.src_ip);
    push("dst_ip", &q.dst_ip);
    push("port", &q.port);
    push("proto", &q.proto);
    push("category", &q.category);
    push("range", &q.range);
    if let Some(p) = page
        && p > 1
    {
        params.push(("page", p.to_string()));
    }
    if params.is_empty() {
        base.to_string()
    } else {
        let qs = params
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencoding_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{base}?{qs}")
    }
}

async fn build_alerts_view(
    state: &AppState,
    ctx: &AuthContext,
    q: &AlertsQuery,
) -> Result<ScourgeAlertsView, WebError> {
    let range = clean(&q.range).unwrap_or_else(|| "24h".to_string());
    let host_id = clean(&q.host).and_then(|h| Uuid::parse_str(&h).ok());
    let filter = AlertFilter {
        host_id,
        severity: clean(&q.severity),
        signature: clean(&q.signature),
        src_ip: clean(&q.src_ip),
        dst_ip: clean(&q.dst_ip),
        port: clean(&q.port).and_then(|p| p.parse::<u32>().ok()),
        proto: clean(&q.proto),
        category: clean(&q.category),
        since: range_since(&range),
    };

    let total = repo::scourge::count_alerts(&state.pool, &filter).await?;
    let page_requested = q.page.unwrap_or(1).max(1);
    let total_u = total.max(0) as u64;
    let page_num =
        if pagination::Page::<()>::page_out_of_range(page_requested, ALERTS_PER_PAGE, total_u) {
            pagination::total_pages(total_u, ALERTS_PER_PAGE)
        } else {
            page_requested
        };
    let offset = pagination::offset(page_num, ALERTS_PER_PAGE) as u32;

    let rows = repo::scourge::list_alerts(&state.pool, &filter, ALERTS_PER_PAGE, offset).await?;

    // Resolve host names once.
    let hosts_all = repo::hosts::list(&state.pool).await?;
    let host_name = |id: Uuid| -> String {
        hosts_all
            .iter()
            .find(|h| h.id == id)
            .map(|h| h.name.clone())
            .unwrap_or_else(|| id.to_string())
    };
    let endpoint = |ip: &Option<String>, port: &Option<u32>| -> String {
        match (ip, port) {
            (Some(ip), Some(p)) => format!("{ip}:{p}"),
            (Some(ip), None) => ip.clone(),
            _ => "-".to_string(),
        }
    };
    // Build the display rows and, in the same pass, one structured result
    // per alert (grouped by host) for the workflow registry. Suggestions are
    // evaluated per host so each button links to the right host's arsenal
    // page; see `suggested_actions_for`.
    let mut alerts: Vec<ScourgeAlertRow> = Vec::with_capacity(rows.len());
    let mut by_host: std::collections::HashMap<Uuid, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for a in rows {
        let mut result = serde_json::json!({
            "severity": a.severity,
            "signature": a.signature,
        });
        if let Some(ip) = &a.src_ip {
            result["src_ip"] = serde_json::json!(ip);
        }
        if let Some(cat) = &a.category {
            result["category"] = serde_json::json!(cat);
        }
        by_host.entry(a.host_id).or_default().push(result);
        alerts.push(ScourgeAlertRow {
            host_name: host_name(a.host_id),
            occurred_at: crate::common::format_in_tz(a.occurred_at, &ctx.user.timezone),
            severity: a.severity,
            sid: a.sid.map(|s| s.to_string()).unwrap_or_default(),
            signature: a.signature,
            category: a.category.unwrap_or_default(),
            proto: a.proto.unwrap_or_default(),
            src: endpoint(&a.src_ip, &a.src_port),
            dst: endpoint(&a.dst_ip, &a.dst_port),
        });
    }

    // Resolve workflow suggestions per host, then dedup across the page
    // (several alerts from one host collapse to one "block the IP" button
    // only when they share the same source IP, so dedup on the final URL).
    let mut suggested_actions: Vec<crate::templates::SuggestedActionView> = Vec::new();
    for (hid, results) in &by_host {
        let mut views =
            crate::common::suggested_actions_for(state, "scourge", "alerts", results, *hid).await;
        suggested_actions.append(&mut views);
    }
    suggested_actions.sort_by(|a, b| a.url.cmp(&b.url).then(a.label.cmp(&b.label)));
    suggested_actions.dedup_by(|a, b| a.url == b.url && a.label == b.label);

    let severity_breakdown = repo::scourge::severity_breakdown(&state.pool, &filter).await?;
    let top_signatures = repo::scourge::top_signatures(&state.pool, &filter, 10).await?;
    let top_talkers = repo::scourge::top_talkers(&state.pool, &filter, 10).await?;

    // Tiles (aggregate across hosts, from the cache).
    let hour_ago = Utc::now() - ChronoDuration::hours(1);
    let alerts_1h = repo::scourge::count_since(&state.pool, None, hour_ago).await?;
    let high_1h = repo::scourge::count_since(&state.pool, Some("high"), hour_ago).await?
        + repo::scourge::count_since(&state.pool, Some("critical"), hour_ago).await?;
    let sensor_states = repo::scourge::list_sensor_state(&state.pool).await?;
    let readable = sensor_states.iter().filter(|s| s.eve_readable).count();
    let unreadable = repo::scourge::count_unreadable(&state.pool).await?;

    let tiles = vec![
        SummaryTile {
            label: "Alerts (1h)".to_string(),
            value: alerts_1h.to_string(),
            sub: "cached from sensors".to_string(),
            tone: if alerts_1h > 0 { "warn" } else { "ok" }.to_string(),
            icon: "alert",
            href: None,
        },
        SummaryTile {
            label: "High severity (1h)".to_string(),
            value: high_1h.to_string(),
            sub: "high + critical".to_string(),
            tone: if high_1h > 0 { "crit" } else { "ok" }.to_string(),
            icon: "shield",
            href: Some(format!("{ALERTS_BASE_PATH}?severity=high&range=1h")),
        },
        SummaryTile {
            label: "Sensors reporting".to_string(),
            value: format!("{readable}/{}", sensor_states.len()),
            sub: "EVE log readable".to_string(),
            tone: if unreadable > 0 { "warn" } else { "ok" }.to_string(),
            icon: "sensor",
            href: None,
        },
        SummaryTile {
            label: "Logs unreadable".to_string(),
            value: unreadable.to_string(),
            sub: "needs permissions".to_string(),
            tone: if unreadable > 0 { "warn" } else { "muted" }.to_string(),
            icon: "warning",
            href: None,
        },
    ];

    let page_meta: pagination::Page<()> =
        pagination::Page::new(vec![], page_num, ALERTS_PER_PAGE, total_u);
    let page = Some(pagination::numbered_page_info(&page_meta, |p| {
        alerts_href(ALERTS_BASE_PATH, q, Some(p))
    }));

    // Poll only the "latest" view: page 1 and a relative (not all-time) range.
    let live_eligible = page_num == 1 && range != "all";

    let hosts = hosts_all
        .iter()
        .map(|h| (h.id.to_string(), h.name.clone()))
        .collect();

    Ok(ScourgeAlertsView {
        tiles,
        severity_breakdown,
        top_signatures,
        top_talkers,
        alerts,
        suggested_actions,
        total,
        page,
        fragment_url: alerts_href(ALERTS_FRAGMENT_PATH, q, Some(page_num)),
        self_url: alerts_href(ALERTS_BASE_PATH, q, Some(page_num)),
        live_eligible,
        hosts,
        f_host: clean(&q.host).unwrap_or_default(),
        f_severity: clean(&q.severity).unwrap_or_default(),
        f_signature: clean(&q.signature).unwrap_or_default(),
        f_src_ip: clean(&q.src_ip).unwrap_or_default(),
        f_dst_ip: clean(&q.dst_ip).unwrap_or_default(),
        f_port: clean(&q.port).unwrap_or_default(),
        f_proto: clean(&q.proto).unwrap_or_default(),
        f_category: clean(&q.category).unwrap_or_default(),
        f_range: range,
    })
}

pub async fn alerts(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<AlertsQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeView)?;
    let view = build_alerts_view(&state, &ctx, &q).await?;

    let refresh_seconds = dashboard_prefs::refresh_seconds(&jar);
    let htmx_pref = dashboard_prefs::htmx_enabled(&jar);
    let live_htmx = htmx_pref && refresh_seconds > 0;

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
    let tpl = ScourgeAlertsTemplate {
        base,
        view,
        refresh_seconds,
        htmx_pref,
        live_htmx,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn alerts_fragment(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<AlertsQuery>,
) -> Result<Response, WebError> {
    // Same permission check as the full page -- a fragment URL is a new URL, not
    // a new permission boundary.
    abyssal_rbac::ensure(&ctx, Permission::ScourgeView)?;
    let view = build_alerts_view(&state, &ctx, &q).await?;
    Ok(ScourgeAlertsFragment { view }.into_response())
}

// ---------------------------------------------------------------------
// Mutating management (phase 4): install, config apply, service control,
// rule updates / SID toggle / suppression, and offline rule testing. Every
// mutating action has a dedicated confirm page (plain, except service-stop
// which is type-to-confirm) and requires `scourge.manage`. Config/ruleset
// changes are additionally gated by the `scourge.config_changes_enabled`
// second gate, re-checked fresh at BOTH the confirm GET and the dispatch POST.
// ---------------------------------------------------------------------

/// The packet-capture second gate (privacy-sensitive), re-checked at every entry
/// point. Rule testing reads captured pcap contents, so it sits behind this gate
/// too.
async fn ensure_capture_enabled(state: &AppState) -> Result<(), WebError> {
    let enabled = repo::settings::get_bool(&state.pool, SCOURGE_CAPTURE_ENABLED, false).await?;
    if !enabled {
        return Err(WebError(AppError::Validation(
            "Scourge packet capture is disabled. An admin must enable it on the Settings page \
             first."
                .into(),
        )));
    }
    Ok(())
}

/// The config/ruleset-change second gate, re-checked at every entry point.
async fn ensure_config_changes_enabled(state: &AppState) -> Result<(), WebError> {
    let enabled =
        repo::settings::get_bool(&state.pool, SCOURGE_CONFIG_CHANGES_ENABLED, false).await?;
    if !enabled {
        return Err(WebError(AppError::Validation(
            "Scourge configuration/ruleset changes are disabled. An admin must enable them on the \
             Settings page first."
                .into(),
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn render_confirm(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    title: &str,
    message: String,
    action_url: String,
    type_to_confirm: Option<TypeToConfirm>,
    extra_hidden_fields: Vec<(String, String)>,
    shred_option: Option<crate::templates::ShredOption>,
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
    // Offer inline elevation on the confirm page when the host isn't already
    // elevated (these ops need sudo on the agent) -- and only to someone who
    // may elevate, like every other arsenal's confirm page.
    let escalate_host_id = (base.can_hosts_elevate && !state.elevation.is_elevated(host_id))
        .then(|| host_id.to_string());
    let tpl = ConfirmTemplate {
        base,
        title: title.to_string(),
        message,
        action_url,
        cancel_url: format!("/arsenals/scourge/{host_id}"),
        escalate_host_id,
        type_to_confirm,
        extra_hidden_fields,
        shred_option,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Shared dispatch for a confirmed management op: elevate inline if a sudo
/// password was supplied, run the op (`scourge.manage`), record an optional
/// typed audit on success, and render the result.
#[allow(clippy::too_many_arguments)]
async fn run_managed(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    kind: OperationKind,
    sudo_password: Option<String>,
    audit: Option<(AuditAction, serde_json::Value)>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    if let Some(pw) = sudo_password.filter(|p| !p.trim().is_empty())
        && let Err(e) = maybe_elevate(state, ctx, host_id, &host.name, Some(pw)).await
    {
        return render_host(state, jar, ctx, host_id, result_label, None, Some(e)).await;
    }

    let elevated = state.elevation.is_elevated(host_id);
    let confirm = kind == OperationKind::Destructive;
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::ScourgeManage,
            kind,
            confirm,
            Duration::from_secs(120),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            if let Some((action, metadata)) = audit {
                let event = AuditEvent::new(action, AuditOutcome::Success)
                    .actor(abyssal_audit::Actor {
                        user_id: ctx.user.id,
                        username: &ctx.user.username,
                    })
                    .resource(&host.name)
                    .metadata(metadata);
                if let Err(e) = abyssal_audit::record(&state.pool, event).await {
                    tracing::error!(error = %e, "scourge: failed to record audit event");
                }
            }
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

/// The confirm POST form shared by the simple (plain-confirm) management
/// actions. Type-to-confirm actions (service stop) use their own form with a
/// `confirm_text` field.
#[derive(Deserialize)]
pub struct ManagedConfirmForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    sudo_password: String,
}

fn check_confirmed(form: &ManagedConfirmForm, jar: &CookieJar) -> Result<(), WebError> {
    require_csrf(jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Action was not confirmed.".into(),
        )));
    }
    Ok(())
}

// ---- Install --------------------------------------------------------

pub async fn install_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        "Install Suricata sensor",
        "This installs the Suricata IDS/IPS engine on this host via Apothecary's package \
         backend. It needs elevation (sudo)."
            .to_string(),
        format!("/arsenals/scourge/{host_id}/install"),
        None,
        vec![],
        None,
    )
    .await
}

pub async fn install(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ManagedConfirmForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    check_confirmed(&form, &jar)?;
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeInstall,
        "Install sensor",
        OperationKind::Write,
        Some(form.sudo_password),
        None,
    )
    .await
}

// ---- Service control ------------------------------------------------

#[derive(Deserialize)]
pub struct ServiceConfirmQuery {
    verb: String,
}

fn valid_service_verb(v: &str) -> bool {
    matches!(v, "start" | "stop" | "restart" | "reload")
}

pub async fn service_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<ServiceConfirmQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    if !valid_service_verb(&q.verb) {
        return Err(WebError(AppError::Validation(
            "Unknown service action.".into(),
        )));
    }
    // Stopping the sensor blinds detection on this host -- type-to-confirm.
    let (ttc, message) = if q.verb == "stop" {
        let host = repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .ok_or(AppError::NotFound)?;
        (
            Some(TypeToConfirm {
                label: "host name".to_string(),
                expected: host.name.clone(),
            }),
            format!(
                "Stopping the sensor leaves {} with NO network intrusion detection until it's \
                 started again. Type the host name to confirm.",
                host.name
            ),
        )
    } else {
        (
            None,
            format!("{} the Suricata sensor on this host.", title_verb(&q.verb)),
        )
    };
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        &format!("{} sensor", title_verb(&q.verb)),
        message,
        format!("/arsenals/scourge/{host_id}/service"),
        ttc,
        vec![("verb".to_string(), q.verb.clone())],
        None,
    )
    .await
}

fn title_verb(v: &str) -> &'static str {
    match v {
        "start" => "Start",
        "stop" => "Stop",
        "restart" => "Restart",
        _ => "Reload",
    }
}

#[derive(Deserialize)]
pub struct ServiceForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: String,
    verb: String,
}

pub async fn service_action(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ServiceForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Action was not confirmed.".into(),
        )));
    }
    if !valid_service_verb(&form.verb) {
        return Err(WebError(AppError::Validation(
            "Unknown service action.".into(),
        )));
    }
    let (kind, _) = if form.verb == "stop" {
        let host = repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .ok_or(AppError::NotFound)?;
        crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
        (OperationKind::Destructive, ())
    } else {
        (OperationKind::Write, ())
    };
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeServiceAction {
            verb: form.verb.clone(),
        },
        &format!("{} sensor", title_verb(&form.verb)),
        kind,
        Some(form.sudo_password),
        None,
    )
    .await
}

// ---- Config apply (second-gated) ------------------------------------

#[derive(Deserialize)]
pub struct ConfigConfirmQuery {
    #[serde(default)]
    interfaces: String,
    #[serde(default)]
    home_net: String,
    #[serde(default)]
    external_net: String,
    #[serde(default)]
    eve_enabled: bool,
}

pub async fn config_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<ConfigConfirmQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_config_changes_enabled(&state).await?;
    let message = format!(
        "Apply this sensor config (validated before reload, with automatic rollback on failure):\n\
         interfaces: {}\nHOME_NET: {}\nEXTERNAL_NET: {}\nEVE JSON: {}",
        if q.interfaces.trim().is_empty() {
            "(unchanged)"
        } else {
            q.interfaces.trim()
        },
        if q.home_net.trim().is_empty() {
            "(unchanged)"
        } else {
            q.home_net.trim()
        },
        if q.external_net.trim().is_empty() {
            "(unchanged)"
        } else {
            q.external_net.trim()
        },
        if q.eve_enabled {
            "enabled"
        } else {
            "unchanged"
        },
    );
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        "Apply sensor config",
        message,
        format!("/arsenals/scourge/{host_id}/config"),
        None,
        vec![
            ("interfaces".to_string(), q.interfaces.clone()),
            ("home_net".to_string(), q.home_net.clone()),
            ("external_net".to_string(), q.external_net.clone()),
            ("eve_enabled".to_string(), q.eve_enabled.to_string()),
        ],
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct ConfigForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    sudo_password: String,
    #[serde(default)]
    interfaces: String,
    #[serde(default)]
    home_net: String,
    #[serde(default)]
    external_net: String,
    #[serde(default)]
    eve_enabled: bool,
}

pub async fn config_apply(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConfigForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_config_changes_enabled(&state).await?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Config apply was not confirmed.".into(),
        )));
    }
    let interfaces: Vec<String> = form
        .interfaces
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let metadata = serde_json::json!({
        "interfaces": interfaces,
        "home_net": form.home_net.trim(),
        "external_net": form.external_net.trim(),
        "eve_enabled": form.eve_enabled,
    });
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeApplyConfig {
            interfaces,
            home_net: form.home_net.trim().to_string(),
            external_net: form.external_net.trim().to_string(),
            eve_enabled: form.eve_enabled,
        },
        "Apply config",
        OperationKind::Write,
        Some(form.sudo_password),
        Some((AuditAction::ScourgeSensorConfigured, metadata)),
    )
    .await
}

// ---- Rule updates / SID toggle / suppression (second-gated) ----------

pub async fn rules_update_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_config_changes_enabled(&state).await?;
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        "Update rules",
        "Fetch the latest rulesets (suricata-update), validate, and reload. If validation fails \
         the sensor keeps running its previous ruleset."
            .to_string(),
        format!("/arsenals/scourge/{host_id}/rules/update"),
        None,
        vec![],
        None,
    )
    .await
}

pub async fn rules_update(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ManagedConfirmForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    check_confirmed(&form, &jar)?;
    ensure_config_changes_enabled(&state).await?;
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeUpdateRules,
        "Update rules",
        OperationKind::Write,
        Some(form.sudo_password),
        Some((
            AuditAction::ScourgeRuleChanged,
            serde_json::json!({ "action": "update_rules" }),
        )),
    )
    .await
}

#[derive(Deserialize)]
pub struct SidConfirmQuery {
    sid: u32,
    #[serde(default)]
    enabled: bool,
}

pub async fn sid_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SidConfirmQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_config_changes_enabled(&state).await?;
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        &format!(
            "{} SID {}",
            if q.enabled { "Enable" } else { "Disable" },
            q.sid
        ),
        format!(
            "{} signature {} and recompile + reload the ruleset.",
            if q.enabled { "Enable" } else { "Disable" },
            q.sid
        ),
        format!("/arsenals/scourge/{host_id}/rules/sid"),
        None,
        vec![
            ("sid".to_string(), q.sid.to_string()),
            ("enabled".to_string(), q.enabled.to_string()),
        ],
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct SidForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    sudo_password: String,
    sid: u32,
    #[serde(default)]
    enabled: bool,
}

pub async fn sid_set(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SidForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_config_changes_enabled(&state).await?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Action was not confirmed.".into(),
        )));
    }
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeSetSidEnabled {
            sid: form.sid,
            enabled: form.enabled,
        },
        "Set SID state",
        OperationKind::Write,
        Some(form.sudo_password),
        Some((
            AuditAction::ScourgeRuleChanged,
            serde_json::json!({ "action": "set_sid_enabled", "sid": form.sid, "enabled": form.enabled }),
        )),
    )
    .await
}

#[derive(Deserialize)]
pub struct SuppressConfirmQuery {
    sid: u32,
    #[serde(default)]
    suppress: bool,
}

pub async fn suppress_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SuppressConfirmQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_config_changes_enabled(&state).await?;
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        &format!(
            "{} SID {}",
            if q.suppress { "Suppress" } else { "Unsuppress" },
            q.sid
        ),
        format!(
            "{} alerts for signature {} (threshold.conf), validate, and reload.",
            if q.suppress {
                "Suppress"
            } else {
                "Stop suppressing"
            },
            q.sid
        ),
        format!("/arsenals/scourge/{host_id}/rules/suppress"),
        None,
        vec![
            ("sid".to_string(), q.sid.to_string()),
            ("suppress".to_string(), q.suppress.to_string()),
        ],
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct SuppressForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    sudo_password: String,
    sid: u32,
    #[serde(default)]
    suppress: bool,
}

pub async fn suppress_set(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SuppressForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_config_changes_enabled(&state).await?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Action was not confirmed.".into(),
        )));
    }
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeSuppressSid {
            sid: form.sid,
            suppress: form.suppress,
        },
        "Set suppression",
        OperationKind::Write,
        Some(form.sudo_password),
        Some((
            AuditAction::ScourgeRuleChanged,
            serde_json::json!({ "action": "suppress_sid", "sid": form.sid, "suppress": form.suppress }),
        )),
    )
    .await
}

// ---- Rule testing (Read; no confirm, no second gate) -----------------

#[derive(Deserialize)]
pub struct RuleTestForm {
    csrf_token: String,
    #[serde(default)]
    pcap_name: String,
}

pub async fn rule_test(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RuleTestForm>,
) -> Result<Response, WebError> {
    // Rule testing runs the engine offline over a captured pcap (reading
    // privacy-sensitive packet data) and needs elevation -- so it requires
    // `scourge.manage`, not just view, and sits behind the capture gate.
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_capture_enabled(&state).await?;
    let pcap_name = form.pcap_name.trim().to_string();
    if pcap_name.is_empty() {
        return Err(WebError(AppError::Validation(
            "Enter a captured pcap filename to test against.".into(),
        )));
    }
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeRuleTest { pcap_name },
        "Rule Test",
        OperationKind::Read,
        None,
        None,
    )
    .await
}

// ---------------------------------------------------------------------
// Packet capture (phase 5): bounded capture as an in-memory AppState job
// (the scan/deploy-job pattern). The agent starts the capture detached and
// returns an id; the progress page refreshes it via a live status dispatch
// and stops polling when done. Capture + pcap deletion require
// `scourge.manage` and the `scourge.capture_enabled` second gate.
// ---------------------------------------------------------------------

fn format_bytes(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1} MB", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1} KB", n as f64 / 1_000.0)
    } else {
        format!("{n} B")
    }
}

#[derive(Deserialize)]
pub struct CaptureConfirmQuery {
    #[serde(default)]
    bpf: String,
    #[serde(default)]
    max_seconds: u32,
    #[serde(default)]
    max_mb: u32,
}

pub async fn capture_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<CaptureConfirmQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_capture_enabled(&state).await?;
    let secs = q.max_seconds.clamp(1, 3600);
    let mb = q.max_mb.clamp(1, 1024);
    let message = format!(
        "Start a bounded packet capture on this host (stops at {secs}s or ~{mb} MB, whichever \
         first). Pcaps stay on the host.\nBPF filter: {}",
        if q.bpf.trim().is_empty() {
            "(capture all)"
        } else {
            q.bpf.trim()
        },
    );
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        "Start packet capture",
        message,
        format!("/arsenals/scourge/{host_id}/capture"),
        None,
        vec![
            ("bpf".to_string(), q.bpf.clone()),
            ("max_seconds".to_string(), secs.to_string()),
            ("max_mb".to_string(), mb.to_string()),
        ],
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct CaptureStartForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    sudo_password: String,
    #[serde(default)]
    bpf: String,
    #[serde(default)]
    max_seconds: u32,
    #[serde(default)]
    max_mb: u32,
}

pub async fn capture_start(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<CaptureStartForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_capture_enabled(&state).await?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Capture was not confirmed.".into(),
        )));
    }
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if let Some(pw) = Some(form.sudo_password).filter(|p| !p.trim().is_empty())
        && let Err(e) = maybe_elevate(&state, &ctx, host_id, &host.name, Some(pw)).await
    {
        return render_host(
            &state,
            &jar,
            &ctx,
            host_id,
            Some("Capture".into()),
            None,
            Some(e),
        )
        .await;
    }

    let max_seconds = form.max_seconds.clamp(1, 3600);
    let max_mb = form.max_mb.clamp(1, 1024);
    let retention_days = repo::settings::get_u32(
        &state.pool,
        SCOURGE_PCAP_RETENTION_DAYS,
        SCOURGE_PCAP_RETENTION_DAYS_DEFAULT,
    )
    .await?;
    let max_total_mb = repo::settings::get_u32(
        &state.pool,
        SCOURGE_PCAP_MAX_TOTAL_MB,
        SCOURGE_PCAP_MAX_TOTAL_MB_DEFAULT,
    )
    .await?;

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ScourgeCaptureStart {
                bpf: form.bpf.trim().to_string(),
                max_seconds,
                max_mb,
                retention_days,
                max_total_mb,
            },
            Permission::ScourgeManage,
            OperationKind::Write,
            false,
            Duration::from_secs(30),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let capture_id = output.stdout.trim().to_string();
            let job_id = Uuid::new_v4();
            let job = std::sync::Arc::new(tokio::sync::RwLock::new(ScourgeCaptureJob {
                id: job_id,
                host_id,
                capture_id: capture_id.clone(),
                bpf: form.bpf.trim().to_string(),
                max_seconds,
                max_mb,
                state: ScourgeCaptureState::Running,
                elapsed_secs: 0,
                size_bytes: 0,
                remaining_secs: u64::from(max_seconds),
                error: None,
            }));
            state.scourge_capture_jobs.write().await.insert(job_id, job);

            let event = AuditEvent::new(AuditAction::ScourgeCaptureStarted, AuditOutcome::Success)
                .actor(abyssal_audit::Actor {
                    user_id: ctx.user.id,
                    username: &ctx.user.username,
                })
                .resource(&host.name)
                .metadata(serde_json::json!({
                    "capture_id": capture_id,
                    "bpf": form.bpf.trim(),
                    "max_seconds": max_seconds,
                    "max_mb": max_mb,
                }));
            if let Err(e) = abyssal_audit::record(&state.pool, event).await {
                tracing::error!(error = %e, "scourge: failed to record capture audit");
            }
            Ok(
                Redirect::to(&format!("/arsenals/scourge/{host_id}/capture/{job_id}"))
                    .into_response(),
            )
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Capture".into()),
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

async fn render_capture(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    job_id: Uuid,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let job_arc = state
        .scourge_capture_jobs
        .read()
        .await
        .get(&job_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let snap = job_arc.read().await;

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
    let tpl = ScourgeCaptureTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        job_id: job_id.to_string(),
        capture_id: snap.capture_id.clone(),
        bpf: if snap.bpf.is_empty() {
            "(capture all)".to_string()
        } else {
            snap.bpf.clone()
        },
        state_label: snap.state.label().to_string(),
        running: snap.state == ScourgeCaptureState::Running,
        elapsed_secs: snap.elapsed_secs,
        size: format_bytes(snap.size_bytes),
        remaining_secs: snap.remaining_secs,
        max_seconds: snap.max_seconds,
        pcap_name: format!("{}.pcap", snap.capture_id),
        error: snap.error.clone(),
        csrf_token: csrf_token.clone(),
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn capture_progress(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((host_id, job_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;

    // Refresh the job from the agent while it's still running (a live status
    // dispatch -- capture control, bounded to this one capture).
    let job_arc = state
        .scourge_capture_jobs
        .read()
        .await
        .get(&job_id)
        .cloned();
    if let Some(job_arc) = job_arc {
        let (capture_id, still_running) = {
            let s = job_arc.read().await;
            (
                s.capture_id.clone(),
                s.state == ScourgeCaptureState::Running,
            )
        };
        if still_running {
            let host = repo::hosts::find_by_id(&state.pool, host_id).await?;
            if let Some(host) = host {
                let elevated = state.elevation.is_elevated(host_id);
                if let Ok(output) = state
                    .executor
                    .execute_on_host(
                        &ctx,
                        &state.hosts,
                        host_id,
                        &host.name,
                        AgentOperation::ScourgeCaptureStatus {
                            capture_id: capture_id.clone(),
                        },
                        Permission::ScourgeManage,
                        OperationKind::Read,
                        false,
                        Duration::from_secs(15),
                        None,
                        elevated,
                    )
                    .await
                {
                    job_arc.write().await.apply_status_line(&output.stdout);
                }
            }
        }
    }

    render_capture(&state, &jar, &ctx, host_id, job_id).await
}

#[derive(Deserialize)]
pub struct CaptureCancelForm {
    csrf_token: String,
}

pub async fn capture_cancel(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((host_id, job_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<CaptureCancelForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let job_arc = state
        .scourge_capture_jobs
        .read()
        .await
        .get(&job_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let capture_id = job_arc.read().await.capture_id.clone();
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let elevated = state.elevation.is_elevated(host_id);
    let _ = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ScourgeCaptureCancel { capture_id },
            Permission::ScourgeManage,
            OperationKind::Write,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;
    job_arc.write().await.state = ScourgeCaptureState::Cancelled;
    Ok(Redirect::to(&format!("/arsenals/scourge/{host_id}/capture/{job_id}")).into_response())
}

// ---- Pcap deletion (Destructive, type-to-confirm, capture-gated) ------

#[derive(Deserialize)]
pub struct PcapDeleteQuery {
    name: String,
}

pub async fn pcap_delete_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<PcapDeleteQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_capture_enabled(&state).await?;
    let name = q.name.trim().to_string();
    if name.is_empty() {
        return Err(WebError(AppError::Validation("No pcap name given.".into())));
    }
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        "Delete pcap",
        format!(
            "Permanently delete the capture \"{name}\" from this host -- captures hold raw \
             network traffic, so shredding is the default. This can't be undone. Type the pcap \
             filename to confirm."
        ),
        format!("/arsenals/scourge/{host_id}/pcap/delete"),
        Some(TypeToConfirm {
            label: "pcap filename".to_string(),
            expected: name.clone(),
        }),
        vec![("name".to_string(), name)],
        Some(crate::templates::ShredOption::for_host(&state, host_id).await?),
    )
    .await
}

#[derive(Deserialize)]
pub struct PcapDeleteForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: String,
    name: String,
    /// Blank or 0 = an ordinary delete; 1-35 = shred the capture first.
    #[serde(default)]
    shred_passes: String,
    /// Witness sign-off for a shred (see `common::sanitization_sign_off`).
    #[serde(default)]
    witnessed: Option<String>,
    #[serde(default)]
    witness_username: String,
    #[serde(default)]
    witness_password: String,
    #[serde(default)]
    sanitization_note: String,
}

pub async fn pcap_delete(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PcapDeleteForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_capture_enabled(&state).await?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Deletion was not confirmed.".into(),
        )));
    }
    let name = form.name.trim().to_string();
    crate::common::require_typed_confirmation(&form.confirm_text, &name)?;
    // Shred like every other sensitive deletion -- verified (and the sign-off
    // recorded) only once the deletion itself is allowed and confirmed.
    let shred_passes = crate::common::shred_passes_for_host(&state, host_id, &form.shred_passes)?;
    let sign_off = crate::common::sanitization_sign_off(
        &state,
        &ctx,
        shred_passes,
        crate::common::SignOffFields {
            witnessed: form.witnessed.is_some(),
            witness_username: form.witness_username.clone(),
            witness_password: form.witness_password.clone(),
            note: form.sanitization_note.clone(),
        },
        Permission::ScourgeManage,
    )
    .await?;
    if let Some(sign_off) = &sign_off {
        let host_name = repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .map(|h| h.name)
            .unwrap_or_default();
        crate::common::record_sign_off(
            &state,
            &ctx,
            sign_off,
            &format!("packet capture {name} on {host_name}"),
            shred_passes,
        )
        .await?;
    }
    let label = if shred_passes == 0 {
        "Delete pcap".to_string()
    } else {
        format!("Shred pcap ({shred_passes} passes)")
    };
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgePcapDelete {
            pcap_name: name.clone(),
            shred_passes,
        },
        &label,
        OperationKind::Destructive,
        Some(form.sudo_password),
        Some((
            AuditAction::ScourgePcapDeleted,
            serde_json::json!({ "pcap": name, "shred_passes": shred_passes }),
        )),
    )
    .await
}

// ---------------------------------------------------------------------
// Inline IPS (phase 6): the highest-risk capability -- most conservative.
// Mode switch + per-SID drop/reject promotion behind `scourge.ips_enabled`
// + type-to-confirm. The agent installs mandatory always-allow lockout rules
// on enable; reverting to passive IDS is fast and plainly confirmed.
// ---------------------------------------------------------------------

/// The inline-IPS second gate, re-checked at every entry point.
async fn ensure_ips_enabled(state: &AppState) -> Result<(), WebError> {
    let enabled = repo::settings::get_bool(&state.pool, SCOURGE_IPS_ENABLED, false).await?;
    if !enabled {
        return Err(WebError(AppError::Validation(
            "Scourge inline IPS is disabled. An admin must enable it on the Settings page first."
                .into(),
        )));
    }
    Ok(())
}

pub async fn ips_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    // Read-only; manage-level feature. No second gate (seeing "passive" is fine).
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeIpsStatus,
        "IPS Status",
        OperationKind::Read,
        None,
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct ModeConfirmQuery {
    #[serde(default)]
    ips: bool,
}

pub async fn mode_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<ModeConfirmQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_ips_enabled(&state).await?;
    // Enabling inline mode is the dangerous direction -> type-to-confirm.
    // Reverting to passive is the safety move -> plain confirm (fast).
    let (ttc, title, message) = if q.ips {
        let host = repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .ok_or(AppError::NotFound)?;
        (
            Some(TypeToConfirm {
                label: "host name".to_string(),
                expected: host.name.clone(),
            }),
            "Switch to inline IPS",
            format!(
                "Switch {} to INLINE IPS. Traffic will pass through the sensor and promoted \
                 signatures will actively block. Mandatory always-allow rules protect the control \
                 plane and SSH, and you can revert to passive IDS at any time. Signatures stay in \
                 'alert' until you promote them individually. Type the host name to confirm.",
                host.name
            ),
        )
    } else {
        (
            None,
            "Revert to passive IDS",
            "Revert this sensor to passive IDS (detection only -- nothing is blocked). This removes \
             the inline hook and is the safe fallback."
                .to_string(),
        )
    };
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        title,
        message,
        format!("/arsenals/scourge/{host_id}/ips/mode"),
        ttc,
        vec![("ips".to_string(), q.ips.to_string())],
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct ModeForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: String,
    #[serde(default)]
    ips: bool,
}

pub async fn mode_set(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ModeForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_ips_enabled(&state).await?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Mode change was not confirmed.".into(),
        )));
    }
    // Enabling inline is Destructive + type-to-confirm; reverting is Write.
    let kind = if form.ips {
        let host = repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .ok_or(AppError::NotFound)?;
        crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
        OperationKind::Destructive
    } else {
        OperationKind::Write
    };
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeSetMode { ips: form.ips },
        if form.ips {
            "Enable inline IPS"
        } else {
            "Revert to passive IDS"
        },
        kind,
        Some(form.sudo_password),
        Some((
            AuditAction::ScourgeModeChanged,
            serde_json::json!({ "mode": if form.ips { "ips" } else { "ids" } }),
        )),
    )
    .await
}

#[derive(Deserialize)]
pub struct SidActionConfirmQuery {
    sid: u32,
    action: String,
}

fn valid_sid_action(a: &str) -> bool {
    matches!(a, "alert" | "drop" | "reject")
}

pub async fn sid_action_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SidActionConfirmQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    ensure_ips_enabled(&state).await?;
    if !valid_sid_action(&q.action) {
        return Err(WebError(AppError::Validation("Unknown action.".into())));
    }
    // Promoting to an active block (drop/reject) is type-to-confirm; demoting
    // back to alert is a plain confirm.
    let ttc = if q.action == "alert" {
        None
    } else {
        let host = repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .ok_or(AppError::NotFound)?;
        Some(TypeToConfirm {
            label: "host name".to_string(),
            expected: host.name,
        })
    };
    render_confirm(
        &state,
        &jar,
        &ctx,
        host_id,
        &format!("Set SID {} to {}", q.sid, q.action),
        format!(
            "Set signature {} to '{}'. In inline mode a '{}' action actively blocks matching \
             traffic (the always-allow rules still protect the control plane and SSH).",
            q.sid, q.action, q.action
        ),
        format!("/arsenals/scourge/{host_id}/ips/sid-action"),
        ttc,
        vec![
            ("sid".to_string(), q.sid.to_string()),
            ("action".to_string(), q.action.clone()),
        ],
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct SidActionForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: String,
    sid: u32,
    action: String,
}

pub async fn sid_action_set(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SidActionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    ensure_ips_enabled(&state).await?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Action was not confirmed.".into(),
        )));
    }
    if !valid_sid_action(&form.action) {
        return Err(WebError(AppError::Validation("Unknown action.".into())));
    }
    let kind = if form.action == "alert" {
        OperationKind::Write
    } else {
        let host = repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .ok_or(AppError::NotFound)?;
        crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;
        OperationKind::Destructive
    };
    run_managed(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScourgeSetSidAction {
            sid: form.sid,
            action: form.action.clone(),
        },
        "Set SID action",
        kind,
        Some(form.sudo_password),
        Some((
            AuditAction::ScourgeModeChanged,
            serde_json::json!({ "sid": form.sid, "action": form.action }),
        )),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_href_carries_filters_and_page() {
        let q = AlertsQuery {
            severity: Some("high".to_string()),
            src_ip: Some("10.0.0.5".to_string()),
            range: Some("1h".to_string()),
            ..Default::default()
        };
        // Page 1 is the default and omitted; filters are carried.
        let p1 = alerts_href(ALERTS_FRAGMENT_PATH, &q, Some(1));
        assert!(p1.starts_with("/arsenals/scourge/alerts/fragment?"));
        assert!(p1.contains("severity=high"));
        assert!(p1.contains("src_ip=10.0.0.5"));
        assert!(p1.contains("range=1h"));
        assert!(!p1.contains("page="));
        // Page > 1 is carried.
        let p2 = alerts_href(ALERTS_FRAGMENT_PATH, &q, Some(2));
        assert!(p2.contains("page=2"));
    }

    #[test]
    fn alerts_href_empty_query_has_no_question_mark() {
        let q = AlertsQuery::default();
        assert_eq!(alerts_href(ALERTS_BASE_PATH, &q, Some(1)), ALERTS_BASE_PATH);
    }

    #[test]
    fn range_since_maps_presets() {
        assert!(range_since("all").is_none());
        assert!(range_since("1h").is_some());
        assert!(range_since("24h").is_some());
        // Unknown falls back to a bounded (24h) window, never all-time.
        assert!(range_since("bogus").is_some());
    }

    #[test]
    fn service_verb_allowlist() {
        for v in ["start", "stop", "restart", "reload"] {
            assert!(valid_service_verb(v));
        }
        assert!(!valid_service_verb("enable"));
        assert!(!valid_service_verb("stop; rm -rf"));
        assert!(!valid_service_verb(""));
    }

    #[test]
    fn sid_action_allowlist() {
        for a in ["alert", "drop", "reject"] {
            assert!(valid_sid_action(a));
        }
        assert!(!valid_sid_action("pass"));
        assert!(!valid_sid_action("drop; rm"));
        assert!(!valid_sid_action(""));
    }

    #[test]
    fn high_severity_alert_suggests_respond_investigate_correlate() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({
            "severity": "high",
            "signature": "ET MALWARE Observed",
            "src_ip": "10.0.0.5",
        });
        let matches = registry.evaluate("scourge", "alerts", &entry).matches;
        let targets: Vec<&str> = matches.iter().map(|m| m.target_arsenal.as_str()).collect();
        assert!(targets.contains(&"inquest"), "block the source IP");
        assert!(targets.contains(&"thanatos"), "correlate");
        assert!(targets.contains(&"postmortem"), "investigate");
        // The Inquest button must carry the source IP forward.
        let inquest = matches
            .iter()
            .find(|m| m.target_arsenal == "inquest")
            .expect("inquest suggestion present");
        assert!(
            inquest
                .context
                .iter()
                .any(|(k, v)| k == "src_ip" && v == "10.0.0.5")
        );
    }

    #[test]
    fn low_severity_alert_suggests_nothing_destructive() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "severity": "low", "signature": "ET INFO ping" });
        let targets: Vec<String> = registry
            .evaluate("scourge", "alerts", &entry)
            .matches
            .iter()
            .map(|m| m.target_arsenal.clone())
            .collect();
        assert!(!targets.contains(&"inquest".to_string()));
        assert!(!targets.contains(&"thanatos".to_string()));
        assert!(!targets.contains(&"postmortem".to_string()));
    }

    #[test]
    fn brute_force_alert_suggests_hardening() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({
            "severity": "medium",
            "signature": "ET SCAN SSH BruteForce",
            "category": "Attempted Administrator Privilege Gain",
        });
        let targets: Vec<String> = registry
            .evaluate("scourge", "alerts", &entry)
            .matches
            .iter()
            .map(|m| m.target_arsenal.clone())
            .collect();
        assert!(
            targets.contains(&"cadavault".to_string()),
            "harden exposed services"
        );
    }
}
