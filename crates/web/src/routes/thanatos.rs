use std::collections::{HashMap, HashSet};
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    THANATOS_DASHBOARD_RENDER_BUDGET, THANATOS_DASHBOARD_RENDER_BUDGET_DEFAULT,
};
use abyssal_core::{AppError, EventStatus, IocType, Permission, Severity};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, RawQuery, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{WorkflowContextRow, maybe_elevate, require_csrf, workflow_context_rows};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::pagination;
use crate::state::AppState;
use crate::templates::{
    AlertRow, BaseCtx, FacetHost, GroupPageInfo, IocView, SearchResultRow, SecurityEventRow,
    SeverityCountRow, SuggestedActionView, SuppressionRuleView, ThanatosHostGroup,
    ThanatosHostTemplate, ThanatosIocsTemplate, ThanatosRulesTemplate, ThanatosSearchTemplate,
    ThanatosTemplate,
};
use crate::theme;

const RECENT_EVENTS_LIMIT: i64 = 200;
const RECENT_ALERTS_LIMIT: i64 = 50;
const SUMMARY_WINDOW_HOURS: i64 = 24;
/// Rows inside one open host group's own pagination -- deliberately
/// smaller than a typical list-view default since several groups can be
/// open on the dashboard at once, same reasoning as Panopticon's Device
/// Inventory.
const GROUP_ROWS_PER_PAGE: u32 = 50;
/// How many host groups the group *list* itself shows per page.
const GROUPS_PER_PAGE: u32 = 25;

fn severity_view(severity: Severity) -> (&'static str, &'static str) {
    match severity {
        Severity::Low => ("Low", "badge-muted"),
        Severity::Medium => ("Medium", "badge-warning"),
        Severity::High => ("High", "badge-danger"),
        Severity::Critical => ("CRITICAL", "badge-danger"),
    }
}

/// What Thanatos's scan actually reads on this host -- differs by
/// platform (see `crates/agent/src/thanatos.rs`'s module doc comment),
/// so the per-host page says so explicitly rather than showing one
/// Linux-flavored sentence regardless of what's actually connected.
fn detection_sources_note(os: Option<&str>) -> &'static str {
    match os {
        Some("windows") => {
            "Scans this host's Security and System event logs (logons, lateral-movement/\
             privileged-logon indicators, account/service/scheduled-task changes, audit-policy \
             tampering, service failures, unexpected shutdowns) plus PowerShell script block \
             logging and Windows Defender's log where enabled, and hashes for tampering its hosts \
             file, machine-wide autorun locations (Run keys, Winlogon, Image File Execution \
             Options, AppInit_DLLs), service configuration, scheduled tasks, WMI event-subscription \
             persistence, firewall profile state, and local Administrators membership. \
             Where Sysmon is deployed, it also flags process injection and process tampering. \
             It additionally checks host security posture (SMBv1, UAC, RDP Network Level \
             Authentication, LSASS protection)."
        }
        Some("macos") => {
            "macOS hosts aren't scanned yet -- Thanatos detection is Linux/Windows only for now."
        }
        // Linux, and any host that hasn't reported an OS yet (an older
        // agent build, or one that's never connected) -- the scan itself
        // still only actually reads something on a real Linux host either
        // way, so this is also the safest default to show.
        _ => {
            "Scans this host's auth log (or journalctl), kernel ring buffer, and systemd unit \
             status, and hashes a small set of security-sensitive files for tampering."
        }
    }
}

fn status_view(status: EventStatus) -> (&'static str, &'static str) {
    match status {
        EventStatus::Open => ("Open", "badge-warning"),
        EventStatus::Acknowledged => ("Acknowledged", "badge-muted"),
        EventStatus::Resolved => ("Resolved", "badge-success"),
        EventStatus::Suppressed => ("Suppressed", "badge-muted"),
    }
}

/// Builds one event's row view-model -- shared by the fleet dashboard's
/// per-host groups and the standalone per-host page, so the status
/// badge/action-button logic (Phase 3) is defined exactly once.
fn security_event_row(event: abyssal_core::SecurityEvent, timezone: &str) -> SecurityEventRow {
    let (severity_label, badge_class) = severity_view(event.severity);
    let (status_label, status_badge_class) = status_view(event.status);
    SecurityEventRow {
        id: event.id.to_string(),
        severity_label,
        badge_class,
        label: event.label,
        technique: event.technique,
        source: event.source,
        raw_line: event.raw_line,
        occurred_at: crate::common::format_in_tz(event.occurred_at, timezone),
        status_label,
        status_badge_class,
        can_acknowledge: event.status == EventStatus::Open,
        can_resolve_or_suppress: event.status.is_active(),
        resolution_note: event.resolution_note,
    }
}

/// Every Thanatos dashboard query-string param, parsed once via
/// `parse_dashboard_query` and re-serialized by `href` -- same pattern as
/// Panopticon's `InventoryQuery` (GitHub issue #10), kept as its own small
/// type here rather than shared, since the two differ in key type (host
/// UUID string vs. subnet string) and Panopticon's also carries a port/
/// ad-hoc-CIDR filter this dashboard has no equivalent of.
#[derive(Default, Clone)]
struct DashboardQuery {
    /// Repeatable `?open=<host_id>` -- which host groups render their
    /// body even when the render budget would otherwise leave them
    /// collapsed.
    open: Vec<String>,
    /// `?group_page=` -- which page of the host-group list itself.
    group_page: Option<u32>,
    /// Repeatable `?gp=<host_id>:<page>` -- one host group's own row
    /// page.
    gp: Vec<(String, u32)>,
    /// `?show_resolved=1` -- Phase 3's alert-lifecycle filter. Off by
    /// default: every list here hides `resolved`/`suppressed` events
    /// unless this is set.
    show_resolved: bool,
}

impl DashboardQuery {
    fn with_open(&self, host_id: &str) -> Self {
        let mut q = self.clone();
        if !q.open.iter().any(|o| o == host_id) {
            q.open.push(host_id.to_string());
        }
        q
    }

    fn with_gp(&self, host_id: &str, page: u32) -> Self {
        let mut q = self.clone();
        q.gp.retain(|(id, _)| id != host_id);
        if page > 1 {
            q.gp.push((host_id.to_string(), page));
        }
        q
    }

    fn with_group_page(&self, page: u32) -> Self {
        let mut q = self.clone();
        q.group_page = if page > 1 { Some(page) } else { None };
        q
    }

    fn with_show_resolved(&self, show_resolved: bool) -> Self {
        let mut q = self.clone();
        q.show_resolved = show_resolved;
        q
    }

    fn href(&self) -> String {
        if self.open.is_empty()
            && self.group_page.is_none()
            && self.gp.is_empty()
            && !self.show_resolved
        {
            return "/arsenals/thanatos".to_string();
        }
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for o in &self.open {
            ser.append_pair("open", o);
        }
        if let Some(p) = self.group_page {
            ser.append_pair("group_page", &p.to_string());
        }
        for (id, page) in &self.gp {
            ser.append_pair("gp", &format!("{id}:{page}"));
        }
        if self.show_resolved {
            ser.append_pair("show_resolved", "1");
        }
        format!("/arsenals/thanatos?{}", ser.finish())
    }
}

/// Hand-parsed via `form_urlencoded` (same "repeated-key form groups need
/// manual parsing" pattern used throughout this session) since a plain
/// `Query<T>` extractor can't deserialize repeated `open=` values into a
/// `Vec` or `gp=host_id:page` pairs. A malformed `group_page`/`gp` value
/// is silently dropped rather than rejected, same as Panopticon's.
fn parse_dashboard_query(raw: Option<&str>) -> DashboardQuery {
    let mut q = DashboardQuery::default();
    let Some(raw) = raw else { return q };
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "open" => {
                let v = value.trim();
                if !v.is_empty() && !q.open.iter().any(|o| o == v) {
                    q.open.push(v.to_string());
                }
            }
            "group_page" => q.group_page = value.trim().parse::<u32>().ok(),
            "gp" => {
                if let Some((id, page)) = value.split_once(':')
                    && !id.is_empty()
                    && let Ok(page) = page.parse::<u32>()
                {
                    q.gp.retain(|(existing, _)| existing != id);
                    q.gp.push((id.to_string(), page));
                }
            }
            "show_resolved" => q.show_resolved = value.trim() == "1",
            _ => {}
        }
    }
    q
}

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    RawQuery(raw): RawQuery,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/thanatos/{host_id}")).into_response());
    }

    let query = parse_dashboard_query(raw.as_deref());
    let only_active = !query.show_resolved;

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

    let severity_summary = crate::thanatos_ops::severity_summary(&state.pool, SUMMARY_WINDOW_HOURS)
        .await?
        .into_iter()
        .map(|(severity, count)| {
            let (label, badge_class) = severity_view(severity);
            SeverityCountRow {
                label,
                badge_class,
                count,
            }
        })
        .collect();

    let mut recent_alerts = Vec::new();
    for event in
        repo::security_events::list_recent_alerts(&state.pool, RECENT_ALERTS_LIMIT, only_active)
            .await?
    {
        let host_name = repo::hosts::find_by_id(&state.pool, event.host_id)
            .await?
            .map(|h| h.name)
            .unwrap_or_else(|| "(removed host)".to_string());
        recent_alerts.push(AlertRow {
            host_name,
            label: event.label,
            technique: event.technique,
            raw_line: event.raw_line,
            occurred_at: crate::common::format_in_tz(event.occurred_at, &ctx.user.timezone),
        });
    }

    // Grouped-by-host dashboard: header (name, event count) always renders
    // for every connected host (one aggregate query, no N+1); a group's
    // own event rows only render when it's explicitly `open=`-named, or
    // every group renders open when the whole fleet's event count fits
    // under the render budget -- identical mechanics to Panopticon's
    // Device Inventory (GitHub issue #10), keyed by host instead of
    // subnet.
    let mut connected_hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            connected_hosts.push(host);
        }
    }
    let host_ids: Vec<Uuid> = connected_hosts.iter().map(|h| h.id).collect();
    let counts =
        repo::security_events::count_for_hosts(&state.pool, &host_ids, only_active).await?;
    let total_event_count: i64 = counts.values().sum();

    let render_budget = repo::settings::get_u32(
        &state.pool,
        THANATOS_DASHBOARD_RENDER_BUDGET,
        THANATOS_DASHBOARD_RENDER_BUDGET_DEFAULT,
    )
    .await
    .unwrap_or(THANATOS_DASHBOARD_RENDER_BUDGET_DEFAULT);
    let render_all = total_event_count.max(0) as u64 <= u64::from(render_budget);
    let open_set: HashSet<&str> = query.open.iter().map(String::as_str).collect();
    let gp_map: HashMap<&str, u32> = query.gp.iter().map(|(id, p)| (id.as_str(), *p)).collect();

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
        query.with_group_page(p).href()
    }));

    let mut groups = Vec::new();
    for host in connected_hosts
        .iter()
        .skip(group_offset)
        .take(GROUPS_PER_PAGE as usize)
    {
        let host_id_str = host.id.to_string();
        let event_count = counts.get(&host.id).copied().unwrap_or(0);
        let is_open = render_all || open_set.contains(host_id_str.as_str());

        let (events, page_info, open_href) = if is_open {
            let requested_page = gp_map
                .get(host_id_str.as_str())
                .copied()
                .unwrap_or(1)
                .max(1);
            let total = event_count.max(0) as u64;
            let page_num = if pagination::Page::<()>::page_out_of_range(
                requested_page,
                GROUP_ROWS_PER_PAGE,
                total,
            ) {
                pagination::total_pages(total, GROUP_ROWS_PER_PAGE)
            } else {
                requested_page
            };
            let offset = pagination::offset(page_num, GROUP_ROWS_PER_PAGE);
            let rows = repo::security_events::list_page_for_host(
                &state.pool,
                host.id,
                i64::from(GROUP_ROWS_PER_PAGE),
                offset,
                only_active,
            )
            .await?;
            let event_rows: Vec<SecurityEventRow> = rows
                .into_iter()
                .map(|e| security_event_row(e, &ctx.user.timezone))
                .collect();
            let page_meta: pagination::Page<()> =
                pagination::Page::new(vec![], page_num, GROUP_ROWS_PER_PAGE, total);
            let opened = query.with_open(&host_id_str);
            let gpi = GroupPageInfo {
                current_page: page_meta.page,
                total_pages: page_meta.total_pages,
                range_start: page_meta.start_index(),
                range_end: page_meta.end_index(),
                total: page_meta.total,
                prev_href: page_meta
                    .has_prev()
                    .then(|| opened.with_gp(&host_id_str, page_meta.page - 1).href()),
                next_href: page_meta
                    .has_next()
                    .then(|| opened.with_gp(&host_id_str, page_meta.page + 1).href()),
            };
            (event_rows, Some(gpi), None)
        } else {
            (vec![], None, Some(query.with_open(&host_id_str).href()))
        };

        groups.push(ThanatosHostGroup {
            host_id: host_id_str,
            host_name: host.name.clone(),
            os_label: crate::common::os_label(host.os.as_deref()),
            event_count,
            is_open,
            events,
            open_href,
            scroll_aria_label: format!("Events for {}", host.name),
            page_info,
        });
    }

    let tpl = ThanatosTemplate {
        base,
        can_manage: ctx.has(Permission::SecurityManage),
        can_respond: ctx.has(Permission::IncidentsRespond),
        severity_summary,
        recent_alerts,
        total_event_count,
        render_budget,
        groups,
        group_list_page,
        show_resolved: query.show_resolved,
        toggle_resolved_href: query.with_show_resolved(!query.show_resolved).href(),
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

// ---- Investigation console (M3) -------------------------------------------

/// Results per page in the cross-host investigation console.
const SEARCH_PER_PAGE: u32 = 50;

/// Raw, string-form investigation-console filters parsed from the query string
/// (echoed back into the form, and re-serialized onto pagination/toggle links).
#[derive(Default)]
struct SearchParams {
    host: String,
    source: String,
    severity: String,
    technique: String,
    text: String,
    from: String,
    to: String,
    show_resolved: bool,
    page: u32,
}

fn parse_search_params(raw: Option<&str>) -> SearchParams {
    let mut p = SearchParams {
        page: 1,
        ..Default::default()
    };
    let Some(raw) = raw else { return p };
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        let value = value.trim().to_string();
        match key.as_ref() {
            "host" => p.host = value,
            "source" => p.source = value,
            "severity" => p.severity = value,
            "technique" => p.technique = value,
            "q" => p.text = value,
            "from" => p.from = value,
            "to" => p.to = value,
            "show_resolved" => p.show_resolved = value == "1",
            "page" => p.page = value.parse::<u32>().ok().filter(|n| *n >= 1).unwrap_or(1),
            _ => {}
        }
    }
    p
}

/// Every set filter as `(key, value)` pairs (excluding `page`) -- the basis for
/// pagination/toggle links so a page change preserves the active filters.
fn search_link_params(p: &SearchParams) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    if !p.host.is_empty() {
        v.push(("host", p.host.clone()));
    }
    if !p.source.is_empty() {
        v.push(("source", p.source.clone()));
    }
    if !p.severity.is_empty() {
        v.push(("severity", p.severity.clone()));
    }
    if !p.technique.is_empty() {
        v.push(("technique", p.technique.clone()));
    }
    if !p.text.is_empty() {
        v.push(("q", p.text.clone()));
    }
    if !p.from.is_empty() {
        v.push(("from", p.from.clone()));
    }
    if !p.to.is_empty() {
        v.push(("to", p.to.clone()));
    }
    if p.show_resolved {
        v.push(("show_resolved", "1".to_string()));
    }
    v
}

fn search_href(params: &[(&'static str, String)]) -> String {
    if params.is_empty() {
        return "/arsenals/thanatos/search".to_string();
    }
    let mut ser = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        ser.append_pair(k, v);
    }
    format!("/arsenals/thanatos/search?{}", ser.finish())
}

/// A `YYYY-MM-DD` filter value as the start-of-day UTC instant (`None` if
/// unset/unparseable). Interpreted as UTC -- a deliberate simplification for a
/// date-granularity filter.
fn parse_date_start(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let date = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    date.and_hms_opt(0, 0, 0)
        .map(|ndt| chrono::DateTime::from_naive_utc_and_offset(ndt, chrono::Utc))
}

/// A `YYYY-MM-DD` filter value as the inclusive end-of-day UTC instant.
fn parse_date_end(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let date = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    date.and_hms_micro_opt(23, 59, 59, 999_999)
        .map(|ndt| chrono::DateTime::from_naive_utc_and_offset(ndt, chrono::Utc))
}

/// The cross-host SIEM investigation console (M3): full-text + faceted search
/// over every stored security event, with pagination and the same
/// acknowledge/resolve/suppress lifecycle actions the per-host page has.
pub async fn search(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    RawQuery(raw): RawQuery,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    let params = parse_search_params(raw.as_deref());

    let mut filter = repo::security_events::EventSearchFilter {
        only_active: !params.show_resolved,
        ..Default::default()
    };
    if !params.host.is_empty()
        && let Ok(id) = Uuid::parse_str(&params.host)
    {
        filter.host_id = Some(id);
    }
    if !params.source.is_empty() {
        filter.source = Some(params.source.clone());
    }
    if !params.severity.is_empty() {
        filter.severity = Severity::from_key(&params.severity);
    }
    if !params.technique.is_empty() {
        filter.technique = Some(params.technique.clone());
    }
    if !params.text.is_empty() {
        filter.text = Some(params.text.clone());
    }
    filter.from = parse_date_start(&params.from);
    filter.to = parse_date_end(&params.to);

    // Facets for the filter dropdowns.
    let all_hosts = repo::hosts::list(&state.pool).await?;
    let host_names: HashMap<Uuid, String> =
        all_hosts.iter().map(|h| (h.id, h.name.clone())).collect();
    let hosts: Vec<FacetHost> = all_hosts
        .iter()
        .map(|h| FacetHost {
            id: h.id.to_string(),
            name: h.name.clone(),
        })
        .collect();
    let sources = repo::security_events::distinct_sources(&state.pool).await?;
    let techniques = repo::security_events::distinct_techniques(&state.pool).await?;

    // Count, clamp the page, fetch the result window.
    let total = repo::security_events::count_events(&state.pool, &filter).await? as u64;
    let (_, per_page) = pagination::normalize(
        Some(params.page),
        Some(SEARCH_PER_PAGE),
        SEARCH_PER_PAGE,
        pagination::MAX_PER_PAGE,
    );
    let total_pages = pagination::total_pages(total, per_page);
    let page_num = params.page.max(1).min(total_pages.max(1));
    let offset = pagination::offset(page_num, per_page);
    let events =
        repo::security_events::search_events(&state.pool, &filter, i64::from(per_page), offset)
            .await?;

    let results: Vec<SearchResultRow> = events
        .into_iter()
        .map(|e| {
            let host_id = e.host_id;
            let host_name = host_names
                .get(&host_id)
                .cloned()
                .unwrap_or_else(|| "(removed host)".to_string());
            SearchResultRow {
                host_id: host_id.to_string(),
                host_name,
                event: security_event_row(e, &ctx.user.timezone),
            }
        })
        .collect();

    // Pagination links preserve every active filter.
    let link_params = search_link_params(&params);
    let page_meta = pagination::Page::<()>::new(Vec::new(), page_num, per_page, total);
    let page = pagination::numbered_page_info(&page_meta, |p| {
        let refs: Vec<(&str, &str)> = link_params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        pagination::page_link("/arsenals/thanatos/search", &refs, p)
    });

    // Toggle-resolved link: same filters, flipped show_resolved, back to page 1.
    let mut toggle_params = link_params.clone();
    toggle_params.retain(|(k, _)| *k != "show_resolved");
    if !params.show_resolved {
        toggle_params.push(("show_resolved", "1".to_string()));
    }
    let toggle_resolved_href = search_href(&toggle_params);

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

    let tpl = ThanatosSearchTemplate {
        base,
        can_manage: ctx.has(Permission::SecurityManage),
        can_respond: ctx.has(Permission::IncidentsRespond),
        f_host: params.host,
        f_source: params.source,
        f_severity: params.severity,
        f_technique: params.technique,
        f_text: params.text,
        f_from: params.from,
        f_to: params.to,
        show_resolved: params.show_resolved,
        hosts,
        sources,
        techniques,
        results,
        page,
        toggle_resolved_href,
        clear_href: "/arsenals/thanatos/search".to_string(),
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

// ---- Suppression / allowlist rules (M4) -----------------------------------

/// Minimum length for a `text_contains` allowlist value -- a one- or two-char
/// token would match far too broadly, so creation rejects it.
const MIN_TEXT_CONTAINS_LEN: usize = 3;

fn optional_trimmed(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// The suppression/allowlist rule management page (`security.manage`).
pub async fn rules(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;

    let all = repo::thanatos_suppression_rules::list_all(&state.pool).await?;
    let all_hosts = repo::hosts::list(&state.pool).await?;
    let host_names: HashMap<Uuid, String> =
        all_hosts.iter().map(|h| (h.id, h.name.clone())).collect();
    let hosts: Vec<FacetHost> = all_hosts
        .iter()
        .map(|h| FacetHost {
            id: h.id.to_string(),
            name: h.name.clone(),
        })
        .collect();
    let sources = repo::security_events::distinct_sources(&state.pool).await?;
    let techniques = repo::security_events::distinct_techniques(&state.pool).await?;

    let now = chrono::Utc::now();
    let rules: Vec<SuppressionRuleView> = all
        .into_iter()
        .map(|r| {
            let scope = match r.host_id {
                None => "All hosts".to_string(),
                Some(h) => host_names
                    .get(&h)
                    .cloned()
                    .unwrap_or_else(|| format!("host {h}")),
            };
            let active = r.expires_at.is_none_or(|e| e > now);
            SuppressionRuleView {
                id: r.id.to_string(),
                scope,
                source: r.source.unwrap_or_else(|| "any".to_string()),
                label: r.label.unwrap_or_else(|| "any".to_string()),
                technique: r.technique.unwrap_or_else(|| "any".to_string()),
                text_contains: r.text_contains.unwrap_or_else(|| "any".to_string()),
                reason: r.reason.unwrap_or_default(),
                created_at: crate::common::format_in_tz(r.created_at, &ctx.user.timezone),
                expires: match r.expires_at {
                    None => "Never".to_string(),
                    Some(e) => crate::common::format_in_tz(e, &ctx.user.timezone),
                },
                active,
            }
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
    let tpl = ThanatosRulesTemplate {
        base,
        rules,
        hosts,
        sources,
        techniques,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct CreateRuleForm {
    csrf_token: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    technique: String,
    #[serde(default)]
    text_contains: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    expires_days: String,
}

pub async fn create_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<CreateRuleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host_id = match optional_trimmed(&form.host) {
        Some(h) => Some(
            Uuid::parse_str(&h)
                .map_err(|_| WebError(AppError::Validation("Invalid host selection.".into())))?,
        ),
        None => None,
    };
    let source = optional_trimmed(&form.source);
    let label = optional_trimmed(&form.label);
    let technique = optional_trimmed(&form.technique);
    let text_contains = optional_trimmed(&form.text_contains);
    let reason = optional_trimmed(&form.reason);

    // At least one criterion, or the rule would suppress everything.
    if host_id.is_none()
        && source.is_none()
        && label.is_none()
        && technique.is_none()
        && text_contains.is_none()
    {
        return Err(WebError(AppError::Validation(
            "A rule needs at least one criterion (host, source, label, technique, or text).".into(),
        )));
    }
    // A too-short text token matches far too broadly.
    if let Some(t) = &text_contains
        && t.chars().count() < MIN_TEXT_CONTAINS_LEN
    {
        return Err(WebError(AppError::Validation(format!(
            "Text to match must be at least {MIN_TEXT_CONTAINS_LEN} characters."
        ))));
    }

    let expires_at = match optional_trimmed(&form.expires_days) {
        None => None,
        Some(d) => {
            let days: i64 = d.parse().map_err(|_| {
                WebError(AppError::Validation(
                    "Expiry must be a whole number of days.".into(),
                ))
            })?;
            if days <= 0 || days > 3650 {
                return Err(WebError(AppError::Validation(
                    "Expiry must be between 1 and 3650 days (leave blank for never).".into(),
                )));
            }
            Some(chrono::Utc::now() + chrono::Duration::days(days))
        }
    };

    repo::thanatos_suppression_rules::create(
        &state.pool,
        host_id,
        source.as_deref(),
        label.as_deref(),
        technique.as_deref(),
        text_contains.as_deref(),
        reason.as_deref(),
        Some(ctx.user.id),
        expires_at,
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("thanatos.suppression_rule"),
    )
    .await?;

    Ok(Redirect::to("/arsenals/thanatos/rules").into_response())
}

#[derive(Deserialize)]
pub struct DeleteRuleForm {
    csrf_token: String,
}

pub async fn delete_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(rule_id): Path<Uuid>,
    Form(form): Form<DeleteRuleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::thanatos_suppression_rules::delete(&state.pool, rule_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("thanatos.suppression_rule"),
    )
    .await?;

    Ok(Redirect::to("/arsenals/thanatos/rules").into_response())
}

// ---- Threat-intel IOCs (M5) -----------------------------------------------

/// The threat-intel IOC management page (`security.manage`).
pub async fn iocs(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;

    let all = repo::thanatos_iocs::list_all(&state.pool).await?;
    let now = chrono::Utc::now();
    let iocs: Vec<IocView> = all
        .into_iter()
        .map(|i| IocView {
            id: i.id.to_string(),
            ioc_type: i.ioc_type.to_string(),
            value: i.value,
            severity: i.severity.to_string(),
            label: i.label.unwrap_or_default(),
            created_at: crate::common::format_in_tz(i.created_at, &ctx.user.timezone),
            expires: match i.expires_at {
                None => "Never".to_string(),
                Some(e) => crate::common::format_in_tz(e, &ctx.user.timezone),
            },
            active: i.expires_at.is_none_or(|e| e > now),
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
    let tpl = ThanatosIocsTemplate { base, iocs };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct CreateIocsForm {
    csrf_token: String,
    ioc_type: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    values: String,
    #[serde(default)]
    expires_days: String,
}

pub async fn create_iocs(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<CreateIocsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let ioc_type = IocType::from_key(form.ioc_type.trim())
        .ok_or_else(|| WebError(AppError::Validation("Invalid IOC type.".into())))?;
    let severity = if form.severity.trim().is_empty() {
        Severity::High
    } else {
        Severity::from_key(form.severity.trim())
            .ok_or_else(|| WebError(AppError::Validation("Invalid severity.".into())))?
    };
    let label = optional_trimmed(&form.label);
    let expires_at = match optional_trimmed(&form.expires_days) {
        None => None,
        Some(d) => {
            let days: i64 = d.parse().map_err(|_| {
                WebError(AppError::Validation(
                    "Expiry must be a whole number of days.".into(),
                ))
            })?;
            if days <= 0 || days > 3650 {
                return Err(WebError(AppError::Validation(
                    "Expiry must be between 1 and 3650 days (leave blank for never).".into(),
                )));
            }
            Some(chrono::Utc::now() + chrono::Duration::days(days))
        }
    };

    // One indicator per line; normalize per type and skip blanks/duplicates.
    let mut added = 0usize;
    for raw in form.values.lines() {
        let Some(value) = ioc_type.normalize(raw) else {
            continue;
        };
        if value.len() > 255 {
            continue;
        }
        if repo::thanatos_iocs::create(
            &state.pool,
            ioc_type,
            &value,
            severity,
            label.as_deref(),
            Some(ctx.user.id),
            expires_at,
        )
        .await?
        {
            added += 1;
        }
    }

    if added == 0 {
        return Err(WebError(AppError::Validation(
            "No new indicators were added (all were blank or already present).".into(),
        )));
    }

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("thanatos.ioc")
            .metadata(serde_json::json!({ "added": added, "type": ioc_type.as_key() })),
    )
    .await?;

    Ok(Redirect::to("/arsenals/thanatos/iocs").into_response())
}

pub async fn delete_ioc(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(ioc_id): Path<Uuid>,
    Form(form): Form<DeleteRuleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::thanatos_iocs::delete(&state.pool, ioc_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("thanatos.ioc"),
    )
    .await?;

    Ok(Redirect::to("/arsenals/thanatos/iocs").into_response())
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
    render_host_with_suggestions(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        Vec::new(),
        Vec::new(),
        true,
    )
    .await
}

/// Same as `render_host`, but also renders a "Suggested Next Steps" section
/// from the workflow registry's matches against this result (`scan`, the
/// one action here that currently produces any) and, separately, an
/// "arrived here from a suggestion" banner for whatever `context` fields
/// came in from another arsenal's own suggestion targeting Thanatos (e.g.
/// Postmortem's or Inquest's -- see `crates/workflows/registry.json`) --
/// same context-banner pattern Inquest's/Postmortem's own host pages
/// already have. `only_active` -- Phase 3's alert-lifecycle filter (see
/// `repo::security_events::status_clause`); `scan`/`elevate` always pass
/// `true` (the default), since neither has a query string of its own to
/// read a "show resolved" preference back from -- only `show_host`, a
/// plain navigation, does.
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
    context: Vec<WorkflowContextRow>,
    only_active: bool,
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

    let mut events = Vec::new();
    for event in repo::security_events::list_recent_for_host(
        &state.pool,
        host_id,
        RECENT_EVENTS_LIMIT,
        only_active,
    )
    .await?
    {
        events.push(security_event_row(event, &ctx.user.timezone));
    }

    let show_resolved = !only_active;
    let toggle_resolved_href = format!(
        "/arsenals/thanatos/{host_id}{}",
        if show_resolved {
            ""
        } else {
            "?show_resolved=1"
        }
    );
    let os_label = crate::common::os_label(host.os.as_deref());
    let detection_sources_note = detection_sources_note(host.os.as_deref());

    let tpl = ThanatosHostTemplate {
        can_manage: ctx.has(Permission::SecurityManage),
        can_respond: ctx.has(Permission::IncidentsRespond),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        os_label,
        detection_sources_note,
        events,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        context,
        show_resolved,
        toggle_resolved_href,
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
    let only_active = query.get("show_resolved").map(String::as_str) != Some("1");
    render_host_with_suggestions(
        &state,
        &jar,
        &ctx,
        host_id,
        None,
        None,
        None,
        Vec::new(),
        workflow_context_rows(&query),
        only_active,
    )
    .await
}

#[derive(Deserialize)]
pub struct ScanForm {
    csrf_token: String,
}

pub async fn scan(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ScanForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Security Event Scan -- {}", host.name));

    let extra_fim_paths_raw = repo::settings::get_string(
        &state.pool,
        abyssal_core::settings::THANATOS_EXTRA_FIM_PATHS,
        "",
    )
    .await?;
    let extra_fim_paths = crate::thanatos_ops::extra_fim_paths_for(
        &crate::thanatos_ops::parse_extra_fim_paths(&extra_fim_paths_raw),
        host.os.as_deref(),
    );

    // Windows hosts read only events newer than their stored per-channel
    // high-water marks; empty (and ignored) for Linux.
    let channel_offsets = if host.os.as_deref() == Some("windows") {
        repo::thanatos_windows_log_offsets::offsets_for_host(&state.pool, host_id)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let c2_ports_raw = repo::settings::get_string(
        &state.pool,
        abyssal_core::settings::THANATOS_C2_PORTS,
        abyssal_core::settings::THANATOS_C2_PORTS_DEFAULT,
    )
    .await?;
    let c2_ports = crate::thanatos_ops::parse_c2_ports(&c2_ports_raw);

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ScanSecurityEvents {
                extra_fim_paths,
                channel_offsets,
                c2_ports,
                fast_only: false,
            },
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(30),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let recipients_raw = repo::settings::get_string(
                &state.pool,
                abyssal_core::settings::THANATOS_ALERT_RECIPIENTS,
                "",
            )
            .await?;
            let recipients = crate::thanatos_ops::parse_recipients(&recipients_raw);

            let ingest = crate::thanatos_ops::ingest_scan(
                &state.pool,
                &state.hosts,
                &state.notifications,
                &recipients,
                host_id,
                &host.name,
                &output.stdout,
            )
            .await;

            let mut suggested_actions = Vec::new();
            let summary = match ingest {
                Ok((persisted, informational, alerted)) => {
                    // Both lines are shown when both apply -- a scan can
                    // persist a FIM-drift event (`persisted > 0`) in the
                    // same run that found nothing in the auth/kernel/
                    // systemd sources it also reports on via `info`
                    // (`persisted == 0` there), and neither should be
                    // silently dropped in favor of the other.
                    let mut lines = vec![format!(
                        "{persisted} new event(s) persisted (already-seen lines from this scan \
                         window were skipped)."
                    )];
                    if let Some(message) = informational {
                        lines.push(message);
                    }
                    if alerted {
                        lines.push(
                            "A correlation alert was raised for this host -- see the Thanatos \
                             dashboard."
                                .to_string(),
                        );
                    }

                    let entry = serde_json::json!({
                        "persisted_count": persisted,
                        "alerted": alerted,
                    });
                    suggested_actions = crate::common::suggested_actions_for(
                        &state,
                        "thanatos",
                        "scan_security_events",
                        std::slice::from_ref(&entry),
                        host_id,
                    )
                    .await;

                    lines.join("\n")
                }
                Err(e) => format!("Scan completed, but failed to persist results: {e}"),
            };

            render_host_with_suggestions(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(summary),
                None,
                suggested_actions,
                Vec::new(),
                true,
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

// ---------------------------------------------------------------------
// Event lifecycle (Phase 3): acknowledge / resolve / suppress -- the
// first real use of `Permission::SecurityManage`. All three are plain
// `Write` actions (no type-to-confirm): they only ever change a status
// label and an optional note, never delete or affect anything on the
// managed host itself. No "reopen" transition exists yet -- resolved/
// suppressed is an end state for this pass (see `SecurityEventRow`'s doc
// comment).
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EventActionForm {
    csrf_token: String,
    #[serde(default)]
    note: String,
}

/// Shared by all three transitions below -- they differ only in which
/// `EventStatus`/`AuditAction` they use and whether a note makes sense to
/// attach (never trimmed away for acknowledge -- `note` is simply ignored
/// there, since the form field doesn't exist on that button's request).
async fn transition_event(
    state: &AppState,
    ctx: &AuthContext,
    event_id: Uuid,
    note: Option<&str>,
    status: EventStatus,
    audit_action: AuditAction,
) -> Result<Uuid, WebError> {
    let event = repo::security_events::find_by_id(&state.pool, event_id)
        .await?
        .ok_or(AppError::NotFound)?;

    repo::security_events::set_status(&state.pool, event_id, status, ctx.user.id, note).await?;

    if let Err(e) = abyssal_audit::record(
        &state.pool,
        AuditEvent::new(audit_action, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&event_id.to_string())
            .metadata(serde_json::json!({
                "host_id": event.host_id,
                "label": event.label,
                "note": note,
            })),
    )
    .await
    {
        tracing::error!(error = %e, event_id = %event_id, "failed to write audit record for Thanatos event lifecycle change");
    }

    Ok(event.host_id)
}

pub async fn acknowledge_event(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(event_id): Path<Uuid>,
    Form(form): Form<EventActionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host_id = transition_event(
        &state,
        &ctx,
        event_id,
        None,
        EventStatus::Acknowledged,
        AuditAction::SecurityEventAcknowledged,
    )
    .await?;
    Ok(Redirect::to(&format!("/arsenals/thanatos/{host_id}")).into_response())
}

fn trimmed_note(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

pub async fn resolve_event(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(event_id): Path<Uuid>,
    Form(form): Form<EventActionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host_id = transition_event(
        &state,
        &ctx,
        event_id,
        trimmed_note(&form.note),
        EventStatus::Resolved,
        AuditAction::SecurityEventResolved,
    )
    .await?;
    Ok(Redirect::to(&format!("/arsenals/thanatos/{host_id}")).into_response())
}

pub async fn suppress_event(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(event_id): Path<Uuid>,
    Form(form): Form<EventActionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host_id = transition_event(
        &state,
        &ctx,
        event_id,
        trimmed_note(&form.note),
        EventStatus::Suppressed,
        AuditAction::SecurityEventSuppressed,
    )
    .await?;
    Ok(Redirect::to(&format!("/arsenals/thanatos/{host_id}")).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_search_params_reads_every_filter() {
        let p = parse_search_params(Some(
            "q=lsass&host=abc&source=sysmon&severity=high&technique=T1003.001&from=2026-01-01&to=2026-01-31&show_resolved=1&page=3",
        ));
        assert_eq!(p.text, "lsass");
        assert_eq!(p.host, "abc");
        assert_eq!(p.source, "sysmon");
        assert_eq!(p.severity, "high");
        assert_eq!(p.technique, "T1003.001");
        assert_eq!(p.from, "2026-01-01");
        assert_eq!(p.to, "2026-01-31");
        assert!(p.show_resolved);
        assert_eq!(p.page, 3);
    }

    #[test]
    fn parse_search_params_defaults_page_to_one() {
        let p = parse_search_params(None);
        assert_eq!(p.page, 1);
        assert!(!p.show_resolved);
        assert!(p.text.is_empty());
        // A non-numeric/zero page falls back to 1.
        assert_eq!(parse_search_params(Some("page=0")).page, 1);
        assert_eq!(parse_search_params(Some("page=abc")).page, 1);
    }

    #[test]
    fn date_filters_cover_the_whole_day() {
        let start = parse_date_start("2026-01-15").unwrap();
        let end = parse_date_end("2026-01-15").unwrap();
        assert_eq!(start.to_rfc3339(), "2026-01-15T00:00:00+00:00");
        assert!(end > start);
        assert_eq!(parse_date_start(""), None);
        assert_eq!(parse_date_start("not-a-date"), None);
    }

    #[test]
    fn search_href_preserves_set_filters_only() {
        let p = parse_search_params(Some("q=foo&severity=high&page=2"));
        let href = search_href(&search_link_params(&p));
        assert!(href.starts_with("/arsenals/thanatos/search?"));
        assert!(href.contains("q=foo"));
        assert!(href.contains("severity=high"));
        // page isn't a link param (pagination adds it separately).
        assert!(!href.contains("page="));
        // Empty filters produce the bare path.
        assert_eq!(
            search_href(&search_link_params(&parse_search_params(None))),
            "/arsenals/thanatos/search"
        );
    }

    #[test]
    fn alerted_scan_suggests_inquest_and_postmortem() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "persisted_count": 5, "alerted": true });

        let matches = registry
            .evaluate("thanatos", "scan_security_events", &entry)
            .matches;
        let targets: Vec<&str> = matches.iter().map(|m| m.target_arsenal.as_str()).collect();

        assert!(targets.contains(&"inquest"));
        assert!(targets.contains(&"postmortem"));
    }

    #[test]
    fn non_alerted_scan_suggests_nothing() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "persisted_count": 3, "alerted": false });

        assert!(
            registry
                .evaluate("thanatos", "scan_security_events", &entry)
                .matches
                .is_empty()
        );
    }
}
