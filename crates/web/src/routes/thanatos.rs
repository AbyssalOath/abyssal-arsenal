use std::collections::{HashMap, HashSet};
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    THANATOS_DASHBOARD_RENDER_BUDGET, THANATOS_DASHBOARD_RENDER_BUDGET_DEFAULT,
};
use abyssal_core::{AppError, EventStatus, Permission, Severity};
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
    AlertRow, BaseCtx, GroupPageInfo, SecurityEventRow, SeverityCountRow, SuggestedActionView,
    ThanatosHostGroup, ThanatosHostTemplate, ThanatosTemplate,
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
             logging and Windows Defender's log where enabled, and hashes its hosts file, \
             machine-wide Run keys, and local Administrators membership for tampering."
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

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ScanSecurityEvents { extra_fim_paths },
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
