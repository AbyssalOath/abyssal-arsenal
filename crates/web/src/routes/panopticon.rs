use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    PANOPTICON_INVENTORY_RENDER_BUDGET, PANOPTICON_INVENTORY_RENDER_BUDGET_DEFAULT,
    PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS, PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS,
    PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS, PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS,
    PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS, PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS,
};
use abyssal_core::{
    AppError, DeviceType, MacroScope, NetworkDevice, Permission, SnmpAuthProtocol,
    SnmpPrivProtocol, SnmpSecurityLevel, SnmpVersion, TrustState,
};
use abyssal_database::repo;
use abyssal_database::repo::network_devices::GroupCount;
use abyssal_execution::OperationParams;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, RawQuery, State};
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
use crate::pagination;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, GroupPageInfo, InventoryGroup, NetworkDeviceRow, PanopticonClassifyTemplate,
    PanopticonTemplate,
};
use crate::theme;

/// Devices within an open subnet group's own row pagination (GitHub issue
/// #10) -- deliberately smaller than a typical list-view default since
/// several groups can be open on the page at once.
const GROUP_ROWS_PER_PAGE: u32 = 50;

/// How many subnet groups the group *list* itself shows per page --
/// independent of `GROUP_ROWS_PER_PAGE`, which paginates the rows inside
/// one already-open group.
const GROUPS_PER_PAGE: u32 = 25;

/// The literal `network` value/query-param sentinel standing in for the
/// "Unassigned / Unknown" group (devices whose `ip_address` never parsed
/// into a `network`) -- never a value `abyssal_core::normalize_cidr` could
/// itself produce, so it can't collide with a real subnet.
const UNASSIGNED: &str = "unassigned";

/// Every Device Inventory query-string param this page understands, parsed
/// once via [`parse_inventory_query`] and threaded through instead of
/// re-parsing `RawQuery` at every call site. Also doubles as the one place
/// that knows how to re-serialize itself (see [`InventoryQuery::href`]),
/// so every link on the page -- "Load devices", a per-group Prev/Next, the
/// group-list pager, the filtered-view pager -- preserves every other
/// active param instead of each hand-rolling its own query string.
#[derive(Default, Clone)]
pub(crate) struct InventoryQuery {
    /// `?port=` -- the existing open-port filter, composed with grouping.
    pub port: Option<u16>,
    /// `?subnet=` -- an ad-hoc CIDR filter that replaces the grouped view
    /// entirely with one filtered, paginated table (GitHub issue #10's
    /// "filters to one group" requirement; accepts any valid CIDR, not
    /// just one that happens to match the configured grouping prefix).
    pub subnet: Option<String>,
    /// Repeatable `?open=<network>` -- which groups render their body
    /// even when the render budget would otherwise leave them collapsed.
    /// Server-rendered back into `details[open]` so state survives
    /// reloads and is shareable, per GitHub issue #10.
    pub open: Vec<String>,
    /// `?group_page=` -- which page of the subnet *list itself* to show,
    /// independent of any single group's own row pagination.
    pub group_page: Option<u32>,
    /// Repeatable `?gp=<network>:<page>` -- one subnet group's own row
    /// page, keyed by network so multiple open groups don't collide. The
    /// scheme is a single repeatable key with a `network:page` value
    /// (rather than dynamic bracket keys like `gp[10.0.1.0/24]=2`) since
    /// axum/serde_urlencoded can't deserialize either shape automatically
    /// either way, and a flat repeatable pair is simpler to hand-parse.
    pub gp: Vec<(String, u32)>,
    /// `?page=` -- the ad-hoc filtered view's own row page (only
    /// meaningful together with `subnet`; the grouped view uses
    /// `group_page`/`gp` instead so the two pagers never share a key).
    pub page: Option<u32>,
}

impl InventoryQuery {
    fn with_open(&self, network: &str) -> Self {
        let mut q = self.clone();
        if !q.open.iter().any(|o| o == network) {
            q.open.push(network.to_string());
        }
        q
    }

    fn with_gp(&self, network: &str, page: u32) -> Self {
        let mut q = self.clone();
        q.gp.retain(|(n, _)| n != network);
        if page > 1 {
            q.gp.push((network.to_string(), page));
        }
        q
    }

    fn with_group_page(&self, page: u32) -> Self {
        let mut q = self.clone();
        q.group_page = if page > 1 { Some(page) } else { None };
        q
    }

    fn with_page(&self, page: u32) -> Self {
        let mut q = self.clone();
        q.page = if page > 1 { Some(page) } else { None };
        q
    }

    fn without_subnet(&self) -> Self {
        let mut q = self.clone();
        q.subnet = None;
        q.page = None;
        q
    }

    /// Re-serializes every active param back into `/arsenals/panopticon`'s
    /// query string -- the one place a Device Inventory link is built, so
    /// "preserve every other filter/sort param" (GitHub issue #10) is
    /// guaranteed rather than re-implemented per link site.
    fn href(&self) -> String {
        if self.port.is_none()
            && self.subnet.is_none()
            && self.open.is_empty()
            && self.group_page.is_none()
            && self.gp.is_empty()
            && self.page.is_none()
        {
            return "/arsenals/panopticon".to_string();
        }
        let mut ser = form_urlencoded::Serializer::new(String::new());
        if let Some(p) = self.port {
            ser.append_pair("port", &p.to_string());
        }
        if let Some(s) = &self.subnet {
            ser.append_pair("subnet", s);
        }
        for o in &self.open {
            ser.append_pair("open", o);
        }
        if let Some(p) = self.group_page {
            ser.append_pair("group_page", &p.to_string());
        }
        for (net, page) in &self.gp {
            ser.append_pair("gp", &format!("{net}:{page}"));
        }
        if let Some(p) = self.page {
            ser.append_pair("page", &p.to_string());
        }
        format!("/arsenals/panopticon?{}", ser.finish())
    }
}

/// Parses the Device Inventory's raw query string into an [`InventoryQuery`]
/// -- a plain `Query<T>` extractor can't deserialize the repeated `open=`
/// values into a `Vec` or the dynamic-ish `gp=network:page` pairs, so this
/// hand-parses via `form_urlencoded` (the same "repeated-key form groups
/// need manual parsing" pattern already used for permissions/module
/// checkboxes elsewhere in this app). A malformed `gp`/`group_page`/`port`
/// value is silently dropped rather than rejected -- falls back to that
/// param's default, never a 500 on a hand-edited or stale bookmark.
pub(crate) fn parse_inventory_query(raw: Option<&str>) -> InventoryQuery {
    let mut q = InventoryQuery::default();
    let Some(raw) = raw else { return q };
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "port" => q.port = value.trim().parse::<u16>().ok(),
            "subnet" => {
                let v = value.trim();
                if !v.is_empty() {
                    q.subnet = Some(v.to_string());
                }
            }
            "open" => {
                let v = value.trim();
                if !v.is_empty() && !q.open.iter().any(|o| o == v) {
                    q.open.push(v.to_string());
                }
            }
            "group_page" => q.group_page = value.trim().parse::<u32>().ok(),
            "gp" => {
                if let Some((net, page)) = value.split_once(':')
                    && !net.is_empty()
                    && let Ok(page) = page.parse::<u32>()
                {
                    q.gp.retain(|(n, _)| n != net);
                    q.gp.push((net.to_string(), page));
                }
            }
            "page" => q.page = value.trim().parse::<u32>().ok(),
            _ => {}
        }
    }
    q
}

/// Builds one inventory row's view-model from a fetched [`NetworkDevice`] --
/// shared by the grouped view and the ad-hoc filtered view so both render
/// devices identically.
fn build_device_row(
    d: NetworkDevice,
    managed_by_ip: &HashMap<String, String>,
    switch_names: &HashMap<Uuid, String>,
    timezone: &str,
) -> NetworkDeviceRow {
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
        first_seen_at: crate::common::format_in_tz(d.first_seen_at, timezone),
        last_seen_at: crate::common::format_in_tz(d.last_seen_at, timezone),
        stale,
        switch_location,
    }
}

pub(crate) async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    query: InventoryQuery,
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
    let switches = repo::panopticon_switches::list(&state.pool).await?;
    let switch_names: HashMap<Uuid, String> =
        switches.into_iter().map(|s| (s.id, s.name)).collect();

    let can_scan = ctx.has(Permission::NetworkScan);
    let can_manage = ctx.has(Permission::NetworkManage);
    let can_deploy = ctx.has(Permission::HostsManage);
    let render_budget = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_INVENTORY_RENDER_BUDGET,
        PANOPTICON_INVENTORY_RENDER_BUDGET_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_INVENTORY_RENDER_BUDGET_DEFAULT);
    let total_device_count = repo::network_devices::total_count(&state.pool).await?;

    // An ad-hoc `?subnet=` filter replaces the grouped view entirely with
    // one filtered, paginated table -- GitHub issue #10's "filters to one
    // group" requirement. An invalid value falls through to the normal
    // grouped view with an error banner instead of a 500 or a silently
    // ignored filter.
    if let Some(raw_subnet) = query
        .subnet
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && let Some((addr, prefix)) = abyssal_core::parse_cidr(raw_subnet)
    {
        let canonical =
            abyssal_core::normalize_cidr(raw_subnet).unwrap_or_else(|| raw_subnet.to_string());
        let (start_ip, end_ip) = abyssal_core::subnet_bounds(addr, prefix);
        let total = repo::network_devices::count_in_range(&state.pool, &start_ip, &end_ip).await?;
        let requested_page = query.page.unwrap_or(1).max(1);
        let total_u64 = total.max(0) as u64;
        let page_num = if pagination::Page::<()>::page_out_of_range(
            requested_page,
            GROUP_ROWS_PER_PAGE,
            total_u64,
        ) {
            pagination::total_pages(total_u64, GROUP_ROWS_PER_PAGE)
        } else {
            requested_page
        };
        let offset = pagination::offset(page_num, GROUP_ROWS_PER_PAGE);
        let rows = repo::network_devices::list_page_in_range(
            &state.pool,
            &start_ip,
            &end_ip,
            i64::from(GROUP_ROWS_PER_PAGE),
            offset,
        )
        .await?;
        let device_rows: Vec<NetworkDeviceRow> = rows
            .into_iter()
            .map(|d| build_device_row(d, &managed_by_ip, &switch_names, &ctx.user.timezone))
            .collect();
        let page_meta: pagination::Page<()> =
            pagination::Page::new(vec![], page_num, GROUP_ROWS_PER_PAGE, total_u64);
        let filtered_page = Some(pagination::numbered_page_info(&page_meta, |p| {
            query.with_page(p).href()
        }));

        let tpl = PanopticonTemplate {
            base,
            can_scan,
            can_manage,
            can_deploy,
            port_filter: query.port.map(|p| p.to_string()).unwrap_or_default(),
            total_device_count,
            render_budget,
            groups: vec![],
            group_list_page: None,
            subnet_filter_input: raw_subnet.to_string(),
            subnet_filter_error: None,
            filtered_subnet: Some(canonical),
            clear_subnet_href: Some(query.without_subnet().href()),
            filtered_devices: device_rows,
            filtered_page,
            result_label,
            result_output,
            result_error,
        };
        let jar = jar.clone();
        let jar = match new_cookie {
            Some(c) => jar.add(c),
            None => jar,
        };
        return Ok((jar, tpl).into_response());
    }

    let subnet_filter_error = query
        .subnet
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            format!(
                "\"{s}\" isn't a valid CIDR -- expected an address and prefix length, e.g. \
                 10.0.1.0/24 or 2001:db8::/64."
            )
        });

    // Grouped view: header counts for every subnet group always render
    // (one aggregate query, no N+1); a group's own device rows only render
    // when it's explicitly `open=`-named, or every group renders open when
    // the whole filtered inventory fits under the render budget.
    let counts: Vec<GroupCount> =
        repo::network_devices::group_counts(&state.pool, query.port).await?;
    let total_matching: i64 = counts.iter().map(|c| c.device_count).sum();
    let render_all = total_matching.max(0) as u64 <= u64::from(render_budget);
    let open_set: HashSet<&str> = query.open.iter().map(String::as_str).collect();
    let gp_map: HashMap<&str, u32> = query.gp.iter().map(|(n, p)| (n.as_str(), *p)).collect();

    let group_total = counts.len() as u64;
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
    for gc in counts
        .iter()
        .skip(group_offset)
        .take(GROUPS_PER_PAGE as usize)
    {
        let network_key = gc.network.clone().unwrap_or_else(|| UNASSIGNED.to_string());
        let display_label = gc
            .network
            .clone()
            .unwrap_or_else(|| "Unassigned / Unknown".to_string());
        let is_unassigned = gc.network.is_none();
        let is_open = render_all || open_set.contains(network_key.as_str());

        let (devices, page_info, open_href) = if is_open {
            let requested_page = gp_map
                .get(network_key.as_str())
                .copied()
                .unwrap_or(1)
                .max(1);
            let total = gc.device_count.max(0) as u64;
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
            let rows = repo::network_devices::list_page(
                &state.pool,
                gc.network.as_deref(),
                query.port,
                i64::from(GROUP_ROWS_PER_PAGE),
                offset,
            )
            .await?;
            let device_rows: Vec<NetworkDeviceRow> = rows
                .into_iter()
                .map(|d| build_device_row(d, &managed_by_ip, &switch_names, &ctx.user.timezone))
                .collect();
            let page_meta: pagination::Page<()> =
                pagination::Page::new(vec![], page_num, GROUP_ROWS_PER_PAGE, total);
            let opened = query.with_open(&network_key);
            let gpi = GroupPageInfo {
                current_page: page_meta.page,
                total_pages: page_meta.total_pages,
                range_start: page_meta.start_index(),
                range_end: page_meta.end_index(),
                total: page_meta.total,
                prev_href: page_meta
                    .has_prev()
                    .then(|| opened.with_gp(&network_key, page_meta.page - 1).href()),
                next_href: page_meta
                    .has_next()
                    .then(|| opened.with_gp(&network_key, page_meta.page + 1).href()),
            };
            (device_rows, Some(gpi), None)
        } else {
            (vec![], None, Some(query.with_open(&network_key).href()))
        };

        let rescan_href = (!is_unassigned).then(|| {
            format!(
                "/arsenals/panopticon/scan/confirm?target={}",
                urlencoding_encode(&network_key)
            )
        });
        let remove_href = Some(format!(
            "/arsenals/panopticon/subnets/remove/confirm?subnet={}",
            urlencoding_encode(&network_key)
        ));

        let scroll_aria_label = format!("Devices in {display_label}");
        groups.push(InventoryGroup {
            display_label,
            is_unassigned,
            device_count: gc.device_count,
            managed_count: gc.managed_count,
            is_open,
            devices,
            open_href,
            scroll_aria_label,
            page_info,
            rescan_href,
            remove_href,
            network: network_key,
        });
    }

    let tpl = PanopticonTemplate {
        base,
        can_scan,
        can_manage,
        can_deploy,
        port_filter: query.port.map(|p| p.to_string()).unwrap_or_default(),
        total_device_count,
        render_budget,
        groups,
        group_list_page,
        subnet_filter_input: query.subnet.clone().unwrap_or_default(),
        subnet_filter_error,
        filtered_subnet: None,
        clear_subnet_href: None,
        filtered_devices: vec![],
        filtered_page: None,
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
    RawQuery(raw): RawQuery,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    let query = parse_inventory_query(raw.as_deref());
    render(&state, &jar, &ctx, query, None, None, None).await
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

/// Whether `target` has been scanned before -- a CIDR target counts as
/// known when at least one inventory device's numeric address already
/// falls inside it (real range containment via `abyssal_core::subnet_bounds`
/// and `count_in_range`, not the /24-string-match heuristic this used
/// before GitHub issue #10 -- and, unlike the old implementation, this
/// never fetches the whole inventory to answer the question); a single
/// host/IP counts as known when it's already in the inventory. Used to
/// decide whether the heavy "type the target to confirm" dialog is
/// warranted (a genuinely new target) or just friction (a rescan of
/// something already vetted once). An unparseable CIDR target is treated
/// as unknown -- `validate_scan_query` already rejected it before this is
/// ever called in practice, so this is defense in depth, not the primary
/// validation.
async fn has_scan_history(pool: &abyssal_database::DbPool, target: &str) -> Result<bool, WebError> {
    if target.contains('/') {
        match abyssal_core::parse_cidr(target) {
            Some((addr, prefix)) => {
                let (start_ip, end_ip) = abyssal_core::subnet_bounds(addr, prefix);
                let count = repo::network_devices::count_in_range(pool, &start_ip, &end_ip).await?;
                Ok(count > 0)
            }
            None => Ok(false),
        }
    } else {
        Ok(repo::network_devices::find_by_ip(pool, target)
            .await?
            .is_some())
    }
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
    let known = has_scan_history(&state.pool, &target).await?;

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

    // Known targets (already in the inventory/topology) skip the "type the
    // target to confirm" friction -- that's a real safety guardrail for a
    // target nobody here has ever scanned before, not something a routine
    // rescan needs every time. `scan()` itself independently re-checks
    // `known` before honoring a plain `confirm=true` without confirm_text,
    // so this is only a UI shortcut, not the actual safety boundary.
    let (title, message, type_to_confirm) = if known {
        (
            "Rescan".to_string(),
            format!(
                "Rescan \"{target}\"{}? This re-sends real network traffic to a target already \
                 in the inventory.",
                match &ports {
                    Some(p) => format!(" (ports: {p})"),
                    None => String::new(),
                }
            ),
            None,
        )
    } else {
        (
            "Run discovery scan".to_string(),
            format!(
                "This will run an nmap TCP connect scan from the control plane against \
                 \"{target}\"{}. This sends real network traffic to that target and may trigger \
                 intrusion detection there or in between -- only scan targets you're authorized \
                 to scan. Discovered devices are added to the inventory below.",
                match &ports {
                    Some(p) => format!(" (ports: {p})"),
                    None => String::new(),
                }
            ),
            Some(crate::templates::TypeToConfirm {
                label: "scan target".to_string(),
                expected: target.clone(),
            }),
        )
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title,
        message,
        action_url,
        cancel_url: "/arsenals/panopticon".to_string(),
        escalate_host_id: None,
        type_to_confirm,
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

/// Starts the scan as a detached background job and redirects to its
/// progress page instead of blocking this request until nmap finishes --
/// see `routes/panopticon_scan.rs` for the progress/status/results
/// handlers and `panopticon_ops::run_scan_job` for the job itself. Every
/// entry point that posts here (the dashboard's own scan form, and the
/// Topology page's one-click Rescan button) gets the progress bar for
/// free, since they all funnel through this one handler.
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
    // Re-checked independently of whatever the confirm page decided to
    // show -- a crafted POST that skips straight here still only gets to
    // skip the typed confirmation for a target that's genuinely already
    // known, never for a brand-new one.
    let known = has_scan_history(&state.pool, &target).await?;
    if !known {
        crate::common::require_typed_confirmation(&form.confirm_text, &target)?;
    }
    let rescan_notice = known.then(|| format!("Rescan of {target} complete."));

    let hosts_total = crate::panopticon_ops::target_host_count(&target);
    let job_id = Uuid::new_v4();
    let job = std::sync::Arc::new(tokio::sync::RwLock::new(
        crate::panopticon_ops::ScanJob::new(job_id, target.clone(), hosts_total, rescan_notice),
    ));
    state.scan_jobs.write().await.insert(job_id, job.clone());

    tokio::spawn(crate::panopticon_ops::run_scan_job(
        state.executor.clone(),
        state.pool.clone(),
        ctx,
        job,
        target,
        ports,
    ));

    Ok(Redirect::to(&format!("/arsenals/panopticon/scan/status/{job_id}")).into_response())
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
// Subnet actions -- a subnet group is purely a grouping of devices by
// their persisted `network` column (GitHub issue #10), never a stored
// entity of its own. "Rescan" needs no dedicated route at all -- it's
// just a link into the existing scan-confirm flow with the subnet as the
// target (see panopticon.html). "Remove" does need one: the only way to
// make a group stop appearing is removing every device that currently
// falls into it. `subnet` in the query string here is a group's `network`
// key -- either a canonical CIDR string or the literal `"unassigned"`
// sentinel (see `UNASSIGNED`), matching whatever `InventoryGroup::network`
// the page itself linked from.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SubnetQuery {
    subnet: String,
}

/// `q.subnet` back into the `Option<&str>` shape every `repo::network_devices`
/// grouping function expects -- `None` for the `UNASSIGNED` sentinel.
fn group_network(subnet: &str) -> Option<&str> {
    (subnet != UNASSIGNED).then_some(subnet)
}

pub async fn subnet_remove_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<SubnetQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;

    let subnet = q.subnet.trim().to_string();
    let display = if subnet == UNASSIGNED {
        "Unassigned / Unknown".to_string()
    } else {
        subnet.clone()
    };
    let ids =
        repo::network_devices::list_ids_for_group(&state.pool, group_network(&subnet)).await?;
    let count = ids.len();

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
        title: "Remove subnet group from inventory".to_string(),
        message: format!(
            "This will remove all {count} device(s) currently grouped under \"{display}\" \
             from the network device inventory -- there's no separate \"group\" record to \
             delete, this has the same effect as removing each of those devices individually. \
             They reappear if a future scan finds them again -- this doesn't block or affect \
             the devices themselves."
        ),
        action_url: format!(
            "/arsenals/panopticon/subnets/remove?subnet={}",
            urlencoding_encode(&subnet)
        ),
        cancel_url: "/arsenals/panopticon".to_string(),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "subnet".to_string(),
            expected: subnet.clone(),
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
pub struct RemoveSubnetForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn subnet_remove(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<SubnetQuery>,
    Form(form): Form<RemoveSubnetForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let subnet = q.subnet.trim().to_string();
    crate::common::require_typed_confirmation(&form.confirm_text, &subnet)?;

    let ids_and_ips =
        repo::network_devices::list_ids_for_group(&state.pool, group_network(&subnet)).await?;
    let ids: Vec<Uuid> = ids_and_ips.iter().map(|(id, _)| *id).collect();
    let ip_addresses: Vec<String> = ids_and_ips.into_iter().map(|(_, ip)| ip).collect();

    let removed = repo::network_devices::delete_by_ids(&state.pool, &ids).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkSubnetRemoved, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&subnet)
            .metadata(serde_json::json!({
                "devices_removed": removed,
                "ip_addresses": ip_addresses,
            })),
    )
    .await?;

    Ok(Redirect::to("/arsenals/panopticon").into_response())
}

/// "Re-derive subnets" -- recomputes every device's `network` column using
/// whatever `panopticon.subnet_prefix_v4`/`_v6` is configured right now.
/// Only needed after deliberately changing that prefix (an ordinary
/// scan/sighting already keeps `network` current going forward via
/// `current_network_of`); the automatic startup backfill
/// (`crates/app/src/main.rs`) only ever touches rows that are still
/// `NULL`, so this is the explicit counterpart for rows that already have
/// a (now stale) value. Gated the same as every other inventory-mutating
/// action here (`network.manage`); no confirmation dialog since it only
/// recomputes a derived value, never deletes anything.
#[derive(Deserialize)]
pub struct RederiveSubnetsForm {
    csrf_token: String,
}

pub async fn subnets_rederive(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<RederiveSubnetsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let updated = repo::network_devices::rederive_all_networks(&state.pool).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkSubnetsRederived, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .metadata(serde_json::json!({ "devices_updated": updated })),
    )
    .await?;

    render(
        &state,
        &jar,
        &ctx,
        InventoryQuery::default(),
        Some("Re-derive subnets".to_string()),
        Some(format!(
            "Recomputed the subnet group for {updated} device(s) using the currently configured prefixes."
        )),
        None,
    )
    .await
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

/// (`T::as_str()` key, label, is this the currently-selected value) for
/// one of the four SNMP dropdowns, built fresh each render from the
/// enum's own `ALL`/`as_str`/`label` rather than duplicating that list in
/// template data.
fn snmp_options<T: Copy + PartialEq>(
    all: &'static [T],
    current: T,
    as_str: impl Fn(T) -> &'static str,
    label: impl Fn(T) -> &'static str,
) -> Vec<(&'static str, &'static str, bool)> {
    all.iter()
        .map(|&v| (as_str(v), label(v), v == current))
        .collect()
}

/// Validates that the fields required by `snmp_version` were actually
/// supplied, returning the exact user-facing message naming what's
/// missing. Pure (no DB, no encryption) so it's directly unit-testable --
/// see `tests::snmp_validation` below.
fn validate_snmp_fields(
    snmp_version: SnmpVersion,
    community: &str,
    v3_username: &str,
    v3_security_level: SnmpSecurityLevel,
    v3_auth_password: &str,
    v3_priv_password: &str,
) -> Result<(), &'static str> {
    match snmp_version {
        SnmpVersion::V1 | SnmpVersion::V2c => {
            if community.is_empty() {
                Err("Community string is required for SNMP v1/v2c.")
            } else {
                Ok(())
            }
        }
        SnmpVersion::V3 => {
            if v3_username.is_empty() {
                return Err("Security username is required for SNMP v3.");
            }
            if v3_security_level != SnmpSecurityLevel::NoAuthNoPriv && v3_auth_password.is_empty() {
                return Err("Authentication password is required for this SNMP v3 security level.");
            }
            if v3_security_level == SnmpSecurityLevel::AuthPriv && v3_priv_password.is_empty() {
                return Err("Privacy password is required for the authPriv security level.");
            }
            Ok(())
        }
    }
}

/// Every SNMP community-string macro visible to this user (their own
/// personal ones plus their roles') -- Panopticon's add-switch "Load"
/// list. `can_edit` is only true for the macro's owner or someone with
/// `Permission::MacrosManageAll`.
async fn visible_community_macro_rows(
    state: &AppState,
    ctx: &AuthContext,
) -> anyhow::Result<Vec<crate::templates::CommunityMacroRow>> {
    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let role_ids: Vec<Uuid> = user_roles.iter().map(|r| r.id).collect();
    let macros = repo::macros::list_visible_to_user(
        &state.pool,
        ctx.user.id,
        &role_ids,
        abyssal_core::MacroType::CommunityString,
    )
    .await?;

    let all_roles = repo::roles::list(&state.pool).await?;
    let role_name = |id: Uuid| -> String {
        all_roles
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "unknown role".to_string())
    };

    Ok(macros
        .into_iter()
        .map(|m| {
            let can_edit = m.owner_user_id == ctx.user.id || ctx.has(Permission::MacrosManageAll);
            let scope_label = match m.scope {
                MacroScope::Personal => "Personal".to_string(),
                MacroScope::Role => format!("Role: {}", role_name(m.role_id.unwrap_or_default())),
            };
            crate::templates::CommunityMacroRow {
                id: m.id.to_string(),
                name: m.name,
                scope_label,
                can_edit,
            }
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
async fn render_switches(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    result_label: Option<String>,
    result_output: Option<String>,
    mut result_error: Option<String>,
    load_macro: Option<Uuid>,
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

    let macros = visible_community_macro_rows(state, ctx).await?;
    let mut prefilled_community = String::new();
    if let Some(macro_id) = load_macro {
        let macro_id_str = macro_id.to_string();
        if macros.iter().any(|m| m.id == macro_id_str) {
            match (
                &state.encryption_key,
                repo::macros::find_by_id(&state.pool, macro_id).await?,
            ) {
                (Some(key), Some(m)) => match m.secret_value_encrypted.as_deref() {
                    Some(encrypted) => match key.decrypt(encrypted) {
                        Ok(value) => prefilled_community = value.to_string(),
                        Err(_) => result_error = Some("Could not decrypt that macro.".to_string()),
                    },
                    None => result_error = Some("That macro has no stored value.".to_string()),
                },
                (None, _) => {
                    result_error = Some(
                        "ENCRYPTION_KEY isn't configured -- can't decrypt that macro.".to_string(),
                    );
                }
                (_, None) => result_error = Some("That macro isn't available.".to_string()),
            }
        } else {
            result_error = Some("That macro isn't available.".to_string());
        }
    }

    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let macro_roles = user_roles
        .into_iter()
        .map(|r| (r.id.to_string(), r.name))
        .collect();

    let switches = repo::panopticon_switches::list(&state.pool).await?;
    let switch_rows = switches
        .into_iter()
        .map(|s| crate::templates::PanopticonSwitchRow {
            id: s.id.to_string(),
            name: s.name,
            ip_address: s.ip_address,
            snmp_port: s.snmp_port,
            snmp_version_label: s.snmp_version.label(),
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
        snmp_versions: snmp_options(
            SnmpVersion::ALL,
            SnmpVersion::default(),
            SnmpVersion::as_str,
            SnmpVersion::label,
        ),
        snmp_security_levels: snmp_options(
            SnmpSecurityLevel::ALL,
            SnmpSecurityLevel::default(),
            SnmpSecurityLevel::as_str,
            SnmpSecurityLevel::label,
        ),
        snmp_auth_protocols: snmp_options(
            SnmpAuthProtocol::ALL,
            SnmpAuthProtocol::default(),
            SnmpAuthProtocol::as_str,
            SnmpAuthProtocol::label,
        ),
        snmp_priv_protocols: snmp_options(
            SnmpPrivProtocol::ALL,
            SnmpPrivProtocol::default(),
            SnmpPrivProtocol::as_str,
            SnmpPrivProtocol::label,
        ),
        macros,
        macro_roles,
        prefilled_community,
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
pub struct SwitchesShowQuery {
    #[serde(default)]
    load_macro: Option<Uuid>,
}

pub async fn switches_show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<SwitchesShowQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkView)?;
    render_switches(&state, &jar, &ctx, None, None, None, q.load_macro).await
}

#[derive(Deserialize)]
pub struct SwitchAddForm {
    csrf_token: String,
    name: String,
    ip_address: String,
    #[serde(default)]
    snmp_port: String,
    #[serde(default)]
    snmp_version: String,
    #[serde(default)]
    community: String,
    #[serde(default)]
    snmp_v3_username: String,
    #[serde(default)]
    snmp_v3_security_level: String,
    #[serde(default)]
    snmp_v3_auth_protocol: String,
    #[serde(default)]
    snmp_v3_auth_password: String,
    #[serde(default)]
    snmp_v3_priv_protocol: String,
    #[serde(default)]
    snmp_v3_priv_password: String,
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
             credentials can't be stored safely without it."
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
    let snmp_version = SnmpVersion::from_str(form.snmp_version.trim()).map_err(|()| {
        WebError(AppError::Validation(
            "Not a recognized SNMP version.".into(),
        ))
    })?;

    let community = form.community.trim();
    let v3_username = form.snmp_v3_username.trim();
    let v3_security_level =
        SnmpSecurityLevel::from_str(form.snmp_v3_security_level.trim()).unwrap_or_default();
    let v3_auth_protocol =
        SnmpAuthProtocol::from_str(form.snmp_v3_auth_protocol.trim()).unwrap_or_default();
    let v3_auth_password = form.snmp_v3_auth_password.trim();
    let v3_priv_protocol =
        SnmpPrivProtocol::from_str(form.snmp_v3_priv_protocol.trim()).unwrap_or_default();
    let v3_priv_password = form.snmp_v3_priv_password.trim();

    validate_snmp_fields(
        snmp_version,
        community,
        v3_username,
        v3_security_level,
        v3_auth_password,
        v3_priv_password,
    )
    .map_err(|msg| WebError(AppError::Validation(msg.into())))?;

    let mut credentials = repo::panopticon_switches::SnmpCredentials::default();
    match snmp_version {
        SnmpVersion::V1 | SnmpVersion::V2c => {
            credentials.community_encrypted =
                Some(encryption_key.encrypt(community).map_err(|e| {
                    WebError(AppError::Validation(format!("Encryption failed: {e}")))
                })?);
        }
        SnmpVersion::V3 => {
            credentials.v3_username = Some(v3_username.to_string());
            credentials.v3_security_level = Some(v3_security_level);
            credentials.v3_auth_protocol = Some(v3_auth_protocol);
            credentials.v3_priv_protocol = Some(v3_priv_protocol);
            if !v3_auth_password.is_empty() {
                credentials.v3_auth_password_encrypted =
                    Some(encryption_key.encrypt(v3_auth_password).map_err(|e| {
                        WebError(AppError::Validation(format!("Encryption failed: {e}")))
                    })?);
            }
            if !v3_priv_password.is_empty() {
                credentials.v3_priv_password_encrypted =
                    Some(encryption_key.encrypt(v3_priv_password).map_err(|e| {
                        WebError(AppError::Validation(format!("Encryption failed: {e}")))
                    })?);
            }
        }
    }

    repo::panopticon_switches::create(
        &state.pool,
        name,
        ip_address,
        snmp_port,
        snmp_version,
        &credentials,
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

// ---------------------------------------------------------------------
// SNMP community-string macros -- GitHub issue #7 follow-up. A macro is
// host-independent (just the community string, no switch it's tied to),
// so "save as macro" is a second submit button on the same add-switch
// form (`formaction`/`formmethod`, no client-side JS) rather than a
// separate page: the browser submits the exact same `community` field
// value either way. Editing/removing a saved macro is shared with the
// Account page -- see `routes/account.rs::community_macro_edit_*`.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SaveCommunityMacroForm {
    csrf_token: String,
    community: String,
    macro_name: String,
    #[serde(default)]
    macro_scope: String,
    #[serde(default)]
    macro_role_id: String,
}

pub async fn save_community_macro(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SaveCommunityMacroForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let Some(encryption_key) = &state.encryption_key else {
        return Err(WebError(AppError::Validation(
            "Set ENCRYPTION_KEY in the environment before saving a macro -- its value can't \
             be stored safely without it."
                .into(),
        )));
    };

    let community = form.community.trim();
    if community.is_empty() {
        return Err(WebError(AppError::Validation(
            "Community string is required.".into(),
        )));
    }
    let macro_name = form.macro_name.trim();
    if macro_name.is_empty() || macro_name.len() > 128 {
        return Err(WebError(AppError::Validation(
            "Macro name must be 1-128 characters.".into(),
        )));
    }

    let scope: MacroScope = form
        .macro_scope
        .trim()
        .parse()
        .unwrap_or(MacroScope::Personal);
    let role_id = match scope {
        MacroScope::Personal => None,
        MacroScope::Role => {
            let role_id: Uuid = form.macro_role_id.trim().parse().map_err(|_| {
                WebError(AppError::Validation(
                    "Pick a role for a role-scoped macro.".into(),
                ))
            })?;
            let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
            if !user_roles.iter().any(|r| r.id == role_id) {
                return Err(WebError(AppError::Validation(
                    "You can only save a role macro for a role you belong to.".into(),
                )));
            }
            Some(role_id)
        }
    };

    let secret_value_encrypted = encryption_key
        .encrypt(community)
        .map_err(|e| WebError(AppError::Validation(format!("Encryption failed: {e}"))))?;

    repo::macros::create(
        &state.pool,
        repo::macros::MacroFields {
            name: macro_name,
            owner_user_id: ctx.user.id,
            scope,
            role_id,
            macro_type: abyssal_core::MacroType::CommunityString,
            job_name: None,
            schedule: None,
            run_as_user: None,
            command: None,
            secret_value_encrypted: Some(&secret_value_encrypted),
        },
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::MacroCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(macro_name),
    )
    .await?;

    Ok(Redirect::to("/arsenals/panopticon/switches").into_response())
}

/// Everything the edit form needs to re-render itself after a validation
/// failure -- bundled into one struct rather than a long parameter list,
/// since it grew past a handful of fields once v3 entered the picture.
struct SwitchEditFormState {
    switch_id: Uuid,
    name: String,
    ip_address: String,
    snmp_port: u16,
    snmp_version: SnmpVersion,
    v3_username: String,
    v3_security_level: SnmpSecurityLevel,
    v3_auth_protocol: SnmpAuthProtocol,
    v3_priv_protocol: SnmpPrivProtocol,
}

async fn render_switch_edit(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    form_state: SwitchEditFormState,
    error: Option<String>,
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

    let tpl = crate::templates::PanopticonSwitchEditTemplate {
        base,
        switch_id: form_state.switch_id.to_string(),
        name: form_state.name,
        ip_address: form_state.ip_address,
        snmp_port: form_state.snmp_port,
        snmp_versions: snmp_options(
            SnmpVersion::ALL,
            form_state.snmp_version,
            SnmpVersion::as_str,
            SnmpVersion::label,
        ),
        snmp_v3_username: form_state.v3_username,
        snmp_security_levels: snmp_options(
            SnmpSecurityLevel::ALL,
            form_state.v3_security_level,
            SnmpSecurityLevel::as_str,
            SnmpSecurityLevel::label,
        ),
        snmp_auth_protocols: snmp_options(
            SnmpAuthProtocol::ALL,
            form_state.v3_auth_protocol,
            SnmpAuthProtocol::as_str,
            SnmpAuthProtocol::label,
        ),
        snmp_priv_protocols: snmp_options(
            SnmpPrivProtocol::ALL,
            form_state.v3_priv_protocol,
            SnmpPrivProtocol::as_str,
            SnmpPrivProtocol::label,
        ),
        error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn switch_edit_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    let switch = repo::panopticon_switches::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    render_switch_edit(
        &state,
        &jar,
        &ctx,
        SwitchEditFormState {
            switch_id: switch.id,
            name: switch.name,
            ip_address: switch.ip_address,
            snmp_port: switch.snmp_port,
            snmp_version: switch.snmp_version,
            v3_username: switch.snmp_v3_username.unwrap_or_default(),
            v3_security_level: switch.snmp_v3_security_level.unwrap_or_default(),
            v3_auth_protocol: switch.snmp_v3_auth_protocol.unwrap_or_default(),
            v3_priv_protocol: switch.snmp_v3_priv_protocol.unwrap_or_default(),
        },
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct SwitchEditForm {
    csrf_token: String,
    name: String,
    ip_address: String,
    #[serde(default)]
    snmp_port: String,
    #[serde(default)]
    snmp_version: String,
    /// Blank means "keep the existing community string" -- but only when
    /// `snmp_version` isn't changing; see `PanopticonSwitchEditTemplate`'s
    /// doc comment.
    #[serde(default)]
    community: String,
    #[serde(default)]
    snmp_v3_username: String,
    #[serde(default)]
    snmp_v3_security_level: String,
    #[serde(default)]
    snmp_v3_auth_protocol: String,
    #[serde(default)]
    snmp_v3_auth_password: String,
    #[serde(default)]
    snmp_v3_priv_protocol: String,
    #[serde(default)]
    snmp_v3_priv_password: String,
}

pub async fn switch_edit(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SwitchEditForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let existing = repo::panopticon_switches::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let name = form.name.trim().to_string();
    let ip_address = form.ip_address.trim().to_string();
    let snmp_version =
        SnmpVersion::from_str(form.snmp_version.trim()).unwrap_or(existing.snmp_version);
    let v3_security_level = SnmpSecurityLevel::from_str(form.snmp_v3_security_level.trim())
        .unwrap_or_else(|()| existing.snmp_v3_security_level.unwrap_or_default());
    let v3_auth_protocol = SnmpAuthProtocol::from_str(form.snmp_v3_auth_protocol.trim())
        .unwrap_or_else(|()| existing.snmp_v3_auth_protocol.unwrap_or_default());
    let v3_priv_protocol = SnmpPrivProtocol::from_str(form.snmp_v3_priv_protocol.trim())
        .unwrap_or_else(|()| existing.snmp_v3_priv_protocol.unwrap_or_default());
    let v3_username = form.snmp_v3_username.trim().to_string();

    let form_state = |name: String, ip_address: String, snmp_port: u16| SwitchEditFormState {
        switch_id: id,
        name,
        ip_address,
        snmp_port,
        snmp_version,
        v3_username: v3_username.clone(),
        v3_security_level,
        v3_auth_protocol,
        v3_priv_protocol,
    };

    let snmp_port_raw = form.snmp_port.trim();
    let snmp_port: u16 = if snmp_port_raw.is_empty() {
        161
    } else {
        match snmp_port_raw.parse() {
            Ok(p) => p,
            Err(_) => {
                return render_switch_edit(
                    &state,
                    &jar,
                    &ctx,
                    form_state(name, ip_address, 161),
                    Some("SNMP port must be 1-65535.".to_string()),
                )
                .await;
            }
        }
    };

    if name.is_empty() || name.len() > 128 {
        return render_switch_edit(
            &state,
            &jar,
            &ctx,
            form_state(name, ip_address, snmp_port),
            Some("Switch name must be 1-128 characters.".to_string()),
        )
        .await;
    }
    if !abyssal_agent_protocol::is_valid_network_target(&ip_address) {
        return render_switch_edit(
            &state,
            &jar,
            &ctx,
            form_state(name, ip_address, snmp_port),
            Some("That doesn't look like a valid IP address or hostname.".to_string()),
        )
        .await;
    }

    let community = form.community.trim();
    let v3_auth_password = form.snmp_v3_auth_password.trim();
    let v3_priv_password = form.snmp_v3_priv_password.trim();
    let version_changed = snmp_version != existing.snmp_version;
    let new_secrets_supplied = match snmp_version {
        SnmpVersion::V1 | SnmpVersion::V2c => !community.is_empty(),
        SnmpVersion::V3 => {
            !v3_username.is_empty() || !v3_auth_password.is_empty() || !v3_priv_password.is_empty()
        }
    };

    if version_changed && !new_secrets_supplied {
        return render_switch_edit(
            &state,
            &jar,
            &ctx,
            form_state(name, ip_address, snmp_port),
            Some("Changing the SNMP version requires entering its credentials.".to_string()),
        )
        .await;
    }

    if version_changed || new_secrets_supplied {
        if let Err(msg) = validate_snmp_fields(
            snmp_version,
            community,
            &v3_username,
            v3_security_level,
            v3_auth_password,
            v3_priv_password,
        ) {
            return render_switch_edit(
                &state,
                &jar,
                &ctx,
                form_state(name, ip_address, snmp_port),
                Some(msg.to_string()),
            )
            .await;
        }

        let Some(encryption_key) = &state.encryption_key else {
            return render_switch_edit(
                &state,
                &jar,
                &ctx,
                form_state(name, ip_address, snmp_port),
                Some(
                    "ENCRYPTION_KEY isn't configured -- can't store new SNMP credentials."
                        .to_string(),
                ),
            )
            .await;
        };

        let mut credentials = repo::panopticon_switches::SnmpCredentials::default();
        match snmp_version {
            SnmpVersion::V1 | SnmpVersion::V2c => match encryption_key.encrypt(community) {
                Ok(v) => credentials.community_encrypted = Some(v),
                Err(e) => {
                    return render_switch_edit(
                        &state,
                        &jar,
                        &ctx,
                        form_state(name, ip_address, snmp_port),
                        Some(format!("Encryption failed: {e}")),
                    )
                    .await;
                }
            },
            SnmpVersion::V3 => {
                credentials.v3_username = Some(v3_username.clone());
                credentials.v3_security_level = Some(v3_security_level);
                credentials.v3_auth_protocol = Some(v3_auth_protocol);
                credentials.v3_priv_protocol = Some(v3_priv_protocol);
                if !v3_auth_password.is_empty() {
                    match encryption_key.encrypt(v3_auth_password) {
                        Ok(v) => credentials.v3_auth_password_encrypted = Some(v),
                        Err(e) => {
                            return render_switch_edit(
                                &state,
                                &jar,
                                &ctx,
                                form_state(name, ip_address, snmp_port),
                                Some(format!("Encryption failed: {e}")),
                            )
                            .await;
                        }
                    }
                }
                if !v3_priv_password.is_empty() {
                    match encryption_key.encrypt(v3_priv_password) {
                        Ok(v) => credentials.v3_priv_password_encrypted = Some(v),
                        Err(e) => {
                            return render_switch_edit(
                                &state,
                                &jar,
                                &ctx,
                                form_state(name, ip_address, snmp_port),
                                Some(format!("Encryption failed: {e}")),
                            )
                            .await;
                        }
                    }
                }
            }
        }

        repo::panopticon_switches::update_credentials(&state.pool, id, snmp_version, &credentials)
            .await?;
    }

    repo::panopticon_switches::update(&state.pool, id, &name, &ip_address, snmp_port).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::NetworkSwitchUpdated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&name),
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
            "This will remove \"{}\" and its stored (encrypted) SNMP credentials. Devices \
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
            "ENCRYPTION_KEY isn't configured -- this switch's SNMP credentials can't be \
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
            render_switches(
                &state,
                &jar,
                &ctx,
                result_label,
                Some(output.stdout),
                None,
                None,
            )
            .await
        }
        Err(e) => {
            render_switches(
                &state,
                &jar,
                &ctx,
                result_label,
                None,
                Some(e.to_string()),
                None,
            )
            .await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_network_maps_the_sentinel_to_none() {
        assert_eq!(group_network(UNASSIGNED), None);
        assert_eq!(group_network("10.0.1.0/24"), Some("10.0.1.0/24"));
    }

    #[test]
    fn parse_inventory_query_reads_every_param() {
        let q = parse_inventory_query(Some(
            "port=22&subnet=10.0.1.0%2F24&open=10.0.1.0%2F24&open=unassigned\
             &group_page=2&gp=10.0.1.0%2F24%3A3&page=4",
        ));
        assert_eq!(q.port, Some(22));
        assert_eq!(q.subnet.as_deref(), Some("10.0.1.0/24"));
        assert_eq!(
            q.open,
            vec!["10.0.1.0/24".to_string(), "unassigned".to_string()]
        );
        assert_eq!(q.group_page, Some(2));
        assert_eq!(q.gp, vec![("10.0.1.0/24".to_string(), 3)]);
        assert_eq!(q.page, Some(4));
    }

    #[test]
    fn parse_inventory_query_is_empty_for_no_query_string() {
        let q = parse_inventory_query(None);
        assert_eq!(q.port, None);
        assert!(q.open.is_empty());
        assert!(q.gp.is_empty());
    }

    #[test]
    fn parse_inventory_query_drops_malformed_values_instead_of_failing() {
        let q = parse_inventory_query(Some("port=not-a-number&gp=missing-page&group_page=nope"));
        assert_eq!(q.port, None);
        assert!(q.gp.is_empty());
        assert_eq!(q.group_page, None);
    }

    #[test]
    fn parse_inventory_query_dedupes_repeated_open_values() {
        let q = parse_inventory_query(Some("open=10.0.1.0%2F24&open=10.0.1.0%2F24"));
        assert_eq!(q.open.len(), 1);
    }

    #[test]
    fn parse_inventory_query_lets_a_later_gp_entry_win_for_the_same_network() {
        let q = parse_inventory_query(Some("gp=10.0.1.0%2F24%3A2&gp=10.0.1.0%2F24%3A5"));
        assert_eq!(q.gp, vec![("10.0.1.0/24".to_string(), 5)]);
    }

    #[test]
    fn inventory_query_href_omits_page_1_defaults() {
        let q = InventoryQuery::default();
        assert_eq!(q.with_group_page(1).href(), "/arsenals/panopticon");
        assert_eq!(
            q.with_group_page(2).href(),
            "/arsenals/panopticon?group_page=2"
        );
    }

    #[test]
    fn inventory_query_with_open_is_idempotent() {
        let q = InventoryQuery::default().with_open("10.0.1.0/24");
        let q2 = q.with_open("10.0.1.0/24");
        assert_eq!(q2.open.len(), 1);
    }

    #[test]
    fn inventory_query_without_subnet_also_clears_its_page() {
        let q = InventoryQuery {
            subnet: Some("10.0.1.0/24".to_string()),
            page: Some(3),
            ..Default::default()
        };
        let cleared = q.without_subnet();
        assert_eq!(cleared.subnet, None);
        assert_eq!(cleared.page, None);
    }

    #[test]
    fn v1_and_v2c_require_a_community_string() {
        assert!(
            validate_snmp_fields(
                SnmpVersion::V1,
                "",
                "",
                SnmpSecurityLevel::default(),
                "",
                ""
            )
            .is_err()
        );
        assert!(
            validate_snmp_fields(
                SnmpVersion::V2c,
                "public",
                "",
                SnmpSecurityLevel::default(),
                "",
                ""
            )
            .is_ok()
        );
    }

    #[test]
    fn v3_no_auth_no_priv_only_needs_a_username() {
        assert!(
            validate_snmp_fields(
                SnmpVersion::V3,
                "",
                "monitor",
                SnmpSecurityLevel::NoAuthNoPriv,
                "",
                ""
            )
            .is_ok()
        );
        assert!(
            validate_snmp_fields(
                SnmpVersion::V3,
                "",
                "",
                SnmpSecurityLevel::NoAuthNoPriv,
                "",
                ""
            )
            .is_err()
        );
    }

    #[test]
    fn v3_auth_no_priv_requires_an_auth_password() {
        assert!(
            validate_snmp_fields(
                SnmpVersion::V3,
                "",
                "monitor",
                SnmpSecurityLevel::AuthNoPriv,
                "",
                ""
            )
            .is_err()
        );
        assert!(
            validate_snmp_fields(
                SnmpVersion::V3,
                "",
                "monitor",
                SnmpSecurityLevel::AuthNoPriv,
                "hunter2",
                ""
            )
            .is_ok()
        );
    }

    #[test]
    fn v3_auth_priv_requires_both_passwords() {
        assert!(
            validate_snmp_fields(
                SnmpVersion::V3,
                "",
                "monitor",
                SnmpSecurityLevel::AuthPriv,
                "hunter2",
                ""
            )
            .is_err()
        );
        assert!(
            validate_snmp_fields(
                SnmpVersion::V3,
                "",
                "monitor",
                SnmpSecurityLevel::AuthPriv,
                "hunter2",
                "swordfish"
            )
            .is_ok()
        );
    }
}
