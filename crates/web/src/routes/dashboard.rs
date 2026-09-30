use std::collections::HashMap;

use abyssal_audit::AuditFilter;
use abyssal_core::{AppError, ModuleCategory, Permission};
use abyssal_database::repo;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::{require_csrf, sparkline_points};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::mortiscope_ops::{METRIC_CPU_BUSY, METRIC_DISK_USED, METRIC_MEM_USED};
use crate::pagination;
use crate::state::AppState;
use crate::templates::{
    ActivityFeedTemplate, ActivityFragment, ActivityGroup, ActivityRow, BaseCtx, ControlPlaneCtx,
    ControlPlaneFragment, DashboardTemplate, FleetHealthCtx, FleetHostRow, FleetHostsFragment,
    FleetHostsTemplate, FleetSortHeader, FleetStatusOption, HeroCtx, HostAttentionRow,
    LastBackupRow, MeterCtx, ModuleGroup, ModuleTile, OverviewFragment, SummaryTile,
    UpdateNoticeCtx,
};
use crate::theme;

/// How far back "open Thanatos alerts" looks.
const ALERT_WINDOW_HOURS: i64 = 24;
/// How far back the "recent failures" tile counts audit failures.
const FAILURE_WINDOW_HOURS: i64 = 24;
/// A self-metrics sample older than this is shown with a "stale" marker --
/// three sample intervals (`self_metrics::SAMPLE_INTERVAL` is 60s), so a
/// single missed tick doesn't flap the badge but a stalled sampler shows.
const SELF_METRICS_STALE_SECS: i64 = 180;
/// Percentage at/above which a usage meter turns "warn", then "crit".
const METER_WARN_PCT: u8 = 70;
const METER_CRIT_PCT: u8 = 90;
/// How many raw audit rows to fetch before filtering out routine reads --
/// generous enough that a busy fleet still leaves `ACTIVITY_LIMIT` rows
/// after filtering, without scanning the whole table.
const ACTIVITY_FETCH: i64 = 50;
const ACTIVITY_LIMIT: usize = 8;

/// Fleet table paging + the window for its per-host CPU sparkline.
const FLEET_DEFAULT_PER_PAGE: u32 = 25;
const FLEET_MAX_PER_PAGE: u32 = 100;
const FLEET_SPARK_HOURS: i64 = 6;
const FLEET_BASE_PATH: &str = "/dashboard/hosts";

/// Activity feed paging.
const ACTIVITY_PER_PAGE: u32 = 30;
const ACTIVITY_BASE_PATH: &str = "/dashboard/activity";

const CATEGORY_ORDER: [ModuleCategory; 4] = [
    ModuleCategory::Operate,
    ModuleCategory::Observe,
    ModuleCategory::Defend,
    ModuleCategory::PreserveRecover,
];

#[derive(Deserialize)]
pub struct DashboardQuery {
    #[serde(default)]
    q: String,
}

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<DashboardQuery>,
) -> Result<Response, WebError> {
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

    let pinned_keys = repo::pinned_modules::list_for_user(&state.pool, ctx.user.id).await?;
    let search = q.q.trim().to_lowercase();
    let role_restriction =
        repo::role_module_visibility::effective_restriction_for_user(&state.pool, ctx.user.id)
            .await?;

    let visible: Vec<ModuleTile> = state
        .modules
        .list(&state.pool)
        .await?
        .into_iter()
        .filter(|m| m.enabled)
        .filter(|m| m.view_permissions.is_empty() || m.view_permissions.iter().any(|p| ctx.has(*p)))
        .filter(|m| match &role_restriction {
            Some(allowed) => allowed.contains(m.key),
            None => true,
        })
        .filter(|m| {
            search.is_empty()
                || m.display_name.to_lowercase().contains(&search)
                || m.description.to_lowercase().contains(&search)
        })
        .map(|m| ModuleTile {
            key: m.key,
            display_name: m.display_name,
            description: m.description,
            category: m.category.to_string(),
            pinned: pinned_keys.iter().any(|k| k == m.key),
        })
        .collect();

    let pinned: Vec<ModuleTile> = visible.iter().filter(|t| t.pinned).cloned().collect();

    let groups: Vec<ModuleGroup> = CATEGORY_ORDER
        .iter()
        .filter_map(|cat| {
            let category = cat.to_string();
            let tiles: Vec<ModuleTile> = visible
                .iter()
                .filter(|t| !t.pinned && t.category == category)
                .cloned()
                .collect();
            if tiles.is_empty() {
                None
            } else {
                Some(ModuleGroup { category, tiles })
            }
        })
        .collect();

    let can_hosts_view = ctx.has(Permission::HostsView);
    let fleet_health = if can_hosts_view {
        build_fleet_health(&state, &ctx).await?
    } else {
        FleetHealthCtx {
            host_count: 0,
            online_count: 0,
            open_alerts: 0,
            hosts_needing_attention: Vec::new(),
            last_backup: None,
        }
    };

    // Hero + control plane + summary tiles are the operational overview: real
    // numbers only for viewers with HostsView, all from data already cached or
    // cheaply aggregated -- never a live agent dispatch on page load.
    let hero = build_hero(&ctx.user.username, can_hosts_view, &fleet_health);
    let control_plane = if can_hosts_view {
        Some(build_control_plane(&state).await)
    } else {
        None
    };
    let summary_tiles = if can_hosts_view {
        build_summary_tiles(&state, &ctx, &fleet_health).await?
    } else {
        Vec::new()
    };

    let recent_activity = if ctx.has(Permission::AuditView) {
        abyssal_audit::list(&state.pool, &AuditFilter::default(), 0, ACTIVITY_FETCH)
            .await?
            .into_iter()
            .filter(|e| {
                e.metadata
                    .as_ref()
                    .and_then(|m| m.get("kind"))
                    .and_then(|k| k.as_str())
                    != Some("read")
            })
            .take(ACTIVITY_LIMIT)
            .map(|e| {
                let occurred_at =
                    crate::common::format_in_tz(e.occurred_at_utc(), &ctx.user.timezone);
                let summary = summarize_activity(&e);
                ActivityRow {
                    occurred_at,
                    username: e.username_snapshot,
                    summary,
                    result: e.result,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let update_status = state.update_status.read().await.clone();
    let update_available = update_status.update_available();
    let update_notice = UpdateNoticeCtx {
        current_version: update_status.current_version,
        latest_version: if update_available {
            update_status
                .latest_version
                .as_deref()
                .map(|v| v.trim_start_matches('v').to_string())
                .unwrap_or_default()
        } else {
            String::new()
        },
        release_url: if update_available {
            update_status.release_url.unwrap_or_default()
        } else {
            String::new()
        },
        update_available,
    };

    let refresh_seconds = crate::dashboard_prefs::refresh_seconds(&jar);
    let htmx_pref = crate::dashboard_prefs::htmx_enabled(&jar);
    let self_url = redirect_target(&q.q);
    let tpl = DashboardTemplate {
        base,
        search_query: q.q,
        pinned,
        groups,
        hero,
        control_plane,
        summary_tiles,
        fleet_health,
        update_notice,
        recent_activity,
        refresh_seconds,
        htmx_pref,
        live_htmx: htmx_pref && refresh_seconds > 0,
        self_url,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Fleet-wide health aggregates for the dashboard: host counts, open
/// Thanatos alerts, hosts the unattended health sweep has flagged, and the
/// most recent Reliquary backup -- all cheap reads against data other
/// pieces already persist (or, for the health sweep, a small periodic
/// background poll -- see `crate::health_ops`), never a live dispatch to
/// every agent on every dashboard load.
async fn build_fleet_health(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
) -> Result<FleetHealthCtx, WebError> {
    let hosts = repo::hosts::list(&state.pool).await?;
    let active_hosts: Vec<_> = hosts.into_iter().filter(|h| h.is_active()).collect();
    let host_count = active_hosts.len();
    let online_count = active_hosts
        .iter()
        .filter(|h| state.hosts.is_connected(h.id))
        .count();
    let host_name = |id: uuid::Uuid| -> String {
        active_hosts
            .iter()
            .find(|h| h.id == id)
            .map(|h| h.name.clone())
            .unwrap_or_else(|| "(removed host)".to_string())
    };

    let open_alerts =
        repo::security_events::count_recent_alerts(&state.pool, ALERT_WINDOW_HOURS).await?;

    let hosts_needing_attention = repo::host_health::needing_attention(&state.pool)
        .await?
        .into_iter()
        .map(|h| HostAttentionRow {
            host_name: host_name(h.host_id),
            reason: match &h.error {
                Some(e) => format!("unreachable: {e}"),
                None => format!(
                    "{} failed unit{}",
                    h.failed_unit_count,
                    if h.failed_unit_count == 1 { "" } else { "s" }
                ),
            },
        })
        .collect();

    let last_backup = repo::backup_records::most_recent(&state.pool)
        .await?
        .map(|b| LastBackupRow {
            host_name: host_name(b.host_id),
            name: b.name,
            when: crate::common::format_in_tz(b.created_at, &ctx.user.timezone),
        });

    Ok(FleetHealthCtx {
        host_count,
        online_count,
        open_alerts,
        hosts_needing_attention,
        last_backup,
    })
}

/// The hero banner's at-a-glance fleet state. Colour (`state_class`) is
/// always paired with a word (`state_label`) and an icon so it never relies
/// on colour alone. Severity ladder, worst first: `crit` when the whole fleet
/// is dark (hosts exist, none online); `warn` when something is off (hosts
/// offline, open alerts, or a host the health sweep flagged); `ok` when every
/// host is online with nothing flagged. A viewer without `HostsView` (or with
/// no hosts enrolled yet) gets a plain welcome with no fleet claims.
fn build_hero(username: &str, can_hosts_view: bool, fleet: &FleetHealthCtx) -> HeroCtx {
    let greeting = format!("Welcome back, {username}");
    if !can_hosts_view || fleet.host_count == 0 {
        return HeroCtx {
            greeting,
            show_fleet: false,
            state_label: if can_hosts_view {
                "No hosts enrolled yet".to_string()
            } else {
                String::new()
            },
            state_class: "muted".to_string(),
            state_icon: "host",
            summary_line: String::new(),
        };
    }

    let offline = fleet.host_count.saturating_sub(fleet.online_count);
    let attention = !fleet.hosts_needing_attention.is_empty();
    let (state_label, state_class, state_icon) = if fleet.online_count == 0 {
        ("Fleet offline", "crit", "danger")
    } else if offline > 0 || fleet.open_alerts > 0 || attention {
        ("Degraded", "warn", "warning")
    } else {
        ("All systems healthy", "ok", "shield-check")
    };

    let alerts_part = if fleet.open_alerts > 0 {
        format!(
            "{} open alert{} (24h)",
            fleet.open_alerts,
            if fleet.open_alerts == 1 { "" } else { "s" }
        )
    } else {
        "no open alerts".to_string()
    };
    let summary_line = format!(
        "{} of {} host{} online · {}",
        fleet.online_count,
        fleet.host_count,
        if fleet.host_count == 1 { "" } else { "s" },
        alerts_part
    );

    HeroCtx {
        greeting,
        show_fleet: true,
        state_label: state_label.to_string(),
        state_class: state_class.to_string(),
        state_icon,
        summary_line,
    }
}

/// Builds the Control Plane card from the cached self-metrics sample plus two
/// cheap queries (a `SELECT 1` health probe and the active-session count).
/// Reads only cached/aggregate data -- no agent dispatch, no per-host work.
async fn build_control_plane(state: &AppState) -> ControlPlaneCtx {
    let (db_ok, db_label) = db_health(&state.pool).await;
    let active_sessions = repo::sessions::count_active(&state.pool).await.unwrap_or(0);
    let version = crate::update_check::CURRENT_VERSION.trim().to_string();

    let sample = state.self_metrics.read().await.clone();
    let Some(s) = sample else {
        return ControlPlaneCtx {
            collecting: true,
            cpu: meter(0, "collecting…"),
            mem: meter(0, "collecting…"),
            disk: meter(0, "collecting…"),
            cpu_spark: String::new(),
            mem_spark: String::new(),
            disk_spark: String::new(),
            uptime: "—".to_string(),
            version,
            db_ok,
            db_label,
            active_sessions,
            sampled_ago: String::new(),
            stale: false,
        };
    };

    // Recent history for the trend sparklines -- three small indexed reads.
    let (cpu_spark, mem_spark, disk_spark) = self_metric_sparklines(&state.pool).await;

    let age_secs = (chrono::Utc::now() - s.sampled_at).num_seconds().max(0);
    ControlPlaneCtx {
        collecting: false,
        cpu: meter(
            s.cpu_percent.round() as i64,
            &format!("{:.0}%", s.cpu_percent),
        ),
        mem: meter(
            percent(s.mem_used_bytes, s.mem_total_bytes),
            &format!(
                "{:.1} / {:.1} GB",
                gib(s.mem_used_bytes),
                gib(s.mem_total_bytes)
            ),
        ),
        disk: meter(
            percent(s.disk_used_bytes, s.disk_total_bytes),
            &format!(
                "{:.1} / {:.1} GB",
                gib(s.disk_used_bytes),
                gib(s.disk_total_bytes)
            ),
        ),
        cpu_spark,
        mem_spark,
        disk_spark,
        uptime: format_uptime(s.uptime_secs),
        version,
        db_ok,
        db_label,
        active_sessions,
        sampled_ago: format_ago(age_secs),
        stale: age_secs > SELF_METRICS_STALE_SECS,
    }
}

/// How many recent control-plane samples a trend sparkline plots.
const SELF_METRIC_TREND_SAMPLES: i64 = 40;

/// Builds the `(cpu, mem, disk)` trend sparklines from control-plane history.
/// Best-effort: an empty string (no line) on any read error or too little data.
async fn self_metric_sparklines(pool: &abyssal_database::DbPool) -> (String, String, String) {
    use abyssal_database::repo::control_plane_metrics as cpm;
    async fn spark(pool: &abyssal_database::DbPool, metric: &str) -> String {
        let values = cpm::recent(pool, metric, SELF_METRIC_TREND_SAMPLES)
            .await
            .unwrap_or_default();
        sparkline_points(&values, 120.0, 24.0)
    }
    (
        spark(pool, cpm::METRIC_CPU).await,
        spark(pool, cpm::METRIC_MEM).await,
        spark(pool, cpm::METRIC_DISK).await,
    )
}

/// The five fleet summary tiles. Each drills into a fuller view when there is
/// a natural one and the viewer can reach it (the "recent failures" tile only
/// links to the audit log for `AuditView` holders, for instance).
async fn build_summary_tiles(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
    fleet: &FleetHealthCtx,
) -> Result<Vec<SummaryTile>, WebError> {
    let offline = fleet.host_count.saturating_sub(fleet.online_count);
    let elevated = state.elevation.snapshot().len();
    let active_sessions = repo::sessions::count_active(&state.pool).await?;
    let recent_failures =
        repo::audit::count_recent_failures(&state.pool, FAILURE_WINDOW_HOURS).await?;

    let mut tiles = Vec::with_capacity(5);

    tiles.push(SummaryTile {
        label: "Hosts".to_string(),
        value: fleet.host_count.to_string(),
        sub: format!("{} online · {} offline", fleet.online_count, offline),
        tone: if fleet.host_count > 0 && fleet.online_count == 0 {
            "crit"
        } else if offline > 0 {
            "warn"
        } else {
            "ok"
        }
        .to_string(),
        icon: "host",
        href: Some(FLEET_BASE_PATH.to_string()),
    });

    tiles.push(SummaryTile {
        label: "Elevated".to_string(),
        value: elevated.to_string(),
        sub: "hosts with active sudo".to_string(),
        tone: if elevated > 0 { "warn" } else { "muted" }.to_string(),
        icon: "elevate",
        href: None,
    });

    tiles.push(SummaryTile {
        label: "Open alerts".to_string(),
        value: fleet.open_alerts.to_string(),
        sub: "Thanatos (24h)".to_string(),
        tone: if fleet.open_alerts > 0 { "crit" } else { "ok" }.to_string(),
        icon: "warning",
        href: None,
    });

    tiles.push(SummaryTile {
        label: "Sessions".to_string(),
        value: active_sessions.to_string(),
        sub: "active operators".to_string(),
        tone: "muted".to_string(),
        icon: "user",
        href: None,
    });

    tiles.push(SummaryTile {
        label: "Recent failures".to_string(),
        value: recent_failures.to_string(),
        sub: "audit failures (24h)".to_string(),
        tone: if recent_failures > 0 { "warn" } else { "ok" }.to_string(),
        icon: "audit",
        href: if ctx.has(Permission::AuditView) {
            Some("/admin/audit".to_string())
        } else {
            None
        },
    });

    Ok(tiles)
}

/// A `SELECT 1` liveness probe against the pool, timed. Returns whether it
/// succeeded and a human label (`"Connected · 3 ms"` / `"Unreachable"`).
/// The dashboard already can't render without the pool, so this is really a
/// latency read-out; it's still worth surfacing when the DB has gone slow.
async fn db_health(pool: &abyssal_database::DbPool) -> (bool, String) {
    let start = std::time::Instant::now();
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => {
            let ms = start.elapsed().as_millis();
            (true, format!("Connected · {ms} ms"))
        }
        Err(_) => (false, "Unreachable".to_string()),
    }
}

/// Builds a `MeterCtx`, clamping the percentage to 0-100 and picking the tone
/// from the shared warn/crit thresholds so every meter reads the same way.
fn meter(pct: i64, label: &str) -> MeterCtx {
    let pct = pct.clamp(0, 100) as u8;
    let tone = if pct >= METER_CRIT_PCT {
        "crit"
    } else if pct >= METER_WARN_PCT {
        "warn"
    } else {
        "ok"
    };
    MeterCtx {
        pct,
        label: label.to_string(),
        tone: tone.to_string(),
    }
}

/// Integer percentage `used/total`, guarding divide-by-zero (returns 0).
fn percent(used: u64, total: u64) -> i64 {
    if total == 0 {
        0
    } else {
        ((used as u128 * 100) / total as u128) as i64
    }
}

/// Bytes to gibibytes as a float, for the `"5.2 / 15.6 GB"` labels.
fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
}

/// Seconds of uptime to a compact `"3d 4h"` / `"4h 12m"` / `"12m"` label.
fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

/// A whole-seconds age to a compact `"12s ago"` / `"4m ago"` / `"2h ago"`.
fn format_ago(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3_600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3_600)
    }
}

/// A single human-readable phrase for one audit row: the operation label
/// persisted in `metadata.operation` for a host-dispatched action (see
/// `AgentOperation::label`), or a title-cased version of the raw action
/// key for everything else (e.g. `"LOGIN_SUCCESS"` -> `"Login Success"`),
/// plus the resource it acted on when there is one (e.g. `"Rebooted —
/// WEB-01"`).
fn summarize_activity(e: &abyssal_audit::AuditEntry) -> String {
    let base = e
        .metadata
        .as_ref()
        .and_then(|m| m.get("operation"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| humanize_action_key(&e.action));

    match &e.resource {
        Some(r) if !r.is_empty() => format!("{base} — {r}"),
        _ => base,
    }
}

/// `"LOGIN_SUCCESS"` -> `"Login Success"`.
fn humanize_action_key(key: &str) -> String {
    key.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn redirect_target(q: &str) -> String {
    if q.trim().is_empty() {
        "/".to_string()
    } else {
        let encoded: String = form_urlencoded::byte_serialize(q.as_bytes()).collect();
        format!("/?q={encoded}")
    }
}

#[derive(Deserialize)]
pub struct PinForm {
    csrf_token: String,
    #[serde(default)]
    q: String,
}

pub async fn pin(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(key): Path<String>,
    Form(form): Form<PinForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;
    if state.modules.find(&key).is_none() {
        return Err(WebError(AppError::NotFound));
    }

    repo::pinned_modules::pin(&state.pool, ctx.user.id, &key).await?;
    Ok(Redirect::to(&redirect_target(&form.q)).into_response())
}

pub async fn unpin(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(key): Path<String>,
    Form(form): Form<PinForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    repo::pinned_modules::unpin(&state.pool, ctx.user.id, &key).await?;
    Ok(Redirect::to(&redirect_target(&form.q)).into_response())
}

// ---- Dashboard live fragments & viewing preferences --------------------

/// `/dashboard/fragments/control-plane`: just the Control Plane card, for the
/// htmx poll -- same `HostsView` gate as the card on the full page.
pub async fn control_plane_fragment(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsView)?;
    let tpl = ControlPlaneFragment {
        control_plane: Some(build_control_plane(&state).await),
    };
    Ok(tpl.into_response())
}

/// `/dashboard/fragments/overview`: hero banner + fleet summary tiles.
pub async fn overview_fragment(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsView)?;
    let fleet_health = build_fleet_health(&state, &ctx).await?;
    let hero = build_hero(&ctx.user.username, true, &fleet_health);
    let summary_tiles = build_summary_tiles(&state, &ctx, &fleet_health).await?;
    let tpl = OverviewFragment {
        hero,
        summary_tiles,
    };
    Ok(tpl.into_response())
}

#[derive(Deserialize)]
pub struct PreferencesForm {
    csrf_token: String,
    #[serde(default)]
    refresh: u32,
    /// Present ("1") only when the "Partial updates" checkbox is ticked.
    #[serde(default)]
    htmx: Option<String>,
    /// The page to return to, carried as a hidden field (this app sends no
    /// `Referer`, so it can't be inferred). Validated as an internal path.
    #[serde(default)]
    return_to: String,
}

/// Stores this browser's dashboard viewing preferences (auto-refresh interval
/// and htmx opt-in) as cookies, then returns to the page the control was on.
/// Purely a per-browser UI preference; never an authorization input.
pub async fn set_preferences(
    jar: CookieJar,
    Form(form): Form<PreferencesForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;
    let seconds = crate::dashboard_prefs::clamp_refresh(form.refresh);
    let htmx_on = form.htmx.as_deref() == Some("1");
    let back = crate::common::safe_return_to(&form.return_to, "/").to_string();
    let jar = jar
        .add(crate::dashboard_prefs::refresh_cookie(seconds))
        .add(crate::dashboard_prefs::htmx_cookie(htmx_on));
    Ok((jar, Redirect::to(&back)).into_response())
}

// ---- Activity feed (/dashboard/activity) -------------------------------

#[derive(Deserialize, Default)]
pub struct ActivityQuery {
    /// `?system=1` shows system-initiated rows too; absent/anything-else hides
    /// them (the default -- the feed is about what people did).
    #[serde(default)]
    system: String,
    page: Option<u32>,
}

/// Everything the activity feed needs to render, shared by the full page and
/// the htmx fragment.
struct ActivityView {
    groups: Vec<ActivityGroup>,
    include_system: bool,
    toggle_href: String,
    page: crate::templates::NumberedPageInfo,
    fragment_url: String,
    self_url: String,
}

/// The full activity feed: audit history grouped by day (in the viewer's
/// timezone), newest first, with numbered pagination and a "show/hide system
/// events" toggle. Routine reads are always excluded. Reads only the audit log;
/// an out-of-range page clamps to the last real page rather than erroring.
pub async fn activity(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<ActivityQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::AuditView)?;
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

    let view = build_activity_view(&state, &ctx, &q).await?;
    let refresh_seconds = crate::dashboard_prefs::refresh_seconds(&jar);
    let htmx_pref = crate::dashboard_prefs::htmx_enabled(&jar);

    let tpl = ActivityFeedTemplate {
        base,
        groups: view.groups,
        include_system: view.include_system,
        toggle_href: view.toggle_href,
        page: view.page,
        refresh_seconds,
        htmx_pref,
        live_htmx: htmx_pref && refresh_seconds > 0,
        fragment_url: view.fragment_url,
        self_url: view.self_url,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// The `/dashboard/fragments/activity` htmx poll target, gated by the same
/// `AuditView` check.
pub async fn activity_fragment(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<ActivityQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::AuditView)?;
    let view = build_activity_view(&state, &ctx, &q).await?;
    let tpl = ActivityFragment {
        groups: view.groups,
        include_system: view.include_system,
        toggle_href: view.toggle_href,
        page: view.page,
    };
    Ok(tpl.into_response())
}

async fn build_activity_view(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
    q: &ActivityQuery,
) -> Result<ActivityView, WebError> {
    let include_system = q.system == "1";
    let total = repo::audit::activity_count(&state.pool, include_system).await? as u64;

    let (mut page, per_page) =
        pagination::normalize(q.page, None, ACTIVITY_PER_PAGE, ACTIVITY_PER_PAGE);
    let total_pages = pagination::total_pages(total, per_page);
    page = page.min(total_pages);
    let offset = pagination::offset(page, per_page);

    let entries =
        repo::audit::activity_page(&state.pool, include_system, i64::from(per_page), offset)
            .await?;
    let groups = group_activity(&entries, &ctx.user.timezone);

    let page_info = pagination::numbered_page_info(
        &pagination::Page::new(Vec::new(), page, per_page, total),
        |p| activity_href(include_system, Some(p)),
    );

    let fragment_url = activity_fragment_href(include_system, (page > 1).then_some(page));
    let self_url = activity_href(include_system, (page > 1).then_some(page));

    Ok(ActivityView {
        groups,
        include_system,
        // The toggle flips the current filter and returns to page 1.
        toggle_href: activity_href(!include_system, None),
        page: page_info,
        fragment_url,
        self_url,
    })
}

/// The `/dashboard/fragments/activity` URL carrying the current filter/page.
fn activity_fragment_href(include_system: bool, page: Option<u32>) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    if include_system {
        ser.append_pair("system", "1");
    }
    if let Some(p) = page.filter(|p| *p > 1) {
        ser.append_pair("page", &p.to_string());
    }
    let query = ser.finish();
    if query.is_empty() {
        "/dashboard/fragments/activity".to_string()
    } else {
        format!("/dashboard/fragments/activity?{query}")
    }
}

/// Groups already-ordered (newest-first) audit rows into per-day buckets in the
/// viewer's timezone, labelling today/yesterday specially. Each row keeps only
/// its time-of-day (the day is the group heading).
fn group_activity(entries: &[abyssal_audit::AuditEntry], tz_name: &str) -> Vec<ActivityGroup> {
    let tz: chrono_tz::Tz = tz_name.parse().unwrap_or(chrono_tz::UTC);
    let today = chrono::Utc::now().with_timezone(&tz).date_naive();
    let yesterday = today.pred_opt().unwrap_or(today);

    let mut groups: Vec<ActivityGroup> = Vec::new();
    for e in entries {
        let local = e.occurred_at_utc().with_timezone(&tz);
        let date = local.date_naive();
        let label = if date == today {
            "Today".to_string()
        } else if date == yesterday {
            "Yesterday".to_string()
        } else {
            date.format("%Y-%m-%d").to_string()
        };
        let row = ActivityRow {
            occurred_at: local.format("%H:%M:%S").to_string(),
            username: e.username_snapshot.clone(),
            summary: summarize_activity(e),
            result: e.result.clone(),
        };
        match groups.last_mut() {
            // Entries are newest-first and contiguous by day, so a matching
            // label is always the current (last) group.
            Some(g) if g.label == label => g.rows.push(row),
            _ => groups.push(ActivityGroup {
                label,
                rows: vec![row],
            }),
        }
    }
    groups
}

/// A `/dashboard/activity` URL with the current filter, optionally a page.
/// Defaults (hide system, page 1) are omitted so a pristine view is a bare
/// path.
fn activity_href(include_system: bool, page: Option<u32>) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    if include_system {
        ser.append_pair("system", "1");
    }
    if let Some(p) = page.filter(|p| *p > 1) {
        ser.append_pair("page", &p.to_string());
    }
    let query = ser.finish();
    if query.is_empty() {
        ACTIVITY_BASE_PATH.to_string()
    } else {
        format!("{ACTIVITY_BASE_PATH}?{query}")
    }
}

// ---- Fleet hosts table (/dashboard/hosts) ------------------------------

#[derive(Deserialize, Default)]
pub struct FleetQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    dir: String,
    page: Option<u32>,
    per_page: Option<u32>,
}

/// The sortable columns of the fleet table, in display order. `numeric`
/// right-aligns the column and makes a fresh click sort descending (busiest
/// first), which is what you want for a usage/count column.
const FLEET_COLUMNS: &[(&str, &str, bool)] = &[
    ("name", "Host", false),
    ("status", "Status", false),
    ("cpu", "CPU", true),
    ("mem", "Memory", true),
    ("disk", "Disk", true),
    ("failed", "Failed units", true),
];

/// A host's latest `(cpu%, mem%, disk%)` sample, each `None` until the metrics
/// sweep has recorded that metric for it.
type HostMetricTriple = (Option<f64>, Option<f64>, Option<f64>);

/// One host with its cached metrics + health, before filtering/sorting. Kept
/// separate from the template row so sorting compares raw numbers, not
/// formatted strings.
struct HostAgg {
    id: uuid::Uuid,
    name: String,
    online: bool,
    cpu: Option<f64>,
    mem: Option<f64>,
    disk: Option<f64>,
    failed_units: i32,
    error: Option<String>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

impl HostAgg {
    fn needs_attention(&self) -> bool {
        self.error.is_some() || self.failed_units > 0
    }
}

/// Everything the fleet table needs to render, independent of whether it's the
/// full page or the htmx fragment -- both build this once and wrap it.
struct FleetView {
    q: String,
    status: String,
    rows: Vec<FleetHostRow>,
    headers: Vec<FleetSortHeader>,
    status_options: Vec<FleetStatusOption>,
    page: crate::templates::NumberedPageInfo,
    total_online: usize,
    total_offline: usize,
    total_attention: usize,
    fragment_url: String,
    self_url: String,
}

/// The dashboard fleet table: every managed host with its cached CPU / memory
/// / disk usage, health flag, and a CPU sparkline, with search, a status
/// filter, sortable columns and pagination. Reads only cached data (the
/// metrics sweep's samples, the health sweep's snapshots, the live connection
/// registry) -- never a live agent dispatch on load. An out-of-range page is
/// clamped to the last real page, never a 500.
pub async fn hosts(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<FleetQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsView)?;
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

    let view = build_fleet_view(&state, &ctx, &q).await?;
    let refresh_seconds = crate::dashboard_prefs::refresh_seconds(&jar);
    let htmx_pref = crate::dashboard_prefs::htmx_enabled(&jar);

    let tpl = FleetHostsTemplate {
        base,
        csrf_token,
        q: view.q,
        status: view.status,
        rows: view.rows,
        headers: view.headers,
        status_options: view.status_options,
        page: view.page,
        total_online: view.total_online,
        total_offline: view.total_offline,
        total_attention: view.total_attention,
        refresh_seconds,
        htmx_pref,
        live_htmx: htmx_pref && refresh_seconds > 0,
        fragment_url: view.fragment_url,
        self_url: view.self_url,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// The `/dashboard/fragments/hosts` htmx poll target: the same table inner
/// content the full page embeds, gated by the same `HostsView` check.
pub async fn hosts_fragment(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<FleetQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsView)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let view = build_fleet_view(&state, &ctx, &q).await?;
    let tpl = FleetHostsFragment {
        csrf_token,
        q: view.q,
        status: view.status,
        rows: view.rows,
        headers: view.headers,
        status_options: view.status_options,
        page: view.page,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

async fn build_fleet_view(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
    q: &FleetQuery,
) -> Result<FleetView, WebError> {
    // One query each for the metric snapshot and health snapshot; joined in
    // memory against the host list. No per-host queries here (the sparklines
    // below are a single batched query for just the visible page).
    let hosts = repo::hosts::list(&state.pool).await?;
    let latest = repo::host_metrics::latest_per_host_metric(&state.pool).await?;
    let health = repo::host_health::all(&state.pool).await?;

    // (cpu%, mem%, disk%) latest per host.
    let mut metrics: HashMap<uuid::Uuid, HostMetricTriple> = HashMap::new();
    for m in &latest {
        let entry = metrics.entry(m.host_id).or_default();
        match m.metric.as_str() {
            x if x == METRIC_CPU_BUSY => entry.0 = Some(m.value),
            x if x == METRIC_MEM_USED => entry.1 = Some(m.value),
            x if x == METRIC_DISK_USED => entry.2 = Some(m.value),
            _ => {}
        }
    }
    let health_by_host: HashMap<uuid::Uuid, &repo::host_health::HostHealth> =
        health.iter().map(|h| (h.host_id, h)).collect();

    let mut aggs: Vec<HostAgg> = hosts
        .into_iter()
        .filter(|h| h.is_active())
        .map(|h| {
            let (cpu, mem, disk) = metrics.get(&h.id).copied().unwrap_or_default();
            let hh = health_by_host.get(&h.id);
            HostAgg {
                online: state.hosts.is_connected(h.id),
                cpu,
                mem,
                disk,
                failed_units: hh.map(|x| x.failed_unit_count).unwrap_or(0),
                error: hh.and_then(|x| x.error.clone()),
                last_seen: h.last_seen_at,
                id: h.id,
                name: h.name,
            }
        })
        .collect();

    // Fleet-wide counts for the filter chips -- always the totals, before the
    // active status filter narrows the list.
    let total_online = aggs.iter().filter(|a| a.online).count();
    let total_offline = aggs.len() - total_online;
    let total_attention = aggs.iter().filter(|a| a.needs_attention()).count();

    // Search + status filter.
    let search = q.q.trim().to_lowercase();
    let status = normalize_status(&q.status);
    aggs.retain(|a| {
        (search.is_empty() || a.name.to_lowercase().contains(&search))
            && match status.as_str() {
                "online" => a.online,
                "offline" => !a.online,
                "attention" => a.needs_attention(),
                _ => true,
            }
    });

    // Sort.
    let sort = normalize_sort(&q.sort);
    let ascending = match q.dir.trim() {
        "asc" => true,
        "desc" => false,
        // Empty or garbage -> the column's natural default (clamp, never error).
        _ => default_ascending_key(&sort),
    };
    sort_aggs(&mut aggs, &sort, ascending);

    // Paginate (clamp, never 500).
    let (mut page, per_page) = pagination::normalize(
        q.page,
        q.per_page,
        FLEET_DEFAULT_PER_PAGE,
        FLEET_MAX_PER_PAGE,
    );
    let total = aggs.len() as u64;
    let total_pages = pagination::total_pages(total, per_page);
    page = page.min(total_pages);
    let start = pagination::offset(page, per_page) as usize;
    let page_aggs: Vec<&HostAgg> = aggs.iter().skip(start).take(per_page as usize).collect();

    // One batched query for the visible page's CPU sparklines.
    let page_ids: Vec<uuid::Uuid> = page_aggs.iter().map(|a| a.id).collect();
    let spark_points = repo::host_metrics::recent_for_hosts(
        &state.pool,
        &page_ids,
        METRIC_CPU_BUSY,
        FLEET_SPARK_HOURS,
    )
    .await?;
    let mut spark_by_host: HashMap<uuid::Uuid, Vec<f64>> = HashMap::new();
    for (host_id, value) in spark_points {
        spark_by_host.entry(host_id).or_default().push(value);
    }

    let rows: Vec<FleetHostRow> = page_aggs
        .iter()
        .map(|a| {
            let cpu_values = spark_by_host.get(&a.id).cloned().unwrap_or_default();
            FleetHostRow {
                host_id: a.id.to_string(),
                name: a.name.clone(),
                online: a.online,
                cpu: a.cpu.map(percent_meter),
                mem: a.mem.map(percent_meter),
                disk: a.disk.map(percent_meter),
                failed_units: a.failed_units,
                attention_reason: attention_reason(a),
                cpu_sparkline: sparkline_points(&cpu_values, 90.0, 22.0),
                last_seen: match a.last_seen {
                    Some(ts) => crate::common::format_in_tz(ts, &ctx.user.timezone),
                    None => "never".to_string(),
                },
            }
        })
        .collect();

    let per_page_param = q.per_page;
    let page_info = pagination::numbered_page_info(
        &pagination::Page::new(Vec::new(), page, per_page, total),
        |p| fleet_href(&q.q, &status, &sort, ascending, per_page_param, Some(p)),
    );

    let headers = FLEET_COLUMNS
        .iter()
        .map(|(key, label, numeric)| {
            let active = sort == *key;
            // A fresh click on a column sorts by its natural default direction;
            // clicking the active column again flips it.
            let next_ascending = if active {
                !ascending
            } else {
                default_ascending_key(key)
            };
            FleetSortHeader {
                label: label.to_string(),
                href: fleet_href(&q.q, &status, key, next_ascending, per_page_param, None),
                active,
                ascending,
                numeric: *numeric,
            }
        })
        .collect();

    let status_options = [
        ("all", "All", total_online + total_offline),
        ("online", "Online", total_online),
        ("offline", "Offline", total_offline),
        ("attention", "Needs attention", total_attention),
    ]
    .into_iter()
    .map(|(value, label, count)| FleetStatusOption {
        label: label.to_string(),
        href: fleet_href(&q.q, value, &sort, ascending, per_page_param, None),
        active: status == value,
        count,
    })
    .collect();

    // The fragment poll must land on the same filtered/sorted page.
    let frag_query = fleet_query(
        &q.q,
        &status,
        &sort,
        ascending,
        per_page_param,
        (page > 1).then_some(page),
    );
    let fragment_url = if frag_query.is_empty() {
        "/dashboard/fragments/hosts".to_string()
    } else {
        format!("/dashboard/fragments/hosts?{frag_query}")
    };
    let self_url = fleet_href(
        &q.q,
        &status,
        &sort,
        ascending,
        per_page_param,
        (page > 1).then_some(page),
    );

    Ok(FleetView {
        q: q.q.clone(),
        status,
        rows,
        headers,
        status_options,
        page: page_info,
        total_online,
        total_offline,
        total_attention,
        fragment_url,
        self_url,
    })
}

/// A usage-percent meter for a fleet-table cell (`"42%"`), reusing the shared
/// tone thresholds.
fn percent_meter(pct: f64) -> MeterCtx {
    meter(pct.round() as i64, &format!("{pct:.0}%"))
}

/// The human phrase for a host that needs a look, or `None` when it's clean.
/// An unreachable host's sweep error wins over a unit count.
fn attention_reason(a: &HostAgg) -> Option<String> {
    if let Some(e) = &a.error {
        Some(format!("unreachable: {e}"))
    } else if a.failed_units > 0 {
        Some(format!(
            "{} failed unit{}",
            a.failed_units,
            if a.failed_units == 1 { "" } else { "s" }
        ))
    } else {
        None
    }
}

/// Clamps an arbitrary `?status=` to one of the known filters -- an unknown or
/// empty value means "all", so an old bookmark never errors.
fn normalize_status(raw: &str) -> String {
    match raw.trim() {
        "online" => "online",
        "offline" => "offline",
        "attention" => "attention",
        _ => "all",
    }
    .to_string()
}

/// Clamps an arbitrary `?sort=` to a known column, defaulting to name.
fn normalize_sort(raw: &str) -> String {
    let raw = raw.trim();
    if FLEET_COLUMNS.iter().any(|(k, _, _)| *k == raw) {
        raw.to_string()
    } else {
        "name".to_string()
    }
}

/// The natural default direction for a sort key: ascending for text columns,
/// descending (busiest/most first) for numeric ones.
fn default_ascending_key(key: &str) -> bool {
    !FLEET_COLUMNS
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, _, numeric)| *numeric)
        .unwrap_or(false)
}

fn sort_aggs(aggs: &mut [HostAgg], sort: &str, ascending: bool) {
    // Missing metrics sort as -1 so a host with no sample yet lands at the
    // "quietest" end rather than jumping to the top of a descending sort.
    let key = |a: &HostAgg| -> f64 {
        match sort {
            "cpu" => a.cpu.unwrap_or(-1.0),
            "mem" => a.mem.unwrap_or(-1.0),
            "disk" => a.disk.unwrap_or(-1.0),
            "failed" => f64::from(a.failed_units),
            "status" => f64::from(u32::from(a.online)),
            _ => 0.0,
        }
    };
    if sort == "name" {
        aggs.sort_by_key(|a| a.name.to_lowercase());
    } else {
        // Tiebreak by name so equal metrics have a stable, readable order.
        aggs.sort_by(|x, y| {
            key(x)
                .partial_cmp(&key(y))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| x.name.to_lowercase().cmp(&y.name.to_lowercase()))
        });
    }
    if !ascending {
        aggs.reverse();
    }
}

/// The fleet table's query string (no leading `?`, empty when everything is at
/// its default) preserving search, status, sort, direction, per-page and page.
/// Shared by the page links (`fleet_href`) and the htmx fragment URL so both
/// carry exactly the same view.
fn fleet_query(
    q: &str,
    status: &str,
    sort: &str,
    ascending: bool,
    per_page: Option<u32>,
    page: Option<u32>,
) -> String {
    let mut ser = form_urlencoded::Serializer::new(String::new());
    let q = q.trim();
    if !q.is_empty() {
        ser.append_pair("q", q);
    }
    if status != "all" {
        ser.append_pair("status", status);
    }
    if sort != "name" {
        ser.append_pair("sort", sort);
    }
    // The direction param is only meaningful (and only emitted) when it differs
    // from the column's natural default, keeping URLs short.
    if ascending != default_ascending_key(sort) {
        ser.append_pair("dir", if ascending { "asc" } else { "desc" });
    }
    if let Some(pp) = per_page {
        ser.append_pair("per_page", &pp.to_string());
    }
    if let Some(p) = page.filter(|p| *p > 1) {
        ser.append_pair("page", &p.to_string());
    }
    ser.finish()
}

/// Builds a `/dashboard/hosts` URL preserving the search, status, sort and
/// direction, optionally setting a page. Default values are omitted so a
/// pristine view stays a bare path. The one place fleet-table links are
/// built, so "preserve every other param" is guaranteed.
fn fleet_href(
    q: &str,
    status: &str,
    sort: &str,
    ascending: bool,
    per_page: Option<u32>,
    page: Option<u32>,
) -> String {
    let query = fleet_query(q, status, sort, ascending, per_page, page);
    if query.is_empty() {
        FLEET_BASE_PATH.to_string()
    } else {
        format!("{FLEET_BASE_PATH}?{query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet(host_count: usize, online_count: usize, open_alerts: i64) -> FleetHealthCtx {
        FleetHealthCtx {
            host_count,
            online_count,
            open_alerts,
            hosts_needing_attention: Vec::new(),
            last_backup: None,
        }
    }

    #[test]
    fn percent_guards_divide_by_zero() {
        assert_eq!(percent(5, 0), 0);
        assert_eq!(percent(0, 0), 0);
        assert_eq!(percent(50, 100), 50);
        // No overflow on large byte counts (u64 near max via u128 math).
        assert_eq!(percent(u64::MAX, u64::MAX), 100);
    }

    #[test]
    fn meter_clamps_and_picks_tone() {
        assert_eq!(meter(-5, "x").pct, 0);
        assert_eq!(meter(150, "x").pct, 100);
        assert_eq!(meter(10, "x").tone, "ok");
        assert_eq!(meter(69, "x").tone, "ok");
        assert_eq!(meter(70, "x").tone, "warn");
        assert_eq!(meter(89, "x").tone, "warn");
        assert_eq!(meter(90, "x").tone, "crit");
        assert_eq!(meter(100, "x").tone, "crit");
    }

    #[test]
    fn uptime_formats_compactly() {
        assert_eq!(format_uptime(0), "0m");
        assert_eq!(format_uptime(59), "0m");
        assert_eq!(format_uptime(600), "10m");
        assert_eq!(format_uptime(3_600 + 12 * 60), "1h 12m");
        assert_eq!(format_uptime(3 * 86_400 + 4 * 3_600), "3d 4h");
    }

    #[test]
    fn ago_formats_by_magnitude() {
        assert_eq!(format_ago(12), "12s ago");
        assert_eq!(format_ago(59), "59s ago");
        assert_eq!(format_ago(60), "1m ago");
        assert_eq!(format_ago(3_599), "59m ago");
        assert_eq!(format_ago(3_600), "1h ago");
    }

    #[test]
    fn stale_threshold_is_three_intervals() {
        // A single missed 60s tick isn't stale; a stalled sampler is.
        assert!(120 <= SELF_METRICS_STALE_SECS);
        assert!(240 > SELF_METRICS_STALE_SECS);
    }

    #[test]
    fn hero_is_plain_welcome_without_hosts_view() {
        let h = build_hero("nyx", false, &fleet(9, 9, 0));
        assert!(!h.show_fleet);
        assert_eq!(h.state_class, "muted");
        assert!(h.summary_line.is_empty());
        assert!(h.greeting.contains("nyx"));
    }

    #[test]
    fn hero_state_ladder() {
        // No hosts enrolled -> muted welcome, no fleet claims.
        let none = build_hero("nyx", true, &fleet(0, 0, 0));
        assert!(!none.show_fleet);
        assert_eq!(none.state_class, "muted");

        // All online, no alerts -> ok.
        let ok = build_hero("nyx", true, &fleet(5, 5, 0));
        assert!(ok.show_fleet);
        assert_eq!(ok.state_class, "ok");
        assert_eq!(ok.state_label, "All systems healthy");

        // Some offline -> warn.
        assert_eq!(build_hero("nyx", true, &fleet(5, 3, 0)).state_class, "warn");
        // Open alerts even with all online -> warn.
        assert_eq!(build_hero("nyx", true, &fleet(5, 5, 2)).state_class, "warn");
        // Attention flag even with all online -> warn.
        let mut attn = fleet(5, 5, 0);
        attn.hosts_needing_attention.push(HostAttentionRow {
            host_name: "WEB-01".to_string(),
            reason: "2 failed units".to_string(),
        });
        assert_eq!(build_hero("nyx", true, &attn).state_class, "warn");

        // Every host dark -> crit, regardless of alerts.
        let crit = build_hero("nyx", true, &fleet(5, 0, 0));
        assert_eq!(crit.state_class, "crit");
        assert_eq!(crit.state_label, "Fleet offline");
    }

    #[test]
    fn hero_summary_line_pluralizes() {
        let one = build_hero("nyx", true, &fleet(1, 1, 1));
        assert!(one.summary_line.contains("1 of 1 host online"));
        assert!(one.summary_line.contains("1 open alert (24h)"));
        let many = build_hero("nyx", true, &fleet(3, 2, 0));
        assert!(many.summary_line.contains("2 of 3 hosts online"));
        assert!(many.summary_line.contains("no open alerts"));
    }

    // ---- Activity feed helpers ----

    fn entry(occurred: chrono::NaiveDateTime, user: Option<&str>) -> abyssal_audit::AuditEntry {
        abyssal_audit::AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            occurred_at: occurred,
            user_id: user.map(|_| uuid::Uuid::new_v4().to_string()),
            username_snapshot: user.unwrap_or("system").to_string(),
            action: "LOGIN_SUCCESS".to_string(),
            resource: None,
            result: "SUCCESS".to_string(),
            source_ip: None,
            auth_method: None,
            metadata: None,
        }
    }

    fn dt(y: i32, m: u32, d: u32, h: u32, min: u32) -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, min, 0)
            .unwrap()
    }

    #[test]
    fn group_activity_buckets_contiguous_days_and_keeps_time_only() {
        let entries = vec![
            entry(dt(2020, 1, 2, 9, 30), Some("nyx")),
            entry(dt(2020, 1, 2, 8, 15), Some("mort")),
            entry(dt(2020, 1, 1, 23, 59), Some("nyx")),
        ];
        let groups = group_activity(&entries, "UTC");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, "2020-01-02");
        assert_eq!(groups[0].rows.len(), 2);
        assert_eq!(groups[0].rows[0].occurred_at, "09:30:00");
        assert_eq!(groups[1].label, "2020-01-01");
        assert_eq!(groups[1].rows.len(), 1);
    }

    #[test]
    fn group_activity_labels_today() {
        let now = chrono::Utc::now().naive_utc();
        let groups = group_activity(&[entry(now, Some("nyx"))], "UTC");
        assert_eq!(groups[0].label, "Today");
    }

    #[test]
    fn group_activity_is_empty_for_no_entries() {
        assert!(group_activity(&[], "UTC").is_empty());
    }

    #[test]
    fn activity_href_omits_defaults() {
        assert_eq!(activity_href(false, None), ACTIVITY_BASE_PATH);
        assert_eq!(activity_href(false, Some(1)), ACTIVITY_BASE_PATH);
    }

    #[test]
    fn activity_href_encodes_filter_and_page() {
        assert_eq!(
            activity_href(true, None),
            format!("{ACTIVITY_BASE_PATH}?system=1")
        );
        let both = activity_href(true, Some(3));
        assert!(both.contains("system=1"));
        assert!(both.contains("page=3"));
        let page_only = activity_href(false, Some(2));
        assert_eq!(page_only, format!("{ACTIVITY_BASE_PATH}?page=2"));
    }

    // ---- Fleet table helpers ----

    fn agg(name: &str, online: bool, cpu: Option<f64>, failed: i32) -> HostAgg {
        HostAgg {
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            online,
            cpu,
            mem: None,
            disk: None,
            failed_units: failed,
            error: None,
            last_seen: None,
        }
    }

    #[test]
    fn normalize_status_clamps_unknown_to_all() {
        assert_eq!(normalize_status("online"), "online");
        assert_eq!(normalize_status(" attention "), "attention");
        assert_eq!(normalize_status(""), "all");
        assert_eq!(normalize_status("nonsense"), "all");
    }

    #[test]
    fn normalize_sort_clamps_unknown_to_name() {
        assert_eq!(normalize_sort("cpu"), "cpu");
        assert_eq!(normalize_sort("disk"), "disk");
        assert_eq!(normalize_sort("'; DROP TABLE"), "name");
        assert_eq!(normalize_sort(""), "name");
    }

    #[test]
    fn default_direction_is_ascending_for_text_descending_for_numeric() {
        assert!(default_ascending_key("name"));
        assert!(default_ascending_key("status"));
        assert!(!default_ascending_key("cpu"));
        assert!(!default_ascending_key("failed"));
    }

    #[test]
    fn sort_by_name_is_case_insensitive() {
        let mut aggs = vec![agg("zeta", true, None, 0), agg("Alpha", true, None, 0)];
        sort_aggs(&mut aggs, "name", true);
        assert_eq!(aggs[0].name, "Alpha");
        assert_eq!(aggs[1].name, "zeta");
    }

    #[test]
    fn sort_by_metric_puts_missing_samples_last_when_descending() {
        let mut aggs = vec![
            agg("a", true, Some(10.0), 0),
            agg("b", true, None, 0),
            agg("c", true, Some(90.0), 0),
        ];
        sort_aggs(&mut aggs, "cpu", false); // busiest first
        assert_eq!(aggs[0].name, "c"); // 90
        assert_eq!(aggs[1].name, "a"); // 10
        assert_eq!(aggs[2].name, "b"); // no sample -> treated as -1, last
    }

    #[test]
    fn attention_reason_prefers_error_then_failed_units() {
        let mut a = agg("web", false, None, 3);
        a.error = Some("timed out".to_string());
        assert_eq!(
            attention_reason(&a),
            Some("unreachable: timed out".to_string())
        );
        let b = agg("db", true, None, 1);
        assert_eq!(attention_reason(&b), Some("1 failed unit".to_string()));
        let c = agg("app", true, None, 2);
        assert_eq!(attention_reason(&c), Some("2 failed units".to_string()));
        let clean = agg("ok", true, None, 0);
        assert_eq!(attention_reason(&clean), None);
    }

    #[test]
    fn percent_meter_rounds_and_tones() {
        let m = percent_meter(69.4);
        assert_eq!(m.label, "69%");
        assert_eq!(m.tone, "ok");
        assert_eq!(percent_meter(95.0).tone, "crit");
    }

    #[test]
    fn fleet_href_omits_defaults_and_keeps_a_bare_path() {
        // Pristine view -> bare path, no query string.
        assert_eq!(
            fleet_href("", "all", "name", true, None, None),
            FLEET_BASE_PATH
        );
        // page 1 is the default and never appears.
        assert_eq!(
            fleet_href("", "all", "name", true, None, Some(1)),
            FLEET_BASE_PATH
        );
    }

    #[test]
    fn fleet_href_preserves_filters_and_encodes() {
        let href = fleet_href("web 01", "online", "cpu", false, None, Some(3));
        // cpu's natural default is descending, so dir is omitted here.
        assert!(href.starts_with("/dashboard/hosts?"));
        assert!(href.contains("q=web+01"));
        assert!(href.contains("status=online"));
        assert!(href.contains("sort=cpu"));
        assert!(href.contains("page=3"));
        assert!(!href.contains("dir="));
    }

    #[test]
    fn fleet_query_is_empty_at_defaults_and_encodes_otherwise() {
        assert_eq!(fleet_query("", "all", "name", true, None, None), "");
        let qs = fleet_query("web 01", "online", "cpu", false, None, Some(2));
        assert!(qs.contains("q=web+01"));
        assert!(qs.contains("status=online"));
        assert!(qs.contains("sort=cpu"));
        assert!(qs.contains("page=2"));
        assert!(!qs.starts_with('?')); // raw query, no leading '?'
    }

    #[test]
    fn activity_fragment_href_matches_the_feed_filter() {
        assert_eq!(
            activity_fragment_href(false, None),
            "/dashboard/fragments/activity"
        );
        let both = activity_fragment_href(true, Some(2));
        assert!(both.starts_with("/dashboard/fragments/activity?"));
        assert!(both.contains("system=1"));
        assert!(both.contains("page=2"));
    }

    #[test]
    fn fleet_href_emits_dir_only_when_it_differs_from_the_column_default() {
        // Ascending CPU is NOT the default (numeric defaults to desc) -> emitted.
        let asc = fleet_href("", "all", "cpu", true, None, None);
        assert!(asc.contains("dir=asc"));
        // Descending name is NOT the default (text defaults to asc) -> emitted.
        let desc = fleet_href("", "all", "name", false, None, None);
        assert!(desc.contains("dir=desc"));
    }
}
