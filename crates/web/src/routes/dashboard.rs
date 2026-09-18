use abyssal_audit::AuditFilter;
use abyssal_core::{AppError, ModuleCategory, Permission};
use abyssal_database::repo;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    ActivityRow, BaseCtx, DashboardTemplate, FleetHealthCtx, HostAttentionRow, LastBackupRow,
    ModuleGroup, ModuleTile, UpdateNoticeCtx,
};
use crate::theme;

/// How far back "open Thanatos alerts" looks.
const ALERT_WINDOW_HOURS: i64 = 24;
/// How many raw audit rows to fetch before filtering out routine reads --
/// generous enough that a busy fleet still leaves `ACTIVITY_LIMIT` rows
/// after filtering, without scanning the whole table.
const ACTIVITY_FETCH: i64 = 50;
const ACTIVITY_LIMIT: usize = 8;

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

    let fleet_health = if ctx.has(Permission::HostsView) {
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

    let tpl = DashboardTemplate {
        base,
        search_query: q.q,
        pinned,
        groups,
        fleet_health,
        update_notice,
        recent_activity,
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
