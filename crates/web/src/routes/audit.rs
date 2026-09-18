use abyssal_audit::AuditFilter;
use abyssal_core::Permission;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{AuditRow, AuditTemplate, BaseCtx};
use crate::theme;

const PAGE_SIZE: i64 = 25;

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    action: String,
    #[serde(default)]
    page: i64,
}

fn build_filter(action: &str) -> AuditFilter {
    AuditFilter {
        action: if action.trim().is_empty() {
            None
        } else {
            Some(action.trim().to_string())
        },
        username: None,
    }
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<AuditQuery>,
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

    let filter = build_filter(&q.action);
    let page = q.page.max(0);
    let total = abyssal_audit::count(&state.pool, &filter).await?;
    let total_pages = ((total as f64) / (PAGE_SIZE as f64)).ceil().max(1.0) as i64;

    let entries = abyssal_audit::list(&state.pool, &filter, page, PAGE_SIZE)
        .await?
        .into_iter()
        .map(|e| AuditRow {
            occurred_at: crate::common::format_in_tz(e.occurred_at_utc(), &ctx.user.timezone),
            username: e.username_snapshot,
            action: e.action,
            resource: e.resource.unwrap_or_default(),
            result: e.result,
            source_ip: e.source_ip.unwrap_or_default(),
        })
        .collect();

    let tpl = AuditTemplate {
        base,
        entries,
        page,
        total_pages,
        action_filter: q.action,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn export(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<AuditQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::AuditExport)?;

    let filter = build_filter(&q.action);
    let mut csv =
        String::from("occurred_at,username,action,resource,result,source_ip,auth_method\n");
    // Bounded export: cap at 10,000 rows per request rather than streaming
    // unbounded audit history in one response.
    let entries = abyssal_audit::list(&state.pool, &filter, 0, 10_000).await?;
    for e in entries {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            e.occurred_at_utc().to_rfc3339(),
            csv_escape(&e.username_snapshot),
            csv_escape(&e.action),
            csv_escape(&e.resource.unwrap_or_default()),
            csv_escape(&e.result),
            csv_escape(&e.source_ip.unwrap_or_default()),
            csv_escape(&e.auth_method.unwrap_or_default()),
        ));
    }

    abyssal_audit::record(
        &state.pool,
        abyssal_audit::AuditEvent::new(
            abyssal_audit::AuditAction::AuditExported,
            abyssal_audit::AuditOutcome::Success,
        )
        .actor(abyssal_audit::Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource("audit_log_export"),
    )
    .await
    .ok();

    Ok((
        [
            (header::CONTENT_TYPE, "text/csv"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"audit_log.csv\"",
            ),
        ],
        csv,
    )
        .into_response())
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
