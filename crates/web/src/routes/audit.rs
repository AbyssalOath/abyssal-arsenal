use abyssal_audit::{AuditCursor, AuditFilter, CursorDirection};
use abyssal_core::Permission;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::urlencoding_encode;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{AuditRow, AuditTemplate, BaseCtx};
use crate::theme;

const PAGE_SIZE: i64 = 25;
/// The export's per-batch fetch size -- unrelated to `PAGE_SIZE`, which is
/// the viewer's on-screen page. Streamed in batches this small purely to
/// keep memory flat regardless of how large the filtered result set is
/// (GitHub issue #10: "exports must stream the full result set, never
/// truncated by page limits").
const EXPORT_BATCH_SIZE: i64 = 500;

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    action: String,
    /// Repeatable in principle only via one active value at a time --
    /// whichever cursor the "Newer"/"Older" link the user just followed
    /// carried. Absent on the first page.
    #[serde(default)]
    cursor: Option<String>,
    /// Which direction `cursor` was reached by paging in -- ignored (and
    /// meaningless) when `cursor` is absent. Defaults to `older` since
    /// that's also the direction a first-page fetch conceptually is.
    #[serde(default)]
    dir: Option<String>,
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
    // An unparseable/stale cursor falls back to the first page rather
    // than erroring -- see `AuditCursor::decode`'s doc comment.
    let cursor = q.cursor.as_deref().and_then(AuditCursor::decode);
    let direction = match q.dir.as_deref() {
        Some("newer") => CursorDirection::Newer,
        _ => CursorDirection::Older,
    };

    let page =
        abyssal_audit::list_keyset(&state.pool, &filter, cursor.as_ref(), direction, PAGE_SIZE)
            .await?;
    let action_query = urlencoding_encode(&q.action);
    let newer_href = page.newer_cursor.map(|c| {
        format!(
            "/admin/audit?action={action_query}&cursor={}&dir=newer",
            urlencoding_encode(&c)
        )
    });
    let older_href = page.older_cursor.map(|c| {
        format!(
            "/admin/audit?action={action_query}&cursor={}&dir=older",
            urlencoding_encode(&c)
        )
    });

    let entries = page
        .items
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
        newer_href,
        older_href,
        action_filter: q.action,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct AuditExportQuery {
    #[serde(default)]
    action: String,
}

pub async fn export(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<AuditExportQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::AuditExport)?;

    let filter = build_filter(&q.action);
    let mut csv =
        String::from("occurred_at,username,action,resource,result,source_ip,auth_method\n");
    // Streams the entire filtered result set in bounded batches (GitHub
    // issue #10) -- never truncated at some fixed row cap the way this
    // used to be (`list(pool, filter, 0, 10_000)`), and never holds more
    // than one batch in memory regardless of how large the export is.
    abyssal_audit::for_each_batch(&state.pool, &filter, EXPORT_BATCH_SIZE, |batch| {
        for e in batch {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                e.occurred_at_utc().to_rfc3339(),
                csv_escape(&e.username_snapshot),
                csv_escape(&e.action),
                csv_escape(e.resource.as_deref().unwrap_or_default()),
                csv_escape(&e.result),
                csv_escape(e.source_ip.as_deref().unwrap_or_default()),
                csv_escape(e.auth_method.as_deref().unwrap_or_default()),
            ));
        }
        Ok(())
    })
    .await?;

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
