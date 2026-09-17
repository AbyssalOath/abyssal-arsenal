use abyssal_audit::AuditFilter;
use abyssal_core::Permission;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;

use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{ActivityRow, BaseCtx, DashboardTemplate, ModuleTile};
use crate::theme;

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let modules = state
        .modules
        .list(&state.pool)
        .await?
        .into_iter()
        .filter(|m| m.enabled)
        .filter(|m| m.view_permissions.is_empty() || m.view_permissions.iter().any(|p| ctx.has(*p)))
        .map(|m| ModuleTile {
            key: m.key,
            display_name: m.display_name,
            description: m.description,
            category: m.category.to_string(),
        })
        .collect();

    let recent_activity = if ctx.has(Permission::AuditView) {
        abyssal_audit::list(&state.pool, &AuditFilter::default(), 0, 8)
            .await?
            .into_iter()
            .map(|e| ActivityRow {
                occurred_at: crate::common::format_in_tz(e.occurred_at_utc(), &ctx.user.timezone),
                username: e.username_snapshot,
                action: e.action,
                result: e.result,
            })
            .collect()
    } else {
        Vec::new()
    };

    let tpl = DashboardTemplate {
        base,
        modules,
        recent_activity,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}
