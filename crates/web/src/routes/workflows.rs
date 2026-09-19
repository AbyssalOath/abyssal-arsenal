use abyssal_core::Permission;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;

use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, WorkflowEntryRow, WorkflowsTemplate};
use crate::theme;

/// Read-only, for debugging why a "Suggested Next Steps" button did or
/// didn't show up -- there is no admin UI for *editing* the registry
/// (`crates/workflows/registry.json` is compiled in, on purpose; see its
/// README), only for seeing what's currently defined.
pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ModulesManage)?;

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

    let entries = state
        .workflows
        .entries()
        .iter()
        .map(|e| WorkflowEntryRow {
            source_arsenal: e.source_arsenal.clone(),
            source_action: e.source_action.clone(),
            condition: e.condition.describe(),
            target_arsenal: e.target_arsenal.clone(),
            target_action: e.target_action.clone(),
            label: e.label.clone(),
            context_fields: e.context_fields.join(", "),
        })
        .collect();

    let tpl = WorkflowsTemplate { base, entries };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}
