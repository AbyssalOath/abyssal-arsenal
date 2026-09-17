use abyssal_audit::Actor;
use abyssal_core::Permission;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, ModuleRow, ModulesTemplate};
use crate::theme;

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ModulesManage)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);

    let modules = state
        .modules
        .list(&state.pool)
        .await?
        .into_iter()
        .map(|m| ModuleRow {
            key: m.key.to_string(),
            display_name: m.display_name.to_string(),
            description: m.description.to_string(),
            category: m.category.to_string(),
            enabled: m.enabled,
        })
        .collect();

    let tpl = ModulesTemplate { base, modules };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ToggleForm {
    csrf_token: String,
}

pub async fn toggle(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(key): Path<String>,
    Form(form): Form<ToggleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ModulesManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let currently_enabled = state.modules.is_enabled(&state.pool, &key).await?;
    state
        .modules
        .set_enabled(
            &state.pool,
            &key,
            !currently_enabled,
            Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            },
        )
        .await?;

    Ok(Redirect::to("/admin/modules").into_response())
}
