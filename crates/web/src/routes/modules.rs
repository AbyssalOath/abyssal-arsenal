use abyssal_audit::Actor;
use abyssal_core::{AppError, Permission};
use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, ConfirmTemplate, ModuleRow, ModulesTemplate};
use crate::theme;

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

/// Enabling a module is additive and easily reversed, so it stays a
/// one-click action -- only *disabling* (below) goes through a confirm
/// step.
pub async fn enable(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(key): Path<String>,
    Form(form): Form<ToggleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ModulesManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    state
        .modules
        .set_enabled(
            &state.pool,
            &key,
            true,
            Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            },
        )
        .await?;

    Ok(Redirect::to("/admin/modules").into_response())
}

pub async fn disable_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(key): Path<String>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ModulesManage)?;

    let arsenal = state.modules.find(&key).ok_or(AppError::NotFound)?;
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

    let tpl = ConfirmTemplate {
        base,
        title: "Disable module".to_string(),
        message: format!(
            "This will disable \"{}\". Its page becomes unreachable for every user until it's re-enabled.",
            arsenal.display_name()
        ),
        action_url: format!("/admin/modules/{key}/disable"),
        cancel_url: "/admin/modules".to_string(),
        escalate_host_id: None,
        type_to_confirm: None,
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct DisableForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
}

pub async fn disable(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(key): Path<String>,
    Form(form): Form<DisableForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ModulesManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Disabling this module was not confirmed.".into(),
        )));
    }

    state
        .modules
        .set_enabled(
            &state.pool,
            &key,
            false,
            Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            },
        )
        .await?;

    Ok(Redirect::to("/admin/modules").into_response())
}
