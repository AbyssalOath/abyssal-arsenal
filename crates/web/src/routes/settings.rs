use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::PUBLIC_REGISTRATION_ENABLED;
use abyssal_core::Permission;
use abyssal_database::repo;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, SettingsTemplate};
use crate::theme;

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token);
    let public_registration_enabled =
        repo::settings::get_bool(&state.pool, PUBLIC_REGISTRATION_ENABLED, false).await?;

    let tpl = SettingsTemplate {
        base,
        public_registration_enabled,
        message: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RegistrationForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_registration(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<RegistrationForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        PUBLIC_REGISTRATION_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(PUBLIC_REGISTRATION_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}
