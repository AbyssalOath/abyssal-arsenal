use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES, APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
    HIGH_RISK_STORAGE_OPS_ENABLED, HOST_ISOLATION_ENABLED, PUBLIC_REGISTRATION_ENABLED,
};
use abyssal_core::{AppError, Permission};
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
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);
    let public_registration_enabled =
        repo::settings::get_bool(&state.pool, PUBLIC_REGISTRATION_ENABLED, false).await?;
    let apotheosis_elevation_window_minutes = repo::settings::get_u32(
        &state.pool,
        APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
        APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES,
    )
    .await?;
    let high_risk_storage_ops_enabled =
        repo::settings::get_bool(&state.pool, HIGH_RISK_STORAGE_OPS_ENABLED, false).await?;
    let host_isolation_enabled =
        repo::settings::get_bool(&state.pool, HOST_ISOLATION_ENABLED, false).await?;

    let tpl = SettingsTemplate {
        base,
        public_registration_enabled,
        apotheosis_elevation_window_minutes,
        high_risk_storage_ops_enabled,
        host_isolation_enabled,
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

#[derive(Deserialize)]
pub struct HighRiskStorageOpsForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_high_risk_storage_ops(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<HighRiskStorageOpsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        HIGH_RISK_STORAGE_OPS_ENABLED,
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
            .resource(HIGH_RISK_STORAGE_OPS_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct HostIsolationForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_host_isolation(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<HostIsolationForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        HOST_ISOLATION_ENABLED,
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
            .resource(HOST_ISOLATION_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ElevationWindowForm {
    csrf_token: String,
    minutes: u32,
}

pub async fn set_elevation_window(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ElevationWindowForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !(1..=1440).contains(&form.minutes) {
        return Err(WebError(AppError::Validation(
            "Elevation window must be between 1 and 1440 minutes.".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
        serde_json::json!(form.minutes),
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
            .resource(APOTHEOSIS_ELEVATION_WINDOW_MINUTES)
            .metadata(serde_json::json!({ "minutes": form.minutes })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}
