use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::AppError;
use abyssal_database::repo;
use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{AccountTemplate, BaseCtx};
use crate::theme;

/// Per-user preferences (theme, timezone) -- deliberately not
/// `/admin/settings`, which is gated by `settings.manage`. Any
/// authenticated user needs to be able to set their own timezone, same
/// as the theme toggle already works for everyone.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
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

    let tpl = AccountTemplate {
        must_change_password: ctx.user.must_change_password,
        base,
        password_error: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct TimezoneForm {
    csrf_token: String,
    timezone: String,
}

/// A personal preference, not an admin action -- any logged-in user can set
/// their own timezone, gated only by being authenticated (`CurrentUser`),
/// same as the theme toggle.
pub async fn set_timezone(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<TimezoneForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    if form.timezone.parse::<chrono_tz::Tz>().is_err() {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a recognized timezone.".into(),
        )));
    }

    repo::users::set_timezone(&state.pool, ctx.user.id, &form.timezone).await?;

    Ok(Redirect::to("/account").into_response())
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    csrf_token: String,
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

async fn render_account_error(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    password_error: String,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(jar),
    )
    .await?;

    let tpl = AccountTemplate {
        must_change_password: ctx.user.must_change_password,
        base,
        password_error: Some(password_error),
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Self-service password change -- covers both a voluntary change and the
/// mandatory one for an account `CurrentUser` is otherwise redirecting
/// straight back to `/account` until this succeeds (see
/// `crates/web/src/extract.rs`).
pub async fn change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ChangePasswordForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let Some(current_hash) = ctx.user.password_hash.as_deref() else {
        return render_account_error(
            &state,
            &jar,
            &ctx,
            "This account has no local password to change.".to_string(),
        )
        .await;
    };

    if !abyssal_auth::password::verify_password(&form.current_password, current_hash) {
        return render_account_error(
            &state,
            &jar,
            &ctx,
            "Current password is incorrect.".to_string(),
        )
        .await;
    }

    if form.new_password != form.new_password_confirm {
        return render_account_error(
            &state,
            &jar,
            &ctx,
            "New password and confirmation don't match.".to_string(),
        )
        .await;
    }

    if let Err(message) = abyssal_auth::password::validate_strength(&form.new_password) {
        return render_account_error(&state, &jar, &ctx, message).await;
    }

    let new_hash = abyssal_auth::password::hash_password(&form.new_password)?;
    repo::users::update_password(&state.pool, ctx.user.id, &new_hash, false).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::PasswordChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&ctx.user.username),
    )
    .await?;

    Ok(Redirect::to("/account").into_response())
}
