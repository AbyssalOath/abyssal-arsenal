use abyssal_core::AppError;
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

    let tpl = AccountTemplate { base };
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
