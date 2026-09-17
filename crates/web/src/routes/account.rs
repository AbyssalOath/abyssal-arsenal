use abyssal_core::AppError;
use abyssal_database::repo;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;

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

    Ok(Redirect::to("/").into_response())
}
