use abyssal_core::AppError;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;

use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{ArsenalDetailTemplate, BaseCtx};
use crate::theme;

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(key): Path<String>,
) -> Result<Response, WebError> {
    let arsenal = state.modules.find(&key).ok_or(AppError::NotFound)?;

    if !arsenal.view_permissions().is_empty()
        && !arsenal.view_permissions().iter().any(|p| ctx.has(*p))
    {
        return Err(WebError(AppError::Forbidden));
    }

    if !state.modules.is_enabled(&state.pool, &key).await? {
        return Err(WebError(AppError::NotFound));
    }

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let tpl = ArsenalDetailTemplate {
        base,
        display_name: arsenal.display_name().to_string(),
        description: arsenal.description().to_string(),
        category: arsenal.category().to_string(),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}
