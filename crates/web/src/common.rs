use abyssal_core::AppError;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use crate::csrf;
use crate::error::WebError;
use crate::state::AppState;

pub fn require_csrf(jar: &CookieJar, submitted: &str) -> Result<(), WebError> {
    if csrf::verify(jar, submitted) {
        Ok(())
    } else {
        Err(WebError(AppError::Validation(
            "Your session expired or this form was submitted from an untrusted origin. Please try again.".into(),
        )))
    }
}

/// Builds the session cookie. Deliberately left without an explicit
/// `Max-Age`/`Expires`, making it a browser "session cookie" (cleared on
/// browser close) in addition to the server-side TTL enforced on every
/// validation — belt and suspenders rather than trusting the client's clock.
pub fn build_session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((state.config.session_cookie_name.clone(), token))
        .path("/")
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(SameSite::Lax)
        .build()
}

pub fn clear_session_cookie(state: &AppState) -> Cookie<'static> {
    Cookie::build((state.config.session_cookie_name.clone(), ""))
        .path("/")
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(-1))
        .build()
}
