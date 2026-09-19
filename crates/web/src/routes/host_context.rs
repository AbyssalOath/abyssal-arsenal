use axum::Form;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::error::WebError;
use crate::host_context::SELECTED_HOST_COOKIE;

#[derive(Deserialize)]
pub struct SelectHostForm {
    csrf_token: String,
    #[serde(default)]
    host_id: String,
}

/// Redirects back to wherever the switcher form was submitted from, using
/// the browser's own `Referer` header rather than threading a hidden field
/// through every page that embeds the switcher. Only the path and query are
/// ever reused -- scheme and host are discarded, so a spoofed or
/// cross-origin `Referer` can only send this back into the app itself.
fn referer_path(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<axum::http::Uri>().ok())
        .map(|u| match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        })
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| "/".to_string())
}

/// Sets (or, with an empty/invalid `host_id` -- "All hosts") clears the
/// globally selected host. Purely a UI convenience: every arsenal action
/// still validates the host it's given from the URL path, never from this
/// cookie.
pub async fn select(
    jar: CookieJar,
    headers: HeaderMap,
    Form(form): Form<SelectHostForm>,
) -> Result<Response, WebError> {
    require_csrf(&jar, &form.csrf_token)?;

    let redirect_to = referer_path(&headers);
    let cookie = match Uuid::parse_str(form.host_id.trim()) {
        Ok(host_id) => Cookie::build((SELECTED_HOST_COOKIE, host_id.to_string()))
            .path("/")
            .build(),
        Err(_) => Cookie::build((SELECTED_HOST_COOKIE, ""))
            .path("/")
            .max_age(time::Duration::seconds(-1))
            .build(),
    };
    let jar = jar.add(cookie);

    Ok((jar, Redirect::to(&redirect_to)).into_response())
}
