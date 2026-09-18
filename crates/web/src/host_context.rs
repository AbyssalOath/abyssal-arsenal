use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

/// Mirrors `crate::theme::THEME_COOKIE` exactly: a plain per-browser
/// preference cookie, not a security boundary. Every arsenal action still
/// re-validates the host from the URL path, never from this cookie.
pub const SELECTED_HOST_COOKIE: &str = "abyssal_selected_host";

pub fn current(jar: &CookieJar) -> Option<Uuid> {
    jar.get(SELECTED_HOST_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok())
}
