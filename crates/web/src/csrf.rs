use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;

pub const CSRF_COOKIE: &str = "abyssal_csrf";
pub const CSRF_FIELD: &str = "csrf_token";

fn generate() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Double-submit CSRF: a token is stored in a (non-HttpOnly, so a same-origin
/// page can read it back into a hidden field) cookie, and every state-changing
/// form must echo it back. A cross-site form can trigger the cookie to be
/// sent, but can't read its value to also forge the matching field.
pub fn ensure_token(jar: &CookieJar) -> (String, Option<Cookie<'static>>) {
    if let Some(existing) = jar.get(CSRF_COOKIE) {
        (existing.value().to_string(), None)
    } else {
        let token = generate();
        let cookie = Cookie::build((CSRF_COOKIE, token.clone()))
            .path("/")
            .same_site(SameSite::Lax)
            .http_only(false)
            .build();
        (token, Some(cookie))
    }
}

pub fn verify(jar: &CookieJar, submitted: &str) -> bool {
    !submitted.is_empty()
        && jar
            .get(CSRF_COOKIE)
            .map(|c| c.value() == submitted)
            .unwrap_or(false)
}
