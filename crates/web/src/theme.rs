use axum_extra::extract::cookie::CookieJar;

pub const THEME_COOKIE: &str = "abyssal_theme";

pub fn current(jar: &CookieJar) -> String {
    match jar.get(THEME_COOKIE).map(|c| c.value()) {
        Some("light") => "light".to_string(),
        _ => "dark".to_string(),
    }
}
