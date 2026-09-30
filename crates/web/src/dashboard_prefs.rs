//! Per-browser dashboard viewing preferences -- the auto-refresh interval and
//! whether to load the (vendored) htmx enhancement -- stored as plain cookies,
//! exactly like `theme` and `host_context`. Not a security boundary and never
//! read for authorization: purely how often this browser re-fetches the
//! dashboard and whether it does so as a full-page reload (a `<meta refresh>`,
//! no JavaScript) or an htmx partial swap. Off by default: with no cookie set,
//! the dashboard is the same static, no-JS page it has always been.

use axum_extra::extract::cookie::{Cookie, CookieJar};

pub const REFRESH_COOKIE: &str = "abyssal_dashboard_refresh";
pub const HTMX_COOKIE: &str = "abyssal_dashboard_htmx";

/// The auto-refresh intervals the UI offers, in seconds. `0` means off. Any
/// other value is clamped to this set so a hand-edited cookie can't set an
/// abusive (e.g. 1-second) reload cadence.
pub const REFRESH_CHOICES: &[u32] = &[0, 15, 30, 60];

/// This browser's chosen auto-refresh interval in seconds, or `0` (off) when
/// unset or not one of the offered choices.
pub fn refresh_seconds(jar: &CookieJar) -> u32 {
    jar.get(REFRESH_COOKIE)
        .and_then(|c| c.value().parse::<u32>().ok())
        .filter(|v| REFRESH_CHOICES.contains(v))
        .unwrap_or(0)
}

/// Clamps an arbitrary requested interval to one of `REFRESH_CHOICES`, falling
/// back to `0` (off) for anything unrecognised.
pub fn clamp_refresh(requested: u32) -> u32 {
    if REFRESH_CHOICES.contains(&requested) {
        requested
    } else {
        0
    }
}

/// Whether this browser has opted into the htmx partial-refresh enhancement.
pub fn htmx_enabled(jar: &CookieJar) -> bool {
    jar.get(HTMX_COOKIE)
        .map(|c| c.value() == "1")
        .unwrap_or(false)
}

/// A cookie storing the chosen refresh interval (seconds).
pub fn refresh_cookie(seconds: u32) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE, seconds.to_string()))
        .path("/")
        .build()
}

/// A cookie recording the htmx opt-in, or a matching expiry when opting out.
pub fn htmx_cookie(enabled: bool) -> Cookie<'static> {
    if enabled {
        Cookie::build((HTMX_COOKIE, "1")).path("/").build()
    } else {
        Cookie::build((HTMX_COOKIE, ""))
            .path("/")
            .max_age(time::Duration::seconds(-1))
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_refresh_only_allows_offered_choices() {
        assert_eq!(clamp_refresh(0), 0);
        assert_eq!(clamp_refresh(15), 15);
        assert_eq!(clamp_refresh(30), 30);
        assert_eq!(clamp_refresh(60), 60);
        // Anything not offered (incl. an abusive 1s) falls back to off.
        assert_eq!(clamp_refresh(1), 0);
        assert_eq!(clamp_refresh(45), 0);
        assert_eq!(clamp_refresh(3600), 0);
    }

    #[test]
    fn refresh_seconds_reads_and_validates_the_cookie() {
        assert_eq!(refresh_seconds(&CookieJar::new()), 0);
        let jar = CookieJar::new().add(refresh_cookie(30));
        assert_eq!(refresh_seconds(&jar), 30);
        // A hand-edited out-of-set value is ignored (treated as off).
        let bad = CookieJar::new().add(Cookie::new(REFRESH_COOKIE, "7"));
        assert_eq!(refresh_seconds(&bad), 0);
        let garbage = CookieJar::new().add(Cookie::new(REFRESH_COOKIE, "abc"));
        assert_eq!(refresh_seconds(&garbage), 0);
    }

    #[test]
    fn htmx_enabled_reads_the_cookie() {
        assert!(!htmx_enabled(&CookieJar::new()));
        assert!(htmx_enabled(&CookieJar::new().add(htmx_cookie(true))));
        // Opting out sets an expiring blank cookie -> not enabled.
        assert!(!htmx_enabled(&CookieJar::new().add(htmx_cookie(false))));
    }
}
