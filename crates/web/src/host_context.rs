use axum_extra::extract::cookie::{Cookie, CookieJar};
use uuid::Uuid;

/// Mirrors `crate::theme::THEME_COOKIE` exactly: a plain per-browser
/// preference cookie, not a security boundary. Every arsenal action still
/// re-validates the host from the URL path, never from this cookie.
pub const SELECTED_HOST_COOKIE: &str = "abyssal_selected_host";

pub fn current(jar: &CookieJar) -> Option<Uuid> {
    jar.get(SELECTED_HOST_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok())
}

/// Phase 9 of Contextual Arsenal Workflow Navigation: "carry the selected
/// host forward." A `Cookie` that sets the globally selected host to
/// `host_id`, for a host-scoped page reached via a workflow suggestion --
/// pass `true` for `arrived_via_suggestion` (a non-empty context) -- so
/// navigating elsewhere afterward (the top nav, a bare arsenal link)
/// continues from the host the suggestion just took you to, instead of
/// snapping back to whatever was previously selected. Returns `None` for
/// an ordinary page view -- visiting a specific host's page on its own has
/// never changed the global default, and this deliberately doesn't change
/// that. Purely a UI convenience, same as `routes::host_context::select`
/// -- never a security boundary, since every arsenal action still
/// re-validates the host from its own URL path.
pub fn carry_forward_cookie(
    host_id: Uuid,
    arrived_via_suggestion: bool,
) -> Option<Cookie<'static>> {
    if !arrived_via_suggestion {
        return None;
    }
    Some(
        Cookie::build((SELECTED_HOST_COOKIE, host_id.to_string()))
            .path("/")
            .build(),
    )
}
