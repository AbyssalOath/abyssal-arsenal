use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use uuid::Uuid;
use zeroize::Zeroizing;

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

/// Shown right after a real Apotheosis elevation over a non-TLS connection.
/// Not an enforcement mechanism (matches the rest of this app's posture:
/// warn for local testing, hard-require TLS in production) -- see
/// SECURITY.md.
const TLS_WARNING: &str =
    "WARNING: this connection is not running over TLS -- the sudo password was sent in \
     plaintext over the network. Do not use Apotheosis over an untrusted network without \
     TLS.\n\n";

/// Escalates a host ("Apotheosis") if a non-empty sudo password was
/// submitted alongside an arsenal action -- a no-op (`Ok(None)`) otherwise,
/// which covers both "this host is already elevated" (no password field
/// shown) and "this action didn't need root after all" (field shown but
/// left blank). Callers should try this before dispatching the action
/// they actually wanted, and only proceed to dispatch it if this returns
/// `Ok`; on `Ok(Some(warning))`, that warning should be prepended to
/// whatever result the caller goes on to show.
///
/// Goes through `execute_on_host` like every other dispatch, so it's
/// permission-checked (`hosts.elevate`, independently of whatever
/// permission the arsenal action itself required -- Apotheosis stays
/// Super-Admin-gated no matter which page triggers it) and audited the
/// same way the original standalone Apotheosis panel was.
pub async fn maybe_elevate(
    state: &AppState,
    ctx: &AuthContext,
    host_id: Uuid,
    host_name: &str,
    sudo_password: Option<String>,
) -> Result<Option<&'static str>, String> {
    let Some(password) = sudo_password.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let password = Zeroizing::new(password);

    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &format!("Elevate Privileges -- {host_name}"),
            AgentOperation::Elevate {
                password: password.to_string(),
            },
            Permission::HostsElevate,
            OperationKind::Write,
            false,
            Duration::from_secs(10),
            None,
        )
        .await;
    drop(password);

    match result {
        Ok(_) => {
            state
                .elevation
                .mark_elevated(host_id, host_name.to_string());
            Ok((!state.config.cookie_secure).then_some(TLS_WARNING))
        }
        Err(e) => Err(format!("Escalation failed: {e}")),
    }
}
