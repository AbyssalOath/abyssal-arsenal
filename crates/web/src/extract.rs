use abyssal_core::secret::hash_token;
use abyssal_core::{AppError, Host};
use abyssal_database::repo;
use abyssal_rbac::AuthContext;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;

use crate::error::WebError;
use crate::state::AppState;

/// The authenticated caller for a request, with their permissions already
/// resolved fresh from the database. Handlers that need auth just take this
/// as a parameter; handlers that don't, don't — there's no global middleware
/// that could silently fail open.
pub struct CurrentUser(pub AuthContext);

#[async_trait::async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = WebError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(&state.config.session_cookie_name)
            .map(|c| c.value().to_string())
            .ok_or(AppError::Unauthenticated)?;

        let session = abyssal_auth::session::validate(&state.pool, &token)
            .await
            .map_err(AppError::Internal)?
            .ok_or(AppError::Unauthenticated)?;

        let user = repo::users::find_by_id(&state.pool, session.user_id)
            .await
            .map_err(AppError::Internal)?
            .ok_or(AppError::Unauthenticated)?;

        if !user.is_active {
            return Err(WebError(AppError::Forbidden));
        }

        let ctx = AuthContext::load(&state.pool, user)
            .await
            .map_err(AppError::Internal)?;

        Ok(CurrentUser(ctx))
    }
}

/// Authenticates a managed host's agent connection via a `Bearer` credential
/// — deliberately separate from `CurrentUser`: an agent is not a logged-in
/// browser session, has no CSRF token, and must never be treated as one.
/// Also captures the agent's self-reported protocol version (if any) off
/// the same request, since both are read from the connection's headers at
/// the same point — see `abyssal_agent_protocol::PROTOCOL_VERSION`. `None`
/// means the header was missing or unparseable, which is itself meaningful:
/// it's what every agent build that predates version reporting will send.
pub struct AgentAuth {
    pub host: Host,
    pub protocol_version: Option<u32>,
}

/// Distinct from `WebError` on purpose: an agent is a machine client, not a
/// browser — it must get a plain 401/500, never `WebError`'s
/// redirect-to-/login special case for `AppError::Unauthenticated`.
pub struct AgentAuthError(StatusCode);

impl IntoResponse for AgentAuthError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

#[async_trait::async_trait]
impl FromRequestParts<AppState> for AgentAuth {
    type Rejection = AgentAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AgentAuthError(StatusCode::UNAUTHORIZED))?;

        let credential = header
            .strip_prefix("Bearer ")
            .ok_or(AgentAuthError(StatusCode::UNAUTHORIZED))?;
        let hash = hash_token(credential);

        let host = repo::hosts::find_by_credential_hash(&state.pool, &hash)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to look up host credential");
                AgentAuthError(StatusCode::INTERNAL_SERVER_ERROR)
            })?
            .ok_or(AgentAuthError(StatusCode::UNAUTHORIZED))?;

        if !host.is_active() {
            return Err(AgentAuthError(StatusCode::FORBIDDEN));
        }

        let protocol_version = parts
            .headers
            .get("X-Agent-Protocol-Version")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());

        Ok(AgentAuth {
            host,
            protocol_version,
        })
    }
}
