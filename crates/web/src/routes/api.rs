use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Liveness (`/healthz`): the process is up and serving. Deliberately does no
/// I/O -- it must stay `200` even while a readiness check would fail (DB down,
/// restore in progress), so an orchestrator's liveness probe never restarts a
/// container that is merely not-ready. Unauthenticated on purpose.
pub async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Readiness (`/readyz`): `200` only when the control plane can actually serve
/// requests -- database reachable, migrations clean, not mid-restore --
/// otherwise `503` with a compact per-component report. Unauthenticated (an
/// external monitor can't log in) but leaks nothing sensitive.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let report = crate::health::readiness(&state).await;
    (report.status_code(), Json(report.to_json())).into_response()
}

/// Establishes the API seam the Tauri desktop client will reuse later — the
/// desktop app authenticates against this same backend and sees the same
/// permissions, rather than duplicating any business logic.
pub async fn me(CurrentUser(ctx): CurrentUser) -> Result<impl IntoResponse, WebError> {
    let permissions: Vec<&'static str> = ctx.permissions.iter().map(|p| p.as_key()).collect();
    Ok(Json(json!({
        "id": ctx.user.id,
        "username": ctx.user.username,
        "email": ctx.user.email,
        "permissions": permissions,
    })))
}
