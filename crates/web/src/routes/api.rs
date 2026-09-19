use axum::Json;
use axum::response::IntoResponse;
use serde_json::json;

use crate::error::WebError;
use crate::extract::CurrentUser;

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
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
