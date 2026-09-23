use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// Blocks ordinary traffic while a Reliquary restore is in progress
/// (`reliquary_backup::restore::MaintenanceMode`) -- GitHub issue #9.
/// Deliberately blunt: every request except the backups page itself (so
/// an admin watching the restore can still see it) and static assets
/// (so that page still renders with its styling) gets the maintenance
/// page instead of whatever it asked for, rather than trying to
/// distinguish "read" from "write" requests -- a write succeeding against
/// a database mid-restore is the exact failure mode this exists to
/// prevent, and erring toward blocking too much for the (short) duration
/// of a restore is the safer mistake to make.
pub async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !state.maintenance_mode.is_active() {
        return next.run(request).await;
    }

    let path = request.uri().path();
    if path.starts_with("/static/") || path.starts_with("/arsenals/reliquary/backups") {
        return next.run(request).await;
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        [("Retry-After", "30")],
        axum::response::Html(
            "<!doctype html><html><head><title>Maintenance</title></head><body \
             style=\"font-family:sans-serif; text-align:center; padding:4rem;\">\
             <h1>Under maintenance</h1>\
             <p>A backup restore is in progress. This page will be available again shortly.</p>\
             </body></html>",
        ),
    )
        .into_response()
}
