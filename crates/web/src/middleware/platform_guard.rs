use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use uuid::Uuid;

use abyssal_database::repo;

use crate::state::AppState;

/// Sends a GET for an arsenal's host page (`/arsenals/<key>/<host id>...`, or
/// Sepulchre's `/arsenals/<key>/hosts/<host id>...`) back to the arsenal's
/// host list when the arsenal isn't for that host's OS -- a typed URL, an old
/// bookmark, a stale link -- instead of a page of actions that would all be
/// refused. The list says which hosts it left out and why. Only GETs: a POST
/// is refused at dispatch anyway (`HostConnectionRegistry::dispatch`), with a
/// message saying so.
pub async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if request.method() != axum::http::Method::GET {
        return next.run(request).await;
    }
    let Some((key, host_id)) = host_page(request.uri().path()) else {
        return next.run(request).await;
    };
    let platforms = crate::platform::arsenal_platforms(&state, &key);
    if platforms == abyssal_agent_protocol::Platforms::Both {
        return next.run(request).await;
    }
    let recorded = if state.hosts.is_connected(host_id) {
        None
    } else {
        match repo::hosts::find_by_id(&state.pool, host_id).await {
            Ok(Some(host)) => host.os,
            // Unknown host or a database error: let the page itself say so.
            _ => return next.run(request).await,
        }
    };
    let os = crate::platform::host_os(&state.hosts, host_id, recorded.as_deref());
    if platforms.allows(os) {
        return next.run(request).await;
    }
    Redirect::to(&format!("/arsenals/{key}?all=1")).into_response()
}

/// `(arsenal key, host id)` for a host-page path.
fn host_page(path: &str) -> Option<(String, Uuid)> {
    let mut parts = path.strip_prefix("/arsenals/")?.split('/');
    let key = parts.next()?;
    let mut next = parts.next()?;
    if next == "hosts" {
        next = parts.next()?;
    }
    let host_id = Uuid::parse_str(next).ok()?;
    Some((key.to_string(), host_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_host_pages_only() {
        let id = Uuid::new_v4();
        assert_eq!(
            host_page(&format!("/arsenals/catacomb/{id}")),
            Some(("catacomb".to_string(), id))
        );
        assert_eq!(
            host_page(&format!("/arsenals/catacomb/{id}/whatever")),
            Some(("catacomb".to_string(), id))
        );
        assert_eq!(
            host_page(&format!("/arsenals/sepulchre/hosts/{id}")),
            Some(("sepulchre".to_string(), id))
        );
        assert_eq!(host_page("/arsenals/catacomb"), None);
        assert_eq!(host_page("/arsenals/gravekeeper/domains/abc"), None);
        assert_eq!(host_page(&format!("/admin/hosts/{id}")), None);
    }
}
