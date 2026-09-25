use std::net::SocketAddr;
use std::time::Duration;

use abyssal_agent_protocol::{AgentMessage, ServerMessage};
use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::Host;
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_database::repo;
use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::extract::AgentAuth;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct EnrollRequest {
    token: String,
    name: String,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    host_id: Uuid,
    credential: String,
}

/// The agent's own enrollment call — authenticated purely by the one-time
/// token (an admin-generated secret, not a browser session), so this is
/// intentionally outside `CurrentUser`/CSRF.
pub async fn enroll(State(state): State<AppState>, Json(req): Json<EnrollRequest>) -> Response {
    let token_hash = hash_token(&req.token);

    match repo::host_enrollment_tokens::consume(&state.pool, &token_hash).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                "invalid, expired, or already-used enrollment token",
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to consume enrollment token");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // `name` is unique on this table -- without this check, re-enrolling
    // the same machine (retrying a failed deploy, or reinstalling after an
    // uninstall, neither of which deregisters the old row here) would hit
    // that constraint and fail with a bare 500 instead of either just
    // working or explaining why not.
    match repo::hosts::find_by_name(&state.pool, &req.name).await {
        Ok(Some(existing)) if state.hosts.is_connected(existing.id) => {
            return (
                StatusCode::CONFLICT,
                format!(
                    "a host named \"{}\" is already connected -- remove it from \
                     /admin/hosts first if you want to re-enroll a different machine \
                     under this name",
                    existing.name
                ),
            )
                .into_response();
        }
        Ok(Some(stale)) => {
            // Not currently connected -- almost always a prior enrollment
            // never cleaned up server-side (uninstalling the agent
            // locally doesn't deregister it here), most often hit
            // retrying a failed deploy or re-enrolling the same machine
            // by hand. Safe to supersede: nothing else references
            // `hosts.id` by foreign key (see `repo::hosts::delete`), and
            // reaching this point already required a real, single-use
            // token an admin just generated -- that's the actual
            // authorization for replacing it, not an extra confirmation
            // this machine-to-machine endpoint has no session to ask for.
            if let Err(e) = repo::hosts::delete(&state.pool, stale.id).await {
                tracing::error!(
                    error = %e,
                    host_id = %stale.id,
                    "failed to remove stale host record before re-enrollment"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            if let Err(e) = abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::HostRemoved, AuditOutcome::Success)
                    .resource(&stale.name)
                    .metadata(serde_json::json!({
                        "reason": "superseded by a new enrollment under the same name",
                        "previous_host_id": stale.id,
                    })),
            )
            .await
            {
                tracing::error!(error = %e, "failed to record audit event for superseded host");
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "failed to check for an existing host with this name");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let credential = generate_token();
    let credential_hash = hash_token(&credential);

    let host = match repo::hosts::create(&state.pool, &req.name, &credential_hash).await {
        Ok(host) => host,
        Err(e) => {
            tracing::error!(error = %e, "failed to create host record");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Err(e) = abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::HostEnrolled, AuditOutcome::Success).resource(&host.name),
    )
    .await
    {
        tracing::error!(error = %e, "failed to write audit record for host enrollment");
    }

    Json(EnrollResponse {
        host_id: host.id,
        credential,
    })
    .into_response()
}

pub async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AgentAuth {
        host,
        protocol_version,
        os,
        agent_version,
    }: AgentAuth,
) -> Response {
    ws.on_upgrade(move |socket| {
        handle_socket(
            socket,
            state,
            host,
            protocol_version,
            os,
            agent_version,
            addr,
        )
    })
}

async fn handle_socket(
    mut socket: WebSocket,
    state: AppState,
    host: Host,
    protocol_version: Option<u32>,
    os: Option<String>,
    agent_version: Option<String>,
    addr: SocketAddr,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ServerMessage>(16);
    state.hosts.register(host.id, tx, protocol_version);
    if state.hosts.agent_protocol_mismatch(host.id) {
        tracing::warn!(
            host_id = %host.id,
            name = %host.name,
            ?protocol_version,
            control_plane_version = abyssal_agent_protocol::PROTOCOL_VERSION,
            "agent connected with a mismatched or unreported protocol version -- it may be running a stale build",
        );
    }
    tracing::info!(host_id = %host.id, name = %host.name, ?os, ?agent_version, "agent connected");
    if let Err(e) = repo::hosts::touch_last_seen_with_ip(
        &state.pool,
        host.id,
        &addr.ip().to_string(),
        os.as_deref(),
        agent_version.as_deref(),
    )
    .await
    {
        tracing::warn!(error = %e, "failed to record host connection time/address");
    }

    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    heartbeat.tick().await; // first tick fires immediately; skip it

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let Ok(payload) = serde_json::to_string(&ServerMessage::Ping) else { continue };
                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            outgoing = rx.recv() => {
                let Some(msg) = outgoing else { break };
                let Ok(payload) = serde_json::to_string(&msg) else { continue };
                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(agent_msg) = serde_json::from_str::<AgentMessage>(&text) {
                            handle_agent_message(&state, host.id, agent_msg).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    state.hosts.unregister(host.id);
    tracing::info!(host_id = %host.id, "agent disconnected");
}

async fn handle_agent_message(state: &AppState, host_id: Uuid, msg: AgentMessage) {
    match msg {
        AgentMessage::Pong => {
            let _ = repo::hosts::touch_last_seen(&state.pool, host_id).await;
        }
        AgentMessage::Response {
            request_id,
            outcome,
        } => {
            state.hosts.resolve(request_id, outcome);
            let _ = repo::hosts::touch_last_seen(&state.pool, host_id).await;
        }
    }
}
