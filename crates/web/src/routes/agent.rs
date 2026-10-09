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
///
/// The token may also be the AAT (`abyssal_agent_protocol::aat`), the
/// reusable install token: never consumed, and the host starts out pending
/// when approval is required.
pub async fn enroll(State(state): State<AppState>, Json(req): Json<EnrollRequest>) -> Response {
    let via_aat = abyssal_agent_protocol::aat::is_aat(&req.token);
    let mut pending_approval = false;
    let mut is_control_plane = false;
    if via_aat {
        match crate::aat::matches(&state.pool, state.encryption_key.as_deref(), &req.token).await {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    "invalid agent install token (AAT) -- it may have been rotated; copy the \
                     current one from /admin/hosts",
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "failed to check the agent install token");
                return aat_unavailable();
            }
        }
        pending_approval = match crate::aat::require_approval(&state.pool).await {
            Ok(required) => required,
            Err(e) => {
                tracing::error!(error = %e, "failed to read the AAT approval setting");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    } else {
        let token_hash = hash_token(&req.token);
        match repo::host_enrollment_tokens::consume(&state.pool, &token_hash).await {
            Ok(true) => {
                // Minted by `install.sh` for the server's own agent.
                is_control_plane =
                    repo::host_enrollment_tokens::is_control_plane(&state.pool, &token_hash)
                        .await
                        .unwrap_or_else(|e| {
                            tracing::error!(error = %e, "failed to read the enrollment token's control-plane flag");
                            false
                        });
            }
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
        // The AAT is shared by every machine it's deployed to, so it never
        // authorizes replacing an existing host -- that would let anything
        // holding it take over a host's name (and its place in the UI) while
        // the real one is offline. A single-use token was minted by an admin
        // for exactly this enrollment; the AAT wasn't.
        Ok(Some(existing)) if via_aat => {
            return (
                StatusCode::CONFLICT,
                format!(
                    "a host named \"{}\" is already enrolled -- remove it from /admin/hosts \
                     first to re-enroll this machine with the install token",
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

    let host = match repo::hosts::create_with_approval(
        &state.pool,
        &req.name,
        &credential_hash,
        pending_approval,
    )
    .await
    {
        Ok(host) => host,
        Err(e) => {
            tracing::error!(error = %e, "failed to create host record");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if is_control_plane {
        // Flag it before its agent can connect, so the guardrails are on
        // from its first command. Failing to is failing the enrollment:
        // an unguarded control-plane agent is what the flag exists to
        // prevent.
        if let Err(e) = repo::hosts::set_control_plane(&state.pool, host.id, true).await {
            tracing::error!(error = %e, "failed to flag the control plane's own host");
            let _ = repo::hosts::delete(&state.pool, host.id).await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        state.hosts.set_control_plane(host.id, true);
    }

    if let Err(e) = abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::HostEnrolled, AuditOutcome::Success)
            .resource(&host.name)
            .metadata(serde_json::json!({
                "via": if via_aat { "aat" } else { "enrollment_token" },
                "pending_approval": pending_approval,
                "control_plane": is_control_plane,
            })),
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

/// The AAT exists but can't be read (most likely `ENCRYPTION_KEY` changed):
/// not the agent's fault, and only an admin can fix it.
fn aat_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "this control plane can't read its agent install token (AAT) -- an admin must rotate \
         it on /admin/hosts",
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CaProofQuery {
    nonce: String,
}

/// `GET /api/agent/ca?nonce=...` -- the control plane's CA bundle plus an
/// AAT-keyed proof over it and the agent's nonce, so a host installing with
/// only the AAT can authenticate the CA before trusting it (see
/// `abyssal_agent_protocol::aat`). Unauthenticated by design: the caller
/// doesn't trust this server yet, and the response proves knowledge of the
/// AAT without revealing it. `ca_pem` is `None` (proof still included) when
/// the certificate is publicly trusted.
pub async fn ca_proof(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<CaProofQuery>,
) -> Response {
    // The agent sends 32 random bytes as hex; anything far off that is not
    // an agent, and an unbounded nonce is just extra HMAC work.
    if !(16..=128).contains(&query.nonce.len()) {
        return (StatusCode::BAD_REQUEST, "nonce must be 16-128 characters").into_response();
    }
    let aat = match crate::aat::current(&state.pool, state.encryption_key.as_deref()).await {
        Ok(Some(aat)) => aat,
        Ok(None) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "this control plane has no agent install token yet",
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "failed to read the agent install token");
            return aat_unavailable();
        }
    };
    let ca_pem =
        crate::internal_tls::trust_bundle().or_else(|| crate::public_ca::load().map(|ca| ca.pem));
    let proof = abyssal_agent_protocol::aat::ca_proof(&aat, &query.nonce, ca_pem.as_deref());
    Json(abyssal_agent_protocol::aat::CaProofResponse { ca_pem, proof }).into_response()
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
    // Before `register`, so no command can reach it unguarded.
    state
        .hosts
        .set_control_plane(host.id, host.is_control_plane);
    state.hosts.register(host.id, tx, protocol_version);
    if host.is_control_plane {
        let hosts = state.hosts.clone();
        let host_id = host.id;
        tokio::spawn(async move {
            crate::control_plane::probe_docker_device(&hosts, host_id).await;
        });
    }
    // Keep the agent's trusted control-plane CA current (a rotation may have
    // started or finished while it was away). Off the connection's own task:
    // the response arrives through the read loop below.
    if crate::internal_tls::is_managed() {
        let hosts = state.hosts.clone();
        let host_id = host.id;
        tokio::spawn(async move {
            crate::internal_tls::push_to_host(&hosts, host_id).await;
        });
    }
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
        AgentMessage::Telemetry { stdout } => {
            // M6 Option B scaffold: unsolicited real-time telemetry push. The
            // agent doesn't emit this yet; when a future producer does it already
            // flows through the same ingest path as a poll. Untrusted input,
            // parsed exactly like scan output.
            let _ = repo::hosts::touch_last_seen(&state.pool, host_id).await;
            if let Err(e) =
                crate::thanatos_ops::ingest_pushed_telemetry(state, host_id, &stdout).await
            {
                tracing::warn!(host_id = %host_id, error = %e, "failed to ingest pushed telemetry");
            }
        }
    }
}
