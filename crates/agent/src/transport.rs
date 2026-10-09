use abyssal_agent_protocol::{AgentMessage, PROTOCOL_VERSION, ServerMessage};
use futures_util::{SinkExt, StreamExt};
use http::{Request, Uri};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::elevation::ElevationState;

pub fn to_ws_url(base: &str) -> anyhow::Result<String> {
    let base = base.trim_end_matches('/');
    let converted = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        anyhow::bail!("control plane URL must start with http:// or https://, got: {base}");
    };
    Ok(format!("{converted}/ws/agent"))
}

/// Connects to the control plane's `/ws/agent` endpoint, authenticating via
/// a `Bearer` header (validated server-side before the WebSocket upgrade
/// completes), and serves incoming commands until the connection closes.
pub async fn connect_and_serve(
    ws_url: &str,
    credential: &str,
    elevation: &ElevationState,
    trust: &crate::tls::Trust,
) -> anyhow::Result<()> {
    let uri: Uri = ws_url.parse()?;
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("invalid websocket URL: missing host"))?
        .as_str();
    // Host only (no port) -- threaded down to `IsolateHost` so it can
    // allow-list exactly the control plane's own address, never an
    // admin-supplied one.
    let control_plane_host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("invalid websocket URL: missing host"))?
        .to_string();

    let request = Request::builder()
        .uri(ws_url)
        .header("Host", authority)
        .header("Authorization", format!("Bearer {credential}"))
        .header("X-Agent-Protocol-Version", PROTOCOL_VERSION.to_string())
        // Coarse platform family + the agent binary's own version --
        // persisted onto the `hosts` row at connect time so features like
        // Thanatos can route to the right per-OS logic instead of
        // assuming every host is Linux.
        .header("X-Agent-Os", std::env::consts::OS)
        .header("X-Agent-Version", env!("CARGO_PKG_VERSION"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())?;

    let (ws_stream, _response) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(trust.rustls_config())),
    )
    .await?;
    tracing::info!("connected to control plane");

    let (mut sink, mut stream) = ws_stream.split();

    while let Some(message) = stream.next().await {
        match message? {
            Message::Text(text) => {
                let server_msg: ServerMessage = match serde_json::from_str(&text) {
                    Ok(msg) => msg,
                    Err(e) => {
                        // A newer control plane sent something this build
                        // doesn't know. Answer a command with an error rather
                        // than dropping the connection: an agent that
                        // disconnects over it is knocked offline every time a
                        // sweep sends it.
                        tracing::warn!(error = %e, "unrecognized message from the control plane");
                        if let Some(response) = unsupported_command(&text) {
                            sink.send(Message::Text(serde_json::to_string(&response)?))
                                .await?;
                        }
                        continue;
                    }
                };
                let response = handle(server_msg, elevation, &control_plane_host).await;
                let payload = serde_json::to_string(&response)?;
                sink.send(Message::Text(payload)).await?;
            }
            Message::Ping(payload) => {
                sink.send(Message::Pong(payload)).await?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    Ok(())
}

/// The reply to a command this build can't parse (an operation added after
/// it, most likely), if `text` is a command at all.
fn unsupported_command(text: &str) -> Option<AgentMessage> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let request_id = value.get("Command")?.get("request_id")?.clone();
    let request_id: uuid::Uuid = serde_json::from_value(request_id).ok()?;
    Some(AgentMessage::Response {
        request_id,
        outcome: abyssal_agent_protocol::CommandOutcome::Err(format!(
            "this agent (v{}, protocol {PROTOCOL_VERSION}) doesn't support this operation -- \
             update it with 'Update agent' on /admin/hosts",
            env!("CARGO_PKG_VERSION")
        )),
    })
}

async fn handle(
    message: ServerMessage,
    elevation: &ElevationState,
    control_plane_host: &str,
) -> AgentMessage {
    match message {
        ServerMessage::Ping => AgentMessage::Pong,
        ServerMessage::Command {
            request_id,
            operation,
        } => {
            let outcome = crate::ops::run(operation, elevation, control_plane_host).await;
            AgentMessage::Response {
                request_id,
                outcome,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_operation_gets_an_error_reply() {
        let id = "4f0c5a0e-8a51-4a59-9d55-6e1b3c1f2a77";
        let text = format!(
            r#"{{"Command":{{"request_id":"{id}","operation":{{"SomeFutureOp":{{"x":1}}}}}}}}"#
        );
        assert!(serde_json::from_str::<ServerMessage>(&text).is_err());
        match unsupported_command(&text) {
            Some(AgentMessage::Response {
                request_id,
                outcome: abyssal_agent_protocol::CommandOutcome::Err(message),
            }) => {
                assert_eq!(request_id.to_string(), id);
                assert!(message.contains("update it"), "{message}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn non_commands_and_garbage_get_no_reply() {
        assert!(unsupported_command(r#""SomeFutureMessage""#).is_none());
        assert!(unsupported_command(r#"{"Command":{"operation":"Ping"}}"#).is_none());
        assert!(unsupported_command("not json").is_none());
    }

    #[test]
    fn a_reply_round_trips_through_the_protocol() {
        let text = r#"{"Command":{"request_id":"4f0c5a0e-8a51-4a59-9d55-6e1b3c1f2a77","operation":"NoSuchOp"}}"#;
        let reply = serde_json::to_string(&unsupported_command(text).unwrap()).unwrap();
        assert!(serde_json::from_str::<AgentMessage>(&reply).is_ok());
    }
}
