use abyssal_agent_protocol::{AgentMessage, ServerMessage, PROTOCOL_VERSION};
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
) -> anyhow::Result<()> {
    let uri: Uri = ws_url.parse()?;
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("invalid websocket URL: missing host"))?
        .as_str();

    let request = Request::builder()
        .uri(ws_url)
        .header("Host", authority)
        .header("Authorization", format!("Bearer {credential}"))
        .header("X-Agent-Protocol-Version", PROTOCOL_VERSION.to_string())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())?;

    let (ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
    tracing::info!("connected to control plane");

    let (mut sink, mut stream) = ws_stream.split();

    while let Some(message) = stream.next().await {
        match message? {
            Message::Text(text) => {
                let server_msg: ServerMessage = serde_json::from_str(&text)?;
                let response = handle(server_msg, elevation).await;
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

async fn handle(message: ServerMessage, elevation: &ElevationState) -> AgentMessage {
    match message {
        ServerMessage::Ping => AgentMessage::Pong,
        ServerMessage::Command {
            request_id,
            operation,
        } => {
            let outcome = crate::ops::run(operation, elevation).await;
            AgentMessage::Response {
                request_id,
                outcome,
            }
        }
    }
}
