use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome, ServerMessage};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("host is not currently connected")]
    NotConnected,
    #[error("host did not respond within the timeout")]
    Timeout,
    #[error("host disconnected before responding")]
    ConnectionClosed,
}

struct Connection {
    sender: mpsc::Sender<ServerMessage>,
}

/// Tracks which hosts currently have a live agent connection and routes
/// command dispatches to them. Process-local, in-memory only — same
/// documented limitation as `abyssal_auth::LoginLimiter`: a multi-instance
/// control plane would need this backed by shared state instead.
#[derive(Default)]
pub struct HostConnectionRegistry {
    connections: Mutex<HashMap<Uuid, Connection>>,
    pending: Mutex<HashMap<Uuid, oneshot::Sender<CommandOutcome>>>,
}

impl HostConnectionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, host_id: Uuid, sender: mpsc::Sender<ServerMessage>) {
        self.connections
            .lock()
            .unwrap()
            .insert(host_id, Connection { sender });
    }

    pub fn unregister(&self, host_id: Uuid) {
        self.connections.lock().unwrap().remove(&host_id);
    }

    pub fn is_connected(&self, host_id: Uuid) -> bool {
        self.connections.lock().unwrap().contains_key(&host_id)
    }

    /// Routes a response already unwrapped from `AgentMessage::Response` to
    /// whichever `dispatch` call is waiting on that `request_id`. A response
    /// with no matching waiter (e.g. arriving after `dispatch` already timed
    /// out) is simply dropped.
    pub fn resolve(&self, request_id: Uuid, outcome: CommandOutcome) {
        if let Some(tx) = self.pending.lock().unwrap().remove(&request_id) {
            let _ = tx.send(outcome);
        }
    }

    pub async fn dispatch(
        &self,
        host_id: Uuid,
        operation: AgentOperation,
        timeout: Duration,
    ) -> Result<CommandOutcome, DispatchError> {
        let sender = {
            let connections = self.connections.lock().unwrap();
            connections.get(&host_id).map(|c| c.sender.clone())
        }
        .ok_or(DispatchError::NotConnected)?;

        let request_id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(request_id, tx);

        if sender
            .send(ServerMessage::Command {
                request_id,
                operation,
            })
            .await
            .is_err()
        {
            self.pending.lock().unwrap().remove(&request_id);
            return Err(DispatchError::ConnectionClosed);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(_)) => Err(DispatchError::ConnectionClosed),
            Err(_) => {
                self.pending.lock().unwrap().remove(&request_id);
                Err(DispatchError::Timeout)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_agent_protocol::OperationOutput;

    #[tokio::test]
    async fn dispatch_fails_fast_when_host_not_connected() {
        let registry = HostConnectionRegistry::new();
        let result = registry
            .dispatch(
                Uuid::new_v4(),
                AgentOperation::Ping,
                Duration::from_millis(50),
            )
            .await;
        assert!(matches!(result, Err(DispatchError::NotConnected)));
    }

    #[tokio::test]
    async fn dispatch_times_out_when_no_response_arrives() {
        let registry = HostConnectionRegistry::new();
        let host_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        registry.register(host_id, tx);

        // Drain the command so the channel doesn't fill up, but never reply.
        tokio::spawn(async move {
            let _ = rx.recv().await;
        });

        let result = registry
            .dispatch(host_id, AgentOperation::Ping, Duration::from_millis(50))
            .await;
        assert!(matches!(result, Err(DispatchError::Timeout)));
    }

    #[tokio::test]
    async fn dispatch_resolves_when_response_arrives() {
        let registry = std::sync::Arc::new(HostConnectionRegistry::new());
        let host_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        registry.register(host_id, tx);

        let registry_clone = registry.clone();
        tokio::spawn(async move {
            if let Some(ServerMessage::Command { request_id, .. }) = rx.recv().await {
                registry_clone.resolve(
                    request_id,
                    CommandOutcome::Ok(OperationOutput {
                        stdout: "pong".into(),
                        stderr: String::new(),
                        exit_code: Some(0),
                    }),
                );
            }
        });

        let result = registry
            .dispatch(host_id, AgentOperation::Ping, Duration::from_secs(1))
            .await;
        match result {
            Ok(CommandOutcome::Ok(output)) => assert_eq!(output.stdout, "pong"),
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
