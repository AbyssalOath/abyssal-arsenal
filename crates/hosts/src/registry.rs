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
    protocol_version: Option<u32>,
}

/// What's known about a connected agent's protocol compatibility, for the UI
/// to surface -- see `abyssal_agent_protocol::PROTOCOL_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProtocolStatus {
    NotConnected,
    /// Connected, but reported no version at all -- every agent build that
    /// predates version reporting looks like this.
    Unknown,
    Version(u32),
}

/// Tracks which hosts currently have a live agent connection and routes
/// command dispatches to them. Process-local, in-memory only — same
/// documented limitation as `abyssal_auth::LoginLimiter`: a multi-instance
/// control plane would need this backed by shared state instead.
#[derive(Default)]
pub struct HostConnectionRegistry {
    connections: Mutex<HashMap<Uuid, Connection>>,
    /// Keyed by request ID; each entry also carries the host ID it was sent
    /// to, so `unregister` can find and drop every request still in flight
    /// to a connection that just went away.
    pending: Mutex<HashMap<Uuid, (Uuid, oneshot::Sender<CommandOutcome>)>>,
}

impl HostConnectionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        host_id: Uuid,
        sender: mpsc::Sender<ServerMessage>,
        protocol_version: Option<u32>,
    ) {
        self.connections.lock().unwrap().insert(
            host_id,
            Connection {
                sender,
                protocol_version,
            },
        );
    }

    /// Also fails any dispatch still waiting on a response from this host
    /// immediately, rather than leaving it to silently burn its full
    /// timeout. Dropping the oneshot sender here (instead of trying to
    /// send an outcome through it) is what makes `dispatch`'s `rx.await`
    /// resolve right away, via the existing `Ok(Err(_)) =>
    /// DispatchError::ConnectionClosed` arm -- no other change needed
    /// there. This is what makes a stale agent build (one that disconnects
    /// because it can't deserialize a newer `AgentOperation` variant)
    /// surface as a clear, fast "host disconnected before responding"
    /// instead of a confusing multi-second timeout.
    pub fn unregister(&self, host_id: Uuid) {
        self.connections.lock().unwrap().remove(&host_id);
        self.pending
            .lock()
            .unwrap()
            .retain(|_, (pending_host_id, _)| *pending_host_id != host_id);
    }

    pub fn is_connected(&self, host_id: Uuid) -> bool {
        self.connections.lock().unwrap().contains_key(&host_id)
    }

    pub fn agent_protocol_status(&self, host_id: Uuid) -> AgentProtocolStatus {
        match self.connections.lock().unwrap().get(&host_id) {
            None => AgentProtocolStatus::NotConnected,
            Some(Connection {
                protocol_version: None,
                ..
            }) => AgentProtocolStatus::Unknown,
            Some(Connection {
                protocol_version: Some(v),
                ..
            }) => AgentProtocolStatus::Version(*v),
        }
    }

    /// True only while connected -- an offline host already shows as
    /// offline, so there's nothing extra to flag until it reconnects.
    pub fn agent_protocol_mismatch(&self, host_id: Uuid) -> bool {
        match self.agent_protocol_status(host_id) {
            AgentProtocolStatus::NotConnected => false,
            AgentProtocolStatus::Unknown => true,
            AgentProtocolStatus::Version(v) => v != abyssal_agent_protocol::PROTOCOL_VERSION,
        }
    }

    /// Routes a response already unwrapped from `AgentMessage::Response` to
    /// whichever `dispatch` call is waiting on that `request_id`. A response
    /// with no matching waiter (e.g. arriving after `dispatch` already timed
    /// out) is simply dropped.
    pub fn resolve(&self, request_id: Uuid, outcome: CommandOutcome) {
        if let Some((_, tx)) = self.pending.lock().unwrap().remove(&request_id) {
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
        self.pending
            .lock()
            .unwrap()
            .insert(request_id, (host_id, tx));

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
        registry.register(host_id, tx, Some(abyssal_agent_protocol::PROTOCOL_VERSION));

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
    async fn unregister_fails_pending_dispatch_immediately_instead_of_waiting_for_timeout() {
        let registry = std::sync::Arc::new(HostConnectionRegistry::new());
        let host_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        registry.register(host_id, tx, Some(abyssal_agent_protocol::PROTOCOL_VERSION));

        let registry_clone = registry.clone();
        tokio::spawn(async move {
            // Simulate the agent choking on the message (e.g. an unknown
            // `AgentOperation` variant on a stale build) and its connection
            // handler unregistering as a result, without ever responding.
            let _ = rx.recv().await;
            registry_clone.unregister(host_id);
        });

        let start = std::time::Instant::now();
        let result = registry
            .dispatch(host_id, AgentOperation::Ping, Duration::from_secs(30))
            .await;
        assert!(matches!(result, Err(DispatchError::ConnectionClosed)));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "should fail fast on unregister, not wait anywhere near the 30s timeout"
        );
    }

    #[tokio::test]
    async fn dispatch_resolves_when_response_arrives() {
        let registry = std::sync::Arc::new(HostConnectionRegistry::new());
        let host_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(1);
        registry.register(host_id, tx, Some(abyssal_agent_protocol::PROTOCOL_VERSION));

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

    #[test]
    fn protocol_status_and_mismatch_by_connection_state() {
        let registry = HostConnectionRegistry::new();
        let host_id = Uuid::new_v4();

        assert_eq!(
            registry.agent_protocol_status(host_id),
            AgentProtocolStatus::NotConnected
        );
        assert!(!registry.agent_protocol_mismatch(host_id));

        let (tx, _rx) = mpsc::channel(1);
        registry.register(host_id, tx, None);
        assert_eq!(
            registry.agent_protocol_status(host_id),
            AgentProtocolStatus::Unknown
        );
        assert!(
            registry.agent_protocol_mismatch(host_id),
            "an agent reporting no version at all should be flagged as mismatched"
        );

        let (tx, _rx) = mpsc::channel(1);
        registry.register(
            host_id,
            tx,
            Some(abyssal_agent_protocol::PROTOCOL_VERSION + 1),
        );
        assert!(registry.agent_protocol_mismatch(host_id));

        let (tx, _rx) = mpsc::channel(1);
        registry.register(host_id, tx, Some(abyssal_agent_protocol::PROTOCOL_VERSION));
        assert_eq!(
            registry.agent_protocol_status(host_id),
            AgentProtocolStatus::Version(abyssal_agent_protocol::PROTOCOL_VERSION)
        );
        assert!(!registry.agent_protocol_mismatch(host_id));
    }
}
