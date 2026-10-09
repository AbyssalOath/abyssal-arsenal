use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome, ServerMessage};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::control_plane_guard::{self, ControlPlaneProtection};

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("host is not currently connected")]
    NotConnected,
    #[error("host did not respond within the timeout")]
    Timeout,
    #[error("host disconnected before responding")]
    ConnectionClosed,
    /// Never sent: the host is the control plane's own server and the
    /// operation would take the control plane down (see
    /// `control_plane_guard`). The message says why, for the admin.
    #[error("{0}")]
    Refused(String),
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
    /// Hosts flagged as the control plane's own server; every dispatch to
    /// one goes through `control_plane_guard::check` first.
    control_plane: Mutex<HashSet<Uuid>>,
    protection: Mutex<ControlPlaneProtection>,
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

    /// Every currently connected host, e.g. to push something to all of
    /// them.
    pub fn connected_ids(&self) -> Vec<Uuid> {
        self.connections.lock().unwrap().keys().copied().collect()
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

    /// True when the host is connected with an agent speaking at least
    /// protocol `min` -- for background sweeps that send operations newer
    /// agents added. An agent that can't parse a message drops its
    /// connection (agents before 0.2.2 do), so sending one to an older
    /// agent on a timer would knock it offline over and over.
    pub fn agent_supports(&self, host_id: Uuid, min: u32) -> bool {
        matches!(self.agent_protocol_status(host_id), AgentProtocolStatus::Version(v) if v >= min)
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

    /// Flags (or unflags) `host_id` as the control plane's own server.
    pub fn set_control_plane(&self, host_id: Uuid, is_control_plane: bool) {
        let mut hosts = self.control_plane.lock().unwrap();
        if is_control_plane {
            hosts.insert(host_id);
        } else {
            hosts.remove(&host_id);
        }
    }

    pub fn is_control_plane(&self, host_id: Uuid) -> bool {
        self.control_plane.lock().unwrap().contains(&host_id)
    }

    /// The control plane's own ports, kept as configured at startup.
    pub fn set_protected_ports(&self, ports: impl IntoIterator<Item = u16>) {
        self.protection.lock().unwrap().ports = ports.into_iter().collect();
    }

    /// The device holding `/var/lib/docker` on the control plane's server,
    /// once its agent has reported it.
    pub fn set_docker_device(&self, device: Option<String>) {
        self.protection.lock().unwrap().docker_device = device;
    }

    pub fn protection(&self) -> ControlPlaneProtection {
        self.protection.lock().unwrap().clone()
    }

    /// `Err(reason)` when `operation` must not be sent to `host_id` because
    /// it's the control plane's own server -- for a UI to grey out a button
    /// ahead of time; `dispatch` enforces it regardless.
    pub fn guard(&self, host_id: Uuid, operation: &AgentOperation) -> Result<(), String> {
        if !self.is_control_plane(host_id) {
            return Ok(());
        }
        control_plane_guard::check(operation, &self.protection.lock().unwrap())
    }

    pub async fn dispatch(
        &self,
        host_id: Uuid,
        operation: AgentOperation,
        timeout: Duration,
    ) -> Result<CommandOutcome, DispatchError> {
        if let Err(reason) = self.guard(host_id, &operation) {
            tracing::warn!(%host_id, ?operation, "refused on the control plane's own server: {reason}");
            return Err(DispatchError::Refused(reason));
        }
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
    fn agent_supports_needs_a_new_enough_reported_version() {
        let registry = HostConnectionRegistry::new();
        let host_id = Uuid::new_v4();
        assert!(!registry.agent_supports(host_id, 1), "not connected");
        let (tx, _rx) = mpsc::channel(1);
        registry.register(host_id, tx, None);
        assert!(!registry.agent_supports(host_id, 1), "unreported version");
        let (tx, _rx) = mpsc::channel(1);
        registry.register(host_id, tx, Some(40));
        assert!(registry.agent_supports(host_id, 40));
        assert!(registry.agent_supports(host_id, 39));
        assert!(!registry.agent_supports(host_id, 41));
    }

    #[tokio::test]
    async fn the_control_plane_host_is_guarded_and_nothing_is_sent() {
        let registry = HostConnectionRegistry::new();
        let host_id = Uuid::new_v4();
        let (tx, mut rx) = mpsc::channel(4);
        registry.register(host_id, tx, Some(abyssal_agent_protocol::PROTOCOL_VERSION));

        // Not flagged: sent (and times out, since nothing answers).
        let result = registry
            .dispatch(
                host_id,
                AgentOperation::IsolateHost,
                Duration::from_millis(20),
            )
            .await;
        assert!(matches!(result, Err(DispatchError::Timeout)));
        assert!(rx.try_recv().is_ok());

        registry.set_control_plane(host_id, true);
        let result = registry
            .dispatch(
                host_id,
                AgentOperation::IsolateHost,
                Duration::from_millis(20),
            )
            .await;
        assert!(matches!(result, Err(DispatchError::Refused(_))));
        assert!(
            rx.try_recv().is_err(),
            "a refused operation must never reach the agent"
        );

        // Other hosts are unaffected.
        assert!(
            registry
                .guard(Uuid::new_v4(), &AgentOperation::IsolateHost)
                .is_ok()
        );
        registry.set_control_plane(host_id, false);
        assert!(
            registry
                .guard(host_id, &AgentOperation::IsolateHost)
                .is_ok()
        );
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
