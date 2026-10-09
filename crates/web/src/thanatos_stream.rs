//! Real-time security events from Windows agents (`AgentOperation::
//! ThanatosStream`; the agent side is `crates/agent/src/thanatos_stream.rs`).
//!
//! While Thanatos monitoring is on, every connected Windows agent new enough
//! to stream is told to, once per connection (a reconnect is a new agent
//! process for all the control plane knows) and again if the C2 port list
//! changes. Turning monitoring off stops them. A host that streams skips the
//! fast poll, which the stream replaces; the full sweep keeps running as the
//! complete record.
//!
//! Pushed telemetry is rate limited per host (`allow_push`): it's
//! unsolicited, so a misbehaving or compromised agent mustn't be able to
//! flood the ingest path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_core::settings::{
    THANATOS_C2_PORTS, THANATOS_C2_PORTS_DEFAULT, THANATOS_MONITORING_ENABLED,
};
use abyssal_database::repo;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::state::AppState;

const TICK: Duration = Duration::from_secs(15);
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);
/// After a failed start, wait this long before trying the same connection
/// again.
const RETRY_AFTER: Duration = Duration::from_secs(300);
/// Pushed telemetry messages accepted per host per window. The agent batches
/// up to 50 events a message, at most once a second.
const PUSHES_PER_WINDOW: u32 = 30;
const PUSH_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct StreamStatus {
    /// The connection streaming was started on (`connection_epoch`).
    epoch: u64,
    c2_ports: Vec<u16>,
    /// `None` while streaming; the error and when, if starting failed.
    failed: Option<(String, Instant)>,
    pub since: DateTime<Utc>,
    /// What the agent reported: which channels it streams, which it can't.
    pub detail: String,
}

static STREAMS: Mutex<Option<HashMap<Uuid, StreamStatus>>> = Mutex::new(None);

fn with_streams<T>(f: impl FnOnce(&mut HashMap<Uuid, StreamStatus>) -> T) -> T {
    let mut guard = STREAMS.lock().unwrap();
    f(guard.get_or_insert_with(HashMap::new))
}

fn stream_op(enabled: bool, c2_ports: Vec<u16>) -> AgentOperation {
    AgentOperation::ThanatosStream { enabled, c2_ports }
}

/// Whether `host_id` is streaming on its current connection -- the fast
/// sweep skips it then.
pub fn is_streaming(state: &AppState, host_id: Uuid) -> bool {
    let Some(epoch) = state.hosts.connection_epoch(host_id) else {
        return false;
    };
    with_streams(|s| {
        s.get(&host_id)
            .is_some_and(|st| st.epoch == epoch && st.failed.is_none())
    })
}

/// For the Thanatos host page: `Some((ok, text))` once streaming has been
/// tried on the host's current connection.
pub fn status(state: &AppState, host_id: Uuid) -> Option<(bool, String)> {
    let epoch = state.hosts.connection_epoch(host_id)?;
    with_streams(|s| {
        let st = s.get(&host_id).filter(|st| st.epoch == epoch)?;
        Some(match &st.failed {
            None => (
                true,
                format!(
                    "Real-time: streaming since {} UTC. {}",
                    st.since.format("%Y-%m-%d %H:%M"),
                    st.detail
                ),
            ),
            Some((error, _)) => (
                false,
                format!("Real-time streaming failed to start: {error}"),
            ),
        })
    })
}

/// What a tick should do for a connected, capable host.
#[derive(Debug, PartialEq)]
enum Action {
    Start,
    Nothing,
}

fn decide(existing: Option<&StreamStatus>, epoch: u64, c2_ports: &[u16], now: Instant) -> Action {
    match existing {
        None => Action::Start,
        Some(st) if st.epoch != epoch => Action::Start,
        Some(st) => match &st.failed {
            Some((_, at)) if now.duration_since(*at) >= RETRY_AFTER => Action::Start,
            Some(_) => Action::Nothing,
            None if st.c2_ports != c2_ports => Action::Start,
            None => Action::Nothing,
        },
    }
}

async fn tick(state: &AppState) -> anyhow::Result<()> {
    let enabled = repo::settings::get_bool(&state.pool, THANATOS_MONITORING_ENABLED, false)
        .await
        .unwrap_or(false);
    if !enabled {
        let streaming: Vec<Uuid> = with_streams(|s| s.drain().map(|(id, _)| id).collect());
        for host_id in streaming {
            if state.hosts.is_connected(host_id) {
                let _ = state
                    .hosts
                    .dispatch(host_id, stream_op(false, Vec::new()), DISPATCH_TIMEOUT)
                    .await;
            }
        }
        return Ok(());
    }

    let c2_ports = crate::thanatos_ops::parse_c2_ports(
        &repo::settings::get_string(&state.pool, THANATOS_C2_PORTS, THANATOS_C2_PORTS_DEFAULT)
            .await
            .unwrap_or_else(|_| THANATOS_C2_PORTS_DEFAULT.to_string()),
    );
    let probe = stream_op(true, Vec::new());
    let hosts = repo::hosts::list(&state.pool).await?;
    // Forget hosts that are gone or offline; they're started afresh.
    with_streams(|s| s.retain(|id, _| state.hosts.is_connected(*id)));

    for host in hosts {
        if !host.is_active()
            || host.pending_approval
            || host.os.as_deref() != Some("windows")
            || !state.hosts.supports(host.id, &probe)
        {
            continue;
        }
        let Some(epoch) = state.hosts.connection_epoch(host.id) else {
            continue;
        };
        let action = with_streams(|s| decide(s.get(&host.id), epoch, &c2_ports, Instant::now()));
        if action == Action::Nothing {
            continue;
        }
        let outcome = state
            .hosts
            .dispatch(host.id, stream_op(true, c2_ports.clone()), DISPATCH_TIMEOUT)
            .await;
        let (failed, detail) = match outcome {
            Ok(CommandOutcome::Ok(output)) => (None, output.stdout.trim().to_string()),
            Ok(CommandOutcome::Err(e)) => (Some((e, Instant::now())), String::new()),
            Err(e) => (Some((e.to_string(), Instant::now())), String::new()),
        };
        match &failed {
            None => {
                tracing::info!(host = %host.name, %detail, "thanatos: real-time streaming started")
            }
            Some((e, _)) => {
                tracing::warn!(host = %host.name, error = %e, "thanatos: real-time streaming didn't start")
            }
        }
        with_streams(|s| {
            s.insert(
                host.id,
                StreamStatus {
                    epoch,
                    c2_ports: c2_ports.clone(),
                    failed,
                    since: Utc::now(),
                    detail,
                },
            )
        });
    }
    Ok(())
}

pub fn spawn_thanatos_stream_manager(state: AppState) {
    use crate::task_health::names;
    const HEARTBEAT_SECS: u64 = 60;
    tokio::spawn(async move {
        state
            .task_health
            .register(names::THANATOS_STREAM, HEARTBEAT_SECS)
            .await;
        let mut interval = tokio::time::interval(TICK);
        loop {
            interval.tick().await;
            match tick(&state).await {
                Ok(()) => {
                    state
                        .task_health
                        .ok(names::THANATOS_STREAM, HEARTBEAT_SECS)
                        .await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "thanatos stream manager tick failed");
                    state
                        .task_health
                        .error(names::THANATOS_STREAM, HEARTBEAT_SECS, e.to_string())
                        .await;
                }
            }
        }
    });
}

/// A fixed-window counter per host.
#[derive(Default)]
struct PushWindow {
    started: Option<Instant>,
    count: u32,
    warned: bool,
}

static PUSHES: Mutex<Option<HashMap<Uuid, PushWindow>>> = Mutex::new(None);

/// Whether to ingest one more pushed telemetry message from `host_id`.
/// Logs once per window when it starts refusing.
pub fn allow_push(host_id: Uuid) -> bool {
    allow_push_at(host_id, Instant::now())
}

fn allow_push_at(host_id: Uuid, now: Instant) -> bool {
    let mut guard = PUSHES.lock().unwrap();
    let window = guard
        .get_or_insert_with(HashMap::new)
        .entry(host_id)
        .or_default();
    if window
        .started
        .is_none_or(|start| now.duration_since(start) >= PUSH_WINDOW)
    {
        *window = PushWindow {
            started: Some(now),
            count: 0,
            warned: false,
        };
    }
    if window.count < PUSHES_PER_WINDOW {
        window.count += 1;
        return true;
    }
    if !window.warned {
        window.warned = true;
        tracing::warn!(%host_id, "thanatos: pushed telemetry over the rate limit; dropping until the window resets (the full sweep still records everything)");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(epoch: u64, ports: &[u16], failed: Option<Instant>) -> StreamStatus {
        StreamStatus {
            epoch,
            c2_ports: ports.to_vec(),
            failed: failed.map(|at| ("boom".to_string(), at)),
            since: Utc::now(),
            detail: String::new(),
        }
    }

    #[test]
    fn starts_once_per_connection_and_on_port_changes() {
        let now = Instant::now();
        assert_eq!(decide(None, 1, &[4444], now), Action::Start);
        let running = status(1, &[4444], None);
        assert_eq!(decide(Some(&running), 1, &[4444], now), Action::Nothing);
        assert_eq!(
            decide(Some(&running), 2, &[4444], now),
            Action::Start,
            "reconnected"
        );
        assert_eq!(
            decide(Some(&running), 1, &[4444, 1337], now),
            Action::Start,
            "ports changed"
        );
    }

    #[test]
    fn a_failed_start_is_retried_later_not_every_tick() {
        let now = Instant::now();
        let failed = status(1, &[], Some(now));
        assert_eq!(
            decide(Some(&failed), 1, &[], now + Duration::from_secs(15)),
            Action::Nothing
        );
        assert_eq!(
            decide(Some(&failed), 1, &[], now + RETRY_AFTER),
            Action::Start
        );
        assert_eq!(
            decide(Some(&failed), 2, &[], now),
            Action::Start,
            "a new connection tries again"
        );
    }

    #[test]
    fn pushes_are_rate_limited_per_host_per_window() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let start = Instant::now();
        for _ in 0..PUSHES_PER_WINDOW {
            assert!(allow_push_at(a, start));
        }
        assert!(!allow_push_at(a, start + Duration::from_secs(1)));
        assert!(allow_push_at(b, start), "another host has its own budget");
        assert!(allow_push_at(a, start + PUSH_WINDOW), "a new window");
    }
}
