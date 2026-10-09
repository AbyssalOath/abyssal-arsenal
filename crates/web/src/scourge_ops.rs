//! Scourge control-plane collection sweep, cache ingest, and retention
//! (phase 3). Modeled on `thanatos_ops`'s sweep: a `tokio::spawn`'d loop that
//! dispatches to each connected host via `HostConnectionRegistry::dispatch`
//! (the system-initiated path, no `AuthContext`), gated fresh each tick on
//! `scourge.monitoring_enabled`, registered with `TaskHeartbeats`.
//!
//! Each tick pulls only *new* EVE alert lines per host (by the stored
//! inode/offset cursor), writes them into Scourge's bounded cache, and forwards
//! qualifying alerts into Thanatos's existing ingest path -- never writing
//! `thanatos_events` directly, never inventing a new schema.

use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::Severity;
use abyssal_core::settings::{
    SCOURGE_EVENT_RETENTION_DAYS, SCOURGE_EVENT_RETENTION_DAYS_DEFAULT,
    SCOURGE_MIN_FORWARD_SEVERITY, SCOURGE_MIN_FORWARD_SEVERITY_DEFAULT, SCOURGE_MONITORING_ENABLED,
    SCOURGE_SWEEP_SECONDS, SCOURGE_SWEEP_SECONDS_DEFAULT, THANATOS_MONITORING_ENABLED,
};
use abyssal_database::repo;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::AppState;

/// A packet-capture job the control plane tracks while it runs on a host. In
/// memory only (like `ScanJob`/`DeployJob`): the capture self-terminates on the
/// host via its hard `timeout`, and the pcap is discoverable afterward, so
/// losing this handle on a control-plane restart loses only the live progress
/// view, not the capture or its output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScourgeCaptureState {
    Running,
    Done,
    Cancelled,
    Failed,
}

impl ScourgeCaptureState {
    pub fn label(self) -> &'static str {
        match self {
            ScourgeCaptureState::Running => "Running",
            ScourgeCaptureState::Done => "Complete",
            ScourgeCaptureState::Cancelled => "Cancelled",
            ScourgeCaptureState::Failed => "Failed",
        }
    }
}

pub struct ScourgeCaptureJob {
    pub id: Uuid,
    pub host_id: Uuid,
    /// The agent's capture id (and the base of the pcap filename).
    pub capture_id: String,
    pub bpf: String,
    pub max_seconds: u32,
    pub max_mb: u32,
    pub state: ScourgeCaptureState,
    pub elapsed_secs: u64,
    pub size_bytes: u64,
    pub remaining_secs: u64,
    pub error: Option<String>,
}

impl ScourgeCaptureJob {
    /// Applies an agent `status\t<state>\t<elapsed>\t<size>\t<remaining>` line.
    pub fn apply_status_line(&mut self, line: &str) {
        let f: Vec<&str> = line.trim().splitn(5, '\t').collect();
        if f.len() != 5 || f[0] != "status" {
            return;
        }
        self.elapsed_secs = f[2].parse().unwrap_or(self.elapsed_secs);
        self.size_bytes = f[3].parse().unwrap_or(self.size_bytes);
        self.remaining_secs = f[4].parse().unwrap_or(self.remaining_secs);
        // Don't resurrect a cancelled job; otherwise track the agent's view.
        if self.state != ScourgeCaptureState::Cancelled {
            self.state = if f[1] == "running" {
                ScourgeCaptureState::Running
            } else {
                ScourgeCaptureState::Done
            };
        }
    }
}

/// Generous heartbeat staleness threshold: the loop idle-polls every 30s when
/// monitoring is off, so a tight threshold would flap (same reasoning as the
/// Thanatos fast sweep).
const HEARTBEAT_SECS: u64 = 120;
/// Cap on EVE alert lines processed per host per tick, so a backlog burst can't
/// stall the sweep; the rest is picked up on following ticks via the cursor.
const MAX_EVENTS_PER_PULL: u32 = 500;
/// Hard row cap on the alert cache, enforced by the retention loop on top of
/// age pruning -- it is a working set, not a history store.
const MAX_CACHE_ROWS: u64 = 200_000;

/// Severity ordering for the min-forward-severity gate.
fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

/// Parses an EVE timestamp (RFC 3339-ish) to UTC, falling back to now on
/// anything unparseable so an odd timestamp never drops the alert.
fn parse_ts(ts: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(ts.trim())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn line_hash(host_id: Uuid, fields: &str) -> String {
    let mut h = Sha256::new();
    h.update(host_id.as_bytes());
    h.update(b"\0");
    h.update(fields.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// One parsed alert ready for caching + optional forwarding.
struct ParsedAlert {
    occurred_at: DateTime<Utc>,
    severity: String,
    sid: Option<u32>,
    signature: String,
    category: Option<String>,
    proto: Option<String>,
    src_ip: Option<String>,
    src_port: Option<u32>,
    dst_ip: Option<String>,
    dst_port: Option<u32>,
    line_hash: String,
}

/// Parses one `alert\t...` line from the agent into a `ParsedAlert`, or `None`
/// if the shape is wrong.
fn parse_alert_line(host_id: Uuid, line: &str) -> Option<ParsedAlert> {
    // alert \t ts \t sev \t sid \t sig \t cat \t proto \t src_ip \t src_port \t dst_ip \t dst_port
    let f: Vec<&str> = line.splitn(11, '\t').collect();
    if f.len() != 11 || f[0] != "alert" {
        return None;
    }
    let opt = |s: &str| (!s.is_empty()).then(|| s.to_string());
    let optnum = |s: &str| s.parse::<u32>().ok();
    let severity = if Severity::from_key(f[2]).is_some() {
        f[2].to_string()
    } else {
        "low".to_string()
    };
    let fields = &format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        f[1], severity, f[3], f[4], f[6], f[7], f[9], f[10]
    );
    Some(ParsedAlert {
        occurred_at: parse_ts(f[1]),
        severity,
        sid: optnum(f[3]),
        signature: f[4].to_string(),
        category: opt(f[5]),
        proto: opt(f[6]),
        src_ip: opt(f[7]),
        src_port: optnum(f[8]),
        dst_ip: opt(f[9]),
        dst_port: optnum(f[10]),
        line_hash: line_hash(host_id, fields),
    })
}

/// Builds the Thanatos tab-format line for a forwarded alert. Source is
/// `scourge`; `raw_line` carries the IPs in a form Thanatos's own
/// `extract_source_ip` recognizes (`IpAddress=<src>`), so cross-host IP
/// correlation works without a new schema.
fn thanatos_line(a: &ParsedAlert) -> String {
    let none = "-".to_string();
    let src = a.src_ip.as_ref().unwrap_or(&none);
    let dst = a.dst_ip.as_ref().unwrap_or(&none);
    let label: String = a.signature.chars().take(180).collect();
    let raw = format!(
        "{sig} sid={sid} proto={proto} src={src}:{sp} dst={dst}:{dp} IpAddress={src}",
        sig = label,
        sid = a.sid.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
        proto = a.proto.as_deref().unwrap_or("-"),
        sp = a
            .src_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into()),
        dp = a
            .dst_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into()),
    );
    format!("{sev}\t{label}\tscourge\t{raw}", sev = a.severity)
}

/// Processes one host's `ScourgeCollectEvents` output: records the cursor (or
/// the unreadable state), caches new alerts, and forwards qualifying ones into
/// Thanatos. Returns `(cached, forwarded)`.
async fn process_output(
    state: &AppState,
    host_id: Uuid,
    host_name: &str,
    stdout: &str,
    min_forward: Severity,
    thanatos_on: bool,
) -> (usize, usize) {
    let mut cached = 0usize;
    let mut forward_lines: Vec<String> = Vec::new();

    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("cursor\t") {
            if let Some((inode, offset)) = rest.split_once('\t')
                && let (Ok(inode), Ok(offset)) =
                    (inode.trim().parse::<u64>(), offset.trim().parse::<u64>())
                && let Err(e) =
                    repo::scourge::record_cursor(&state.pool, host_id, inode, offset).await
            {
                tracing::warn!(error = %e, host = %host_name, "scourge: failed to record cursor");
            }
            continue;
        }
        if let Some(reason) = line.strip_prefix("unreadable\t") {
            if let Err(e) = repo::scourge::set_eve_unreadable(&state.pool, host_id, reason).await {
                tracing::warn!(error = %e, host = %host_name, "scourge: failed to record unreadable state");
            }
            continue;
        }
        let Some(alert) = parse_alert_line(host_id, line) else {
            continue;
        };
        let new = repo::scourge::NewAlert {
            host_id,
            occurred_at: alert.occurred_at,
            severity: &alert.severity,
            sid: alert.sid,
            signature: &alert.signature,
            category: alert.category.as_deref(),
            proto: alert.proto.as_deref(),
            src_ip: alert.src_ip.as_deref(),
            src_port: alert.src_port,
            dst_ip: alert.dst_ip.as_deref(),
            dst_port: alert.dst_port,
            line_hash: &alert.line_hash,
        };
        match repo::scourge::insert_alert(&state.pool, &new).await {
            Ok(true) => {
                cached += 1;
                // Forward only genuinely-new alerts at/above the threshold, and
                // only when Thanatos monitoring is on (respect its own gate).
                if thanatos_on
                    && let Some(sev) = Severity::from_key(&alert.severity)
                    && sev_rank(sev) >= sev_rank(min_forward)
                {
                    forward_lines.push(thanatos_line(&alert));
                }
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, host = %host_name, "scourge: failed to cache alert");
            }
        }
    }

    let forwarded = forward_lines.len();
    if forwarded > 0 {
        let text = forward_lines.join("\n");
        if let Err(e) = crate::thanatos_ops::ingest_pushed_telemetry(state, host_id, &text).await {
            tracing::warn!(error = %e, host = %host_name, "scourge: failed to forward alerts to Thanatos");
        }
    }
    (cached, forwarded)
}

/// The unattended Scourge collection sweep.
pub fn spawn_scourge_sweep(state: AppState) {
    use crate::task_health::names;
    tokio::spawn(async move {
        state
            .task_health
            .register(names::SCOURGE_SWEEP, HEARTBEAT_SECS)
            .await;
        loop {
            // Beat at the top: alive even on ticks where monitoring is off.
            state
                .task_health
                .ok(names::SCOURGE_SWEEP, HEARTBEAT_SECS)
                .await;

            let enabled = repo::settings::get_bool(&state.pool, SCOURGE_MONITORING_ENABLED, false)
                .await
                .unwrap_or(false);
            if !enabled {
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }

            let interval = repo::settings::get_u32(
                &state.pool,
                SCOURGE_SWEEP_SECONDS,
                SCOURGE_SWEEP_SECONDS_DEFAULT,
            )
            .await
            .unwrap_or(SCOURGE_SWEEP_SECONDS_DEFAULT)
            .clamp(5, 60);

            let min_forward = Severity::from_key(
                &repo::settings::get_string(
                    &state.pool,
                    SCOURGE_MIN_FORWARD_SEVERITY,
                    SCOURGE_MIN_FORWARD_SEVERITY_DEFAULT,
                )
                .await
                .unwrap_or_else(|_| SCOURGE_MIN_FORWARD_SEVERITY_DEFAULT.to_string()),
            )
            .unwrap_or(Severity::Medium);

            let thanatos_on =
                repo::settings::get_bool(&state.pool, THANATOS_MONITORING_ENABLED, false)
                    .await
                    .unwrap_or(false);

            let hosts = match repo::hosts::list(&state.pool).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!(error = %e, "scourge sweep failed to list hosts");
                    tokio::time::sleep(Duration::from_secs(u64::from(interval))).await;
                    continue;
                }
            };

            for host in hosts {
                if !host.is_active() || !state.hosts.is_connected(host.id) {
                    continue;
                }
                // Linux-only sensor; skip other OSes rather than dispatch an op
                // that always returns "unsupported".
                if host.os.as_deref().is_some_and(|os| os != "linux") {
                    continue;
                }
                // An agent from before Scourge can't run it (dispatch would
                // refuse it anyway); skip quietly rather than log a refusal
                // every sweep. The host already shows "Agent out of date".
                let probe = AgentOperation::ScourgeCollectEvents {
                    eve_offset: 0,
                    eve_inode: 0,
                    max_events: 0,
                };
                if !state.hosts.supports(host.id, &probe) {
                    continue;
                }
                let (inode, offset) = match repo::scourge::get_cursor(&state.pool, host.id).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, host = %host.name, "scourge: failed to read cursor");
                        continue;
                    }
                };
                let outcome = state
                    .hosts
                    .dispatch(
                        host.id,
                        AgentOperation::ScourgeCollectEvents {
                            eve_offset: offset,
                            eve_inode: inode,
                            max_events: MAX_EVENTS_PER_PULL,
                        },
                        Duration::from_secs(20),
                    )
                    .await;
                let stdout = match outcome {
                    Ok(CommandOutcome::Ok(output)) => output.stdout,
                    Ok(CommandOutcome::Err(message)) => {
                        tracing::warn!(host = %host.name, message, "scourge: collect op errored");
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(host = %host.name, error = %e, "scourge: collect dispatch failed");
                        continue;
                    }
                };

                let (cached, forwarded) = process_output(
                    &state,
                    host.id,
                    &host.name,
                    &stdout,
                    min_forward,
                    thanatos_on,
                )
                .await;
                if cached > 0 {
                    let event =
                        AuditEvent::new(AuditAction::ScourgeEventScanRun, AuditOutcome::Success)
                            .resource(&host.name)
                            .metadata(serde_json::json!({
                                "cached": cached,
                                "forwarded": forwarded,
                                "trigger": "sweep",
                            }));
                    if let Err(e) = abyssal_audit::record(&state.pool, event).await {
                        tracing::error!(error = %e, "scourge: failed to record sweep audit");
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(u64::from(interval))).await;
        }
    });
}

/// Prunes the alert cache by age and enforces the hard row cap.
pub fn spawn_scourge_retention(state: AppState) {
    use crate::task_health::names;
    const RETENTION_INTERVAL_SECS: u64 = 60 * 60;
    tokio::spawn(async move {
        state
            .task_health
            .register(names::SCOURGE_RETENTION, RETENTION_INTERVAL_SECS)
            .await;
        tokio::time::sleep(Duration::from_secs(90)).await;
        loop {
            state
                .task_health
                .ok(names::SCOURGE_RETENTION, RETENTION_INTERVAL_SECS)
                .await;

            let days = repo::settings::get_u32(
                &state.pool,
                SCOURGE_EVENT_RETENTION_DAYS,
                SCOURGE_EVENT_RETENTION_DAYS_DEFAULT,
            )
            .await
            .unwrap_or(SCOURGE_EVENT_RETENTION_DAYS_DEFAULT);
            if let Err(e) =
                repo::scourge::prune_alerts_older_than(&state.pool, i64::from(days)).await
            {
                tracing::error!(error = %e, "scourge retention prune failed");
                state
                    .task_health
                    .error(
                        names::SCOURGE_RETENTION,
                        RETENTION_INTERVAL_SECS,
                        e.to_string(),
                    )
                    .await;
            }
            if let Err(e) = repo::scourge::enforce_row_cap(&state.pool, MAX_CACHE_ROWS).await {
                tracing::error!(error = %e, "scourge retention row-cap enforcement failed");
            }

            tokio::time::sleep(Duration::from_secs(RETENTION_INTERVAL_SECS)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_alert_line() {
        let hid = Uuid::nil();
        let line = "alert\t2026-01-02T03:04:05.000Z\thigh\t2001\tET SCAN SSH\tScan\tTCP\t10.0.0.5\t44321\t203.0.113.9\t443";
        let a = parse_alert_line(hid, line).expect("parses");
        assert_eq!(a.severity, "high");
        assert_eq!(a.sid, Some(2001));
        assert_eq!(a.signature, "ET SCAN SSH");
        assert_eq!(a.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(a.dst_port, Some(443));
        assert_eq!(a.line_hash.len(), 64);
    }

    #[test]
    fn rejects_non_alert_and_malformed() {
        let hid = Uuid::nil();
        assert!(parse_alert_line(hid, "cursor\t12\t34").is_none());
        assert!(parse_alert_line(hid, "unreadable\tpermission denied").is_none());
        assert!(parse_alert_line(hid, "alert\ttoo\tfew\tcols").is_none());
    }

    #[test]
    fn invalid_severity_falls_back_to_low() {
        let hid = Uuid::nil();
        let line = "alert\t2026-01-02T03:04:05Z\tbogus\t1\tsig\t\tTCP\t1.1.1.1\t1\t2.2.2.2\t2";
        let a = parse_alert_line(hid, line).unwrap();
        assert_eq!(a.severity, "low");
    }

    #[test]
    fn thanatos_line_carries_ip_for_correlation() {
        let hid = Uuid::nil();
        let line = "alert\t2026-01-02T03:04:05Z\thigh\t9\tbad\tScan\tTCP\t10.0.0.5\t5\t8.8.8.8\t53";
        let a = parse_alert_line(hid, line).unwrap();
        let t = thanatos_line(&a);
        let cols: Vec<&str> = t.splitn(4, '\t').collect();
        assert_eq!(cols[0], "high"); // severity
        assert_eq!(cols[2], "scourge"); // source
        assert!(cols[3].contains("IpAddress=10.0.0.5"));
    }

    #[test]
    fn sev_rank_orders_correctly() {
        assert!(sev_rank(Severity::Critical) > sev_rank(Severity::High));
        assert!(sev_rank(Severity::High) > sev_rank(Severity::Medium));
        assert!(sev_rank(Severity::Medium) > sev_rank(Severity::Low));
    }

    fn job() -> ScourgeCaptureJob {
        ScourgeCaptureJob {
            id: Uuid::nil(),
            host_id: Uuid::nil(),
            capture_id: "capture-1".into(),
            bpf: String::new(),
            max_seconds: 60,
            max_mb: 50,
            state: ScourgeCaptureState::Running,
            elapsed_secs: 0,
            size_bytes: 0,
            remaining_secs: 60,
            error: None,
        }
    }

    #[test]
    fn apply_status_line_updates_running_job() {
        let mut j = job();
        j.apply_status_line("status\trunning\t12\t34567\t48");
        assert_eq!(j.state, ScourgeCaptureState::Running);
        assert_eq!(j.elapsed_secs, 12);
        assert_eq!(j.size_bytes, 34567);
        assert_eq!(j.remaining_secs, 48);
        // A "done" status transitions the state.
        j.apply_status_line("status\tdone\t60\t99999\t0");
        assert_eq!(j.state, ScourgeCaptureState::Done);
    }

    #[test]
    fn apply_status_line_never_resurrects_cancelled() {
        let mut j = job();
        j.state = ScourgeCaptureState::Cancelled;
        j.apply_status_line("status\trunning\t5\t100\t55");
        // Metrics still update, but a cancelled job stays cancelled.
        assert_eq!(j.state, ScourgeCaptureState::Cancelled);
        assert_eq!(j.elapsed_secs, 5);
    }

    #[test]
    fn apply_status_line_ignores_garbage() {
        let mut j = job();
        j.apply_status_line("not a status line");
        assert_eq!(j.elapsed_secs, 0);
        assert_eq!(j.state, ScourgeCaptureState::Running);
    }
}
