//! Liveness tracking for the control plane's background tasks. Each `spawn_*`
//! loop registers itself and records a "beat" every tick, so a task that
//! panics or silently stalls becomes visible (its last-run timestamp goes
//! stale) instead of failing invisibly. Purely observational: a stale sweep
//! never blocks request serving, it just shows up on the diagnostics page and
//! (later milestone) can raise a self-alert.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

/// Stable identifiers for each instrumented background task, shared by the
/// loops that beat and the diagnostics page that reads them.
pub mod names {
    pub const HEALTH_SWEEP: &str = "health_sweep";
    pub const THANATOS_SWEEP: &str = "thanatos_sweep";
    pub const MORTISCOPE_METRICS_SWEEP: &str = "mortiscope_metrics_sweep";
    pub const SELF_METRICS_SAMPLER: &str = "self_metrics_sampler";
    pub const UPDATE_CHECK_SWEEP: &str = "update_check_sweep";
    pub const BACKUP_SCHEDULE: &str = "reliquary_backup_schedule";
    pub const AUDIT_SYSLOG_SWEEP: &str = "audit_syslog_sweep";
    pub const PANOPTICON_SWEEP: &str = "panopticon_sweep";
    pub const PANOPTICON_SNMP_SWEEP: &str = "panopticon_snmp_sweep";
    pub const PANOPTICON_TRAFFIC_ROLLUP: &str = "panopticon_traffic_rollup";
    pub const ELEVATION_EXPIRY_SWEEP: &str = "elevation_expiry_sweep";
    pub const SELF_MONITOR_SWEEP: &str = "self_monitor_sweep";
    pub const INTERNAL_TLS_SWEEP: &str = "internal_tls_sweep";
}

/// One task's most recent liveness state.
#[derive(Clone, Debug)]
pub struct TaskBeat {
    /// When the task last completed a cycle (ok or error). `None` = never yet.
    pub last_run: Option<DateTime<Utc>>,
    /// When the task last completed a cycle cleanly.
    pub last_ok: Option<DateTime<Utc>>,
    /// The most recent error message, if any (kept even after a later success,
    /// so a flapping task is visible).
    pub last_error: Option<String>,
    pub run_count: u64,
    /// The loop's current cadence, for staleness judgement.
    pub interval_secs: u64,
}

impl TaskBeat {
    fn new(interval_secs: u64) -> Self {
        Self {
            last_run: None,
            last_ok: None,
            last_error: None,
            run_count: 0,
            interval_secs,
        }
    }

    /// Whether the task is overdue: never ran, or its last run is older than
    /// `grace` times its interval (with a floor so a fast loop isn't flagged
    /// on a single slightly-late tick). A `0` interval (an unregistered or
    /// event-driven task) is never considered stale on a timer.
    pub fn is_stale(&self, now: DateTime<Utc>, grace: u32) -> bool {
        if self.interval_secs == 0 {
            return self.last_run.is_none();
        }
        let allowed = (self.interval_secs * u64::from(grace)).max(30);
        match self.last_run {
            None => true,
            Some(last) => (now - last).num_seconds().max(0) as u64 > allowed,
        }
    }
}

/// A shared, cloneable registry of background-task liveness. `Arc` inside, so a
/// clone shares the same map -- one lives in `AppState`, clones go to the
/// pool-only spawn functions.
#[derive(Clone, Default)]
pub struct TaskHeartbeats {
    inner: Arc<RwLock<BTreeMap<&'static str, TaskBeat>>>,
}

impl TaskHeartbeats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Announce a task at spawn time so it appears (as "never ran") even if it
    /// panics before its first beat. Idempotent; refreshes the interval hint.
    pub async fn register(&self, name: &'static str, interval_secs: u64) {
        let mut guard = self.inner.write().await;
        guard
            .entry(name)
            .and_modify(|b| b.interval_secs = interval_secs)
            .or_insert_with(|| TaskBeat::new(interval_secs));
    }

    /// Record a clean cycle.
    pub async fn ok(&self, name: &'static str, interval_secs: u64) {
        let mut guard = self.inner.write().await;
        let beat = guard
            .entry(name)
            .or_insert_with(|| TaskBeat::new(interval_secs));
        let now = Utc::now();
        beat.last_run = Some(now);
        beat.last_ok = Some(now);
        beat.run_count += 1;
        beat.interval_secs = interval_secs;
    }

    /// Record a cycle that ended in an error (the loop is alive, but its work
    /// failed this time).
    pub async fn error(&self, name: &'static str, interval_secs: u64, err: impl Into<String>) {
        let mut guard = self.inner.write().await;
        let beat = guard
            .entry(name)
            .or_insert_with(|| TaskBeat::new(interval_secs));
        beat.last_run = Some(Utc::now());
        beat.last_error = Some(err.into());
        beat.run_count += 1;
        beat.interval_secs = interval_secs;
    }

    /// Every task's current beat, ordered by name.
    pub async fn snapshot(&self) -> Vec<(&'static str, TaskBeat)> {
        self.inner
            .read()
            .await
            .iter()
            .map(|(name, beat)| (*name, beat.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_run_is_stale() {
        let beat = TaskBeat::new(60);
        assert!(beat.is_stale(Utc::now(), 3));
    }

    #[test]
    fn recent_run_is_not_stale() {
        let mut beat = TaskBeat::new(60);
        beat.last_run = Some(Utc::now());
        assert!(!beat.is_stale(Utc::now(), 3));
    }

    #[test]
    fn overdue_beyond_grace_is_stale() {
        let mut beat = TaskBeat::new(60);
        let now = Utc::now();
        // 4 minutes ago, grace 3 * 60s = 180s allowed -> stale.
        beat.last_run = Some(now - chrono::Duration::seconds(240));
        assert!(beat.is_stale(now, 3));
        // 2 minutes ago -> within 180s -> not stale.
        beat.last_run = Some(now - chrono::Duration::seconds(120));
        assert!(!beat.is_stale(now, 3));
    }

    #[test]
    fn short_interval_has_a_floor() {
        // A 1s interval * grace 3 = 3s, but the floor is 30s, so a run 10s ago
        // isn't flagged.
        let mut beat = TaskBeat::new(1);
        let now = Utc::now();
        beat.last_run = Some(now - chrono::Duration::seconds(10));
        assert!(!beat.is_stale(now, 3));
    }

    #[tokio::test]
    async fn records_and_snapshots() {
        let hb = TaskHeartbeats::new();
        hb.register("t", 60).await;
        hb.ok("t", 60).await;
        hb.ok("t", 60).await;
        hb.error("t", 60, "boom").await;
        let snap = hb.snapshot().await;
        assert_eq!(snap.len(), 1);
        let (name, beat) = &snap[0];
        assert_eq!(*name, "t");
        assert_eq!(beat.run_count, 3);
        assert_eq!(beat.last_error.as_deref(), Some("boom"));
        assert!(beat.last_ok.is_some());
    }
}
