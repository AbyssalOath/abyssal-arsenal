//! The control plane's own best-effort mirror of which hosts it believes
//! are currently elevated ("Apotheosis"), purely for UI purposes -- the
//! nav panel's pulsing indicator and per-action "do you need to escalate?"
//! prompts. This is **not** a security boundary: the agent's own
//! `ElevationState` (`crates/agent/src/elevation.rs`) is what actually
//! gates privileged commands via `sudo -n`. This tracker can drift from
//! that real state (e.g. the agent's sliding window lapses without this
//! control plane ever finding out), and that's fine -- worst case the UI
//! is briefly wrong and a subsequent privileged dispatch just fails with
//! a normal permission error, same as it always could.
//!
//! Deliberately simpler than the agent's own sliding-window tracking: a
//! fixed 20-minute window from the moment this control plane last
//! successfully elevated a host, with no refresh-on-use. Callers are
//! expected to call `mark_deescalated` defensively whenever a dispatch to
//! a "believed elevated" host fails, so a stale-positive entry clears
//! itself out reasonably quickly in practice rather than lingering for
//! the full window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

const IDLE_TIMEOUT: Duration = Duration::from_secs(20 * 60);

pub struct ElevatedHost {
    pub host_id: Uuid,
    pub host_name: String,
    pub remaining: Duration,
}

#[derive(Default)]
pub struct ElevationTracker {
    elevated: Mutex<HashMap<Uuid, (String, Instant)>>,
}

impl ElevationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_elevated(&self, host_id: Uuid, host_name: String) {
        self.elevated
            .lock()
            .unwrap()
            .insert(host_id, (host_name, Instant::now()));
    }

    pub fn mark_deescalated(&self, host_id: Uuid) {
        self.elevated.lock().unwrap().remove(&host_id);
    }

    /// True if this host is believed elevated and the window hasn't
    /// lapsed; evicts it if it has.
    pub fn is_elevated(&self, host_id: Uuid) -> bool {
        let mut guard = self.elevated.lock().unwrap();
        match guard.get(&host_id) {
            Some((_, since)) if since.elapsed() < IDLE_TIMEOUT => true,
            Some(_) => {
                guard.remove(&host_id);
                false
            }
            None => false,
        }
    }

    /// Every currently-believed-elevated host with its remaining time, for
    /// the nav panel. Lazily evicts any that have lapsed.
    pub fn snapshot(&self) -> Vec<ElevatedHost> {
        let mut guard = self.elevated.lock().unwrap();
        guard.retain(|_, (_, since)| since.elapsed() < IDLE_TIMEOUT);
        guard
            .iter()
            .map(|(host_id, (host_name, since))| ElevatedHost {
                host_id: *host_id,
                host_name: host_name.clone(),
                remaining: IDLE_TIMEOUT.saturating_sub(since.elapsed()),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_elevated_by_default() {
        let tracker = ElevationTracker::new();
        assert!(!tracker.is_elevated(Uuid::new_v4()));
        assert!(tracker.snapshot().is_empty());
    }

    #[test]
    fn mark_and_check() {
        let tracker = ElevationTracker::new();
        let id = Uuid::new_v4();
        tracker.mark_elevated(id, "web-01".to_string());
        assert!(tracker.is_elevated(id));
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].host_name, "web-01");
    }

    #[test]
    fn deescalate_clears_it() {
        let tracker = ElevationTracker::new();
        let id = Uuid::new_v4();
        tracker.mark_elevated(id, "web-01".to_string());
        tracker.mark_deescalated(id);
        assert!(!tracker.is_elevated(id));
        assert!(tracker.snapshot().is_empty());
    }

    #[test]
    fn expired_entry_is_evicted() {
        let tracker = ElevationTracker::new();
        let id = Uuid::new_v4();
        tracker.mark_elevated(id, "web-01".to_string());
        {
            let mut guard = tracker.elevated.lock().unwrap();
            let entry = guard.get_mut(&id).unwrap();
            entry.1 = Instant::now() - (IDLE_TIMEOUT + Duration::from_secs(1));
        }
        assert!(!tracker.is_elevated(id));
        assert!(tracker.snapshot().is_empty());
    }
}
