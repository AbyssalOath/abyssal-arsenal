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
//! fixed window (admin-configurable via Settings, default 20 minutes) from
//! the moment this control plane last successfully elevated a host, with no
//! refresh-on-use. Callers are expected to call `mark_deescalated`
//! defensively whenever a dispatch to a "believed elevated" host fails, so
//! a stale-positive entry clears itself out reasonably quickly in practice
//! rather than lingering for the full window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

/// Used only by tests -- real callers look up the admin-configured setting
/// (`abyssal_core::settings::APOTHEOSIS_ELEVATION_WINDOW_MINUTES`) instead.
#[cfg(test)]
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(20 * 60);

pub struct ElevatedHost {
    pub host_id: Uuid,
    pub host_name: String,
    pub remaining: Duration,
}

#[derive(Default)]
pub struct ElevationTracker {
    elevated: Mutex<HashMap<Uuid, (String, Instant, Duration)>>,
}

impl ElevationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `host_id` as elevated for `window` from now. `window` is the
    /// admin-configured Apotheosis elevation window (Settings), looked up
    /// by the caller -- a changed setting takes effect for new elevations
    /// immediately, without restarting the control plane.
    pub fn mark_elevated(&self, host_id: Uuid, host_name: String, window: Duration) {
        self.elevated
            .lock()
            .unwrap()
            .insert(host_id, (host_name, Instant::now(), window));
    }

    pub fn mark_deescalated(&self, host_id: Uuid) {
        self.elevated.lock().unwrap().remove(&host_id);
    }

    /// True if this host is believed elevated and its window hasn't
    /// lapsed; evicts it if it has.
    pub fn is_elevated(&self, host_id: Uuid) -> bool {
        let mut guard = self.elevated.lock().unwrap();
        match guard.get(&host_id) {
            Some((_, since, window)) if since.elapsed() < *window => true,
            Some(_) => {
                guard.remove(&host_id);
                false
            }
            None => false,
        }
    }

    /// Remaining elevation time for one host, if it's currently believed
    /// elevated; evicts it if its window has lapsed. Used by the hosts list
    /// page to show a per-row "Elevated (Xm left)" badge without needing
    /// the whole nav-panel snapshot.
    pub fn remaining_for(&self, host_id: Uuid) -> Option<Duration> {
        let mut guard = self.elevated.lock().unwrap();
        match guard.get(&host_id) {
            Some((_, since, window)) if since.elapsed() < *window => {
                Some(window.saturating_sub(since.elapsed()))
            }
            Some(_) => {
                guard.remove(&host_id);
                None
            }
            None => None,
        }
    }

    /// Every currently-believed-elevated host with its remaining time, for
    /// the nav panel. Lazily evicts any that have lapsed.
    pub fn snapshot(&self) -> Vec<ElevatedHost> {
        let mut guard = self.elevated.lock().unwrap();
        guard.retain(|_, (_, since, window)| since.elapsed() < *window);
        guard
            .iter()
            .map(|(host_id, (host_name, since, window))| ElevatedHost {
                host_id: *host_id,
                host_name: host_name.clone(),
                remaining: window.saturating_sub(since.elapsed()),
            })
            .collect()
    }

    /// Evicts every lapsed entry and returns what was just removed, for the
    /// background sweep task to audit-log as `HostElevationExpired`. Unlike
    /// `snapshot`/`is_elevated`'s lazy eviction (which only notices an entry
    /// has lapsed the next time something happens to look at it), this is
    /// the one active, unconditional check -- called on a fixed interval
    /// regardless of whether anything else touches the tracker meanwhile.
    pub fn sweep_expired(&self) -> Vec<(Uuid, String)> {
        let mut guard = self.elevated.lock().unwrap();
        let expired: Vec<Uuid> = guard
            .iter()
            .filter(|(_, (_, since, window))| since.elapsed() >= *window)
            .map(|(host_id, _)| *host_id)
            .collect();
        expired
            .into_iter()
            .filter_map(|host_id| guard.remove(&host_id).map(|(name, _, _)| (host_id, name)))
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
        tracker.mark_elevated(id, "web-01".to_string(), DEFAULT_IDLE_TIMEOUT);
        assert!(tracker.is_elevated(id));
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].host_name, "web-01");
    }

    #[test]
    fn deescalate_clears_it() {
        let tracker = ElevationTracker::new();
        let id = Uuid::new_v4();
        tracker.mark_elevated(id, "web-01".to_string(), DEFAULT_IDLE_TIMEOUT);
        tracker.mark_deescalated(id);
        assert!(!tracker.is_elevated(id));
        assert!(tracker.snapshot().is_empty());
    }

    #[test]
    fn expired_entry_is_evicted() {
        let tracker = ElevationTracker::new();
        let id = Uuid::new_v4();
        tracker.mark_elevated(id, "web-01".to_string(), DEFAULT_IDLE_TIMEOUT);
        {
            let mut guard = tracker.elevated.lock().unwrap();
            let entry = guard.get_mut(&id).unwrap();
            entry.1 = Instant::now() - (DEFAULT_IDLE_TIMEOUT + Duration::from_secs(1));
        }
        assert!(!tracker.is_elevated(id));
        assert!(tracker.snapshot().is_empty());
    }

    #[test]
    fn a_shorter_configured_window_is_honored() {
        let tracker = ElevationTracker::new();
        let id = Uuid::new_v4();
        let short_window = Duration::from_secs(1);
        tracker.mark_elevated(id, "web-01".to_string(), short_window);
        {
            let mut guard = tracker.elevated.lock().unwrap();
            let entry = guard.get_mut(&id).unwrap();
            entry.1 = Instant::now() - Duration::from_secs(2);
        }
        assert!(!tracker.is_elevated(id));
    }

    #[test]
    fn sweep_expired_evicts_and_returns_lapsed_entries() {
        let tracker = ElevationTracker::new();
        let expired_id = Uuid::new_v4();
        let live_id = Uuid::new_v4();
        tracker.mark_elevated(expired_id, "web-01".to_string(), DEFAULT_IDLE_TIMEOUT);
        tracker.mark_elevated(live_id, "web-02".to_string(), DEFAULT_IDLE_TIMEOUT);
        {
            let mut guard = tracker.elevated.lock().unwrap();
            let entry = guard.get_mut(&expired_id).unwrap();
            entry.1 = Instant::now() - (DEFAULT_IDLE_TIMEOUT + Duration::from_secs(1));
        }

        let swept = tracker.sweep_expired();
        assert_eq!(swept, vec![(expired_id, "web-01".to_string())]);
        assert!(!tracker.is_elevated(expired_id));
        assert!(tracker.is_elevated(live_id));
    }
}
