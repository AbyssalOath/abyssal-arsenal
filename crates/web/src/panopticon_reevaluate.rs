//! Live re-evaluation of open RADIUS sessions (0.2.9 Q3,
//! `docs/roadmap/0.2.9.md`).
//!
//! A decision is made at login. CoA already follows a device's trust change,
//! an enforcement action and a guest registration
//! (`panopticon_coa::spawn_reauthorize_*`), but nothing followed a security
//! signal starting or clearing (0.2.8 P3), or a change to the RADIUS policy
//! itself (VLANs, roles, AD group rules). This sweep catches all of them at
//! once: for every open accounted session it re-runs the decision the
//! session would get now -- with the AD groups its login brought, which the
//! decision record kept (0.2.9 Q2), since the sweep can't ask AD -- and where
//! the outcome, VLAN or role sent would differ from the recorded decision,
//! re-authorizes the session through its NAS (per the NAS client's CoA
//! mode). The NAS's re-authentication then makes and records the new
//! decision, so the next sweep finds nothing to do.
//!
//! Off by default (`panopticon.radius_reevaluate_enabled`). Guards: a NAS
//! client with CoA off is skipped (Session-Timeout covers it, 0.2.8 P4); a
//! session re-authorized by anything within the cooldown isn't touched; at
//! most N CoAs per sweep, least recently touched sessions first; the control
//! plane's own server is never touched; a session with no recorded decision
//! (accounted before 0.2.9, say) has nothing to compare and is left alone.

use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use abyssal_core::settings::{
    PANOPTICON_RADIUS_REEVALUATE_COOLDOWN_MINUTES,
    PANOPTICON_RADIUS_REEVALUATE_COOLDOWN_MINUTES_DEFAULT, PANOPTICON_RADIUS_REEVALUATE_ENABLED,
    PANOPTICON_RADIUS_REEVALUATE_MAX_PER_SWEEP, PANOPTICON_RADIUS_REEVALUATE_MAX_PER_SWEEP_DEFAULT,
    PANOPTICON_RADIUS_REEVALUATE_SECONDS, PANOPTICON_RADIUS_REEVALUATE_SECONDS_DEFAULT,
    PANOPTICON_RADIUS_REEVALUATE_SECONDS_MAX, PANOPTICON_RADIUS_REEVALUATE_SECONDS_MIN,
    PANOPTICON_RADIUS_SESSION_STALE_HOURS,
};
use abyssal_core::{
    CoaMode, DECISION_BEFORE_SESSION_SLACK_SECS, EncryptionKey, RadiusDecisionRecord,
    RadiusSession, decision_for_session, split_group_list,
};
use abyssal_database::{DbPool, repo};
use chrono::{DateTime, Duration, Utc};

use crate::panopticon_radius::{
    Admission, DecisionContext, FrontEnd, client_by_ip, decide_for_login, normalize_mac,
};
use crate::task_health::TaskHeartbeats;
use crate::task_health::names::PANOPTICON_RADIUS_REEVALUATE as TASK;

/// How often the loop wakes to check its settings; a sweep runs when
/// enabled and its interval has passed.
const TICK: StdDuration = StdDuration::from_secs(10);
/// Open sessions looked at per sweep at most.
const MAX_SESSIONS: u32 = 5000;
/// Decisions read per session to find the one it runs on.
const DECISIONS_PER_SESSION: u32 = 50;

/// The sweep's settings, read before each sweep.
#[derive(Debug, Clone, Copy)]
struct Settings {
    enabled: bool,
    interval: StdDuration,
    cooldown: Duration,
    max_per_sweep: u32,
}

async fn settings(pool: &DbPool) -> Settings {
    let u = |key: &'static str, default: u32| {
        let pool = pool.clone();
        async move {
            repo::settings::get_u32(&pool, key, default)
                .await
                .unwrap_or(default)
        }
    };
    Settings {
        enabled: repo::settings::get_bool(pool, PANOPTICON_RADIUS_REEVALUATE_ENABLED, false)
            .await
            .unwrap_or(false),
        interval: StdDuration::from_secs(u64::from(
            u(
                PANOPTICON_RADIUS_REEVALUATE_SECONDS,
                PANOPTICON_RADIUS_REEVALUATE_SECONDS_DEFAULT,
            )
            .await
            .clamp(
                PANOPTICON_RADIUS_REEVALUATE_SECONDS_MIN,
                PANOPTICON_RADIUS_REEVALUATE_SECONDS_MAX,
            ),
        )),
        cooldown: Duration::minutes(i64::from(
            u(
                PANOPTICON_RADIUS_REEVALUATE_COOLDOWN_MINUTES,
                PANOPTICON_RADIUS_REEVALUATE_COOLDOWN_MINUTES_DEFAULT,
            )
            .await
            .clamp(1, 1440),
        )),
        max_per_sweep: u(
            PANOPTICON_RADIUS_REEVALUATE_MAX_PER_SWEEP,
            PANOPTICON_RADIUS_REEVALUATE_MAX_PER_SWEEP_DEFAULT,
        )
        .await
        .clamp(1, 500),
    }
}

/// Whether the decision a session would get now differs from the one it
/// runs on in anything the NAS enforces: accept or reject, the VLAN, the
/// role sent. A different Session-Timeout alone isn't worth a CoA.
pub(crate) fn changed(running: &RadiusDecisionRecord, now: &RadiusDecisionRecord) -> bool {
    running.outcome != now.outcome || running.vlan != now.vlan || running.role != now.role
}

/// Whether a session was re-authorized (by anything) within `cooldown`.
pub(crate) fn in_cooldown(session: &RadiusSession, now: DateTime<Utc>, cooldown: Duration) -> bool {
    session.last_coa_at.is_some_and(|at| now - at < cooldown)
}

/// "accept, VLAN 10, role EMPLOYEE.in", without the re-auth interval.
fn enforced_summary(d: &RadiusDecisionRecord) -> String {
    let mut d = d.clone();
    d.session_timeout = None;
    d.summary()
}

/// What one sweep did, for the log.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SweepStats {
    pub sessions: usize,
    pub changed: usize,
    pub reauthorized: usize,
    /// Changed, but over the per-sweep cap: next sweep.
    pub deferred: usize,
}

/// Whether a device is the control plane's own server: by its managed host,
/// or an active control-plane host at its address. Errors count as yes, so
/// the sweep skips it rather than risk it.
async fn is_control_plane(pool: &DbPool, mac: &str) -> bool {
    let device = match repo::network_devices::find_by_mac(pool, mac).await {
        Ok(Some(d)) => d,
        Ok(None) => return false,
        Err(_) => return true,
    };
    let host =
        repo::panopticon_signals::host_for_device(pool, device.host_id, &device.ip_address).await;
    let by_ip = repo::panopticon_signals::is_control_plane_ip(pool, &device.ip_address).await;
    match (host, by_ip) {
        (Ok(host), Ok(by_ip)) => by_ip || host.is_some_and(|(_, cp)| cp),
        _ => true,
    }
}

/// One sweep over the open sessions.
async fn sweep(pool: &DbPool, key: &EncryptionKey, s: &Settings) -> anyhow::Result<SweepStats> {
    let now = Utc::now();
    let since = now - Duration::hours(i64::from(PANOPTICON_RADIUS_SESSION_STALE_HOURS));
    let sessions =
        repo::panopticon_radius::open_sessions_seen_since(pool, since, MAX_SESSIONS).await?;
    let mut stats = SweepStats {
        sessions: sessions.len(),
        ..SweepStats::default()
    };
    for session in &sessions {
        if in_cooldown(session, now, s.cooldown) {
            continue;
        }
        let Some(mac) = session.mac_address.as_deref().and_then(normalize_mac) else {
            continue;
        };
        let Some(nas_ip) = session.nas_ip.as_deref().and_then(|ip| ip.parse().ok()) else {
            continue;
        };
        let Some(client) = client_by_ip(pool, nas_ip).await else {
            continue;
        };
        if client.coa_mode == CoaMode::Off {
            continue;
        }
        let decisions = repo::panopticon_radius_decisions::for_mac_since(
            pool,
            &mac,
            session.started_at - Duration::seconds(DECISION_BEFORE_SESSION_SLACK_SECS),
            DECISIONS_PER_SESSION,
        )
        .await?;
        let Some(running) = decision_for_session(session, &decisions) else {
            tracing::debug!(
                mac,
                "RADIUS re-evaluation: no recorded decision for the session"
            );
            continue;
        };
        let admission = if running.admission == "dot1x" {
            Admission::Authenticated
        } else {
            Admission::Mab
        };
        let groups = running
            .ad_groups
            .as_deref()
            .map(split_group_list)
            .unwrap_or_default();
        let fresh = decide_for_login(pool, &mac, admission, Some(&client), &groups).await;
        let fresh_record = fresh.to_record(&DecisionContext {
            front_end: FrontEnd::Embedded,
            admission,
            mac: &mac,
            identity: None,
            nas: Some(&client),
            nas_address: None,
        });
        if !changed(running, &fresh_record) {
            continue;
        }
        if is_control_plane(pool, &mac).await {
            tracing::debug!(
                mac,
                "RADIUS re-evaluation: the control plane's own server; left alone"
            );
            continue;
        }
        stats.changed += 1;
        if stats.reauthorized >= s.max_per_sweep as usize {
            stats.deferred += 1;
            continue;
        }
        let why = format!(
            "re-evaluation: {} -> {} ({})",
            enforced_summary(running),
            enforced_summary(&fresh_record),
            fresh.reason
        );
        if crate::panopticon_coa::reauthorize_session(pool, key, session, &why, &None)
            .await
            .is_some()
        {
            stats.reauthorized += 1;
        }
    }
    Ok(stats)
}

/// Starts the re-evaluation loop. Without an encryption key there's no
/// NAS secret to sign a CoA with, so it doesn't start.
pub fn spawn_radius_reevaluation(
    pool: DbPool,
    key: Option<Arc<EncryptionKey>>,
    task_health: TaskHeartbeats,
) {
    let Some(key) = key else {
        return;
    };
    tokio::spawn(async move {
        let interval_hint = u64::from(PANOPTICON_RADIUS_REEVALUATE_SECONDS_DEFAULT);
        task_health.register(TASK, interval_hint).await;
        let mut last_run: Option<Instant> = None;
        loop {
            tokio::time::sleep(TICK).await;
            let s = settings(&pool).await;
            // Beat every tick, enabled or not: the loop itself is alive.
            let beat = s.interval.as_secs().max(TICK.as_secs());
            if !s.enabled || last_run.is_some_and(|t| t.elapsed() < s.interval) {
                task_health.ok(TASK, beat).await;
                continue;
            }
            last_run = Some(Instant::now());
            match sweep(&pool, &key, &s).await {
                Ok(stats) => {
                    if stats.changed > 0 {
                        tracing::info!(
                            sessions = stats.sessions,
                            changed = stats.changed,
                            reauthorized = stats.reauthorized,
                            deferred = stats.deferred,
                            "RADIUS re-evaluation"
                        );
                    }
                    task_health.ok(TASK, beat).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "RADIUS re-evaluation failed");
                    task_health.error(TASK, beat, e.to_string()).await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn record(
        outcome: &str,
        vlan: Option<u16>,
        role: Option<&str>,
        timeout: Option<u32>,
    ) -> RadiusDecisionRecord {
        RadiusDecisionRecord {
            id: Uuid::new_v4(),
            decided_at: Utc::now(),
            mac_address: Some("aa:bb:cc:00:00:01".into()),
            nas_client_id: None,
            nas_name: None,
            nas_address: None,
            front_end: "embedded".into(),
            admission: "mab".into(),
            identity: None,
            outcome: outcome.into(),
            vlan,
            role: role.map(Into::into),
            session_timeout: timeout,
            reason: "trusted device".into(),
            trust_state: None,
            enforcement: None,
            signal_action: None,
            signal_detail: None,
            group_rule: None,
            ad_groups: None,
        }
    }

    #[test]
    fn only_what_the_nas_enforces_counts_as_a_change() {
        let running = record("accept", Some(10), Some("EMPLOYEE.in"), Some(28800));
        assert!(!changed(
            &running,
            &record("accept", Some(10), Some("EMPLOYEE.in"), Some(28800))
        ));
        // The re-auth interval alone: no CoA.
        assert!(!changed(
            &running,
            &record("accept", Some(10), Some("EMPLOYEE.in"), Some(600))
        ));
        assert!(changed(
            &running,
            &record("accept", Some(999), Some("EMPLOYEE.in"), None)
        ));
        assert!(changed(
            &running,
            &record("accept", Some(10), Some("QUARANTINE.in"), None)
        ));
        assert!(changed(&running, &record("accept", Some(10), None, None)));
        assert!(changed(&running, &record("reject", None, None, None)));
        assert_eq!(
            enforced_summary(&running),
            "accept, VLAN 10, role EMPLOYEE.in"
        );
    }

    #[test]
    fn a_recent_coa_holds_the_session_back() {
        let now = Utc::now();
        let mut s = RadiusSession {
            id: Uuid::new_v4(),
            username: None,
            mac_address: Some("aa:bb:cc:00:00:01".into()),
            nas_ip: Some("10.0.0.1".into()),
            nas_port: None,
            framed_ip: None,
            acct_session_id: None,
            auth_method: None,
            started_at: now - Duration::hours(1),
            last_seen_at: now,
            stopped_at: None,
            terminate_cause: None,
            last_coa_at: None,
            last_coa_result: None,
        };
        let cooldown = Duration::minutes(15);
        assert!(!in_cooldown(&s, now, cooldown));
        s.last_coa_at = Some(now - Duration::minutes(5));
        assert!(in_cooldown(&s, now, cooldown));
        s.last_coa_at = Some(now - Duration::minutes(16));
        assert!(!in_cooldown(&s, now, cooldown));
    }
}
