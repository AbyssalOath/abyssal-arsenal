//! The control plane watching itself. An opt-in background sweep that raises
//! notifications when the server's own health degrades: sustained CPU / memory
//! / disk pressure, a background task that has stalled, or backups gone
//! overdue. Fires once on the transition into a bad state and clears once on
//! recovery (firing state persisted in `control_plane_alert_state`), so a
//! standing problem doesn't spam every tick.
//!
//! Deliberately *not* covered here: "database unreachable." This loop reads its
//! own config and firing state from that same database, so it can't reliably
//! act when the database is down -- that condition is what `/readyz` and an
//! external monitor are for.

use std::time::Duration;

use abyssal_core::settings::{
    CONTROL_PLANE_ALERT_RECIPIENTS, CONTROL_PLANE_BACKUP_OVERDUE_HOURS,
    CONTROL_PLANE_BACKUP_OVERDUE_HOURS_DEFAULT, CONTROL_PLANE_CPU_THRESHOLD,
    CONTROL_PLANE_CPU_THRESHOLD_DEFAULT, CONTROL_PLANE_DISK_THRESHOLD,
    CONTROL_PLANE_DISK_THRESHOLD_DEFAULT, CONTROL_PLANE_MEM_THRESHOLD,
    CONTROL_PLANE_MEM_THRESHOLD_DEFAULT, CONTROL_PLANE_MONITORING_ENABLED,
};
use abyssal_database::repo;
use abyssal_database::repo::control_plane_metrics as cpm;
use abyssal_notifications::{NotificationMessage, Severity};
use chrono::Utc;

use crate::state::AppState;
use crate::task_health::names;

const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const SWEEP_INTERVAL_SECS: u64 = 60;
/// How many consecutive recent samples must all breach before a resource alert
/// fires -- never alert on a single spike.
const SUSTAINED_SAMPLES: i64 = 3;
/// Grace multiplier for judging a background task stalled (matches the
/// diagnostics page).
const TASK_STALE_GRACE: u32 = 3;

pub fn spawn_self_monitor_sweep(state: AppState) {
    tokio::spawn(async move {
        state
            .task_health
            .register(names::SELF_MONITOR_SWEEP, SWEEP_INTERVAL_SECS)
            .await;
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            // Beat first: the monitor is alive even on ticks where it's toggled
            // off and does nothing.
            state
                .task_health
                .ok(names::SELF_MONITOR_SWEEP, SWEEP_INTERVAL_SECS)
                .await;

            let enabled =
                repo::settings::get_bool(&state.pool, CONTROL_PLANE_MONITORING_ENABLED, false)
                    .await
                    .unwrap_or(false);
            if !enabled {
                continue;
            }
            if let Err(e) = evaluate(&state).await {
                tracing::error!(error = %e, "control-plane self-monitor evaluation failed");
            }
        }
    });
}

/// One evaluation pass: resource thresholds, task liveness, backup overdue.
/// Shared by the sweep and the on-demand "evaluate now" path (if added later).
pub async fn evaluate(state: &AppState) -> anyhow::Result<()> {
    let recipients_raw =
        repo::settings::get_string(&state.pool, CONTROL_PLANE_ALERT_RECIPIENTS, "").await?;
    let recipients = crate::thanatos_ops::parse_recipients(&recipients_raw);

    evaluate_resource(
        state,
        &recipients,
        "cpu",
        "CPU",
        cpm::METRIC_CPU,
        repo::settings::get_u32(
            &state.pool,
            CONTROL_PLANE_CPU_THRESHOLD,
            CONTROL_PLANE_CPU_THRESHOLD_DEFAULT,
        )
        .await?,
    )
    .await?;
    evaluate_resource(
        state,
        &recipients,
        "mem",
        "Memory",
        cpm::METRIC_MEM,
        repo::settings::get_u32(
            &state.pool,
            CONTROL_PLANE_MEM_THRESHOLD,
            CONTROL_PLANE_MEM_THRESHOLD_DEFAULT,
        )
        .await?,
    )
    .await?;
    evaluate_resource(
        state,
        &recipients,
        "disk",
        "Disk",
        cpm::METRIC_DISK,
        repo::settings::get_u32(
            &state.pool,
            CONTROL_PLANE_DISK_THRESHOLD,
            CONTROL_PLANE_DISK_THRESHOLD_DEFAULT,
        )
        .await?,
    )
    .await?;

    evaluate_tasks(state, &recipients).await?;
    evaluate_backup_overdue(state, &recipients).await?;
    Ok(())
}

/// Fires/clears a sustained-usage alert for one resource metric.
async fn evaluate_resource(
    state: &AppState,
    recipients: &[String],
    key: &str,
    label: &str,
    metric: &str,
    threshold: u32,
) -> anyhow::Result<()> {
    let samples = cpm::recent(&state.pool, metric, SUSTAINED_SAMPLES).await?;
    let breaching = sustained_breach(&samples, SUSTAINED_SAMPLES as usize, f64::from(threshold));
    let latest = samples.last().copied().unwrap_or_default();
    reconcile(
        state,
        key,
        breaching,
        || NotificationMessage {
            subject: format!("[Abyssal Arsenal] Control plane {label} high"),
            body: format!(
                "{label} on the control plane has been at or above {threshold}% across the last {SUSTAINED_SAMPLES} samples (now {latest:.0}%)."
            ),
            severity: Severity::Warning,
            recipients: recipients.to_vec(),
        },
        || NotificationMessage {
            subject: format!("[Abyssal Arsenal] Control plane {label} recovered"),
            body: format!("{label} on the control plane is back below {threshold}%."),
            severity: Severity::Info,
            recipients: recipients.to_vec(),
        },
    )
    .await
}

/// Fires/clears a single aggregate alert when any background task has stalled.
async fn evaluate_tasks(state: &AppState, recipients: &[String]) -> anyhow::Result<()> {
    let now = Utc::now();
    let stalled: Vec<String> = state
        .task_health
        .snapshot()
        .await
        .into_iter()
        // The monitor's own task can't be stale while it's the one running this.
        .filter(|(name, _)| *name != names::SELF_MONITOR_SWEEP)
        .filter(|(_, beat)| beat.is_stale(now, TASK_STALE_GRACE))
        .map(|(name, _)| name.to_string())
        .collect();

    let firing = !stalled.is_empty();
    let list = stalled.join(", ");
    reconcile(
        state,
        "tasks_stalled",
        firing,
        || NotificationMessage {
            subject: "[Abyssal Arsenal] Background task stalled".to_string(),
            body: format!("These control-plane background tasks are overdue: {list}."),
            severity: Severity::Critical,
            recipients: recipients.to_vec(),
        },
        || NotificationMessage {
            subject: "[Abyssal Arsenal] Background tasks recovered".to_string(),
            body: "All control-plane background tasks are ticking again.".to_string(),
            severity: Severity::Info,
            recipients: recipients.to_vec(),
        },
    )
    .await
}

/// Fires/clears an alert when the most recent successful backup is older than
/// the configured overdue window. A `0` window disables the check.
async fn evaluate_backup_overdue(state: &AppState, recipients: &[String]) -> anyhow::Result<()> {
    let overdue_hours = repo::settings::get_u32(
        &state.pool,
        CONTROL_PLANE_BACKUP_OVERDUE_HOURS,
        CONTROL_PLANE_BACKUP_OVERDUE_HOURS_DEFAULT,
    )
    .await?;
    if overdue_hours == 0 {
        return Ok(());
    }
    let last = repo::reliquary_backups::most_recent_backup_time(&state.pool).await?;
    let overdue = backup_overdue(last, overdue_hours, Utc::now());
    let age = match last {
        Some(ts) => format!("{} h ago", (Utc::now() - ts).num_hours().max(0)),
        None => "never".to_string(),
    };
    reconcile(
        state,
        "backup_overdue",
        overdue,
        || NotificationMessage {
            subject: "[Abyssal Arsenal] Backups overdue".to_string(),
            body: format!(
                "No successful backup within the last {overdue_hours} h (last successful backup: {age})."
            ),
            severity: Severity::Warning,
            recipients: recipients.to_vec(),
        },
        || NotificationMessage {
            subject: "[Abyssal Arsenal] Backups current again".to_string(),
            body: "A recent successful backup has been recorded.".to_string(),
            severity: Severity::Info,
            recipients: recipients.to_vec(),
        },
    )
    .await
}

/// Compares a desired firing state against the persisted one and dispatches a
/// notification only on a transition (raise on entering, clear on leaving).
async fn reconcile(
    state: &AppState,
    key: &str,
    should_fire: bool,
    raise: impl Fn() -> NotificationMessage,
    clear: impl Fn() -> NotificationMessage,
) -> anyhow::Result<()> {
    let was_firing = repo::control_plane_alerts::is_firing(&state.pool, key).await?;
    match (should_fire, was_firing) {
        (true, false) => {
            repo::control_plane_alerts::set_firing(&state.pool, key, true).await?;
            state.notifications.dispatch(&raise()).await;
        }
        (false, true) => {
            repo::control_plane_alerts::set_firing(&state.pool, key, false).await?;
            state.notifications.dispatch(&clear()).await;
        }
        _ => {}
    }
    Ok(())
}

/// Whether the last `required` samples all meet/exceed `threshold`. False if
/// there isn't enough history yet -- never alert right after startup.
pub fn sustained_breach(samples: &[f64], required: usize, threshold: f64) -> bool {
    if required == 0 || samples.len() < required {
        return false;
    }
    samples[samples.len() - required..]
        .iter()
        .all(|v| *v >= threshold)
}

/// Whether backups are overdue: never taken, or the last one is older than
/// `overdue_hours`.
pub fn backup_overdue(
    last: Option<chrono::DateTime<Utc>>,
    overdue_hours: u32,
    now: chrono::DateTime<Utc>,
) -> bool {
    match last {
        None => true,
        Some(ts) => (now - ts) >= chrono::Duration::hours(i64::from(overdue_hours)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sustained_breach_needs_enough_history() {
        // Only two samples, need three -> not yet.
        assert!(!sustained_breach(&[95.0, 96.0], 3, 90.0));
    }

    #[test]
    fn sustained_breach_all_must_exceed() {
        assert!(sustained_breach(&[91.0, 92.0, 90.0], 3, 90.0));
        // One dip below breaks the sustained breach.
        assert!(!sustained_breach(&[91.0, 80.0, 95.0], 3, 90.0));
    }

    #[test]
    fn sustained_breach_uses_only_the_last_n() {
        // Older low samples are ignored; the last three all breach.
        assert!(sustained_breach(&[10.0, 20.0, 91.0, 92.0, 93.0], 3, 90.0));
    }

    #[test]
    fn backup_overdue_when_never_taken() {
        assert!(backup_overdue(None, 48, Utc::now()));
    }

    #[test]
    fn backup_overdue_respects_window() {
        let now = Utc::now();
        let recent = now - chrono::Duration::hours(10);
        let old = now - chrono::Duration::hours(50);
        assert!(!backup_overdue(Some(recent), 48, now));
        assert!(backup_overdue(Some(old), 48, now));
    }
}
