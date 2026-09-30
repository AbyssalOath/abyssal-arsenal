//! Mortiscope's unattended metrics sweep: polls a small core set of health
//! metrics on an interval and persists one time-series sample per metric per
//! host, so the Mortiscope page can show recent trends without re-polling on
//! every load. Same shape as `health_ops::spawn_health_sweep` -- system-
//! initiated, so it bypasses `Executor::execute_on_host` (there's no
//! `AuthContext`) and dispatches directly through `HostConnectionRegistry` --
//! and it reuses the same parsers the on-demand read handlers use, so a swept
//! sample and an on-demand reading are computed identically.

use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_core::settings::{
    MORTISCOPE_ALERT_RECIPIENTS, MORTISCOPE_MONITORING_ENABLED, MORTISCOPE_SUSTAINED_SAMPLES,
    MORTISCOPE_SUSTAINED_SAMPLES_DEFAULT,
};
use abyssal_database::repo;
use abyssal_notifications::{NotificationMessage, Severity};
use uuid::Uuid;

use crate::routes::mortiscope::{parse_cpu_utilization, parse_load_average, parse_memory_detail};
use crate::state::AppState;

const SWEEP_INTERVAL: Duration = Duration::from_secs(300);
const SWEEP_INTERVAL_SECS: u64 = 300;
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);
/// How long swept samples are kept before pruning.
const RETENTION_DAYS: i64 = 7;

/// The metric keys this sweep records. Public so the page's trend display and
/// the (later) threshold config refer to the same names.
pub const METRIC_LOAD_PER_CORE: &str = "load_per_core";
pub const METRIC_CPU_BUSY: &str = "cpu_busy_percent";
pub const METRIC_MEM_USED: &str = "mem_used_percent";
pub const METRIC_SWAP_USED: &str = "swap_used_percent";
/// The busiest real filesystem's usage percent (`df -Ph`, max across mounts) --
/// the "how close is any disk to full" figure the dashboard fleet table's disk
/// mini-meter and (optionally) a threshold read from.
pub const METRIC_DISK_USED: &str = "disk_used_percent";

/// The metrics shown as trends, as `(key, label, unit)`, in display order.
pub const TREND_METRICS: &[(&str, &str, &str)] = &[
    (METRIC_LOAD_PER_CORE, "Load per core", ""),
    (METRIC_CPU_BUSY, "CPU busy", "%"),
    (METRIC_MEM_USED, "Memory used", "%"),
    (METRIC_SWAP_USED, "Swap used", "%"),
    (METRIC_DISK_USED, "Disk used", "%"),
];

pub fn spawn_mortiscope_metrics_sweep(state: AppState) {
    tokio::spawn(async move {
        state
            .task_health
            .register(
                crate::task_health::names::MORTISCOPE_METRICS_SWEEP,
                SWEEP_INTERVAL_SECS,
            )
            .await;
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;

            let hosts = match repo::hosts::list(&state.pool).await {
                Ok(hosts) => hosts,
                Err(e) => {
                    tracing::error!(error = %e, "mortiscope metrics sweep failed to list hosts");
                    state
                        .task_health
                        .error(
                            crate::task_health::names::MORTISCOPE_METRICS_SWEEP,
                            SWEEP_INTERVAL_SECS,
                            e.to_string(),
                        )
                        .await;
                    continue;
                }
            };

            for host in hosts {
                if !host.is_active() || !state.hosts.is_connected(host.id) {
                    continue;
                }
                sample_host(&state, host.id).await;
            }

            if let Err(e) = repo::host_metrics::prune_older_than(&state.pool, RETENTION_DAYS).await
            {
                tracing::error!(error = %e, "mortiscope metrics sweep failed to prune old samples");
            }

            // History is always collected above; alerting is opt-in and its
            // enable flag is re-read every tick, so toggling it takes effect
            // without a restart (same as the Thanatos sweep).
            match repo::settings::get_bool(&state.pool, MORTISCOPE_MONITORING_ENABLED, false).await
            {
                Ok(true) => {
                    if let Err(e) = evaluate_thresholds(&state).await {
                        tracing::error!(error = %e, "mortiscope threshold evaluation failed");
                    }
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(error = %e, "failed to read mortiscope monitoring setting")
                }
            }
            state
                .task_health
                .ok(
                    crate::task_health::names::MORTISCOPE_METRICS_SWEEP,
                    SWEEP_INTERVAL_SECS,
                )
                .await;
        }
    });
}

/// A human label for a metric key, for alert messages and the UI.
pub fn metric_label(metric: &str) -> &str {
    TREND_METRICS
        .iter()
        .find(|(k, _, _)| *k == metric)
        .map(|(_, label, _)| *label)
        .unwrap_or(metric)
}

fn notification_severity(severity: &str) -> Severity {
    match severity {
        "critical" => Severity::Critical,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Rank so the most severe breaching threshold on a metric wins when several
/// are configured.
pub(crate) fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "warning" => 2,
        _ => 1,
    }
}

pub(crate) fn breaches(value: f64, comparator: &str, threshold: f64) -> bool {
    match comparator {
        "le" => value <= threshold,
        _ => value >= threshold, // "ge" and any unknown fall back to >=
    }
}

/// Evaluates every enabled threshold against each connected host's recent
/// samples, alerting on the transition into a sustained breach and clearing on
/// recovery. Returns how many new alerts fired. Shared by the sweep and the
/// on-demand "evaluate now" route.
pub async fn evaluate_thresholds(state: &AppState) -> anyhow::Result<usize> {
    let thresholds = repo::monitoring::list_enabled_thresholds(&state.pool).await?;
    if thresholds.is_empty() {
        return Ok(0);
    }

    let sustained = repo::settings::get_u32(
        &state.pool,
        MORTISCOPE_SUSTAINED_SAMPLES,
        MORTISCOPE_SUSTAINED_SAMPLES_DEFAULT,
    )
    .await
    .unwrap_or(MORTISCOPE_SUSTAINED_SAMPLES_DEFAULT)
    .max(1) as i64;

    let recipients_raw = repo::settings::get_string(&state.pool, MORTISCOPE_ALERT_RECIPIENTS, "")
        .await
        .unwrap_or_default();
    let recipients = crate::thanatos_ops::parse_recipients(&recipients_raw);

    // Distinct metrics that have at least one enabled threshold.
    let mut metrics: Vec<&str> = thresholds.iter().map(|t| t.metric.as_str()).collect();
    metrics.sort_unstable();
    metrics.dedup();

    let mut fired = 0usize;
    let hosts = repo::hosts::list(&state.pool).await?;
    for host in hosts {
        if !host.is_active() || !state.hosts.is_connected(host.id) {
            continue;
        }
        for metric in &metrics {
            fired += evaluate_host_metric(
                state,
                host.id,
                &host.name,
                metric,
                &thresholds,
                sustained,
                &recipients,
            )
            .await?;
        }
    }
    Ok(fired)
}

/// Evaluates one host+metric: finds the highest-severity threshold whose last
/// `sustained` samples all breach, then reconciles that against the stored
/// firing state. Returns 1 if this call newly raised an alert.
async fn evaluate_host_metric(
    state: &AppState,
    host_id: Uuid,
    host_name: &str,
    metric: &str,
    thresholds: &[repo::monitoring::Threshold],
    sustained: i64,
    recipients: &[String],
) -> anyhow::Result<usize> {
    let samples = repo::host_metrics::recent(&state.pool, host_id, metric, sustained).await?;
    // Not enough history to call a breach "sustained" -- never alert on a spike
    // or right after enabling.
    if (samples.len() as i64) < sustained {
        return Ok(0);
    }
    let values: Vec<f64> = samples.iter().map(|s| s.value).collect();

    // The most severe threshold for this metric that every recent sample breaches.
    let breaching = thresholds
        .iter()
        .filter(|t| t.metric == metric)
        .filter(|t| {
            values
                .iter()
                .all(|v| breaches(*v, &t.comparator, t.threshold))
        })
        .max_by_key(|t| severity_rank(&t.severity));

    let was_firing = repo::monitoring::is_firing(&state.pool, host_id, metric).await?;

    match (breaching, was_firing) {
        (Some(t), false) => {
            repo::monitoring::set_firing(&state.pool, host_id, metric, true).await?;
            let latest = values.last().copied().unwrap_or_default();
            let message = NotificationMessage {
                subject: format!(
                    "[Mortiscope] {host_name}: {} threshold breached",
                    metric_label(metric)
                ),
                body: format!(
                    "{} on {host_name} has been {} {} across the last {sustained} samples (now {latest:.1}).",
                    metric_label(metric),
                    if t.comparator == "le" {
                        "at or below"
                    } else {
                        "at or above"
                    },
                    t.threshold,
                ),
                severity: notification_severity(&t.severity),
                recipients: recipients.to_vec(),
            };
            state.notifications.dispatch(&message).await;
            Ok(1)
        }
        (None, true) => {
            repo::monitoring::set_firing(&state.pool, host_id, metric, false).await?;
            let message = NotificationMessage {
                subject: format!(
                    "[Mortiscope] {host_name}: {} recovered",
                    metric_label(metric)
                ),
                body: format!(
                    "{} on {host_name} is back within its threshold.",
                    metric_label(metric)
                ),
                severity: Severity::Info,
                recipients: recipients.to_vec(),
            };
            state.notifications.dispatch(&message).await;
            Ok(0)
        }
        _ => Ok(0),
    }
}

/// Dispatches one read op and returns its stdout, or `None` if the host is
/// unreachable or the op failed -- a missing sample is fine, the next tick
/// tries again.
async fn dispatch(state: &AppState, host_id: Uuid, op: AgentOperation) -> Option<String> {
    match state.hosts.dispatch(host_id, op, DISPATCH_TIMEOUT).await {
        Ok(CommandOutcome::Ok(output)) => Some(output.stdout),
        _ => None,
    }
}

async fn record(state: &AppState, host_id: Uuid, metric: &str, value: f64) {
    if let Err(e) = repo::host_metrics::insert(&state.pool, host_id, metric, value).await {
        tracing::error!(metric, error = %e, "failed to persist metric sample");
    }
}

/// Extracts a numeric field from a parser's structured output.
fn field(entry: &Option<serde_json::Value>, key: &str) -> Option<f64> {
    entry.as_ref()?.get(key)?.as_f64()
}

async fn sample_host(state: &AppState, host_id: Uuid) {
    if let Some(out) = dispatch(state, host_id, AgentOperation::LoadAverage).await {
        let entry = parse_load_average(&out);
        if let Some(v) = field(&entry, "load_per_core") {
            record(state, host_id, METRIC_LOAD_PER_CORE, v).await;
        }
    }
    if let Some(out) = dispatch(state, host_id, AgentOperation::CpuUtilization).await
        && let Some(v) = field(&parse_cpu_utilization(&out), "cpu_busy_percent")
    {
        record(state, host_id, METRIC_CPU_BUSY, v).await;
    }
    if let Some(out) = dispatch(state, host_id, AgentOperation::MemoryDetail).await {
        let entry = parse_memory_detail(&out);
        if let Some(v) = field(&entry, "mem_used_percent") {
            record(state, host_id, METRIC_MEM_USED, v).await;
        }
        if let Some(v) = field(&entry, "swap_used_percent") {
            record(state, host_id, METRIC_SWAP_USED, v).await;
        }
    }
    if let Some(out) = dispatch(state, host_id, AgentOperation::DiskSpaceCritical).await
        && let Some(v) = max_disk_used_percent(&out)
    {
        record(state, host_id, METRIC_DISK_USED, v).await;
    }
}

/// The busiest real filesystem's usage percent from `df -Ph` output -- the max
/// `Use%` across every data row. `None` when there's nothing parseable (e.g. an
/// empty or error reading), so no bogus sample is recorded. Mirrors
/// `routes::resurrection::parse_disk_space`'s per-row field extraction but
/// collapses to a single fleet-table figure.
fn max_disk_used_percent(stdout: &str) -> Option<f64> {
    stdout
        .lines()
        .skip(1) // df header row
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            f.iter()
                .find(|x| x.ends_with('%'))?
                .trim_end_matches('%')
                .parse::<f64>()
                .ok()
        })
        .fold(None, |acc, pct| Some(acc.map_or(pct, |m: f64| m.max(pct))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breach_respects_comparator_direction() {
        // ge: at or above breaches.
        assert!(breaches(90.0, "ge", 90.0));
        assert!(breaches(91.0, "ge", 90.0));
        assert!(!breaches(89.9, "ge", 90.0));
        // le: at or below breaches (e.g. free memory low).
        assert!(breaches(5.0, "le", 10.0));
        assert!(!breaches(11.0, "le", 10.0));
        // Unknown comparator falls back to ge.
        assert!(breaches(90.0, "xx", 90.0));
    }

    #[test]
    fn severity_rank_orders_critical_highest() {
        assert!(severity_rank("critical") > severity_rank("warning"));
        assert!(severity_rank("warning") > severity_rank("info"));
        assert_eq!(severity_rank("nonsense"), severity_rank("info"));
    }

    #[test]
    fn metric_label_falls_back_to_the_key() {
        assert_eq!(metric_label(METRIC_LOAD_PER_CORE), "Load per core");
        assert_eq!(metric_label("unknown_metric"), "unknown_metric");
    }

    #[test]
    fn disk_used_takes_the_busiest_filesystem() {
        let df = "Filesystem Size Used Avail Use% Mounted on\n\
                  /dev/sda1 100G 42G 58G 42% /\n\
                  /dev/sda2 200G 190G 10G 95% /var\n\
                  tmpfs 8G 0 8G 0% /run";
        assert_eq!(max_disk_used_percent(df), Some(95.0));
    }

    #[test]
    fn disk_used_is_none_for_unparseable_output() {
        assert_eq!(max_disk_used_percent(""), None);
        assert_eq!(max_disk_used_percent("df: command not found"), None);
    }
}
