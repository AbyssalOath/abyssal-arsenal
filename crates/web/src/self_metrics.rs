//! Periodic sampling of the control plane's OWN host resources (CPU,
//! memory, disk, uptime) via `sysinfo`, cached so the dashboard's Control
//! Plane card is a cheap read rather than a live sample on every page load --
//! the same "sample on a timer, read from a cache" pattern `update_check`'s
//! `UpdateStatus` uses. Best-effort: until the first sample lands the cache is
//! `None` and the card shows an "collecting…" state.

use std::sync::Arc;
use std::time::Duration;

use abyssal_database::DbPool;
use abyssal_database::repo::control_plane_metrics;
use chrono::{DateTime, Utc};
use sysinfo::{Disks, MINIMUM_CPU_UPDATE_INTERVAL, System};
use tokio::sync::RwLock;

use crate::task_health::{TaskHeartbeats, names};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
const SAMPLE_INTERVAL_SECS: u64 = 60;
/// How long control-plane self-metrics history is kept before pruning.
const RETENTION_DAYS: i64 = 7;

/// One snapshot of the control plane host's own resource usage.
#[derive(Clone, Debug)]
pub struct SelfMetrics {
    pub cpu_percent: f64,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub uptime_secs: u64,
    pub sampled_at: DateTime<Utc>,
}

/// The shared cache the sampler writes and the dashboard reads.
pub type SelfMetricsCache = Arc<RwLock<Option<SelfMetrics>>>;

pub fn spawn_self_metrics_sampler(
    cache: SelfMetricsCache,
    heartbeats: TaskHeartbeats,
    pool: DbPool,
) {
    tokio::spawn(async move {
        heartbeats
            .register(names::SELF_METRICS_SAMPLER, SAMPLE_INTERVAL_SECS)
            .await;
        let mut sys = System::new();
        // CPU usage is a delta between two refreshes; prime it once, a moment
        // apart, so the first published sample isn't a bogus 0/100%.
        sys.refresh_cpu_usage();
        tokio::time::sleep(MINIMUM_CPU_UPDATE_INTERVAL).await;
        loop {
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            let (disk_used_bytes, disk_total_bytes) = root_disk();
            let sample = SelfMetrics {
                cpu_percent: f64::from(sys.global_cpu_usage()),
                mem_used_bytes: sys.used_memory(),
                mem_total_bytes: sys.total_memory(),
                disk_used_bytes,
                disk_total_bytes,
                uptime_secs: System::uptime(),
                sampled_at: Utc::now(),
            };
            persist_history(&pool, &sample).await;
            *cache.write().await = Some(sample);
            heartbeats
                .ok(names::SELF_METRICS_SAMPLER, SAMPLE_INTERVAL_SECS)
                .await;
            tokio::time::sleep(SAMPLE_INTERVAL).await;
        }
    });
}

/// Persists CPU / memory / disk percentages as history (best-effort -- a failed
/// write just skips this sample, the next tick tries again) and prunes anything
/// past the retention window.
async fn persist_history(pool: &DbPool, sample: &SelfMetrics) {
    let records = [
        (control_plane_metrics::METRIC_CPU, sample.cpu_percent),
        (
            control_plane_metrics::METRIC_MEM,
            percent(sample.mem_used_bytes, sample.mem_total_bytes),
        ),
        (
            control_plane_metrics::METRIC_DISK,
            percent(sample.disk_used_bytes, sample.disk_total_bytes),
        ),
    ];
    for (metric, value) in records {
        if let Err(e) = control_plane_metrics::insert(pool, metric, value).await {
            tracing::error!(metric, error = %e, "failed to persist control-plane metric sample");
        }
    }
    if let Err(e) = control_plane_metrics::prune_older_than(pool, RETENTION_DAYS).await {
        tracing::error!(error = %e, "failed to prune control-plane metric history");
    }
}

/// Integer-safe percentage `used/total` as a float, guarding divide-by-zero.
fn percent(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
    }
}

/// Used/total bytes of the filesystem the control plane runs from: the `/`
/// mount if present, else the disk with the largest total space (the main
/// one). `(0, 0)` when no disk info is available.
fn root_disk() -> (u64, u64) {
    let disks = Disks::new_with_refreshed_list();
    let mut best: Option<(u64, u64)> = None; // (total, available)
    for disk in disks.list() {
        let total = disk.total_space();
        let available = disk.available_space();
        if disk.mount_point() == std::path::Path::new("/") {
            return (total.saturating_sub(available), total);
        }
        if best.is_none_or(|(best_total, _)| total > best_total) {
            best = Some((total, available));
        }
    }
    match best {
        Some((total, available)) => (total.saturating_sub(available), total),
        None => (0, 0),
    }
}
