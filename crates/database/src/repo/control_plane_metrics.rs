//! Time-series of the control plane's OWN resource usage (CPU / memory / disk
//! percent), written by `crate::self_metrics` and read for the diagnostics
//! page's trend sparklines. Mirrors `host_metrics` but with no host dimension --
//! there's exactly one control plane.

use crate::DbPool;

/// Canonical metric keys, shared by the sampler (writer) and the UI (reader).
pub const METRIC_CPU: &str = "cpu_percent";
pub const METRIC_MEM: &str = "mem_used_percent";
pub const METRIC_DISK: &str = "disk_used_percent";

/// Appends one sample of a control-plane metric.
pub async fn insert(pool: &DbPool, metric: &str, value: f64) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO control_plane_metric_samples (metric, value) VALUES (?, ?)")
        .bind(metric)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}

/// The most recent `limit` values for one metric, oldest-first so they plot
/// left-to-right.
pub async fn recent(pool: &DbPool, metric: &str, limit: i64) -> anyhow::Result<Vec<f64>> {
    let mut values: Vec<f64> = sqlx::query_scalar(
        "SELECT value FROM control_plane_metric_samples \
         WHERE metric = ? ORDER BY sampled_at DESC LIMIT ?",
    )
    .bind(metric)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    // Fetched newest-first (so LIMIT keeps the newest); reverse for plotting.
    values.reverse();
    Ok(values)
}

/// Deletes samples older than `days`, keeping the table bounded. Returns how
/// many rows were removed.
pub async fn prune_older_than(pool: &DbPool, days: i64) -> anyhow::Result<u64> {
    let result = sqlx::query(
        "DELETE FROM control_plane_metric_samples WHERE sampled_at < (NOW() - INTERVAL ? DAY)",
    )
    .bind(days)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
