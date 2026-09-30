use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct MetricSampleRow {
    value: f64,
    sampled_at: NaiveDateTime,
}

/// One time-series sample of a metric for a host.
pub struct MetricSample {
    pub value: f64,
    pub sampled_at: DateTime<Utc>,
}

impl From<MetricSampleRow> for MetricSample {
    fn from(row: MetricSampleRow) -> Self {
        MetricSample {
            value: row.value,
            sampled_at: DateTime::from_naive_utc_and_offset(row.sampled_at, Utc),
        }
    }
}

/// Appends one sample. Unlike `host_health` (one row per host), this is a
/// history -- one row per sweep tick per metric, pruned by `prune_older_than`.
pub async fn insert(pool: &DbPool, host_id: Uuid, metric: &str, value: f64) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO host_metric_samples (host_id, metric, value) VALUES (?, ?, ?)")
        .bind(host_id.to_string())
        .bind(metric)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}

/// The most recent `limit` samples for one host+metric, returned oldest-first
/// so they can be plotted left-to-right.
pub async fn recent(
    pool: &DbPool,
    host_id: Uuid,
    metric: &str,
    limit: i64,
) -> anyhow::Result<Vec<MetricSample>> {
    let mut rows: Vec<MetricSampleRow> = sqlx::query_as(
        "SELECT value, sampled_at FROM host_metric_samples \
         WHERE host_id = ? AND metric = ? \
         ORDER BY sampled_at DESC \
         LIMIT ?",
    )
    .bind(host_id.to_string())
    .bind(metric)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    // Fetched newest-first (so LIMIT keeps the newest); reverse for plotting.
    rows.reverse();
    Ok(rows.into_iter().map(Into::into).collect())
}

#[derive(FromRow)]
struct LatestMetricRow {
    host_id: String,
    metric: String,
    value: f64,
}

/// The newest value of each metric, for each host that has any samples --
/// the fleet-overview snapshot, read in one query instead of per host.
pub struct LatestMetric {
    pub host_id: Uuid,
    pub metric: String,
    pub value: f64,
}

impl From<LatestMetricRow> for LatestMetric {
    fn from(row: LatestMetricRow) -> Self {
        LatestMetric {
            host_id: Uuid::parse_str(&row.host_id).unwrap_or_default(),
            metric: row.metric,
            value: row.value,
        }
    }
}

/// The latest sample of every (host, metric) pair. Joins each row against the
/// max `sampled_at` for its host+metric group.
pub async fn latest_per_host_metric(pool: &DbPool) -> anyhow::Result<Vec<LatestMetric>> {
    let rows: Vec<LatestMetricRow> = sqlx::query_as(
        "SELECT s.host_id, s.metric, s.value \
         FROM host_metric_samples s \
         JOIN ( \
             SELECT host_id, metric, MAX(sampled_at) AS mx \
             FROM host_metric_samples GROUP BY host_id, metric \
         ) m ON s.host_id = m.host_id AND s.metric = m.metric AND s.sampled_at = m.mx",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

#[derive(FromRow)]
struct HostMetricPointRow {
    host_id: String,
    value: f64,
}

/// One metric's recent samples for several hosts at once, oldest-first per
/// host -- a single query for a whole page of the dashboard fleet table's
/// sparklines instead of one query per host (no N+1). Returns
/// `(host_id, value)` pairs ordered by host then time; the caller groups them.
/// `since_hours` bounds the window so the scan stays small. An empty
/// `host_ids` returns an empty vec without touching the database.
pub async fn recent_for_hosts(
    pool: &DbPool,
    host_ids: &[Uuid],
    metric: &str,
    since_hours: i64,
) -> anyhow::Result<Vec<(Uuid, f64)>> {
    if host_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", host_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT host_id, value, sampled_at FROM host_metric_samples \
         WHERE metric = ? AND sampled_at >= (NOW() - INTERVAL ? HOUR) \
         AND host_id IN ({placeholders}) \
         ORDER BY host_id, sampled_at ASC"
    );
    let mut query = sqlx::query_as::<_, HostMetricPointRow>(&sql)
        .bind(metric)
        .bind(since_hours.max(0));
    for id in host_ids {
        query = query.bind(id.to_string());
    }
    let rows = query.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|r| (Uuid::parse_str(&r.host_id).unwrap_or_default(), r.value))
        .collect())
}

/// Deletes samples older than `days`, keeping the table bounded. Returns how
/// many rows were removed.
pub async fn prune_older_than(pool: &DbPool, days: i64) -> anyhow::Result<u64> {
    let result =
        sqlx::query("DELETE FROM host_metric_samples WHERE sampled_at < (NOW() - INTERVAL ? DAY)")
            .bind(days)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}
