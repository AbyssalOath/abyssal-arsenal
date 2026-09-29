use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct ThresholdRow {
    id: String,
    metric: String,
    comparator: String,
    threshold: f64,
    severity: String,
    enabled: bool,
}

/// One operator-configured metric threshold.
pub struct Threshold {
    pub id: Uuid,
    pub metric: String,
    pub comparator: String,
    pub threshold: f64,
    pub severity: String,
    pub enabled: bool,
}

impl From<ThresholdRow> for Threshold {
    fn from(row: ThresholdRow) -> Self {
        Threshold {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            metric: row.metric,
            comparator: row.comparator,
            threshold: row.threshold,
            severity: row.severity,
            enabled: row.enabled,
        }
    }
}

/// Every configured threshold, for the management page.
pub async fn list_thresholds(pool: &DbPool) -> anyhow::Result<Vec<Threshold>> {
    let rows: Vec<ThresholdRow> = sqlx::query_as(
        "SELECT id, metric, comparator, threshold, severity, enabled \
         FROM monitoring_thresholds ORDER BY metric, severity",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Only the enabled thresholds, for the sweep's evaluation.
pub async fn list_enabled_thresholds(pool: &DbPool) -> anyhow::Result<Vec<Threshold>> {
    let rows: Vec<ThresholdRow> = sqlx::query_as(
        "SELECT id, metric, comparator, threshold, severity, enabled \
         FROM monitoring_thresholds WHERE enabled = 1 ORDER BY metric",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn create_threshold(
    pool: &DbPool,
    metric: &str,
    comparator: &str,
    threshold: f64,
    severity: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO monitoring_thresholds (id, metric, comparator, threshold, severity) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(metric)
    .bind(comparator)
    .bind(threshold)
    .bind(severity)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_threshold(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM monitoring_thresholds WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Whether an alert for this host+metric is currently firing (so the sweep can
/// alert only on the transition into breach, not every tick).
pub async fn is_firing(pool: &DbPool, host_id: Uuid, metric: &str) -> anyhow::Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT firing FROM monitoring_alert_state WHERE host_id = ? AND metric = ?",
    )
    .bind(host_id.to_string())
    .bind(metric)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0).unwrap_or(false))
}

/// Records whether an alert for this host+metric is firing, refreshing `since`
/// when it transitions into firing.
pub async fn set_firing(
    pool: &DbPool,
    host_id: Uuid,
    metric: &str,
    firing: bool,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO monitoring_alert_state (host_id, metric, firing, since) \
         VALUES (?, ?, ?, CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE \
             since = IF(firing = VALUES(firing), since, CURRENT_TIMESTAMP(6)), \
             firing = VALUES(firing)",
    )
    .bind(host_id.to_string())
    .bind(metric)
    .bind(firing)
    .execute(pool)
    .await?;
    Ok(())
}
