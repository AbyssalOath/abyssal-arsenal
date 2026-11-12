//! Security signals for the Panopticon NAC policy engine (0.2.7 N1, see
//! `docs/roadmap/0.2.7.md`): what Scourge, Thanatos and Cadavault already
//! know, read in bulk once per policy sweep. The matching itself is in
//! `abyssal_web::panopticon_policy`.

use std::collections::HashMap;

use abyssal_core::Severity;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::DbPool;

/// `low`..`critical` as 1..4 (0 for anything else), so SQL can take a MAX.
const RANK: &str = "FIELD(severity, 'low', 'medium', 'high', 'critical')";

fn severity_of_rank(rank: i64) -> Option<Severity> {
    match rank {
        1 => Some(Severity::Low),
        2 => Some(Severity::Medium),
        3 => Some(Severity::High),
        4 => Some(Severity::Critical),
        _ => None,
    }
}

fn rank_of(severity: Severity) -> i64 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// The worst Scourge alert severity per *source* address since `since`.
pub async fn ids_alert_severities(
    pool: &DbPool,
    since: DateTime<Utc>,
) -> anyhow::Result<HashMap<String, Severity>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(&format!(
        "SELECT src_ip, MAX({RANK}) FROM scourge_alerts \
         WHERE occurred_at >= ? AND src_ip IS NOT NULL GROUP BY src_ip"
    ))
    .bind(since.naive_utc())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(ip, rank)| Some((ip, severity_of_rank(rank)?)))
        .collect())
}

/// The worst, then latest, Scourge alert from `src_ip` at or above `min`
/// since `since`: its severity and signature, for the enforcement reason.
pub async fn top_ids_alert(
    pool: &DbPool,
    src_ip: &str,
    since: DateTime<Utc>,
    min: Severity,
) -> anyhow::Result<Option<(Severity, String)>> {
    let row: Option<(i64, String)> = sqlx::query_as(&format!(
        "SELECT {RANK} AS r, signature FROM scourge_alerts \
         WHERE src_ip = ? AND occurred_at >= ? AND {RANK} >= ? \
         ORDER BY r DESC, occurred_at DESC LIMIT 1"
    ))
    .bind(src_ip)
    .bind(since.naive_utc())
    .bind(rank_of(min))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(rank, sig)| Some((severity_of_rank(rank)?, sig))))
}

/// The worst *open* Thanatos event severity per host since `since`.
pub async fn open_event_severities(
    pool: &DbPool,
    since: DateTime<Utc>,
) -> anyhow::Result<HashMap<Uuid, Severity>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(&format!(
        "SELECT host_id, MAX({RANK}) FROM thanatos_events \
         WHERE status = 'open' AND occurred_at >= ? GROUP BY host_id"
    ))
    .bind(since.naive_utc())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, rank)| Some((Uuid::parse_str(&id).ok()?, severity_of_rank(rank)?)))
        .collect())
}

/// The worst, then latest, open Thanatos event on `host_id` at or above
/// `min` since `since`: its severity and label.
pub async fn top_open_event(
    pool: &DbPool,
    host_id: Uuid,
    since: DateTime<Utc>,
    min: Severity,
) -> anyhow::Result<Option<(Severity, String)>> {
    let row: Option<(i64, String)> = sqlx::query_as(&format!(
        "SELECT {RANK} AS r, label FROM thanatos_events \
         WHERE host_id = ? AND status = 'open' AND occurred_at >= ? AND {RANK} >= ? \
         ORDER BY r DESC, occurred_at DESC LIMIT 1"
    ))
    .bind(host_id.to_string())
    .bind(since.naive_utc())
    .bind(rank_of(min))
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(rank, label)| Some((severity_of_rank(rank)?, label))))
}

/// Each host's latest Cadavault posture score. Hosts whose latest run has
/// no score (every check not applicable) are left out: no score isn't a
/// failing score.
pub async fn latest_posture_scores(pool: &DbPool) -> anyhow::Result<HashMap<Uuid, u8>> {
    let rows: Vec<(String, Option<u8>)> = sqlx::query_as(
        "SELECT r.host_id, r.score FROM posture_runs r \
         JOIN (SELECT host_id, MAX(created_at) AS latest FROM posture_runs GROUP BY host_id) l \
           ON r.host_id = l.host_id AND r.created_at = l.latest",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, score)| Some((Uuid::parse_str(&id).ok()?, score?)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_round_trip_and_order_like_severity() {
        for s in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(severity_of_rank(rank_of(s)), Some(s));
        }
        assert!(rank_of(Severity::Low) < rank_of(Severity::Critical));
        assert_eq!(severity_of_rank(0), None);
    }
}
