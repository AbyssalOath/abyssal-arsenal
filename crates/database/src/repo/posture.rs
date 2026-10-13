//! Cadavault posture runs and their per-check results
//! (`migrations/0048_posture.sql`).

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

/// Runs kept per host; older ones are deleted as new ones arrive.
const KEEP_RUNS_PER_HOST: i64 = 60;

pub struct NewResult<'a> {
    pub check_id: &'a str,
    pub status: &'a str,
    pub evidence: &'a str,
}

#[derive(Debug, Clone)]
pub struct Run {
    pub id: Uuid,
    pub host_id: Uuid,
    pub platform: String,
    pub started_by: String,
    pub created_at: DateTime<Utc>,
    pub passed: i32,
    pub failed: i32,
    pub not_applicable: i32,
    pub score: Option<u8>,
}

#[derive(FromRow)]
struct RunRow {
    id: String,
    host_id: String,
    platform: String,
    started_by: String,
    created_at: NaiveDateTime,
    passed: i32,
    failed: i32,
    not_applicable: i32,
    score: Option<u8>,
}

impl From<RunRow> for Run {
    fn from(r: RunRow) -> Self {
        Run {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            host_id: Uuid::parse_str(&r.host_id).unwrap_or_default(),
            platform: r.platform,
            started_by: r.started_by,
            created_at: DateTime::from_naive_utc_and_offset(r.created_at, Utc),
            passed: r.passed,
            failed: r.failed,
            not_applicable: r.not_applicable,
            score: r.score,
        }
    }
}

const RUN_COLUMNS: &str =
    "id, host_id, platform, started_by, created_at, passed, failed, not_applicable, score";

/// Stores a run and its results in one transaction, then trims the host's
/// history to the newest `KEEP_RUNS_PER_HOST`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_run(
    pool: &DbPool,
    host_id: Uuid,
    platform: &str,
    started_by: &str,
    passed: i32,
    failed: i32,
    not_applicable: i32,
    score: Option<u8>,
    results: &[NewResult<'_>],
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO posture_runs \
         (id, host_id, platform, started_by, passed, failed, not_applicable, score) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(host_id.to_string())
    .bind(platform)
    .bind(started_by)
    .bind(passed)
    .bind(failed)
    .bind(not_applicable)
    .bind(score)
    .execute(&mut *tx)
    .await?;
    for r in results {
        sqlx::query(
            "INSERT INTO posture_results (run_id, check_id, status, evidence) VALUES (?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(r.check_id)
        .bind(r.status)
        .bind(r.evidence)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    // History beyond the newest runs: results first, then the runs.
    let old: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM posture_runs WHERE host_id = ? ORDER BY created_at DESC LIMIT 1000 OFFSET ?",
    )
    .bind(host_id.to_string())
    .bind(KEEP_RUNS_PER_HOST)
    .fetch_all(pool)
    .await?;
    for (old_id,) in old {
        sqlx::query("DELETE FROM posture_results WHERE run_id = ?")
            .bind(&old_id)
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM posture_runs WHERE id = ?")
            .bind(&old_id)
            .execute(pool)
            .await?;
    }
    Ok(id)
}

/// A host's runs, newest first.
pub async fn runs_for_host(pool: &DbPool, host_id: Uuid, limit: i64) -> anyhow::Result<Vec<Run>> {
    let rows: Vec<RunRow> = sqlx::query_as(&format!(
        "SELECT {RUN_COLUMNS} FROM posture_runs WHERE host_id = ? ORDER BY created_at DESC LIMIT ?"
    ))
    .bind(host_id.to_string())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn find_run(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<Run>> {
    let row: Option<RunRow> = sqlx::query_as(&format!(
        "SELECT {RUN_COLUMNS} FROM posture_runs WHERE id = ?"
    ))
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Every host's newest run, and the one before it (for the trend).
pub async fn latest_two_per_host(pool: &DbPool) -> anyhow::Result<Vec<Run>> {
    let rows: Vec<RunRow> = sqlx::query_as(&format!(
        "SELECT {RUN_COLUMNS} FROM ( \
           SELECT {RUN_COLUMNS}, ROW_NUMBER() OVER (PARTITION BY host_id ORDER BY created_at DESC) AS n \
           FROM posture_runs \
         ) ranked WHERE n <= 2 ORDER BY host_id, created_at DESC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

#[derive(Debug, Clone, FromRow)]
pub struct ResultRow {
    pub check_id: String,
    pub status: String,
    pub evidence: String,
}

pub async fn results(pool: &DbPool, run_id: Uuid) -> anyhow::Result<Vec<ResultRow>> {
    Ok(
        sqlx::query_as("SELECT check_id, status, evidence FROM posture_results WHERE run_id = ?")
            .bind(run_id.to_string())
            .fetch_all(pool)
            .await?,
    )
}

/// (run ID, check ID) for every failed check in these runs.
pub async fn failed_in_runs(
    pool: &DbPool,
    run_ids: &[Uuid],
) -> anyhow::Result<Vec<(Uuid, String)>> {
    if run_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; run_ids.len()].join(",");
    let sql = format!(
        "SELECT run_id, check_id FROM posture_results WHERE status = 'failed' AND run_id IN ({placeholders})"
    );
    let mut query = sqlx::query_as::<_, (String, String)>(&sql);
    for id in run_ids {
        query = query.bind(id.to_string());
    }
    Ok(query
        .fetch_all(pool)
        .await?
        .into_iter()
        .filter_map(|(run, check)| Some((Uuid::parse_str(&run).ok()?, check)))
        .collect())
}

/// When each host last had a run (for the daily schedule).
pub async fn last_run_times(pool: &DbPool) -> anyhow::Result<Vec<(Uuid, DateTime<Utc>)>> {
    let rows: Vec<(String, NaiveDateTime)> =
        sqlx::query_as("SELECT host_id, MAX(created_at) FROM posture_runs GROUP BY host_id")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(h, t)| {
            Some((
                Uuid::parse_str(&h).ok()?,
                DateTime::from_naive_utc_and_offset(t, Utc),
            ))
        })
        .collect())
}
