//! Thanatos suppression / allowlist rules (M4) -- see
//! `abyssal_core::SuppressionRule` for the matching semantics. A finding
//! matching any *active* rule is dropped at ingest. Rules are small and few, so
//! the ingest path loads all active ones once per scan and matches in memory
//! rather than running a query per finding.

use abyssal_core::SuppressionRule;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct SuppressionRuleRow {
    id: String,
    host_id: Option<String>,
    source: Option<String>,
    label: Option<String>,
    technique: Option<String>,
    text_contains: Option<String>,
    reason: Option<String>,
    created_by: Option<String>,
    created_at: NaiveDateTime,
    expires_at: Option<NaiveDateTime>,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<SuppressionRuleRow> for SuppressionRule {
    fn from(row: SuppressionRuleRow) -> Self {
        SuppressionRule {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            host_id: row.host_id.and_then(|s| Uuid::parse_str(&s).ok()),
            source: row.source,
            label: row.label,
            technique: row.technique,
            text_contains: row.text_contains,
            reason: row.reason,
            created_by: row.created_by.and_then(|s| Uuid::parse_str(&s).ok()),
            created_at: utc(row.created_at),
            expires_at: row.expires_at.map(utc),
        }
    }
}

/// Every rule that is currently active (unexpired) -- the ingest path's input.
pub async fn list_active(pool: &DbPool) -> anyhow::Result<Vec<SuppressionRule>> {
    let rows: Vec<SuppressionRuleRow> = sqlx::query_as(
        "SELECT * FROM thanatos_suppression_rules \
         WHERE expires_at IS NULL OR expires_at > NOW() \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Every rule, active or expired -- the management page's list.
pub async fn list_all(pool: &DbPool) -> anyhow::Result<Vec<SuppressionRule>> {
    let rows: Vec<SuppressionRuleRow> =
        sqlx::query_as("SELECT * FROM thanatos_suppression_rules ORDER BY created_at DESC")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Creates a rule. The caller is responsible for validating that at least one
/// criterion is set (`SuppressionRule::has_criteria`) before calling.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &DbPool,
    host_id: Option<Uuid>,
    source: Option<&str>,
    label: Option<&str>,
    technique: Option<&str>,
    text_contains: Option<&str>,
    reason: Option<&str>,
    created_by: Option<Uuid>,
    expires_at: Option<DateTime<Utc>>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO thanatos_suppression_rules \
         (id, host_id, source, label, technique, text_contains, reason, created_by, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(host_id.map(|u| u.to_string()))
    .bind(source)
    .bind(label)
    .bind(technique)
    .bind(text_contains)
    .bind(reason)
    .bind(created_by.map(|u| u.to_string()))
    .bind(expires_at.map(|d| d.naive_utc()))
    .execute(pool)
    .await?;
    Ok(id)
}

/// Deletes one rule by id. Returns whether a row matched.
pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM thanatos_suppression_rules WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
