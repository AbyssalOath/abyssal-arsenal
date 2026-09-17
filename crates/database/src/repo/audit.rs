use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(Debug, Clone)]
pub struct NewAuditEntry<'a> {
    pub user_id: Option<Uuid>,
    pub username_snapshot: &'a str,
    pub action: &'a str,
    pub resource: Option<&'a str>,
    pub result: &'a str,
    pub source_ip: Option<&'a str>,
    pub auth_method: Option<&'a str>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditEntry {
    pub id: String,
    pub occurred_at: NaiveDateTime,
    pub user_id: Option<String>,
    pub username_snapshot: String,
    pub action: String,
    pub resource: Option<String>,
    pub result: String,
    pub source_ip: Option<String>,
    pub auth_method: Option<String>,
    pub metadata: Option<Value>,
}

impl AuditEntry {
    pub fn occurred_at_utc(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(self.occurred_at, Utc)
    }
}

pub async fn record(pool: &DbPool, entry: NewAuditEntry<'_>) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_log \
         (id, user_id, username_snapshot, action, resource, result, source_ip, auth_method, metadata) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(entry.user_id.map(|u| u.to_string()))
    .bind(entry.username_snapshot)
    .bind(entry.action)
    .bind(entry.resource)
    .bind(entry.result)
    .bind(entry.source_ip)
    .bind(entry.auth_method)
    .bind(entry.metadata)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    pub action: Option<String>,
    pub username: Option<String>,
}

pub async fn list(
    pool: &DbPool,
    filter: &AuditFilter,
    page: i64,
    page_size: i64,
) -> anyhow::Result<Vec<AuditEntry>> {
    let offset = page.max(0) * page_size;
    let rows: Vec<AuditEntry> = sqlx::query_as(
        "SELECT * FROM audit_log \
         WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username_snapshot = ?) \
         ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
    )
    .bind(&filter.action)
    .bind(&filter.action)
    .bind(&filter.username)
    .bind(&filter.username)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn count(pool: &DbPool, filter: &AuditFilter) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log \
         WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username_snapshot = ?)",
    )
    .bind(&filter.action)
    .bind(&filter.action)
    .bind(&filter.username)
    .bind(&filter.username)
    .fetch_one(pool)
    .await?;
    Ok(count)
}
