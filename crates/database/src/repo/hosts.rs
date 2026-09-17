use abyssal_core::Host;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct HostRow {
    id: String,
    name: String,
    credential_hash: String,
    enrolled_at: NaiveDateTime,
    last_seen_at: Option<NaiveDateTime>,
    revoked_at: Option<NaiveDateTime>,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<HostRow> for Host {
    fn from(row: HostRow) -> Self {
        Host {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            name: row.name,
            credential_hash: row.credential_hash,
            enrolled_at: utc(row.enrolled_at),
            last_seen_at: row.last_seen_at.map(utc),
            revoked_at: row.revoked_at.map(utc),
        }
    }
}

pub async fn create(pool: &DbPool, name: &str, credential_hash: &str) -> anyhow::Result<Host> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO hosts (id, name, credential_hash) VALUES (?, ?, ?)")
        .bind(id.to_string())
        .bind(name)
        .bind(credential_hash)
        .execute(pool)
        .await?;
    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("host vanished immediately after insert"))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<Host>> {
    let row: Option<HostRow> = sqlx::query_as("SELECT * FROM hosts WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_credential_hash(
    pool: &DbPool,
    credential_hash: &str,
) -> anyhow::Result<Option<Host>> {
    let row: Option<HostRow> = sqlx::query_as("SELECT * FROM hosts WHERE credential_hash = ?")
        .bind(credential_hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<Host>> {
    let rows: Vec<HostRow> = sqlx::query_as("SELECT * FROM hosts ORDER BY enrolled_at ASC")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn touch_last_seen(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE hosts SET last_seen_at = CURRENT_TIMESTAMP(6) WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE hosts SET revoked_at = CURRENT_TIMESTAMP(6) WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
