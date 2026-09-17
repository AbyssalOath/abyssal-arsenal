use abyssal_core::Session;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct SessionRow {
    id: String,
    token_hash: String,
    user_id: String,
    created_at: NaiveDateTime,
    expires_at: NaiveDateTime,
    revoked_at: Option<NaiveDateTime>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        Session {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            token_hash: row.token_hash,
            user_id: Uuid::parse_str(&row.user_id).unwrap_or_default(),
            created_at: utc(row.created_at),
            expires_at: utc(row.expires_at),
            revoked_at: row.revoked_at.map(utc),
            ip_address: row.ip_address,
            user_agent: row.user_agent,
        }
    }
}

pub async fn create(
    pool: &DbPool,
    user_id: Uuid,
    token_hash: &str,
    expires_at: DateTime<Utc>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> anyhow::Result<Session> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sessions (id, token_hash, user_id, expires_at, ip_address, user_agent) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(token_hash)
    .bind(user_id.to_string())
    .bind(expires_at.naive_utc())
    .bind(ip_address)
    .bind(user_agent)
    .execute(pool)
    .await?;

    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session vanished immediately after insert"))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<Session>> {
    let row: Option<SessionRow> = sqlx::query_as("SELECT * FROM sessions WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_token_hash(
    pool: &DbPool,
    token_hash: &str,
) -> anyhow::Result<Option<Session>> {
    let row: Option<SessionRow> = sqlx::query_as("SELECT * FROM sessions WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn revoke(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(6) WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn revoke_all_for_user(pool: &DbPool, user_id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(6) WHERE user_id = ? AND revoked_at IS NULL",
    )
    .bind(user_id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}
