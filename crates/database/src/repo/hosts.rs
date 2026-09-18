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
    last_seen_ip: Option<String>,
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
            last_seen_ip: row.last_seen_ip,
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

/// Like `touch_last_seen`, but also records the connecting address --
/// called once at WebSocket upgrade time (see `routes/agent.rs`), not on
/// every subsequent heartbeat/pong, since the address is constant for the
/// life of that connection.
pub async fn touch_last_seen_with_ip(pool: &DbPool, id: Uuid, ip: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE hosts SET last_seen_at = CURRENT_TIMESTAMP(6), last_seen_ip = ? WHERE id = ?",
    )
    .bind(ip)
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

/// Hard-deletes the host row. Nothing else references `hosts.id` by foreign
/// key (the audit log stores a free-text resource label, not an FK, by
/// design -- see the append-only audit model), so this is safe on its own;
/// callers are still expected to revoke first so an already-connected agent
/// can't keep being dispatched to after its row is gone.
pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM hosts WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
