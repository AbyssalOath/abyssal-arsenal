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
    os: Option<String>,
    agent_version: Option<String>,
    pending_approval: bool,
    is_control_plane: bool,
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
            os: row.os,
            agent_version: row.agent_version,
            pending_approval: row.pending_approval,
            is_control_plane: row.is_control_plane,
            revoked_at: row.revoked_at.map(utc),
        }
    }
}

pub async fn create(pool: &DbPool, name: &str, credential_hash: &str) -> anyhow::Result<Host> {
    create_with_approval(pool, name, credential_hash, false).await
}

/// [`create`], but `pending_approval` hosts are refused on the agent
/// connection until [`approve`]d.
pub async fn create_with_approval(
    pool: &DbPool,
    name: &str,
    credential_hash: &str,
    pending_approval: bool,
) -> anyhow::Result<Host> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO hosts (id, name, credential_hash, pending_approval) VALUES (?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(credential_hash)
    .bind(pending_approval)
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

/// `name` is unique (`uq_hosts_name`) -- used to detect a name collision
/// before `create` would otherwise fail on that constraint with a raw DB
/// error (see `routes/agent.rs::enroll`, which turns that into either a
/// clean re-enrollment over a stale, disconnected row or a clear "already
/// connected" error instead of a bare 500).
pub async fn find_by_name(pool: &DbPool, name: &str) -> anyhow::Result<Option<Host>> {
    let row: Option<HostRow> = sqlx::query_as("SELECT * FROM hosts WHERE name = ?")
        .bind(name)
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
    let rows: Vec<HostRow> =
        sqlx::query_as("SELECT * FROM hosts ORDER BY is_control_plane DESC, enrolled_at ASC")
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

/// Like `touch_last_seen`, but also records the connecting address plus
/// whatever platform/version the agent reported (`X-Agent-Os`/
/// `X-Agent-Version` -- absent on an older agent build, in which case the
/// existing stored value is left alone via `COALESCE`, never blanked out
/// just because this particular connection didn't repeat it) -- called
/// once at WebSocket upgrade time (see `routes/agent.rs`), not on every
/// subsequent heartbeat/pong, since all of this is constant for the life
/// of that connection.
pub async fn touch_last_seen_with_ip(
    pool: &DbPool,
    id: Uuid,
    ip: &str,
    os: Option<&str>,
    agent_version: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE hosts SET last_seen_at = CURRENT_TIMESTAMP(6), last_seen_ip = ?, \
         os = COALESCE(?, os), agent_version = COALESCE(?, agent_version) WHERE id = ?",
    )
    .bind(ip)
    .bind(os)
    .bind(agent_version)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Lets a pending host's agent connect. Returns false if no pending host has
/// this id.
pub async fn approve(pool: &DbPool, id: Uuid) -> anyhow::Result<bool> {
    let result =
        sqlx::query("UPDATE hosts SET pending_approval = 0 WHERE id = ? AND pending_approval = 1")
            .bind(id.to_string())
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

/// Flags (or unflags) a host as the control plane's own server, which turns
/// on `abyssal_hosts::control_plane_guard` for it. Returns false if there's
/// no such host.
pub async fn set_control_plane(
    pool: &DbPool,
    id: Uuid,
    is_control_plane: bool,
) -> anyhow::Result<bool> {
    let result = sqlx::query("UPDATE hosts SET is_control_plane = ? WHERE id = ?")
        .bind(is_control_plane)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    // MariaDB reports 0 affected rows when the value didn't change.
    Ok(result.rows_affected() == 1 || find_by_id(pool, id).await?.is_some())
}

/// Every host flagged as the control plane, to load into the connection
/// registry at startup.
pub async fn control_plane_ids(pool: &DbPool) -> anyhow::Result<Vec<Uuid>> {
    let ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM hosts WHERE is_control_plane = 1")
        .fetch_all(pool)
        .await?;
    Ok(ids
        .into_iter()
        .filter_map(|(id,)| Uuid::parse_str(&id).ok())
        .collect())
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
