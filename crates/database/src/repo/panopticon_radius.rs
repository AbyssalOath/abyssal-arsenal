//! Persistence for Panopticon's embedded RADIUS server (phase 5): the NAS
//! clients it accepts requests from and the sessions it accounts.

use abyssal_core::{RadiusClient, RadiusSession};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

// ---- Clients ----

#[derive(FromRow)]
struct ClientRow {
    id: String,
    name: String,
    nas_address: String,
    shared_secret_encrypted: String,
    enabled: bool,
    created_at: NaiveDateTime,
}

impl From<ClientRow> for RadiusClient {
    fn from(r: ClientRow) -> Self {
        RadiusClient {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            name: r.name,
            nas_address: r.nas_address,
            shared_secret_encrypted: r.shared_secret_encrypted,
            enabled: r.enabled,
            created_at: utc(r.created_at),
        }
    }
}

pub async fn create_client(
    pool: &DbPool,
    name: &str,
    nas_address: &str,
    shared_secret_encrypted: &str,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO panopticon_radius_clients (id, name, nas_address, shared_secret_encrypted) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(nas_address)
    .bind(shared_secret_encrypted)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn list_clients(pool: &DbPool) -> anyhow::Result<Vec<RadiusClient>> {
    let rows: Vec<ClientRow> =
        sqlx::query_as("SELECT * FROM panopticon_radius_clients ORDER BY name ASC")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Only enabled clients -- the set the server actually matches an incoming NAS
/// source against. Kept small; iterated per request so CIDR matches work.
pub async fn list_enabled_clients(pool: &DbPool) -> anyhow::Result<Vec<RadiusClient>> {
    let rows: Vec<ClientRow> = sqlx::query_as(
        "SELECT * FROM panopticon_radius_clients WHERE enabled = TRUE ORDER BY name ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn set_client_enabled(pool: &DbPool, id: Uuid, enabled: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE panopticon_radius_clients SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_client(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM panopticon_radius_clients WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

// ---- Sessions ----

#[derive(FromRow)]
struct SessionRow {
    id: String,
    username: Option<String>,
    mac_address: Option<String>,
    nas_ip: Option<String>,
    nas_port: Option<String>,
    framed_ip: Option<String>,
    acct_session_id: Option<String>,
    auth_method: Option<String>,
    started_at: NaiveDateTime,
    last_seen_at: NaiveDateTime,
    stopped_at: Option<NaiveDateTime>,
    terminate_cause: Option<String>,
}

impl From<SessionRow> for RadiusSession {
    fn from(r: SessionRow) -> Self {
        RadiusSession {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            username: r.username,
            mac_address: r.mac_address,
            nas_ip: r.nas_ip,
            nas_port: r.nas_port,
            framed_ip: r.framed_ip,
            acct_session_id: r.acct_session_id,
            auth_method: r.auth_method,
            started_at: utc(r.started_at),
            last_seen_at: utc(r.last_seen_at),
            stopped_at: r.stopped_at.map(utc),
            terminate_cause: r.terminate_cause,
        }
    }
}

/// What a single accounting packet carries about a session. The server fills
/// this from the parsed attributes; `upsert_session` persists it.
#[derive(Default)]
pub struct SessionUpdate<'a> {
    pub username: Option<&'a str>,
    pub mac_address: Option<&'a str>,
    pub nas_ip: Option<&'a str>,
    pub nas_port: Option<&'a str>,
    pub framed_ip: Option<&'a str>,
    pub acct_session_id: Option<&'a str>,
    pub auth_method: Option<&'a str>,
    /// True for an Acct-Status-Type = Stop packet -- sets `stopped_at`.
    pub stop: bool,
    pub terminate_cause: Option<&'a str>,
}

/// Inserts or updates a session keyed by (`nas_ip`, `acct_session_id`). Start /
/// Interim-Update refresh `last_seen_at` (and fill any newly-present fields via
/// COALESCE so a sparse Interim packet never blanks earlier data); Stop also
/// sets `stopped_at` + terminate cause.
pub async fn upsert_session(pool: &DbPool, u: &SessionUpdate<'_>) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let stopped_marker = if u.stop {
        Some(Utc::now().naive_utc())
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO panopticon_radius_sessions \
         (id, username, mac_address, nas_ip, nas_port, framed_ip, acct_session_id, \
          auth_method, started_at, last_seen_at, stopped_at, terminate_cause) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), ?, ?) \
         ON DUPLICATE KEY UPDATE \
             username = COALESCE(VALUES(username), username), \
             mac_address = COALESCE(VALUES(mac_address), mac_address), \
             nas_port = COALESCE(VALUES(nas_port), nas_port), \
             framed_ip = COALESCE(VALUES(framed_ip), framed_ip), \
             auth_method = COALESCE(VALUES(auth_method), auth_method), \
             last_seen_at = CURRENT_TIMESTAMP(6), \
             stopped_at = COALESCE(VALUES(stopped_at), stopped_at), \
             terminate_cause = COALESCE(VALUES(terminate_cause), terminate_cause)",
    )
    .bind(id.to_string())
    .bind(u.username)
    .bind(u.mac_address)
    .bind(u.nas_ip)
    .bind(u.nas_port)
    .bind(u.framed_ip)
    .bind(u.acct_session_id)
    .bind(u.auth_method)
    .bind(stopped_marker)
    .bind(u.terminate_cause)
    .execute(pool)
    .await?;
    Ok(())
}

/// Recent sessions, newest activity first -- what the RADIUS admin page lists.
pub async fn list_recent_sessions(pool: &DbPool, limit: u32) -> anyhow::Result<Vec<RadiusSession>> {
    let rows: Vec<SessionRow> = sqlx::query_as(
        "SELECT * FROM panopticon_radius_sessions ORDER BY last_seen_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// The most recent session for a MAC (case-insensitive) -- the inventory's
/// "latest authenticated identity" for a device.
pub async fn latest_session_for_mac(
    pool: &DbPool,
    mac: &str,
) -> anyhow::Result<Option<RadiusSession>> {
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT * FROM panopticon_radius_sessions WHERE UPPER(mac_address) = UPPER(?) \
         ORDER BY last_seen_at DESC LIMIT 1",
    )
    .bind(mac)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Deletes accounted sessions last seen before `cutoff` -- housekeeping so the
/// table doesn't grow without bound. (Called opportunistically by the server.)
pub async fn prune_sessions_older_than(
    pool: &DbPool,
    cutoff: DateTime<Utc>,
) -> anyhow::Result<u64> {
    let r = sqlx::query("DELETE FROM panopticon_radius_sessions WHERE last_seen_at < ?")
        .bind(cutoff.naive_utc())
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}
