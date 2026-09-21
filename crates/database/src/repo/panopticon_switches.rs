use abyssal_core::PanopticonSwitch;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct SwitchRow {
    id: String,
    name: String,
    ip_address: String,
    snmp_port: u16,
    community_encrypted: String,
    enabled: bool,
    last_polled_at: Option<NaiveDateTime>,
    last_poll_error: Option<String>,
    created_at: NaiveDateTime,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<SwitchRow> for PanopticonSwitch {
    fn from(row: SwitchRow) -> Self {
        PanopticonSwitch {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            name: row.name,
            ip_address: row.ip_address,
            snmp_port: row.snmp_port,
            community_encrypted: row.community_encrypted,
            enabled: row.enabled,
            last_polled_at: row.last_polled_at.map(utc),
            last_poll_error: row.last_poll_error,
            created_at: utc(row.created_at),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &DbPool,
    name: &str,
    ip_address: &str,
    snmp_port: u16,
    community_encrypted: &str,
    enabled: bool,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO panopticon_switches \
         (id, name, ip_address, snmp_port, community_encrypted, enabled) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(ip_address)
    .bind(snmp_port)
    .bind(community_encrypted)
    .bind(enabled)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<PanopticonSwitch>> {
    let rows: Vec<SwitchRow> =
        sqlx::query_as("SELECT * FROM panopticon_switches ORDER BY name ASC")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Only switches with `enabled = TRUE` -- what the background SNMP sweep
/// actually iterates.
pub async fn list_enabled(pool: &DbPool) -> anyhow::Result<Vec<PanopticonSwitch>> {
    let rows: Vec<SwitchRow> =
        sqlx::query_as("SELECT * FROM panopticon_switches WHERE enabled = TRUE ORDER BY name ASC")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<PanopticonSwitch>> {
    let row: Option<SwitchRow> = sqlx::query_as("SELECT * FROM panopticon_switches WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn set_enabled(pool: &DbPool, id: Uuid, enabled: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE panopticon_switches SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Records the outcome of a poll attempt -- `error = None` on success
/// (clearing any previous failure), `Some(message)` on failure. Either way
/// `last_polled_at` advances, so "last polled" always reflects the most
/// recent attempt, not just the most recent success.
pub async fn record_poll_result(
    pool: &DbPool,
    id: Uuid,
    error: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_switches SET last_polled_at = CURRENT_TIMESTAMP(6), last_poll_error = ? \
         WHERE id = ?",
    )
    .bind(error)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM panopticon_switches WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
