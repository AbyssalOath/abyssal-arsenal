//! Device enforcement actions (0.2.7): quarantine or block a MAC through the
//! RADIUS decision, for switches Panopticon can't write over SNMP. See
//! `abyssal_core::DeviceEnforcement`.

use std::collections::HashSet;

use abyssal_core::{DeviceEnforcement, EnforcementKind, EnforcementState};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(FromRow)]
struct Row {
    id: String,
    mac_address: String,
    device_ip: Option<String>,
    kind: String,
    state: String,
    reason: Option<String>,
    created_by: Option<String>,
    created_by_username: Option<String>,
    created_at: NaiveDateTime,
    expires_at: Option<NaiveDateTime>,
    reverted_at: Option<NaiveDateTime>,
}

impl From<Row> for DeviceEnforcement {
    fn from(r: Row) -> Self {
        DeviceEnforcement {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            mac_address: r.mac_address,
            device_ip: r.device_ip,
            kind: r.kind.parse().unwrap_or(EnforcementKind::Quarantine),
            state: if r.state == "active" {
                EnforcementState::Active
            } else {
                EnforcementState::Reverted
            },
            reason: r.reason,
            created_by: r.created_by.and_then(|s| Uuid::parse_str(&s).ok()),
            created_by_username: r.created_by_username,
            created_at: utc(r.created_at),
            expires_at: r.expires_at.map(utc),
            reverted_at: r.reverted_at.map(utc),
        }
    }
}

pub struct NewDeviceAction<'a> {
    pub mac_address: &'a str,
    pub device_ip: Option<&'a str>,
    pub kind: EnforcementKind,
    pub reason: Option<&'a str>,
    pub created_by: Option<Uuid>,
    pub created_by_username: Option<&'a str>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Records an active action -- unless one is already in effect for the MAC,
/// checked in the same statement, so two writers can't both create one.
/// Returns the new id, or `None` if the device was already enforced.
pub async fn create(pool: &DbPool, new: &NewDeviceAction<'_>) -> anyhow::Result<Option<Uuid>> {
    let id = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO panopticon_device_enforcements \
         (id, mac_address, device_ip, kind, state, reason, created_by, created_by_username, expires_at) \
         SELECT ?, LOWER(?), ?, ?, 'active', ?, ?, ?, ? FROM DUAL \
         WHERE NOT EXISTS (SELECT 1 FROM panopticon_device_enforcements \
                           WHERE mac_address = LOWER(?) AND state = 'active')",
    )
    .bind(id.to_string())
    .bind(new.mac_address)
    .bind(new.device_ip)
    .bind(new.kind.as_str())
    .bind(new.reason)
    .bind(new.created_by.map(|u| u.to_string()))
    .bind(new.created_by_username)
    .bind(new.expires_at.map(|t| t.naive_utc()))
    .bind(new.mac_address)
    .execute(pool)
    .await?;
    Ok((result.rows_affected() > 0).then_some(id))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<DeviceEnforcement>> {
    let row: Option<Row> =
        sqlx::query_as("SELECT * FROM panopticon_device_enforcements WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(row.map(Into::into))
}

/// The action in effect for a MAC -- what the RADIUS decision honors.
pub async fn find_in_effect_for_mac(
    pool: &DbPool,
    mac: &str,
) -> anyhow::Result<Option<DeviceEnforcement>> {
    let row: Option<Row> = sqlx::query_as(
        "SELECT * FROM panopticon_device_enforcements \
         WHERE mac_address = LOWER(?) AND state = 'active' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(mac)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Whether a MAC was enforced or released since `since` -- the policy
/// engine's cooldown, so a manual release isn't re-applied at once.
pub async fn has_recent_for_mac(
    pool: &DbPool,
    mac: &str,
    since: DateTime<Utc>,
) -> anyhow::Result<bool> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM panopticon_device_enforcements \
         WHERE mac_address = LOWER(?) AND (created_at >= ? OR reverted_at >= ?)",
    )
    .bind(mac)
    .bind(since.naive_utc())
    .bind(since.naive_utc())
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

pub async fn list_in_effect(pool: &DbPool) -> anyhow::Result<Vec<DeviceEnforcement>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT * FROM panopticon_device_enforcements WHERE state = 'active' \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Every MAC under an active action, for the policy sweep.
pub async fn macs_in_effect(pool: &DbPool) -> anyhow::Result<HashSet<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT mac_address FROM panopticon_device_enforcements WHERE state = 'active'",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(m,)| m).collect())
}

pub async fn list_recent(pool: &DbPool, limit: u32) -> anyhow::Result<Vec<DeviceEnforcement>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT * FROM panopticon_device_enforcements ORDER BY created_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Active actions past their expiry.
pub async fn list_due(pool: &DbPool, now: DateTime<Utc>) -> anyhow::Result<Vec<DeviceEnforcement>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT * FROM panopticon_device_enforcements \
         WHERE state = 'active' AND expires_at IS NOT NULL AND expires_at <= ?",
    )
    .bind(now.naive_utc())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Lifts an active action. Returns whether it was still active (so a release
/// racing the revert sweep happens once).
pub async fn mark_reverted(pool: &DbPool, id: Uuid) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE panopticon_device_enforcements \
         SET state = 'reverted', reverted_at = CURRENT_TIMESTAMP(6) \
         WHERE id = ? AND state = 'active'",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn make_permanent(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_device_enforcements SET expires_at = NULL \
         WHERE id = ? AND state = 'active'",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}
