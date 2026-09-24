//! Sepulchre: `connection_consumers` -- which Arsenal/job references a
//! connection and what it needs from it. See
//! `migrations/0019_sepulchre_storage.sql`.

use std::collections::HashSet;

use abyssal_core::{Capability, ConnectionRole};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(Debug, Clone)]
pub struct ConnectionConsumer {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub arsenal: String,
    pub reference_id: String,
    pub purpose: String,
    pub role: ConnectionRole,
    pub required_capabilities: HashSet<Capability>,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ConsumerRow {
    id: String,
    connection_id: String,
    arsenal: String,
    reference_id: String,
    purpose: String,
    role: String,
    required_capabilities: serde_json::Value,
    created_at: NaiveDateTime,
}

impl TryFrom<ConsumerRow> for ConnectionConsumer {
    type Error = anyhow::Error;
    fn try_from(row: ConsumerRow) -> Result<Self, Self::Error> {
        let capability_keys: Vec<String> = serde_json::from_value(row.required_capabilities)?;
        Ok(ConnectionConsumer {
            id: Uuid::parse_str(&row.id)?,
            connection_id: Uuid::parse_str(&row.connection_id)?,
            arsenal: row.arsenal,
            reference_id: row.reference_id,
            purpose: row.purpose,
            role: row
                .role
                .parse()
                .map_err(|_| anyhow::anyhow!("unknown role: {}", row.role))?,
            required_capabilities: capability_keys
                .iter()
                .filter_map(|k| k.parse().ok())
                .collect(),
            created_at: utc(row.created_at),
        })
    }
}

/// Registers (or re-registers -- idempotent) a consumer's use of a
/// connection. Called by the consuming Arsenal (e.g. Reliquary), never by
/// Sepulchre itself.
pub async fn register(
    pool: &DbPool,
    connection_id: Uuid,
    arsenal: &str,
    reference_id: &str,
    purpose: &str,
    role: ConnectionRole,
    required_capabilities: &HashSet<Capability>,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let capability_keys: Vec<&str> = required_capabilities.iter().map(|c| c.as_str()).collect();
    let capabilities_json = serde_json::to_value(capability_keys)?;
    sqlx::query(
        "INSERT INTO connection_consumers \
         (id, connection_id, arsenal, reference_id, purpose, role, required_capabilities) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE purpose = VALUES(purpose), role = VALUES(role), \
         required_capabilities = VALUES(required_capabilities)",
    )
    .bind(id.to_string())
    .bind(connection_id.to_string())
    .bind(arsenal)
    .bind(reference_id)
    .bind(purpose)
    .bind(role.as_str())
    .bind(capabilities_json)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn unregister(
    pool: &DbPool,
    connection_id: Uuid,
    arsenal: &str,
    reference_id: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "DELETE FROM connection_consumers WHERE connection_id = ? AND arsenal = ? AND reference_id = ?",
    )
    .bind(connection_id.to_string())
    .bind(arsenal)
    .bind(reference_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn for_connection(
    pool: &DbPool,
    connection_id: Uuid,
) -> anyhow::Result<Vec<ConnectionConsumer>> {
    let rows: Vec<ConsumerRow> = sqlx::query_as(
        "SELECT * FROM connection_consumers WHERE connection_id = ? ORDER BY created_at",
    )
    .bind(connection_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(TryFrom::try_from).collect()
}

pub async fn count_for_connection(pool: &DbPool, connection_id: Uuid) -> anyhow::Result<i64> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM connection_consumers WHERE connection_id = ?")
            .bind(connection_id.to_string())
            .fetch_one(pool)
            .await?;
    Ok(count)
}
