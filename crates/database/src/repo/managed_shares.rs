//! Sepulchre: `managed_shares` -- host-side provisioned SFTP chroots/SMB
//! shares. See `migrations/0019_sepulchre_storage.sql`.

use abyssal_core::Protocol;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(Debug, Clone)]
pub struct ManagedShare {
    pub id: Uuid,
    pub host_id: Uuid,
    pub protocol: Protocol,
    pub local_path: String,
    pub share_name: Option<String>,
    pub chroot_user: Option<String>,
    pub access_principals: serde_json::Value,
    pub rendered_config_hash: Option<String>,
    pub desired_state: serde_json::Value,
    pub observed_state: Option<serde_json::Value>,
    pub connection_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ShareRow {
    id: String,
    host_id: String,
    protocol: String,
    local_path: String,
    share_name: Option<String>,
    chroot_user: Option<String>,
    access_principals: serde_json::Value,
    rendered_config_hash: Option<String>,
    desired_state: serde_json::Value,
    observed_state: Option<serde_json::Value>,
    connection_id: Option<String>,
    created_by: Option<String>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl TryFrom<ShareRow> for ManagedShare {
    type Error = anyhow::Error;
    fn try_from(row: ShareRow) -> Result<Self, Self::Error> {
        Ok(ManagedShare {
            id: Uuid::parse_str(&row.id)?,
            host_id: Uuid::parse_str(&row.host_id)?,
            protocol: row
                .protocol
                .parse()
                .map_err(|_| anyhow::anyhow!("unknown protocol: {}", row.protocol))?,
            local_path: row.local_path,
            share_name: row.share_name,
            chroot_user: row.chroot_user,
            access_principals: row.access_principals,
            rendered_config_hash: row.rendered_config_hash,
            desired_state: row.desired_state,
            observed_state: row.observed_state,
            connection_id: row
                .connection_id
                .map(|id| Uuid::parse_str(&id))
                .transpose()?,
            created_by: row.created_by.map(|id| Uuid::parse_str(&id)).transpose()?,
            created_at: utc(row.created_at),
            updated_at: utc(row.updated_at),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &DbPool,
    host_id: Uuid,
    protocol: Protocol,
    local_path: &str,
    share_name: Option<&str>,
    chroot_user: Option<&str>,
    access_principals: &serde_json::Value,
    desired_state: &serde_json::Value,
    connection_id: Option<Uuid>,
    created_by: Option<Uuid>,
) -> anyhow::Result<ManagedShare> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO managed_shares \
         (id, host_id, protocol, local_path, share_name, chroot_user, access_principals, \
          desired_state, connection_id, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(host_id.to_string())
    .bind(protocol.as_str())
    .bind(local_path)
    .bind(share_name)
    .bind(chroot_user)
    .bind(access_principals)
    .bind(desired_state)
    .bind(connection_id.map(|c| c.to_string()))
    .bind(created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("managed share vanished immediately after insert"))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<ManagedShare>> {
    let row: Option<ShareRow> = sqlx::query_as("SELECT * FROM managed_shares WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    row.map(TryFrom::try_from).transpose()
}

pub async fn for_host(pool: &DbPool, host_id: Uuid) -> anyhow::Result<Vec<ManagedShare>> {
    let rows: Vec<ShareRow> =
        sqlx::query_as("SELECT * FROM managed_shares WHERE host_id = ? ORDER BY created_at")
            .bind(host_id.to_string())
            .fetch_all(pool)
            .await?;
    rows.into_iter().map(TryFrom::try_from).collect()
}

pub async fn record_observed_state(
    pool: &DbPool,
    id: Uuid,
    observed_state: &serde_json::Value,
    rendered_config_hash: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE managed_shares SET observed_state = ?, rendered_config_hash = ? WHERE id = ?",
    )
    .bind(observed_state)
    .bind(rendered_config_hash)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM managed_shares WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
