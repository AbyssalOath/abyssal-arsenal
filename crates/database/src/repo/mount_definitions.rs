//! Sepulchre: `mount_definitions` -- host-side SSHFS/CIFS mounts. See
//! `migrations/0019_sepulchre_storage.sql`.

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceMethod {
    SystemdUnit,
    Fstab,
}

impl PersistenceMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            PersistenceMethod::SystemdUnit => "systemd_unit",
            PersistenceMethod::Fstab => "fstab",
        }
    }
}

impl std::str::FromStr for PersistenceMethod {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "systemd_unit" => Ok(PersistenceMethod::SystemdUnit),
            "fstab" => Ok(PersistenceMethod::Fstab),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountState {
    Planned,
    Applied,
    Failed,
    Removed,
}

impl MountState {
    pub const fn as_str(self) -> &'static str {
        match self {
            MountState::Planned => "planned",
            MountState::Applied => "applied",
            MountState::Failed => "failed",
            MountState::Removed => "removed",
        }
    }
}

impl std::str::FromStr for MountState {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "planned" => Ok(MountState::Planned),
            "applied" => Ok(MountState::Applied),
            "failed" => Ok(MountState::Failed),
            "removed" => Ok(MountState::Removed),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MountDefinition {
    pub id: Uuid,
    pub host_id: Uuid,
    pub connection_id: Uuid,
    pub mount_point: String,
    pub options: serde_json::Value,
    pub persistence_method: PersistenceMethod,
    pub state: MountState,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct MountRow {
    id: String,
    host_id: String,
    connection_id: String,
    mount_point: String,
    options: serde_json::Value,
    persistence_method: String,
    state: String,
    created_by: Option<String>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl TryFrom<MountRow> for MountDefinition {
    type Error = anyhow::Error;
    fn try_from(row: MountRow) -> Result<Self, Self::Error> {
        Ok(MountDefinition {
            id: Uuid::parse_str(&row.id)?,
            host_id: Uuid::parse_str(&row.host_id)?,
            connection_id: Uuid::parse_str(&row.connection_id)?,
            mount_point: row.mount_point,
            options: row.options,
            persistence_method: row.persistence_method.parse().map_err(|_| {
                anyhow::anyhow!("unknown persistence method: {}", row.persistence_method)
            })?,
            state: row
                .state
                .parse()
                .map_err(|_| anyhow::anyhow!("unknown mount state: {}", row.state))?,
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
    connection_id: Uuid,
    mount_point: &str,
    options: &serde_json::Value,
    persistence_method: PersistenceMethod,
    created_by: Option<Uuid>,
) -> anyhow::Result<MountDefinition> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mount_definitions \
         (id, host_id, connection_id, mount_point, options, persistence_method, state, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(host_id.to_string())
    .bind(connection_id.to_string())
    .bind(mount_point)
    .bind(options)
    .bind(persistence_method.as_str())
    .bind(MountState::Planned.as_str())
    .bind(created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("mount definition vanished immediately after insert"))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<MountDefinition>> {
    let row: Option<MountRow> = sqlx::query_as("SELECT * FROM mount_definitions WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    row.map(TryFrom::try_from).transpose()
}

pub async fn for_host(pool: &DbPool, host_id: Uuid) -> anyhow::Result<Vec<MountDefinition>> {
    let rows: Vec<MountRow> =
        sqlx::query_as("SELECT * FROM mount_definitions WHERE host_id = ? ORDER BY created_at")
            .bind(host_id.to_string())
            .fetch_all(pool)
            .await?;
    rows.into_iter().map(TryFrom::try_from).collect()
}

pub async fn set_state(pool: &DbPool, id: Uuid, state: MountState) -> anyhow::Result<()> {
    sqlx::query("UPDATE mount_definitions SET state = ? WHERE id = ?")
        .bind(state.as_str())
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM mount_definitions WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
