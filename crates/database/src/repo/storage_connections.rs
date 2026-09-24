//! Sepulchre: `storage_connections` and its tightly-coupled tables
//! (secret, roles, capabilities, access methods) -- see
//! `migrations/0019_sepulchre_storage.sql` and
//! `crates/core/src/storage.rs`.

use std::collections::HashSet;

use abyssal_core::{
    AccessMethod, Capability, ConnectionAccessMethod, ConnectionCapability, ConnectionOrigin,
    ConnectionRole, ExecutionContext, Protocol, ProtocolConfig, StorageConnection,
    ValidationStatus,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(FromRow)]
struct ConnectionRow {
    id: String,
    name: String,
    protocol: String,
    origin: String,
    managed_host_id: Option<String>,
    protocol_config: serde_json::Value,
    enabled: bool,
    last_validation_status: Option<String>,
    last_validation_at: Option<NaiveDateTime>,
    created_by: Option<String>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl TryFrom<ConnectionRow> for StorageConnection {
    type Error = anyhow::Error;
    fn try_from(row: ConnectionRow) -> Result<Self, Self::Error> {
        Ok(StorageConnection {
            id: Uuid::parse_str(&row.id)?,
            name: row.name,
            protocol: row
                .protocol
                .parse()
                .map_err(|_| anyhow::anyhow!("unknown protocol: {}", row.protocol))?,
            origin: row
                .origin
                .parse()
                .map_err(|_| anyhow::anyhow!("unknown origin: {}", row.origin))?,
            managed_host_id: row
                .managed_host_id
                .map(|id| Uuid::parse_str(&id))
                .transpose()?,
            protocol_config: serde_json::from_value(row.protocol_config)?,
            enabled: row.enabled,
            last_validation_status: row
                .last_validation_status
                .and_then(|s| s.parse::<ValidationStatus>().ok()),
            last_validation_at: row.last_validation_at.map(utc),
            created_by: row.created_by.map(|id| Uuid::parse_str(&id)).transpose()?,
            created_at: utc(row.created_at),
            updated_at: utc(row.updated_at),
        })
    }
}

pub struct NewConnection<'a> {
    pub name: &'a str,
    pub origin: ConnectionOrigin,
    pub managed_host_id: Option<Uuid>,
    pub protocol_config: &'a ProtocolConfig,
    pub created_by: Option<Uuid>,
}

pub async fn create(pool: &DbPool, new: NewConnection<'_>) -> anyhow::Result<StorageConnection> {
    let id = Uuid::new_v4();
    let protocol = new.protocol_config.protocol();
    let config_json = serde_json::to_value(new.protocol_config)?;
    sqlx::query(
        "INSERT INTO storage_connections \
         (id, name, protocol, origin, managed_host_id, protocol_config, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(new.name)
    .bind(protocol.as_str())
    .bind(new.origin.as_str())
    .bind(new.managed_host_id.map(|h| h.to_string()))
    .bind(config_json)
    .bind(new.created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("connection vanished immediately after insert"))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<StorageConnection>> {
    let row: Option<ConnectionRow> =
        sqlx::query_as("SELECT * FROM storage_connections WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    row.map(TryFrom::try_from).transpose()
}

pub async fn find_by_name(pool: &DbPool, name: &str) -> anyhow::Result<Option<StorageConnection>> {
    let row: Option<ConnectionRow> =
        sqlx::query_as("SELECT * FROM storage_connections WHERE name = ?")
            .bind(name)
            .fetch_optional(pool)
            .await?;
    row.map(TryFrom::try_from).transpose()
}

#[derive(Debug, Default, Clone)]
pub struct ConnectionFilter {
    pub protocol: Option<Protocol>,
    pub role: Option<ConnectionRole>,
}

pub async fn list(
    pool: &DbPool,
    filter: &ConnectionFilter,
    page: i64,
    page_size: i64,
) -> anyhow::Result<Vec<StorageConnection>> {
    let offset = page.max(0) * page_size;
    let protocol_key = filter.protocol.map(|p| p.as_str());
    let role_key = filter.role.map(|r| r.as_str());
    let rows: Vec<ConnectionRow> = sqlx::query_as(
        "SELECT DISTINCT sc.* FROM storage_connections sc \
         LEFT JOIN connection_roles cr ON cr.connection_id = sc.id \
         WHERE (? IS NULL OR sc.protocol = ?) AND (? IS NULL OR cr.role = ?) \
         ORDER BY sc.name LIMIT ? OFFSET ?",
    )
    .bind(protocol_key)
    .bind(protocol_key)
    .bind(role_key)
    .bind(role_key)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(TryFrom::try_from).collect()
}

pub async fn count(pool: &DbPool, filter: &ConnectionFilter) -> anyhow::Result<i64> {
    let protocol_key = filter.protocol.map(|p| p.as_str());
    let role_key = filter.role.map(|r| r.as_str());
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT sc.id) FROM storage_connections sc \
         LEFT JOIN connection_roles cr ON cr.connection_id = sc.id \
         WHERE (? IS NULL OR sc.protocol = ?) AND (? IS NULL OR cr.role = ?)",
    )
    .bind(protocol_key)
    .bind(protocol_key)
    .bind(role_key)
    .bind(role_key)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn update_protocol_config(
    pool: &DbPool,
    id: Uuid,
    config: &ProtocolConfig,
) -> anyhow::Result<()> {
    let config_json = serde_json::to_value(config)?;
    sqlx::query("UPDATE storage_connections SET protocol_config = ? WHERE id = ?")
        .bind(config_json)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn rename(pool: &DbPool, id: Uuid, name: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE storage_connections SET name = ? WHERE id = ?")
        .bind(name)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_enabled(pool: &DbPool, id: Uuid, enabled: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE storage_connections SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn record_validation_summary(
    pool: &DbPool,
    id: Uuid,
    status: ValidationStatus,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE storage_connections SET last_validation_status = ?, \
         last_validation_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(status.as_str())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM storage_connections WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

// -----------------------------------------------------------------------
// Secret (storage_connection_secrets)
// -----------------------------------------------------------------------

/// Fixed for now -- this platform has exactly one master key
/// (`ENCRYPTION_KEY`), no rotation support yet. Present as a real column
/// so multi-key rotation doesn't need a schema change later.
pub const FIXED_SECRET_KEY_ID: &str = "env:ENCRYPTION_KEY";

pub struct SecretRecord {
    pub secret_ciphertext: String,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

#[derive(FromRow)]
struct SecretRow {
    secret_ciphertext: String,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
    updated_at: NaiveDateTime,
    updated_by: Option<String>,
}

pub async fn find_secret(
    pool: &DbPool,
    connection_id: Uuid,
) -> anyhow::Result<Option<SecretRecord>> {
    let row: Option<SecretRow> = sqlx::query_as(
        "SELECT secret_ciphertext, public_key, key_fingerprint, updated_at, updated_by \
         FROM storage_connection_secrets WHERE connection_id = ?",
    )
    .bind(connection_id.to_string())
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(SecretRecord {
            secret_ciphertext: r.secret_ciphertext,
            public_key: r.public_key,
            key_fingerprint: r.key_fingerprint,
            updated_at: utc(r.updated_at),
            updated_by: r.updated_by.map(|id| Uuid::parse_str(&id)).transpose()?,
        })
    })
    .transpose()
}

/// Write-only replace (insert or overwrite) -- there is no "read back the
/// plaintext" path anywhere in Sepulchre's own UI; only the decrypt-on-
/// use path inside the protocol backends ever sees the plaintext secret.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_secret(
    pool: &DbPool,
    connection_id: Uuid,
    secret_ciphertext: &str,
    public_key: Option<&str>,
    key_fingerprint: Option<&str>,
    updated_by: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO storage_connection_secrets \
         (connection_id, secret_ciphertext, secret_key_id, public_key, key_fingerprint, updated_by) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE secret_ciphertext = VALUES(secret_ciphertext), \
         secret_key_id = VALUES(secret_key_id), public_key = VALUES(public_key), \
         key_fingerprint = VALUES(key_fingerprint), updated_by = VALUES(updated_by), \
         secret_version = secret_version + 1",
    )
    .bind(connection_id.to_string())
    .bind(secret_ciphertext)
    .bind(FIXED_SECRET_KEY_ID)
    .bind(public_key)
    .bind(key_fingerprint)
    .bind(updated_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(())
}

// -----------------------------------------------------------------------
// Roles (connection_roles)
// -----------------------------------------------------------------------

pub async fn roles_for_connection(
    pool: &DbPool,
    connection_id: Uuid,
) -> anyhow::Result<HashSet<ConnectionRole>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT role FROM connection_roles WHERE connection_id = ?")
            .bind(connection_id.to_string())
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().filter_map(|(r,)| r.parse().ok()).collect())
}

/// Replaces the full role set for a connection.
pub async fn set_roles(
    pool: &DbPool,
    connection_id: Uuid,
    roles: &HashSet<ConnectionRole>,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM connection_roles WHERE connection_id = ?")
        .bind(connection_id.to_string())
        .execute(&mut *tx)
        .await?;
    for role in roles {
        sqlx::query("INSERT INTO connection_roles (connection_id, role) VALUES (?, ?)")
            .bind(connection_id.to_string())
            .bind(role.as_str())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

// -----------------------------------------------------------------------
// Capabilities (connection_capabilities)
// -----------------------------------------------------------------------

#[derive(FromRow)]
struct CapabilityRow {
    capability: String,
    declared: bool,
    verified_at: Option<NaiveDateTime>,
    verified_by_validation_run_id: Option<String>,
}

pub async fn capabilities_for_connection(
    pool: &DbPool,
    connection_id: Uuid,
) -> anyhow::Result<Vec<ConnectionCapability>> {
    let rows: Vec<CapabilityRow> = sqlx::query_as(
        "SELECT capability, declared, verified_at, verified_by_validation_run_id \
         FROM connection_capabilities WHERE connection_id = ?",
    )
    .bind(connection_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .filter_map(|r| {
            let capability = r.capability.parse().ok()?;
            Some((|| {
                Ok(ConnectionCapability {
                    capability,
                    declared: r.declared,
                    verified_at: r.verified_at.map(utc),
                    verified_by_validation_run_id: r
                        .verified_by_validation_run_id
                        .map(|id| Uuid::parse_str(&id))
                        .transpose()?,
                })
            })())
        })
        .collect()
}

/// Sets the *declared* capability set (admin intent) -- never touches
/// `verified_at`, which only a validation run may set or clear.
pub async fn set_declared_capabilities(
    pool: &DbPool,
    connection_id: Uuid,
    capabilities: &HashSet<Capability>,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    for cap in Capability::ALL {
        let declared = capabilities.contains(cap);
        sqlx::query(
            "INSERT INTO connection_capabilities (connection_id, capability, declared) \
             VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE declared = VALUES(declared)",
        )
        .bind(connection_id.to_string())
        .bind(cap.as_str())
        .bind(declared)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Sets a capability's *verified* state -- called only by the validation
/// engine, never directly from a connection-edit form.
pub async fn set_verified_capability(
    pool: &DbPool,
    connection_id: Uuid,
    capability: Capability,
    verified: bool,
    validation_run_id: Uuid,
) -> anyhow::Result<()> {
    if verified {
        sqlx::query(
            "INSERT INTO connection_capabilities \
             (connection_id, capability, declared, verified_at, verified_by_validation_run_id) \
             VALUES (?, ?, TRUE, CURRENT_TIMESTAMP(6), ?) \
             ON DUPLICATE KEY UPDATE verified_at = CURRENT_TIMESTAMP(6), \
             verified_by_validation_run_id = VALUES(verified_by_validation_run_id)",
        )
        .bind(connection_id.to_string())
        .bind(capability.as_str())
        .bind(validation_run_id.to_string())
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE connection_capabilities SET verified_at = NULL, \
             verified_by_validation_run_id = NULL WHERE connection_id = ? AND capability = ?",
        )
        .bind(connection_id.to_string())
        .bind(capability.as_str())
        .execute(pool)
        .await?;
    }
    Ok(())
}

// -----------------------------------------------------------------------
// Access methods (connection_access_methods)
// -----------------------------------------------------------------------

#[derive(FromRow)]
struct AccessMethodRow {
    method: String,
    context: String,
    managed_host_id: Option<String>,
}

pub async fn access_methods_for_connection(
    pool: &DbPool,
    connection_id: Uuid,
) -> anyhow::Result<Vec<ConnectionAccessMethod>> {
    let rows: Vec<AccessMethodRow> = sqlx::query_as(
        "SELECT method, context, managed_host_id FROM connection_access_methods \
         WHERE connection_id = ?",
    )
    .bind(connection_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .filter_map(|r| {
            let method: AccessMethod = r.method.parse().ok()?;
            let context: ExecutionContext = r.context.parse().ok()?;
            Some((|| {
                Ok(ConnectionAccessMethod {
                    method,
                    context,
                    managed_host_id: r
                        .managed_host_id
                        .map(|id| Uuid::parse_str(&id))
                        .transpose()?,
                })
            })())
        })
        .collect()
}

pub async fn add_access_method(
    pool: &DbPool,
    connection_id: Uuid,
    method: AccessMethod,
    context: ExecutionContext,
    managed_host_id: Option<Uuid>,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT IGNORE INTO connection_access_methods \
         (id, connection_id, method, context, managed_host_id) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(connection_id.to_string())
    .bind(method.as_str())
    .bind(context.as_str())
    .bind(managed_host_id.map(|h| h.to_string()))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn remove_access_method(
    pool: &DbPool,
    connection_id: Uuid,
    method: AccessMethod,
    managed_host_id: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query(
        "DELETE FROM connection_access_methods \
         WHERE connection_id = ? AND method = ? AND managed_host_id <=> ?",
    )
    .bind(connection_id.to_string())
    .bind(method.as_str())
    .bind(managed_host_id.map(|h| h.to_string()))
    .execute(pool)
    .await?;
    Ok(())
}
