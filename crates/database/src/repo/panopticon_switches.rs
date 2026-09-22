use abyssal_core::{
    PanopticonSwitch, SnmpAuthProtocol, SnmpPrivProtocol, SnmpSecurityLevel, SnmpVersion,
};
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
    snmp_version: String,
    community_encrypted: Option<String>,
    snmp_v3_username: Option<String>,
    snmp_v3_security_level: Option<String>,
    snmp_v3_auth_protocol: Option<String>,
    snmp_v3_auth_password_encrypted: Option<String>,
    snmp_v3_priv_protocol: Option<String>,
    snmp_v3_priv_password_encrypted: Option<String>,
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
            // A row written before this column existed can't happen (the
            // migration backfills every existing row to 'v2c'), but an
            // unrecognized value falls back to the same default rather
            // than panicking -- see `SnmpVersion`'s own doc comment.
            snmp_version: row.snmp_version.parse().unwrap_or_default(),
            community_encrypted: row.community_encrypted,
            snmp_v3_username: row.snmp_v3_username,
            snmp_v3_security_level: row
                .snmp_v3_security_level
                .as_deref()
                .and_then(|s| s.parse::<SnmpSecurityLevel>().ok()),
            snmp_v3_auth_protocol: row
                .snmp_v3_auth_protocol
                .as_deref()
                .and_then(|s| s.parse::<SnmpAuthProtocol>().ok()),
            snmp_v3_auth_password_encrypted: row.snmp_v3_auth_password_encrypted,
            snmp_v3_priv_protocol: row
                .snmp_v3_priv_protocol
                .as_deref()
                .and_then(|s| s.parse::<SnmpPrivProtocol>().ok()),
            snmp_v3_priv_password_encrypted: row.snmp_v3_priv_password_encrypted,
            enabled: row.enabled,
            last_polled_at: row.last_polled_at.map(utc),
            last_poll_error: row.last_poll_error,
            created_at: utc(row.created_at),
        }
    }
}

/// Everything `create` needs beyond name/address/port -- grouped into one
/// struct rather than piling on more positional arguments, since which
/// fields matter depends entirely on `snmp_version` (v1/v2c only ever
/// populate `community_encrypted`; v3 only ever populates the rest).
/// Validated by the caller (`routes/panopticon.rs::switch_add`) before
/// this is built -- this layer just persists whatever it's handed.
#[derive(Default)]
pub struct SnmpCredentials {
    pub community_encrypted: Option<String>,
    pub v3_username: Option<String>,
    pub v3_security_level: Option<SnmpSecurityLevel>,
    pub v3_auth_protocol: Option<SnmpAuthProtocol>,
    pub v3_auth_password_encrypted: Option<String>,
    pub v3_priv_protocol: Option<SnmpPrivProtocol>,
    pub v3_priv_password_encrypted: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &DbPool,
    name: &str,
    ip_address: &str,
    snmp_port: u16,
    snmp_version: SnmpVersion,
    credentials: &SnmpCredentials,
    enabled: bool,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO panopticon_switches \
         (id, name, ip_address, snmp_port, snmp_version, community_encrypted, \
          snmp_v3_username, snmp_v3_security_level, snmp_v3_auth_protocol, \
          snmp_v3_auth_password_encrypted, snmp_v3_priv_protocol, \
          snmp_v3_priv_password_encrypted, enabled) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(ip_address)
    .bind(snmp_port)
    .bind(snmp_version.as_str())
    .bind(&credentials.community_encrypted)
    .bind(&credentials.v3_username)
    .bind(credentials.v3_security_level.map(|v| v.as_str()))
    .bind(credentials.v3_auth_protocol.map(|v| v.as_str()))
    .bind(&credentials.v3_auth_password_encrypted)
    .bind(credentials.v3_priv_protocol.map(|v| v.as_str()))
    .bind(&credentials.v3_priv_password_encrypted)
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

/// Updates a switch's non-secret fields -- name/address/port, the sort of
/// thing an admin fixes after a typo. Leaves every credential column
/// untouched; see `update_credentials` for those, which is deliberately a
/// separate call so the edit form can leave secret fields blank to mean
/// "keep the existing one" rather than forcing them to be retyped just to
/// fix an IP address.
pub async fn update(
    pool: &DbPool,
    id: Uuid,
    name: &str,
    ip_address: &str,
    snmp_port: u16,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_switches SET name = ?, ip_address = ?, snmp_port = ? WHERE id = ?",
    )
    .bind(name)
    .bind(ip_address)
    .bind(snmp_port)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Switches this switch's `snmp_version` and replaces every credential
/// column wholesale (the old version's credentials are cleared, since
/// e.g. a leftover `community_encrypted` on a switch now set to v3 would
/// be stale, misleading state). Called only when the edit form actually
/// supplies new credentials for the newly-selected version -- see
/// `routes/panopticon.rs::switch_edit`.
pub async fn update_credentials(
    pool: &DbPool,
    id: Uuid,
    snmp_version: SnmpVersion,
    credentials: &SnmpCredentials,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_switches SET snmp_version = ?, community_encrypted = ?, \
         snmp_v3_username = ?, snmp_v3_security_level = ?, snmp_v3_auth_protocol = ?, \
         snmp_v3_auth_password_encrypted = ?, snmp_v3_priv_protocol = ?, \
         snmp_v3_priv_password_encrypted = ? WHERE id = ?",
    )
    .bind(snmp_version.as_str())
    .bind(&credentials.community_encrypted)
    .bind(&credentials.v3_username)
    .bind(credentials.v3_security_level.map(|v| v.as_str()))
    .bind(credentials.v3_auth_protocol.map(|v| v.as_str()))
    .bind(&credentials.v3_auth_password_encrypted)
    .bind(credentials.v3_priv_protocol.map(|v| v.as_str()))
    .bind(&credentials.v3_priv_password_encrypted)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
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
