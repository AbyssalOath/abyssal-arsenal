//! Switch neighbors (LLDP / CDP) and imported DHCP leases -- see migration
//! 0045.

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

/// Cuts `value` to at most `max` characters (the column widths), on a
/// character boundary.
fn cap(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

pub struct NewNeighbor<'a> {
    pub protocol: &'a str,
    pub local_port: &'a str,
    pub local_if_index: Option<u32>,
    pub remote_name: &'a str,
    pub remote_port: &'a str,
    pub remote_address: Option<&'a str>,
    pub remote_platform: &'a str,
    pub chassis_id: &'a str,
}

#[derive(Debug, Clone, FromRow)]
pub struct Neighbor {
    pub switch_id: String,
    pub protocol: String,
    pub local_port: String,
    pub local_if_index: Option<u32>,
    pub remote_name: String,
    pub remote_port: String,
    pub remote_address: Option<String>,
    pub remote_platform: String,
    pub chassis_id: String,
    seen_at: NaiveDateTime,
}

impl Neighbor {
    pub fn seen_at(&self) -> DateTime<Utc> {
        utc(self.seen_at)
    }
}

/// Replaces a switch's neighbors with what this poll saw.
pub async fn replace_neighbors(
    pool: &DbPool,
    switch_id: Uuid,
    neighbors: &[NewNeighbor<'_>],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM panopticon_switch_neighbors WHERE switch_id = ?")
        .bind(switch_id.to_string())
        .execute(&mut *tx)
        .await?;
    for n in neighbors {
        sqlx::query(
            "INSERT INTO panopticon_switch_neighbors \
             (id, switch_id, protocol, local_port, local_if_index, remote_name, remote_port, \
              remote_address, remote_platform, chassis_id, seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP(6))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(switch_id.to_string())
        .bind(cap(n.protocol, 8))
        .bind(cap(n.local_port, 255))
        .bind(n.local_if_index)
        .bind(cap(n.remote_name, 255))
        .bind(cap(n.remote_port, 255))
        .bind(n.remote_address.map(|a| cap(a, 45)))
        .bind(cap(n.remote_platform, 512))
        .bind(cap(n.chassis_id, 255))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn list_neighbors(pool: &DbPool) -> anyhow::Result<Vec<Neighbor>> {
    Ok(sqlx::query_as(
        "SELECT switch_id, protocol, local_port, local_if_index, remote_name, remote_port, \
                remote_address, remote_platform, chassis_id, seen_at \
         FROM panopticon_switch_neighbors ORDER BY switch_id, local_port, remote_name",
    )
    .fetch_all(pool)
    .await?)
}

pub struct NewLease<'a> {
    pub ip_address: &'a str,
    pub mac_address: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Stores leases from one import (`source` says where from); a newer import
/// of the same address replaces the older one.
pub async fn upsert_leases(
    pool: &DbPool,
    source: &str,
    leases: &[NewLease<'_>],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    for l in leases {
        sqlx::query(
            "INSERT INTO panopticon_dhcp_leases \
             (ip_address, mac_address, hostname, expires_at, source, imported_at) \
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP(6)) \
             ON DUPLICATE KEY UPDATE mac_address = VALUES(mac_address), \
                 hostname = VALUES(hostname), expires_at = VALUES(expires_at), \
                 source = VALUES(source), imported_at = VALUES(imported_at)",
        )
        .bind(cap(l.ip_address, 45))
        .bind(l.mac_address.map(|m| cap(m, 17)))
        .bind(l.hostname.map(|h| cap(h, 255)))
        .bind(l.expires_at.map(|t| t.naive_utc()))
        .bind(cap(source, 255))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The hostname a lease gives `ip`, if it's current (unexpired, or with no
/// expiry recorded).
pub async fn lease_hostname(pool: &DbPool, ip: &str) -> anyhow::Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT hostname FROM panopticon_dhcp_leases \
         WHERE ip_address = ? AND hostname IS NOT NULL AND hostname <> '' \
           AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))",
    )
    .bind(ip)
    .fetch_optional(pool)
    .await?)
}

/// Fills in what a lease knows on a device already in the inventory: its
/// hostname and MAC, only where there's none yet. Returns whether a device
/// changed.
pub async fn apply_lease_to_device(
    pool: &DbPool,
    ip: &str,
    mac: Option<&str>,
    hostname: Option<&str>,
) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE panopticon_devices SET \
             hostname = COALESCE(hostname, ?), mac_address = COALESCE(mac_address, ?) \
         WHERE ip_address = ? AND ((hostname IS NULL AND ? IS NOT NULL) \
             OR (mac_address IS NULL AND ? IS NOT NULL))",
    )
    .bind(hostname)
    .bind(mac)
    .bind(ip)
    .bind(hostname)
    .bind(mac)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn lease_count(pool: &DbPool) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM panopticon_dhcp_leases")
            .fetch_one(pool)
            .await?,
    )
}
