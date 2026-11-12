//! DHCP fingerprints from Panopticon's passive capture (0.2.7 N3), the
//! strongest evidence the device classifier (`abyssal_core::classify`) has.

use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;

use crate::DbPool;

#[derive(Debug, Clone, FromRow)]
pub struct DhcpFingerprint {
    pub mac_address: String,
    pub prl: Option<String>,
    pub vendor_class: Option<String>,
    pub hostname: Option<String>,
    first_seen_at: NaiveDateTime,
    last_seen_at: NaiveDateTime,
}

impl DhcpFingerprint {
    pub fn first_seen_at(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(self.first_seen_at, Utc)
    }

    pub fn last_seen_at(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(self.last_seen_at, Utc)
    }
}

/// Records what a client's latest DHCP packet said. A field the packet
/// didn't carry keeps its previous value.
pub async fn upsert(
    pool: &DbPool,
    mac: &str,
    prl: Option<&str>,
    vendor_class: Option<&str>,
    hostname: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_dhcp_fingerprints (mac_address, prl, vendor_class, hostname) \
         VALUES (LOWER(?), ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             prl = COALESCE(VALUES(prl), prl), \
             vendor_class = COALESCE(VALUES(vendor_class), vendor_class), \
             hostname = COALESCE(VALUES(hostname), hostname), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(mac)
    .bind(prl)
    .bind(vendor_class)
    .bind(hostname)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find(pool: &DbPool, mac: &str) -> anyhow::Result<Option<DhcpFingerprint>> {
    Ok(
        sqlx::query_as("SELECT * FROM panopticon_dhcp_fingerprints WHERE mac_address = LOWER(?)")
            .bind(mac)
            .fetch_optional(pool)
            .await?,
    )
}

/// Every fingerprint, by lowercase MAC -- for the classification sweep.
pub async fn all(pool: &DbPool) -> anyhow::Result<HashMap<String, DhcpFingerprint>> {
    let rows: Vec<DhcpFingerprint> = sqlx::query_as("SELECT * FROM panopticon_dhcp_fingerprints")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|f| (f.mac_address.clone(), f))
        .collect())
}

pub async fn count(pool: &DbPool) -> anyhow::Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM panopticon_dhcp_fingerprints")
        .fetch_one(pool)
        .await?;
    Ok(n)
}
