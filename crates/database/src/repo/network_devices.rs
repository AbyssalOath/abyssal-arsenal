use abyssal_core::NetworkDevice;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct NetworkDeviceRow {
    id: String,
    ip_address: String,
    mac_address: Option<String>,
    hostname: Option<String>,
    open_ports: Option<String>,
    first_seen_at: NaiveDateTime,
    last_seen_at: NaiveDateTime,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<NetworkDeviceRow> for NetworkDevice {
    fn from(row: NetworkDeviceRow) -> Self {
        NetworkDevice {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            ip_address: row.ip_address,
            mac_address: row.mac_address,
            hostname: row.hostname,
            open_ports: row.open_ports,
            first_seen_at: utc(row.first_seen_at),
            last_seen_at: utc(row.last_seen_at),
        }
    }
}

/// Inserts a newly-discovered device, or refreshes an already-known one at
/// the same IP -- `first_seen_at` is left untouched on a refresh (only set
/// by the initial `INSERT`), so the inventory keeps remembering how long a
/// device has actually been on the network, not just when it was last seen.
pub async fn upsert(
    pool: &DbPool,
    ip_address: &str,
    mac_address: Option<&str>,
    hostname: Option<&str>,
    open_ports: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_devices (id, ip_address, mac_address, hostname, open_ports) \
         VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             mac_address = COALESCE(VALUES(mac_address), mac_address), \
             hostname = VALUES(hostname), \
             open_ports = VALUES(open_ports), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ip_address)
    .bind(mac_address)
    .bind(hostname)
    .bind(open_ports)
    .execute(pool)
    .await?;
    Ok(())
}

/// Ordered numerically (via `INET6_ATON`, which handles both IPv4 and IPv6)
/// rather than lexicographically -- a plain string sort would put
/// `"192.168.1.20"` before `"192.168.1.3"`.
pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<NetworkDevice>> {
    let rows: Vec<NetworkDeviceRow> =
        sqlx::query_as("SELECT * FROM panopticon_devices ORDER BY INET6_ATON(ip_address) ASC")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<NetworkDevice>> {
    let row: Option<NetworkDeviceRow> =
        sqlx::query_as("SELECT * FROM panopticon_devices WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(row.map(Into::into))
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM panopticon_devices WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
