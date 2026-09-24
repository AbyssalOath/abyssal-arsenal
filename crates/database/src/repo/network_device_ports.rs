use std::collections::HashMap;

use abyssal_core::NetworkDevicePort;
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct PortRow {
    device_id: String,
    // `u16` to match the column's `SMALLINT UNSIGNED` exactly -- sqlx's
    // MySQL driver requires the Rust and SQL integer types to agree (an
    // `i32`/`INT` mismatch fails at decode time even though every value
    // fits).
    port: u16,
    protocol: String,
    service: Option<String>,
}

/// Replaces every open-port row for `device_id` with `ports` in one
/// transaction -- a scan's port list for a device is a full snapshot, not
/// an incremental delta, so stale ports from a previous scan (since closed)
/// shouldn't linger.
pub async fn replace_for_device(
    pool: &DbPool,
    device_id: Uuid,
    ports: &[NetworkDevicePort],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM panopticon_device_ports WHERE device_id = ?")
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await?;
    for p in ports {
        sqlx::query(
            "INSERT INTO panopticon_device_ports (device_id, port, protocol, service) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(device_id.to_string())
        .bind(p.port)
        .bind(&p.protocol)
        .bind(&p.service)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// All open ports for every device, grouped by device id -- fetched in one
/// query and grouped in-process rather than per-device, since the caller
/// (`repo::network_devices::list`) already loads the whole inventory at
/// once.
pub async fn list_grouped(pool: &DbPool) -> anyhow::Result<HashMap<Uuid, Vec<NetworkDevicePort>>> {
    let rows: Vec<PortRow> = sqlx::query_as(
        "SELECT device_id, port, protocol, service FROM panopticon_device_ports \
         ORDER BY device_id, port, protocol",
    )
    .fetch_all(pool)
    .await?;

    let mut grouped: HashMap<Uuid, Vec<NetworkDevicePort>> = HashMap::new();
    for row in rows {
        let Ok(id) = Uuid::parse_str(&row.device_id) else {
            continue;
        };
        grouped.entry(id).or_default().push(NetworkDevicePort {
            port: row.port,
            protocol: row.protocol,
            service: row.service,
        });
    }
    Ok(grouped)
}

/// Open ports for exactly the devices in `device_ids`, grouped -- the
/// paginated middle ground between `list_grouped` (every device) and
/// `list_for_device` (one device): a page of a subnet group's rows needs
/// ports for just that page's devices, not the whole inventory's.
pub async fn list_grouped_for_devices(
    pool: &DbPool,
    device_ids: &[Uuid],
) -> anyhow::Result<HashMap<Uuid, Vec<NetworkDevicePort>>> {
    if device_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; device_ids.len()].join(",");
    let query = format!(
        "SELECT device_id, port, protocol, service FROM panopticon_device_ports \
         WHERE device_id IN ({placeholders}) ORDER BY device_id, port, protocol"
    );
    let mut q = sqlx::query_as::<_, PortRow>(&query);
    for id in device_ids {
        q = q.bind(id.to_string());
    }
    let rows: Vec<PortRow> = q.fetch_all(pool).await?;

    let mut grouped: HashMap<Uuid, Vec<NetworkDevicePort>> = HashMap::new();
    for row in rows {
        let Ok(id) = Uuid::parse_str(&row.device_id) else {
            continue;
        };
        grouped.entry(id).or_default().push(NetworkDevicePort {
            port: row.port,
            protocol: row.protocol,
            service: row.service,
        });
    }
    Ok(grouped)
}

/// Open ports for a single device -- used where the caller only needs one
/// device's ports rather than the whole inventory's (`list_grouped`).
pub async fn list_for_device(
    pool: &DbPool,
    device_id: Uuid,
) -> anyhow::Result<Vec<NetworkDevicePort>> {
    let rows: Vec<PortRow> = sqlx::query_as(
        "SELECT device_id, port, protocol, service FROM panopticon_device_ports \
         WHERE device_id = ? ORDER BY port, protocol",
    )
    .bind(device_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| NetworkDevicePort {
            port: row.port,
            protocol: row.protocol,
            service: row.service,
        })
        .collect())
}
