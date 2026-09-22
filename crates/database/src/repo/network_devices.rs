use std::str::FromStr;

use abyssal_core::{DeviceType, NetworkDevice, TrustState};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;
use crate::repo::network_device_ports;

#[derive(FromRow)]
struct NetworkDeviceRow {
    id: String,
    ip_address: String,
    mac_address: Option<String>,
    hostname: Option<String>,
    device_type: String,
    trust_state: String,
    notes: Option<String>,
    switch_id: Option<String>,
    switch_port: Option<String>,
    switch_port_seen_at: Option<NaiveDateTime>,
    first_seen_at: NaiveDateTime,
    last_seen_at: NaiveDateTime,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl NetworkDeviceRow {
    /// `ports` is fetched separately (see `repo::network_device_ports`) and
    /// threaded in by the caller rather than joined in SQL, since every
    /// caller here loads either the whole inventory or one device and a
    /// join would multiply device rows per port.
    fn into_device(self, ports: Vec<abyssal_core::NetworkDevicePort>) -> NetworkDevice {
        NetworkDevice {
            id: Uuid::parse_str(&self.id).unwrap_or_default(),
            ip_address: self.ip_address,
            mac_address: self.mac_address,
            hostname: self.hostname,
            device_type: DeviceType::from_str(&self.device_type).unwrap_or(DeviceType::Unknown),
            trust_state: TrustState::from_str(&self.trust_state).unwrap_or(TrustState::Unknown),
            notes: self.notes,
            ports,
            switch_id: self.switch_id.and_then(|s| Uuid::parse_str(&s).ok()),
            switch_port: self.switch_port,
            switch_port_seen_at: self.switch_port_seen_at.map(utc),
            first_seen_at: utc(self.first_seen_at),
            last_seen_at: utc(self.last_seen_at),
        }
    }
}

/// Inserts a newly-discovered device, or refreshes an already-known one at
/// the same IP -- `first_seen_at` is left untouched on a refresh (only set
/// by the initial `INSERT`), so the inventory keeps remembering how long a
/// device has actually been on the network, not just when it was last seen.
/// Classification fields (`device_type`/`trust_state`/`notes`) are never
/// touched by a scan -- only `classify` writes them -- so a re-scan doesn't
/// clobber an admin's earlier classification of the device.
///
/// `hostname` is `COALESCE`d exactly like `mac_address` -- a rescan that
/// doesn't happen to resolve a hostname this time (flaky reverse DNS is
/// the normal case on most internal networks, not the exception) must
/// never blank out one an earlier scan already found. This previously
/// used `VALUES(hostname)` unconditionally, which did exactly that: any
/// device's resolved hostname would get wiped out the next time the
/// continuous background sweep (`spawn_panopticon_sweep`) ran and PTR
/// happened not to resolve that round.
///
/// Returns the device's id (fetched with a follow-up lookup by the unique
/// `ip_address`, since `LAST_INSERT_ID()` isn't meaningful on an `ON
/// DUPLICATE KEY UPDATE` that hit the update branch) so the caller can
/// attach this scan's open ports to it.
pub async fn upsert(
    pool: &DbPool,
    ip_address: &str,
    mac_address: Option<&str>,
    hostname: Option<&str>,
) -> anyhow::Result<Uuid> {
    sqlx::query(
        "INSERT INTO panopticon_devices (id, ip_address, mac_address, hostname) \
         VALUES (?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             mac_address = COALESCE(VALUES(mac_address), mac_address), \
             hostname = COALESCE(VALUES(hostname), hostname), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ip_address)
    .bind(mac_address)
    .bind(hostname)
    .execute(pool)
    .await?;

    let (id,): (String,) = sqlx::query_as("SELECT id FROM panopticon_devices WHERE ip_address = ?")
        .bind(ip_address)
        .fetch_one(pool)
        .await?;
    Ok(Uuid::parse_str(&id)?)
}

/// Records a passive sighting from the control plane's own kernel neighbor
/// table (`ip neigh` -- see `panopticon_ops.rs`'s background sweep) --
/// unlike `upsert`, never touches `hostname` (passive sightings have none
/// to report and shouldn't blank out one an earlier active scan found) or
/// the classification fields.
pub async fn touch(pool: &DbPool, ip_address: &str, mac_address: &str) -> anyhow::Result<Uuid> {
    sqlx::query(
        "INSERT INTO panopticon_devices (id, ip_address, mac_address) VALUES (?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             mac_address = VALUES(mac_address), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ip_address)
    .bind(mac_address)
    .execute(pool)
    .await?;

    let (id,): (String,) = sqlx::query_as("SELECT id FROM panopticon_devices WHERE ip_address = ?")
        .bind(ip_address)
        .fetch_one(pool)
        .await?;
    Ok(Uuid::parse_str(&id)?)
}

/// Records a passive sighting from the mDNS listener
/// (`panopticon_mdns.rs`) -- unlike `touch`, may also carry a hostname
/// (mDNS's own self-announced `*.local` name), and unlike `upsert`, never
/// blanks out an existing MAC/hostname when this particular packet didn't
/// carry one (`COALESCE`, not `VALUES()`) -- a hostname learned from one
/// mDNS packet shouldn't be erased by the next one that happens not to
/// repeat it.
pub async fn note_sighting(
    pool: &DbPool,
    ip_address: &str,
    mac_address: Option<&str>,
    hostname: Option<&str>,
) -> anyhow::Result<Uuid> {
    sqlx::query(
        "INSERT INTO panopticon_devices (id, ip_address, mac_address, hostname) \
         VALUES (?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             mac_address = COALESCE(VALUES(mac_address), mac_address), \
             hostname = COALESCE(VALUES(hostname), hostname), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ip_address)
    .bind(mac_address)
    .bind(hostname)
    .execute(pool)
    .await?;

    let (id,): (String,) = sqlx::query_as("SELECT id FROM panopticon_devices WHERE ip_address = ?")
        .bind(ip_address)
        .fetch_one(pool)
        .await?;
    Ok(Uuid::parse_str(&id)?)
}

/// Clears every device currently pointing at `switch_id` -- called once at
/// the start of each poll, before `update_switch_location` reapplies
/// whatever the poll actually found, so a device that moved to a
/// different port (or left the switch's forwarding database entirely)
/// doesn't keep showing a stale location forever. Same "full snapshot
/// replace" shape as `network_device_ports::replace_for_device`.
pub async fn clear_switch_location(pool: &DbPool, switch_id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_devices SET switch_port = NULL, switch_port_seen_at = NULL \
         WHERE switch_id = ?",
    )
    .bind(switch_id.to_string())
    .execute(pool)
    .await?;
    // A separate statement (rather than also clearing switch_id above) so
    // a device between `clear` and the matching `update_switch_location`
    // call for the same poll still shows *which* switch it was last seen
    // on, even though the port is briefly blank.
    Ok(())
}

/// Sets `switch_id`/`switch_port` on whichever device has this MAC address
/// -- matched case-insensitively, since `ip neigh`/nmap and a switch's own
/// BRIDGE-MIB don't necessarily agree on hex-digit casing for the same
/// address. Only ever updates an already-known device (matched by MAC);
/// see `panopticon_snmp.rs`'s module doc for why a MAC the switch reports
/// but that Panopticon has never otherwise seen at the IP layer doesn't
/// create a new inventory row by itself. Returns whether a device actually
/// matched.
pub async fn update_switch_location(
    pool: &DbPool,
    mac_address: &str,
    switch_id: Uuid,
    switch_port: &str,
) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE panopticon_devices \
         SET switch_id = ?, switch_port = ?, switch_port_seen_at = CURRENT_TIMESTAMP(6) \
         WHERE UPPER(mac_address) = UPPER(?)",
    )
    .bind(switch_id.to_string())
    .bind(switch_port)
    .bind(mac_address)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Sets an admin's classification of a device -- purely advisory in this
/// phase, nothing else in Panopticon reads these fields to make a decision.
pub async fn classify(
    pool: &DbPool,
    id: Uuid,
    device_type: DeviceType,
    trust_state: TrustState,
    notes: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_devices SET device_type = ?, trust_state = ?, notes = ? WHERE id = ?",
    )
    .bind(device_type.as_str())
    .bind(trust_state.as_str())
    .bind(notes)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Ordered numerically (via `INET6_ATON`, which handles both IPv4 and IPv6)
/// rather than lexicographically -- a plain string sort would put
/// `"192.168.1.20"` before `"192.168.1.3"`. Every device's open ports come
/// back attached (`NetworkDevice::ports`); the caller filters/searches on
/// them in-memory (see `routes/panopticon.rs`) rather than this needing its
/// own query variant per filter.
pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<NetworkDevice>> {
    let rows: Vec<NetworkDeviceRow> =
        sqlx::query_as("SELECT * FROM panopticon_devices ORDER BY INET6_ATON(ip_address) ASC")
            .fetch_all(pool)
            .await?;

    let mut ports_by_device = network_device_ports::list_grouped(pool).await?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let id = Uuid::parse_str(&row.id).ok()?;
            let ports = ports_by_device.remove(&id).unwrap_or_default();
            Some(row.into_device(ports))
        })
        .collect())
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<NetworkDevice>> {
    let row: Option<NetworkDeviceRow> =
        sqlx::query_as("SELECT * FROM panopticon_devices WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    match row {
        Some(row) => {
            let ports = network_device_ports::list_for_device(pool, id).await?;
            Ok(Some(row.into_device(ports)))
        }
        None => Ok(None),
    }
}

/// Looks up a device by its (unique) IP address rather than its id --
/// used by the sweep to capture a device's state *before* recording a new
/// sighting for it, so it can tell a brand-new device or a reappearing
/// `Untrusted` one from routine re-confirmation of an already-known,
/// already-fresh device (see `panopticon_ops.rs::audit_sighting`).
pub async fn find_by_ip(pool: &DbPool, ip_address: &str) -> anyhow::Result<Option<NetworkDevice>> {
    let row: Option<NetworkDeviceRow> =
        sqlx::query_as("SELECT * FROM panopticon_devices WHERE ip_address = ?")
            .bind(ip_address)
            .fetch_optional(pool)
            .await?;
    match row {
        Some(row) => {
            let id = Uuid::parse_str(&row.id)?;
            let ports = network_device_ports::list_for_device(pool, id).await?;
            Ok(Some(row.into_device(ports)))
        }
        None => Ok(None),
    }
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM panopticon_devices WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Removes every listed device in one transaction -- the "Remove" action
/// on a Topology subnet row, which has no row of its own to delete (a
/// subnet is purely a grouping of `list()`'s results by IP, computed in
/// `routes/panopticon.rs::subnet_of`, never a stored entity) -- the only
/// way to make one stop appearing there is removing every device that
/// currently falls into it, same as removing each individually.
pub async fn delete_by_ids(pool: &DbPool, ids: &[Uuid]) -> anyhow::Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    let mut tx = pool.begin().await?;
    let mut deleted = 0u64;
    for id in ids {
        let result = sqlx::query("DELETE FROM panopticon_devices WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        deleted += result.rows_affected();
    }
    tx.commit().await?;
    Ok(deleted)
}
