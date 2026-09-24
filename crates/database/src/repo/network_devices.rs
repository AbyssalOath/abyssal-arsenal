use std::str::FromStr;

use abyssal_core::settings::{
    PANOPTICON_SUBNET_PREFIX_V4, PANOPTICON_SUBNET_PREFIX_V4_DEFAULT, PANOPTICON_SUBNET_PREFIX_V6,
    PANOPTICON_SUBNET_PREFIX_V6_DEFAULT,
};
use abyssal_core::{DeviceType, NetworkDevice, TrustState};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;
use crate::repo::{network_device_ports, settings};

/// Reads the currently-configured subnet prefixes and computes `ip`'s
/// network string -- shared by every write path below, so a device
/// always gets grouped by whatever's configured *right now*, not
/// whatever was configured when this module was first written. One
/// extra pair of cheap settings lookups per device write (not per
/// request), traded deliberately for not having to thread the prefix
/// through every call site across `panopticon_ops.rs`/`panopticon_mdns.rs`/
/// `panopticon_arp.rs`/`panopticon_snmp.rs`.
async fn current_network_of(pool: &DbPool, ip: &str) -> Option<String> {
    let prefix_v4 = settings::get_u32(
        pool,
        PANOPTICON_SUBNET_PREFIX_V4,
        PANOPTICON_SUBNET_PREFIX_V4_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_SUBNET_PREFIX_V4_DEFAULT);
    let prefix_v6 = settings::get_u32(
        pool,
        PANOPTICON_SUBNET_PREFIX_V6,
        PANOPTICON_SUBNET_PREFIX_V6_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_SUBNET_PREFIX_V6_DEFAULT);
    abyssal_core::network_of(ip, prefix_v4 as u8, prefix_v6 as u8)
}

#[derive(FromRow)]
struct NetworkDeviceRow {
    id: String,
    ip_address: String,
    network: Option<String>,
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
            network: self.network,
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
    let network = current_network_of(pool, ip_address).await;
    sqlx::query(
        "INSERT INTO panopticon_devices (id, ip_address, network, mac_address, hostname) \
         VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             network = VALUES(network), \
             mac_address = COALESCE(VALUES(mac_address), mac_address), \
             hostname = COALESCE(VALUES(hostname), hostname), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ip_address)
    .bind(&network)
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
    let network = current_network_of(pool, ip_address).await;
    sqlx::query(
        "INSERT INTO panopticon_devices (id, ip_address, network, mac_address) VALUES (?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             network = VALUES(network), \
             mac_address = VALUES(mac_address), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ip_address)
    .bind(&network)
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
    let network = current_network_of(pool, ip_address).await;
    sqlx::query(
        "INSERT INTO panopticon_devices (id, ip_address, network, mac_address, hostname) \
         VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             network = VALUES(network), \
             mac_address = COALESCE(VALUES(mac_address), mac_address), \
             hostname = COALESCE(VALUES(hostname), hostname), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ip_address)
    .bind(&network)
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

/// One subnet group's header: everything the Device Inventory page's
/// `<summary>` needs, without fetching a single full device row (see
/// `group_counts` below).
pub struct GroupCount {
    /// `None` is the "Unassigned / Unknown" group -- devices whose
    /// `ip_address` didn't parse when `network` was last computed.
    pub network: Option<String>,
    pub device_count: i64,
    pub managed_count: i64,
}

/// One row per distinct `network` (plus a `None` row for "Unassigned /
/// Unknown", if any exist), each with its device count and how many of
/// those devices match a currently-connected managed host's
/// `last_seen_ip` -- the Device Inventory page's group headers, always
/// rendered regardless of which groups' bodies are open. A single
/// `GROUP BY` plus a correlated `EXISTS` against the (small) `hosts`
/// table, deliberately never a full `NetworkDevice` fetch -- that's the
/// whole point of storing `network` instead of computing it per-request
/// from every device row. `port`, when given, narrows every count to
/// devices with that port open too, so a group with zero matching
/// devices under the active filter simply doesn't appear -- headers stay
/// consistent with whatever a group's own (also `port`-filtered) body
/// would show.
pub async fn group_counts(pool: &DbPool, port: Option<u16>) -> anyhow::Result<Vec<GroupCount>> {
    let port_clause = if port.is_some() {
        " WHERE EXISTS (SELECT 1 FROM panopticon_device_ports p \
           WHERE p.device_id = panopticon_devices.id AND p.port = ?)"
    } else {
        ""
    };
    // `COUNT(CASE WHEN ... THEN 1 END)`, not `SUM(CASE WHEN ... THEN 1 ELSE
    // 0 END)` -- MariaDB's `SUM()` over an integer `CASE` promotes to
    // `DECIMAL` (to guard against overflow), which sqlx then refuses to
    // decode into `i64`; `COUNT()` ignores the `NULL`s the unmatched
    // branch produces and always returns `BIGINT`, exactly like the plain
    // `COUNT(*)` beside it.
    let sql = format!(
        "SELECT network, COUNT(*), \
                COUNT(CASE WHEN EXISTS ( \
                    SELECT 1 FROM hosts h \
                    WHERE h.last_seen_ip = panopticon_devices.ip_address \
                      AND h.revoked_at IS NULL \
                ) THEN 1 END) \
         FROM panopticon_devices{port_clause} \
         GROUP BY network \
         ORDER BY network IS NULL, network"
    );
    let mut q = sqlx::query_as::<_, (Option<String>, i64, i64)>(&sql);
    if let Some(p) = port {
        q = q.bind(p);
    }
    let rows = q.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|(network, device_count, managed_count)| GroupCount {
            network,
            device_count,
            managed_count,
        })
        .collect())
}

/// Total device count across every group -- the render-budget decision
/// (`docs/device-inventory.md`) needs this without paying for
/// `group_counts`' per-group `EXISTS` correlation.
pub async fn total_count(pool: &DbPool) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM panopticon_devices")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// One subnet group's device count -- the per-group pagination math
/// needs this independent of `group_counts`' full sweep, since only the
/// currently-open group(s) need it at all.
/// `port`, when given, restricts to devices with that port open
/// (`EXISTS` against `panopticon_device_ports` -- the same open-port
/// filter the old flat inventory table already offered, now composed
/// with grouping/pagination instead of only working over an unbounded
/// full fetch).
pub async fn count_for_group(
    pool: &DbPool,
    network: Option<&str>,
    port: Option<u16>,
) -> anyhow::Result<i64> {
    let network_clause = if network.is_some() {
        "network = ?"
    } else {
        "network IS NULL"
    };
    let port_clause = if port.is_some() {
        " AND EXISTS (SELECT 1 FROM panopticon_device_ports p \
           WHERE p.device_id = panopticon_devices.id AND p.port = ?)"
    } else {
        ""
    };
    let sql =
        format!("SELECT COUNT(*) FROM panopticon_devices WHERE {network_clause}{port_clause}");
    let mut q = sqlx::query_as::<_, (i64,)>(&sql);
    if let Some(net) = network {
        q = q.bind(net);
    }
    if let Some(p) = port {
        q = q.bind(p);
    }
    let (count,) = q.fetch_one(pool).await?;
    Ok(count)
}

/// One page of devices within a single subnet group, numerically ordered
/// by IP (see `list`'s doc comment for why `INET6_ATON`, not a plain
/// string sort). `network = None` selects the "Unassigned / Unknown"
/// group; `port` composes the same open-port filter as [`count_for_group`].
pub async fn list_page(
    pool: &DbPool,
    network: Option<&str>,
    port: Option<u16>,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<NetworkDevice>> {
    let network_clause = if network.is_some() {
        "network = ?"
    } else {
        "network IS NULL"
    };
    let port_clause = if port.is_some() {
        " AND EXISTS (SELECT 1 FROM panopticon_device_ports p \
           WHERE p.device_id = panopticon_devices.id AND p.port = ?)"
    } else {
        ""
    };
    let sql = format!(
        "SELECT * FROM panopticon_devices WHERE {network_clause}{port_clause} \
         ORDER BY INET6_ATON(ip_address) ASC LIMIT ? OFFSET ?"
    );
    let mut q = sqlx::query_as::<_, NetworkDeviceRow>(&sql);
    if let Some(net) = network {
        q = q.bind(net);
    }
    if let Some(p) = port {
        q = q.bind(p);
    }
    let rows: Vec<NetworkDeviceRow> = q.bind(limit).bind(offset).fetch_all(pool).await?;

    let ids: Vec<Uuid> = rows
        .iter()
        .filter_map(|r| Uuid::parse_str(&r.id).ok())
        .collect();
    let mut ports_by_device = network_device_ports::list_grouped_for_devices(pool, &ids).await?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let id = Uuid::parse_str(&row.id).ok()?;
            let ports = ports_by_device.remove(&id).unwrap_or_default();
            Some(row.into_device(ports))
        })
        .collect())
}

/// Every device's `(id, ip_address)` within one subnet group -- the
/// "Remove subnet" action needs every matching row regardless of how
/// many, but that's naturally bounded by one group's own realistic size,
/// never the whole inventory the way the old `list()`-then-filter-in-Rust
/// implementation was (GitHub issue #10). `network = None` selects the
/// "Unassigned / Unknown" group.
pub async fn list_ids_for_group(
    pool: &DbPool,
    network: Option<&str>,
) -> anyhow::Result<Vec<(Uuid, String)>> {
    let rows: Vec<(String, String)> = match network {
        Some(net) => {
            sqlx::query_as("SELECT id, ip_address FROM panopticon_devices WHERE network = ?")
                .bind(net)
                .fetch_all(pool)
                .await?
        }
        None => {
            sqlx::query_as("SELECT id, ip_address FROM panopticon_devices WHERE network IS NULL")
                .fetch_all(pool)
                .await?
        }
    };
    Ok(rows
        .into_iter()
        .filter_map(|(id, ip)| Some((Uuid::parse_str(&id).ok()?, ip)))
        .collect())
}

/// Devices whose numeric address falls within `[start_ip, end_ip]`
/// (inclusive), via `INET6_ATON` -- real numeric-range containment,
/// never a `LIKE` prefix match (GitHub issue #10). Backs the `?subnet=`
/// ad-hoc filter, which accepts *any* valid CIDR an admin types, not just
/// one that happens to exactly match the currently-configured grouping
/// prefix (`network` column) -- so this deliberately re-derives
/// membership numerically at read time rather than trying to match
/// against `network` first. `start_ip`/`end_ip` come from
/// `abyssal_core::subnet_bounds`, already validated CIDR text.
pub async fn list_page_in_range(
    pool: &DbPool,
    start_ip: &str,
    end_ip: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<NetworkDevice>> {
    let rows: Vec<NetworkDeviceRow> = sqlx::query_as(
        "SELECT * FROM panopticon_devices \
         WHERE INET6_ATON(ip_address) BETWEEN INET6_ATON(?) AND INET6_ATON(?) \
         ORDER BY INET6_ATON(ip_address) ASC LIMIT ? OFFSET ?",
    )
    .bind(start_ip)
    .bind(end_ip)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    let ids: Vec<Uuid> = rows
        .iter()
        .filter_map(|r| Uuid::parse_str(&r.id).ok())
        .collect();
    let mut ports_by_device = network_device_ports::list_grouped_for_devices(pool, &ids).await?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let id = Uuid::parse_str(&row.id).ok()?;
            let ports = ports_by_device.remove(&id).unwrap_or_default();
            Some(row.into_device(ports))
        })
        .collect())
}

/// Companion count for [`list_page_in_range`] -- the one `COUNT(*)` the
/// ad-hoc filtered view needs (bounded to a single admin-chosen range,
/// never the whole table, so this is cheap regardless of inventory size).
pub async fn count_in_range(pool: &DbPool, start_ip: &str, end_ip: &str) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM panopticon_devices \
         WHERE INET6_ATON(ip_address) BETWEEN INET6_ATON(?) AND INET6_ATON(?)",
    )
    .bind(start_ip)
    .bind(end_ip)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Recomputes and stores `network` for every row where it's currently
/// `NULL` -- a fresh install's very first devices (written before this
/// column existed anywhere) and any row a prefix-setting change has left
/// stale. Called once at every startup (`crates/app/src/main.rs`),
/// idempotent (a row already carrying a `network` value is left alone --
/// see "Re-derive subnets" on the inventory page for the explicit,
/// admin-triggered version that *does* touch already-populated rows,
/// used after deliberately changing the configured prefix).
pub async fn backfill_network(pool: &DbPool) -> anyhow::Result<u64> {
    rederive_networks(pool, "WHERE network IS NULL").await
}

/// Re-derives `network` for *every* row (not just `NULL` ones) using
/// whatever prefix is configured right now -- the explicit, admin-
/// triggered counterpart to `backfill_network`, for after deliberately
/// changing `panopticon.subnet_prefix_v4`/`_v6`.
pub async fn rederive_all_networks(pool: &DbPool) -> anyhow::Result<u64> {
    rederive_networks(pool, "").await
}

/// Shared implementation: `filter` is a fixed, hard-coded `WHERE` clause
/// (never caller-supplied/user-controlled) selecting which rows to
/// touch, empty meaning "every row."
async fn rederive_networks(pool: &DbPool, filter: &str) -> anyhow::Result<u64> {
    let query = format!("SELECT id, ip_address FROM panopticon_devices {filter}");
    let ids_and_ips: Vec<(String, String)> = sqlx::query_as(&query).fetch_all(pool).await?;
    let mut updated = 0u64;
    for (id, ip) in ids_and_ips {
        let network = current_network_of(pool, &ip).await;
        sqlx::query("UPDATE panopticon_devices SET network = ? WHERE id = ?")
            .bind(&network)
            .bind(&id)
            .execute(pool)
            .await?;
        updated += 1;
    }
    Ok(updated)
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
