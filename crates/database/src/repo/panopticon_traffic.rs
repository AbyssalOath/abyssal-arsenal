use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

/// A port a poll has seen on a switch -- independent of whether it
/// currently has a device mapped to it (see the migration's own comment).
#[derive(Debug, Clone)]
pub struct SwitchPort {
    pub if_index: u32,
    /// The port's label: its name on the switch (`ifAlias`) if it has one,
    /// else `ifDescr` (migration 0044).
    pub if_descr: Option<String>,
    /// The raw `ifDescr` ("Slot: 0 Port: 3 Gigabit - Level"), from polls
    /// since migration 0044.
    pub hw_descr: Option<String>,
    /// IF-MIB `ifAdminStatus`/`ifOperStatus` raw integer codes from the
    /// last poll that read them (M2), or `None` for a port only ever seen
    /// before port-status polling existed, or on a switch that doesn't
    /// expose IF-MIB's status columns. `abyssal_core::IfAdminStatus` /
    /// `IfOperStatus` map the standard codes to labels.
    pub admin_status: Option<i64>,
    pub oper_status: Option<i64>,
    /// Negotiated link speed in Mbps (`ifHighSpeed`, or `ifSpeed`/1e6), or
    /// `None` if the switch didn't report it.
    pub speed_mbps: Option<u32>,
    /// When `admin_status`/`oper_status`/`speed_mbps` were last read -- may
    /// predate `last_seen_at` if a later poll saw the port (FDB/traffic)
    /// but failed to read IF-MIB status that round.
    pub status_seen_at: Option<DateTime<Utc>>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct SwitchPortRow {
    if_index: u32,
    if_descr: Option<String>,
    hw_descr: Option<String>,
    // TINYINT UNSIGNED (migration 0037): sqlx won't decode an unsigned
    // column into a signed type, so read as u8 and widen below.
    admin_status: Option<u8>,
    oper_status: Option<u8>,
    speed_mbps: Option<u32>,
    status_seen_at: Option<NaiveDateTime>,
    last_seen_at: NaiveDateTime,
}

impl From<SwitchPortRow> for SwitchPort {
    fn from(row: SwitchPortRow) -> Self {
        SwitchPort {
            if_index: row.if_index,
            if_descr: row.if_descr,
            hw_descr: row.hw_descr,
            admin_status: row.admin_status.map(i64::from),
            oper_status: row.oper_status.map(i64::from),
            speed_mbps: row.speed_mbps,
            status_seen_at: row.status_seen_at.map(utc),
            last_seen_at: utc(row.last_seen_at),
        }
    }
}

pub async fn upsert_port(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    if_descr: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_switch_ports (switch_id, if_index, if_descr, last_seen_at) \
         VALUES (?, ?, ?, CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE \
             if_descr = COALESCE(VALUES(if_descr), if_descr), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(if_descr)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a port's label (its name, else `ifDescr`) and raw `ifDescr`,
/// creating the port row if needed. Unlike [`upsert_port`] the label is
/// overwritten, so renaming or un-naming a port on the switch shows up on
/// the next poll.
pub async fn record_port_names(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    label: &str,
    hw_descr: &str,
) -> anyhow::Result<()> {
    let hw_descr = (!hw_descr.is_empty()).then_some(hw_descr);
    sqlx::query(
        "INSERT INTO panopticon_switch_ports (switch_id, if_index, if_descr, hw_descr, last_seen_at) \
         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE \
             if_descr = VALUES(if_descr), \
             hw_descr = COALESCE(VALUES(hw_descr), hw_descr), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(label)
    .bind(hw_descr)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every port this switch has ever had a poll observe, ordered by
/// `if_index` -- what the traffic page lists.
pub async fn list_ports(pool: &DbPool, switch_id: Uuid) -> anyhow::Result<Vec<SwitchPort>> {
    let rows: Vec<SwitchPortRow> = sqlx::query_as(
        "SELECT if_index, if_descr, hw_descr, admin_status, oper_status, speed_mbps, status_seen_at, \
                last_seen_at \
         FROM panopticon_switch_ports \
         WHERE switch_id = ? ORDER BY if_index ASC",
    )
    .bind(switch_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Resolves a port's IF-MIB `ifIndex` from the human label a device row stores
/// in `switch_port` (the `ifDescr` the poll recorded). Used by the NAC policy
/// engine, which knows a device's port only by that label but needs the ifIndex
/// to enforce. Falls back to parsing an `if<n>` style label (the poll's own
/// fallback when a switch didn't expose an ifDescr) so those ports resolve too.
pub async fn find_if_index_by_label(
    pool: &DbPool,
    switch_id: Uuid,
    label: &str,
) -> anyhow::Result<Option<u32>> {
    let found: Option<u32> = sqlx::query_scalar(
        "SELECT if_index FROM panopticon_switch_ports \
         WHERE switch_id = ? AND if_descr = ? LIMIT 1",
    )
    .bind(switch_id.to_string())
    .bind(label)
    .fetch_optional(pool)
    .await?;
    if let Some(idx) = found {
        return Ok(Some(idx));
    }
    // Fallback label shape `if<n>` from the poll when no ifDescr was available.
    if let Some(rest) = label.strip_prefix("if")
        && let Ok(idx) = rest.parse::<u32>()
    {
        return Ok(Some(idx));
    }
    Ok(None)
}

/// Records IF-MIB port state (M2) for one port, creating the port row if a
/// prior poll never did. Mirrors `upsert_port`'s shape but writes the
/// status columns; `COALESCE`s each field so a poll that reads admin/oper
/// but not speed (or vice versa) never blanks out what an earlier poll
/// already learned. `status_seen_at` is always advanced so the UI can show
/// how fresh the state reading is independently of `last_seen_at`.
pub async fn update_port_status(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    if_descr: Option<&str>,
    admin_status: Option<i64>,
    oper_status: Option<i64>,
    speed_mbps: Option<u32>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_switch_ports \
             (switch_id, if_index, if_descr, admin_status, oper_status, speed_mbps, \
              status_seen_at, last_seen_at) \
         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE \
             if_descr = COALESCE(VALUES(if_descr), if_descr), \
             admin_status = COALESCE(VALUES(admin_status), admin_status), \
             oper_status = COALESCE(VALUES(oper_status), oper_status), \
             speed_mbps = COALESCE(VALUES(speed_mbps), speed_mbps), \
             status_seen_at = CURRENT_TIMESTAMP(6), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(if_descr)
    .bind(admin_status)
    .bind(oper_status)
    .bind(speed_mbps)
    .execute(pool)
    .await?;
    Ok(())
}

/// One raw counter reading -- cumulative octets, not yet a rate.
#[derive(Debug, Clone, Copy)]
pub struct RawSample {
    pub polled_at: DateTime<Utc>,
    pub in_octets: u64,
    pub out_octets: u64,
    pub counter_bits: u8,
}

#[derive(FromRow)]
struct RawSampleRow {
    polled_at: NaiveDateTime,
    in_octets: u64,
    out_octets: u64,
    counter_bits: u8,
}

impl From<RawSampleRow> for RawSample {
    fn from(row: RawSampleRow) -> Self {
        RawSample {
            polled_at: utc(row.polled_at),
            in_octets: row.in_octets,
            out_octets: row.out_octets,
            counter_bits: row.counter_bits,
        }
    }
}

pub async fn insert_raw_sample(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    in_octets: u64,
    out_octets: u64,
    counter_bits: u8,
    polled_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_port_traffic_raw \
         (switch_id, if_index, in_octets, out_octets, counter_bits, polled_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(in_octets)
    .bind(out_octets)
    .bind(counter_bits)
    .bind(polled_at.naive_utc())
    .execute(pool)
    .await?;
    Ok(())
}

/// Raw samples for one port within `[since, until)`, oldest first --
/// consecutive pairs are what `panopticon_traffic.rs::rates_from_raw`
/// turns into actual rate points.
pub async fn raw_samples_between(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> anyhow::Result<Vec<RawSample>> {
    let rows: Vec<RawSampleRow> = sqlx::query_as(
        "SELECT polled_at, in_octets, out_octets, counter_bits FROM panopticon_port_traffic_raw \
         WHERE switch_id = ? AND if_index = ? AND polled_at >= ? AND polled_at < ? \
         ORDER BY polled_at ASC",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(since.naive_utc())
    .bind(until.naive_utc())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// The most recent two raw samples for one port -- enough to compute a
/// single "current rate" figure without pulling a whole range.
pub async fn latest_raw_samples(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    limit: u32,
) -> anyhow::Result<Vec<RawSample>> {
    let rows: Vec<RawSampleRow> = sqlx::query_as(
        "SELECT polled_at, in_octets, out_octets, counter_bits FROM panopticon_port_traffic_raw \
         WHERE switch_id = ? AND if_index = ? ORDER BY polled_at DESC LIMIT ?",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut samples: Vec<RawSample> = rows.into_iter().map(Into::into).collect();
    samples.reverse(); // oldest first, matching raw_samples_between's order
    Ok(samples)
}

pub async fn prune_raw_older_than(pool: &DbPool, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
    let result = sqlx::query("DELETE FROM panopticon_port_traffic_raw WHERE polled_at < ?")
        .bind(cutoff.naive_utc())
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// One rollup bucket, already a rate (bytes/sec) rather than a raw
/// counter -- the shape both the hourly and daily tiers share, and what
/// the chart renderer ultimately consumes regardless of which tier (or
/// raw, via `rates_from_raw`) it came from.
#[derive(Debug, Clone, Copy)]
pub struct TrafficBucket {
    pub at: DateTime<Utc>,
    pub avg_in_bps: f64,
    pub avg_out_bps: f64,
    pub max_in_bps: f64,
    pub max_out_bps: f64,
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_hourly_bucket(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    bucket_start: DateTime<Utc>,
    avg_in_bps: f64,
    avg_out_bps: f64,
    max_in_bps: f64,
    max_out_bps: f64,
    sample_count: u32,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_port_traffic_hourly \
         (switch_id, if_index, bucket_start, avg_in_bps, avg_out_bps, max_in_bps, max_out_bps, sample_count) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             avg_in_bps = VALUES(avg_in_bps), avg_out_bps = VALUES(avg_out_bps), \
             max_in_bps = VALUES(max_in_bps), max_out_bps = VALUES(max_out_bps), \
             sample_count = VALUES(sample_count)",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(bucket_start.naive_utc())
    .bind(avg_in_bps)
    .bind(avg_out_bps)
    .bind(max_in_bps)
    .bind(max_out_bps)
    .bind(sample_count)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(FromRow)]
struct HourlyRow {
    bucket_start: NaiveDateTime,
    avg_in_bps: f64,
    avg_out_bps: f64,
    max_in_bps: f64,
    max_out_bps: f64,
}

pub async fn hourly_between(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> anyhow::Result<Vec<TrafficBucket>> {
    let rows: Vec<HourlyRow> = sqlx::query_as(
        "SELECT bucket_start, avg_in_bps, avg_out_bps, max_in_bps, max_out_bps \
         FROM panopticon_port_traffic_hourly \
         WHERE switch_id = ? AND if_index = ? AND bucket_start >= ? AND bucket_start < ? \
         ORDER BY bucket_start ASC",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(since.naive_utc())
    .bind(until.naive_utc())
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| TrafficBucket {
            at: utc(r.bucket_start),
            avg_in_bps: r.avg_in_bps,
            avg_out_bps: r.avg_out_bps,
            max_in_bps: r.max_in_bps,
            max_out_bps: r.max_out_bps,
        })
        .collect())
}

pub async fn prune_hourly_older_than(pool: &DbPool, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
    let result = sqlx::query("DELETE FROM panopticon_port_traffic_hourly WHERE bucket_start < ?")
        .bind(cutoff.naive_utc())
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn delete_all_hourly(pool: &DbPool) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM panopticon_port_traffic_hourly")
        .execute(pool)
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_daily_bucket(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    day: NaiveDate,
    avg_in_bps: f64,
    avg_out_bps: f64,
    max_in_bps: f64,
    max_out_bps: f64,
    sample_count: u32,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_port_traffic_daily \
         (switch_id, if_index, day, avg_in_bps, avg_out_bps, max_in_bps, max_out_bps, sample_count) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             avg_in_bps = VALUES(avg_in_bps), avg_out_bps = VALUES(avg_out_bps), \
             max_in_bps = VALUES(max_in_bps), max_out_bps = VALUES(max_out_bps), \
             sample_count = VALUES(sample_count)",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(day)
    .bind(avg_in_bps)
    .bind(avg_out_bps)
    .bind(max_in_bps)
    .bind(max_out_bps)
    .bind(sample_count)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(FromRow)]
struct DailyRow {
    day: NaiveDate,
    avg_in_bps: f64,
    avg_out_bps: f64,
    max_in_bps: f64,
    max_out_bps: f64,
}

pub async fn daily_between(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    since: NaiveDate,
    until: NaiveDate,
) -> anyhow::Result<Vec<TrafficBucket>> {
    let rows: Vec<DailyRow> = sqlx::query_as(
        "SELECT day, avg_in_bps, avg_out_bps, max_in_bps, max_out_bps \
         FROM panopticon_port_traffic_daily \
         WHERE switch_id = ? AND if_index = ? AND day >= ? AND day < ? \
         ORDER BY day ASC",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| TrafficBucket {
            at: DateTime::from_naive_utc_and_offset(r.day.and_hms_opt(0, 0, 0).unwrap(), Utc),
            avg_in_bps: r.avg_in_bps,
            avg_out_bps: r.avg_out_bps,
            max_in_bps: r.max_in_bps,
            max_out_bps: r.max_out_bps,
        })
        .collect())
}

pub async fn prune_daily_older_than(pool: &DbPool, cutoff: NaiveDate) -> anyhow::Result<u64> {
    let result = sqlx::query("DELETE FROM panopticon_port_traffic_daily WHERE day < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn delete_all_daily(pool: &DbPool) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM panopticon_port_traffic_daily")
        .execute(pool)
        .await?;
    Ok(())
}
