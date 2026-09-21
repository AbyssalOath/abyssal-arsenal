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
    pub if_descr: Option<String>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct SwitchPortRow {
    if_index: u32,
    if_descr: Option<String>,
    last_seen_at: NaiveDateTime,
}

impl From<SwitchPortRow> for SwitchPort {
    fn from(row: SwitchPortRow) -> Self {
        SwitchPort {
            if_index: row.if_index,
            if_descr: row.if_descr,
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

/// Every port this switch has ever had a poll observe, ordered by
/// `if_index` -- what the traffic page lists.
pub async fn list_ports(pool: &DbPool, switch_id: Uuid) -> anyhow::Result<Vec<SwitchPort>> {
    let rows: Vec<SwitchPortRow> = sqlx::query_as(
        "SELECT if_index, if_descr, last_seen_at FROM panopticon_switch_ports \
         WHERE switch_id = ? ORDER BY if_index ASC",
    )
    .bind(switch_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
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
