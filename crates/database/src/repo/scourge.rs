//! Persistence for Scourge's bounded alert cache and per-host sensor state
//! (phase 3). The cache backs Scourge's own filterable live views only; the
//! collection sweep forwards qualifying alerts into Thanatos separately. Pruned
//! by age and a hard row cap -- never a history store.

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::{FromRow, QueryBuilder};
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

// ---- Alerts ----

#[derive(Debug, Clone)]
pub struct ScourgeAlert {
    pub id: Uuid,
    pub host_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub severity: String,
    pub sid: Option<u32>,
    pub signature: String,
    pub category: Option<String>,
    pub proto: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<u32>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u32>,
}

#[derive(FromRow)]
struct AlertRow {
    id: String,
    host_id: String,
    occurred_at: NaiveDateTime,
    severity: String,
    sid: Option<u32>,
    signature: String,
    category: Option<String>,
    proto: Option<String>,
    src_ip: Option<String>,
    src_port: Option<u32>,
    dst_ip: Option<String>,
    dst_port: Option<u32>,
}

impl From<AlertRow> for ScourgeAlert {
    fn from(r: AlertRow) -> Self {
        ScourgeAlert {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            host_id: Uuid::parse_str(&r.host_id).unwrap_or_default(),
            occurred_at: utc(r.occurred_at),
            severity: r.severity,
            sid: r.sid,
            signature: r.signature,
            category: r.category,
            proto: r.proto,
            src_ip: r.src_ip,
            src_port: r.src_port,
            dst_ip: r.dst_ip,
            dst_port: r.dst_port,
        }
    }
}

/// A new cached alert. `line_hash` is computed by the caller (the sweep) so the
/// database crate stays hashing-dependency-free; the UNIQUE index on it makes
/// re-inserts idempotent (a rotation-reset re-read never duplicates a row).
pub struct NewAlert<'a> {
    pub host_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub severity: &'a str,
    pub sid: Option<u32>,
    pub signature: &'a str,
    pub category: Option<&'a str>,
    pub proto: Option<&'a str>,
    pub src_ip: Option<&'a str>,
    pub src_port: Option<u32>,
    pub dst_ip: Option<&'a str>,
    pub dst_port: Option<u32>,
    pub line_hash: &'a str,
}

/// Inserts an alert, ignoring a duplicate `line_hash`. Returns whether a new row
/// was actually inserted.
pub async fn insert_alert(pool: &DbPool, a: &NewAlert<'_>) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "INSERT IGNORE INTO scourge_alerts \
         (id, host_id, occurred_at, severity, sid, signature, category, proto, \
          src_ip, src_port, dst_ip, dst_port, line_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(a.host_id.to_string())
    .bind(a.occurred_at.naive_utc())
    .bind(a.severity)
    .bind(a.sid)
    .bind(a.signature)
    .bind(a.category)
    .bind(a.proto)
    .bind(a.src_ip)
    .bind(a.src_port)
    .bind(a.dst_ip)
    .bind(a.dst_port)
    .bind(a.line_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Filters for the alert-inspection views. All optional; `None` = no constraint.
#[derive(Debug, Default, Clone)]
pub struct AlertFilter {
    pub host_id: Option<Uuid>,
    pub severity: Option<String>,
    /// Substring match on the signature.
    pub signature: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub port: Option<u32>,
    pub proto: Option<String>,
    pub category: Option<String>,
    /// Only alerts with `occurred_at >= since`.
    pub since: Option<DateTime<Utc>>,
}

/// Escapes `%` and `_` so a user-supplied substring is matched literally in a
/// `LIKE`. Mirrors the Thanatos event-search escaping.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn apply_filter<'a>(qb: &mut QueryBuilder<'a, sqlx::MySql>, f: &'a AlertFilter) {
    if let Some(host_id) = f.host_id {
        qb.push(" AND host_id = ").push_bind(host_id.to_string());
    }
    if let Some(sev) = &f.severity {
        qb.push(" AND severity = ").push_bind(sev.clone());
    }
    if let Some(sig) = &f.signature {
        qb.push(" AND signature LIKE ")
            .push_bind(format!("%{}%", escape_like(sig)))
            .push(" ESCAPE '\\\\'");
    }
    if let Some(ip) = &f.src_ip {
        qb.push(" AND src_ip = ").push_bind(ip.clone());
    }
    if let Some(ip) = &f.dst_ip {
        qb.push(" AND dst_ip = ").push_bind(ip.clone());
    }
    if let Some(port) = f.port {
        qb.push(" AND (src_port = ")
            .push_bind(port)
            .push(" OR dst_port = ")
            .push_bind(port)
            .push(")");
    }
    if let Some(proto) = &f.proto {
        qb.push(" AND proto = ").push_bind(proto.clone());
    }
    if let Some(cat) = &f.category {
        qb.push(" AND category = ").push_bind(cat.clone());
    }
    if let Some(since) = f.since {
        qb.push(" AND occurred_at >= ").push_bind(since.naive_utc());
    }
}

/// A page of matching alerts, newest first.
pub async fn list_alerts(
    pool: &DbPool,
    filter: &AlertFilter,
    limit: u32,
    offset: u32,
) -> anyhow::Result<Vec<ScourgeAlert>> {
    let mut qb = QueryBuilder::new(
        "SELECT id, host_id, occurred_at, severity, sid, signature, category, proto, \
         src_ip, src_port, dst_ip, dst_port FROM scourge_alerts WHERE 1=1",
    );
    apply_filter(&mut qb, filter);
    qb.push(" ORDER BY occurred_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows: Vec<AlertRow> = qb.build_query_as().fetch_all(pool).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn count_alerts(pool: &DbPool, filter: &AlertFilter) -> anyhow::Result<i64> {
    let mut qb = QueryBuilder::new("SELECT COUNT(*) FROM scourge_alerts WHERE 1=1");
    apply_filter(&mut qb, filter);
    let (count,): (i64,) = qb.build_query_as().fetch_one(pool).await?;
    Ok(count)
}

/// Count of matching alerts since a point in time -- the tile counters.
pub async fn count_since(
    pool: &DbPool,
    severity: Option<&str>,
    since: DateTime<Utc>,
) -> anyhow::Result<i64> {
    let filter = AlertFilter {
        severity: severity.map(str::to_string),
        since: Some(since),
        ..Default::default()
    };
    count_alerts(pool, &filter).await
}

/// `(severity, count)` breakdown for matching alerts.
pub async fn severity_breakdown(
    pool: &DbPool,
    filter: &AlertFilter,
) -> anyhow::Result<Vec<(String, i64)>> {
    let mut qb = QueryBuilder::new("SELECT severity, COUNT(*) AS c FROM scourge_alerts WHERE 1=1");
    apply_filter(&mut qb, filter);
    qb.push(" GROUP BY severity");
    let rows: Vec<(String, i64)> = qb.build_query_as().fetch_all(pool).await?;
    Ok(rows)
}

/// Top signatures by count for matching alerts.
pub async fn top_signatures(
    pool: &DbPool,
    filter: &AlertFilter,
    limit: u32,
) -> anyhow::Result<Vec<(String, i64)>> {
    let mut qb = QueryBuilder::new("SELECT signature, COUNT(*) AS c FROM scourge_alerts WHERE 1=1");
    apply_filter(&mut qb, filter);
    qb.push(" GROUP BY signature ORDER BY c DESC LIMIT ")
        .push_bind(limit);
    let rows: Vec<(String, i64)> = qb.build_query_as().fetch_all(pool).await?;
    Ok(rows)
}

/// Top source talkers by alert count for matching alerts (ignoring NULL src_ip).
pub async fn top_talkers(
    pool: &DbPool,
    filter: &AlertFilter,
    limit: u32,
) -> anyhow::Result<Vec<(String, i64)>> {
    let mut qb = QueryBuilder::new(
        "SELECT src_ip, COUNT(*) AS c FROM scourge_alerts WHERE src_ip IS NOT NULL",
    );
    apply_filter(&mut qb, filter);
    qb.push(" GROUP BY src_ip ORDER BY c DESC LIMIT ")
        .push_bind(limit);
    let rows: Vec<(String, i64)> = qb.build_query_as().fetch_all(pool).await?;
    Ok(rows)
}

/// Prunes alerts older than `days`; `0` disables age pruning. Returns the number
/// removed.
pub async fn prune_alerts_older_than(pool: &DbPool, days: i64) -> anyhow::Result<u64> {
    if days <= 0 {
        return Ok(0);
    }
    let result =
        sqlx::query("DELETE FROM scourge_alerts WHERE occurred_at < (NOW() - INTERVAL ? DAY)")
            .bind(days)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

/// Enforces a hard row cap: deletes the oldest alerts beyond `max_rows`, so the
/// cache can't grow unbounded between age-prunes (or when age pruning is off).
pub async fn enforce_row_cap(pool: &DbPool, max_rows: u64) -> anyhow::Result<u64> {
    // Keep the newest `max_rows`; delete everything older than the cap boundary.
    // Done as a correlated delete against the cutoff row's timestamp to avoid a
    // giant IN-list.
    let result = sqlx::query(
        "DELETE FROM scourge_alerts WHERE id NOT IN ( \
             SELECT id FROM ( \
                 SELECT id FROM scourge_alerts ORDER BY occurred_at DESC LIMIT ? \
             ) AS keep )",
    )
    .bind(max_rows)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// ---- Per-host sensor state / EVE cursor ----

#[derive(Debug, Clone)]
pub struct SensorState {
    pub host_id: Uuid,
    pub eve_inode: u64,
    pub eve_offset: u64,
    pub eve_readable: bool,
    pub last_error: Option<String>,
    pub last_collected_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct SensorStateRow {
    host_id: String,
    eve_inode: u64,
    eve_offset: u64,
    eve_readable: bool,
    last_error: Option<String>,
    last_collected_at: Option<NaiveDateTime>,
}

impl From<SensorStateRow> for SensorState {
    fn from(r: SensorStateRow) -> Self {
        SensorState {
            host_id: Uuid::parse_str(&r.host_id).unwrap_or_default(),
            eve_inode: r.eve_inode,
            eve_offset: r.eve_offset,
            eve_readable: r.eve_readable,
            last_error: r.last_error,
            last_collected_at: r.last_collected_at.map(utc),
        }
    }
}

/// The host's EVE read cursor `(inode, offset)`, or `(0, 0)` if never collected.
pub async fn get_cursor(pool: &DbPool, host_id: Uuid) -> anyhow::Result<(u64, u64)> {
    let row: Option<(u64, u64)> =
        sqlx::query_as("SELECT eve_inode, eve_offset FROM scourge_sensor_state WHERE host_id = ?")
            .bind(host_id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(row.unwrap_or((0, 0)))
}

/// Advances the cursor after a successful collection and marks the EVE log
/// readable.
pub async fn record_cursor(
    pool: &DbPool,
    host_id: Uuid,
    inode: u64,
    offset: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO scourge_sensor_state \
         (host_id, eve_inode, eve_offset, eve_readable, last_error, last_collected_at) \
         VALUES (?, ?, ?, 1, NULL, CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE \
             eve_inode = VALUES(eve_inode), \
             eve_offset = VALUES(eve_offset), \
             eve_readable = 1, \
             last_error = NULL, \
             last_collected_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(host_id.to_string())
    .bind(inode)
    .bind(offset)
    .execute(pool)
    .await?;
    Ok(())
}

/// Marks the host's EVE log unreadable with a reason, leaving the cursor
/// untouched. Shown on the page/tiles as a clear "needs permissions" state.
pub async fn set_eve_unreadable(pool: &DbPool, host_id: Uuid, reason: &str) -> anyhow::Result<()> {
    let reason = &reason.chars().take(512).collect::<String>();
    sqlx::query(
        "INSERT INTO scourge_sensor_state \
         (host_id, eve_readable, last_error, last_collected_at) \
         VALUES (?, 0, ?, CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE \
             eve_readable = 0, \
             last_error = VALUES(last_error), \
             last_collected_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(host_id.to_string())
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_sensor_state(pool: &DbPool) -> anyhow::Result<Vec<SensorState>> {
    let rows: Vec<SensorStateRow> = sqlx::query_as("SELECT * FROM scourge_sensor_state")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// How many hosts currently have an unreadable EVE log -- a tile counter.
pub async fn count_unreadable(pool: &DbPool) -> anyhow::Result<i64> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM scourge_sensor_state WHERE eve_readable = 0")
            .fetch_one(pool)
            .await?;
    Ok(count)
}
