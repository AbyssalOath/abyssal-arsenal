use std::collections::HashMap;

use abyssal_core::security_event::hash_event_line;
use abyssal_core::{EventStatus, SecurityEvent, Severity};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct SecurityEventRow {
    id: String,
    host_id: String,
    source: String,
    severity: String,
    label: String,
    technique: String,
    raw_line: String,
    occurred_at: NaiveDateTime,
    status: String,
    acknowledged_by: Option<String>,
    acknowledged_at: Option<NaiveDateTime>,
    resolution_note: Option<String>,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<SecurityEventRow> for SecurityEvent {
    fn from(row: SecurityEventRow) -> Self {
        SecurityEvent {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            host_id: Uuid::parse_str(&row.host_id).unwrap_or_default(),
            source: row.source,
            // A row with a severity/status key this build doesn't
            // recognize (e.g. rolled back to an older binary after a
            // newer one wrote data) falls back to a safe default rather
            // than failing the whole query -- one mislabeled row is far
            // better than the entire event log becoming unreadable.
            severity: Severity::from_key(&row.severity).unwrap_or(Severity::Low),
            label: row.label,
            technique: row.technique,
            raw_line: row.raw_line,
            occurred_at: utc(row.occurred_at),
            status: EventStatus::from_key(&row.status).unwrap_or_default(),
            acknowledged_by: row.acknowledged_by.and_then(|s| Uuid::parse_str(&s).ok()),
            acknowledged_at: row.acknowledged_at.map(utc),
            resolution_note: row.resolution_note,
        }
    }
}

/// `only_active`, when true, restricts a query to `status IN ('open',
/// 'acknowledged')` -- the default "hide settled events" view every
/// Thanatos list uses; `false` shows everything including resolved/
/// suppressed events, the explicit "show all" toggle.
fn status_clause(only_active: bool) -> &'static str {
    if only_active {
        " AND status IN ('open', 'acknowledged')"
    } else {
        ""
    }
}

/// Inserts one classified event, deduplicating on content hash --
/// re-scanning the same log tail window on every sweep produces the same
/// hash and is silently ignored, not a duplicate row. Returns whether this
/// call actually inserted a new row (`rows_affected() == 1` for a real
/// insert, `0` when `INSERT IGNORE` skipped a duplicate).
pub async fn insert_if_new(
    pool: &DbPool,
    host_id: Uuid,
    source: &str,
    severity: Severity,
    label: &str,
    technique: &str,
    raw_line: &str,
) -> anyhow::Result<bool> {
    let hash = hash_event_line(host_id, source, raw_line);
    let result = sqlx::query(
        "INSERT IGNORE INTO thanatos_events (id, host_id, line_hash, source, severity, label, technique, raw_line) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(host_id.to_string())
    .bind(hash)
    .bind(source)
    .bind(severity.as_key())
    .bind(label)
    .bind(technique)
    .bind(raw_line)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_recent_for_host(
    pool: &DbPool,
    host_id: Uuid,
    limit: i64,
    only_active: bool,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let sql = format!(
        "SELECT * FROM thanatos_events WHERE host_id = ?{} \
         ORDER BY occurred_at DESC LIMIT ?",
        status_clause(only_active)
    );
    let rows: Vec<SecurityEventRow> = sqlx::query_as(&sql)
        .bind(host_id.to_string())
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// One page of a single host's event history, numerically offset --
/// backs the Thanatos fleet dashboard's per-host collapsible group rows
/// (Panopticon-style grouped+paginated pattern, keyed by host instead of
/// by subnet). `only_active` -- see `status_clause`.
pub async fn list_page_for_host(
    pool: &DbPool,
    host_id: Uuid,
    limit: i64,
    offset: i64,
    only_active: bool,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let sql = format!(
        "SELECT * FROM thanatos_events WHERE host_id = ?{} \
         ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
        status_clause(only_active)
    );
    let rows: Vec<SecurityEventRow> = sqlx::query_as(&sql)
        .bind(host_id.to_string())
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Every listed host's total event count in one aggregate query -- the
/// fleet dashboard's group headers, always rendered regardless of which
/// groups are open, never one `COUNT(*)` per host (no N+1, same reasoning
/// as Panopticon's `group_counts`). A host with zero events is simply
/// absent from the returned map rather than present with `0`. `only_active`
/// -- see `status_clause`; kept consistent with whatever a group's own
/// (also `only_active`-filtered) body would show.
pub async fn count_for_hosts(
    pool: &DbPool,
    host_ids: &[Uuid],
    only_active: bool,
) -> anyhow::Result<HashMap<Uuid, i64>> {
    if host_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = vec!["?"; host_ids.len()].join(",");
    let sql = format!(
        "SELECT host_id, COUNT(*) FROM thanatos_events WHERE host_id IN ({placeholders}){} \
         GROUP BY host_id",
        status_clause(only_active)
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&sql);
    for id in host_ids {
        q = q.bind(id.to_string());
    }
    let rows = q.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, count)| Some((Uuid::parse_str(&id).ok()?, count)))
        .collect())
}

/// Correlation-raised findings across every host, most recent first --
/// the "alerts" view. `only_active` -- see `status_clause`.
pub async fn list_recent_alerts(
    pool: &DbPool,
    limit: i64,
    only_active: bool,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let sql = format!(
        "SELECT * FROM thanatos_events WHERE source = 'correlation'{} \
         ORDER BY occurred_at DESC LIMIT ?",
        status_clause(only_active)
    );
    let rows: Vec<SecurityEventRow> = sqlx::query_as(&sql).bind(limit).fetch_all(pool).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// How many correlation alerts have been raised across the fleet in the
/// last `hours` -- the dashboard's "open Thanatos alerts" count. Always
/// `only_active` (an already-resolved alert shouldn't keep counting
/// toward "how many need attention right now") -- unlike the list views
/// above, this one has no "show all" toggle to respect.
pub async fn count_recent_alerts(pool: &DbPool, hours: i64) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM thanatos_events \
         WHERE source = 'correlation' AND occurred_at >= NOW() - INTERVAL ? HOUR \
           AND status IN ('open', 'acknowledged')",
    )
    .bind(hours)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Looks up one event by id -- the acknowledge/resolve/suppress routes'
/// existence check before mutating.
pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<SecurityEvent>> {
    let row: Option<SecurityEventRow> =
        sqlx::query_as("SELECT * FROM thanatos_events WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(row.map(Into::into))
}

/// Moves one event to a new lifecycle status -- acknowledge/resolve/
/// suppress all go through this one setter, differing only in which
/// `EventStatus` and whether a `resolution_note` is attached (a plain
/// acknowledge never carries one). `acknowledged_by`/`acknowledged_at`
/// are overwritten on every call, not just the first -- they track *who
/// last changed the status*, not who first touched it. Returns whether a
/// row actually matched `id`.
pub async fn set_status(
    pool: &DbPool,
    id: Uuid,
    status: EventStatus,
    acknowledged_by: Uuid,
    resolution_note: Option<&str>,
) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE thanatos_events \
         SET status = ?, acknowledged_by = ?, acknowledged_at = CURRENT_TIMESTAMP(6), \
             resolution_note = ? \
         WHERE id = ?",
    )
    .bind(status.as_key())
    .bind(acknowledged_by.to_string())
    .bind(resolution_note)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Every `(host_id, raw_line)` pair for `high`/`critical` events (excluding
/// past correlation findings) across **every** host in the last `minutes`
/// -- the cross-host correlation check's input (Thanatos SIEM/EDR
/// build-out, Phase 2): a source IP hammering several distinct
/// hosts at once is a lateral-movement/credential-stuffing signal a
/// per-host threshold alone can't see. Fleet-wide by design, unlike
/// `count_high_severity_since` -- kept as a separate query rather than a
/// parameter on that one, since the two callers need genuinely different
/// shapes (a count for one host vs. raw lines across all of them).
pub async fn list_recent_high_severity_all_hosts(
    pool: &DbPool,
    minutes: i64,
) -> anyhow::Result<Vec<(Uuid, String)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT host_id, raw_line FROM thanatos_events \
         WHERE source != 'correlation' AND severity IN ('high', 'critical') \
           AND occurred_at > (NOW() - INTERVAL ? MINUTE)",
    )
    .bind(minutes)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, raw_line)| Some((Uuid::parse_str(&id).ok()?, raw_line)))
        .collect())
}

/// How many `high`/`critical` events a host has logged (excluding its own
/// past correlation findings, which shouldn't feed back into triggering
/// new ones) in the last `minutes` -- the threshold check a correlation
/// sweep runs per host.
pub async fn count_high_severity_since(
    pool: &DbPool,
    host_id: Uuid,
    minutes: i64,
) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM thanatos_events \
         WHERE host_id = ? AND source != 'correlation' \
           AND severity IN ('high', 'critical') \
           AND occurred_at > (NOW() - INTERVAL ? MINUTE)",
    )
    .bind(host_id.to_string())
    .bind(minutes)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// The correlation sweep's own cooldown check: has this host already had
/// a correlation finding raised in the last `minutes`? Prevents one
/// ongoing burst from generating a fresh alert on every sweep tick.
pub async fn has_recent_correlation_event(
    pool: &DbPool,
    host_id: Uuid,
    minutes: i64,
) -> anyhow::Result<bool> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM thanatos_events \
         WHERE host_id = ? AND source = 'correlation' \
           AND occurred_at > (NOW() - INTERVAL ? MINUTE)",
    )
    .bind(host_id.to_string())
    .bind(minutes)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// Filters for the cross-host investigation console (M3). Every field is
/// optional/additive: an unset field doesn't constrain the query. `text` is a
/// substring match over `raw_line` and `label` (so it serves as the pivot for a
/// source IP, username, process name, pipe name, etc. -- whatever appears in
/// the finding). `only_active` hides resolved/suppressed events unless `false`.
#[derive(Default)]
pub struct EventSearchFilter {
    pub host_id: Option<Uuid>,
    pub source: Option<String>,
    pub severity: Option<Severity>,
    pub technique: Option<String>,
    pub text: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub only_active: bool,
}

/// Escapes a user-supplied `LIKE` operand so `%`/`_`/`\` in it match literally
/// rather than acting as wildcards (default `\` escape char).
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn push_search_filters<'a>(qb: &mut sqlx::QueryBuilder<'a, sqlx::MySql>, f: &'a EventSearchFilter) {
    if let Some(host_id) = f.host_id {
        qb.push(" AND host_id = ").push_bind(host_id.to_string());
    }
    if let Some(source) = &f.source {
        qb.push(" AND source = ").push_bind(source.clone());
    }
    if let Some(severity) = f.severity {
        qb.push(" AND severity = ").push_bind(severity.as_key());
    }
    if let Some(technique) = &f.technique {
        qb.push(" AND technique = ").push_bind(technique.clone());
    }
    if let Some(text) = &f.text {
        let like = format!("%{}%", escape_like(text));
        qb.push(" AND (raw_line LIKE ")
            .push_bind(like.clone())
            .push(" OR label LIKE ")
            .push_bind(like)
            .push(")");
    }
    if let Some(from) = f.from {
        qb.push(" AND occurred_at >= ").push_bind(from.naive_utc());
    }
    if let Some(to) = f.to {
        qb.push(" AND occurred_at <= ").push_bind(to.naive_utc());
    }
    if f.only_active {
        qb.push(" AND status IN ('open', 'acknowledged')");
    }
}

/// One page of the investigation console's results -- every matching event
/// across the fleet, newest first. `limit`/`offset` paginate; `count_events`
/// gives the total for the pager.
pub async fn search_events(
    pool: &DbPool,
    filter: &EventSearchFilter,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<SecurityEvent>> {
    let mut qb =
        sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT * FROM thanatos_events WHERE 1 = 1");
    push_search_filters(&mut qb, filter);
    qb.push(" ORDER BY occurred_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows: Vec<SecurityEventRow> = qb.build_query_as().fetch_all(pool).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Total number of events matching a search filter -- the investigation
/// console's result count and pager denominator.
pub async fn count_events(pool: &DbPool, filter: &EventSearchFilter) -> anyhow::Result<i64> {
    let mut qb =
        sqlx::QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM thanatos_events WHERE 1 = 1");
    push_search_filters(&mut qb, filter);
    let count: i64 = qb.build_query_scalar().fetch_one(pool).await?;
    Ok(count)
}

/// Distinct `source` values present in the event log -- populates the
/// investigation console's source filter dropdown.
pub async fn distinct_sources(pool: &DbPool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT source FROM thanatos_events ORDER BY source")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

/// Distinct non-empty `technique` values present -- the console's technique
/// filter dropdown.
pub async fn distinct_techniques(pool: &DbPool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT technique FROM thanatos_events WHERE technique <> '' ORDER BY technique",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

/// Deletes events older than `days` days -- the retention sweep
/// (`thanatos_ops::spawn_thanatos_retention`). Returns how many rows were
/// pruned. Age-based only, by design: retention is a data-lifecycle policy, so
/// it prunes strictly by `occurred_at` regardless of an event's status or
/// source (including correlation findings). Caller guards `days <= 0` (disabled).
pub async fn prune_older_than(pool: &DbPool, days: i64) -> anyhow::Result<u64> {
    let result =
        sqlx::query("DELETE FROM thanatos_events WHERE occurred_at < (NOW() - INTERVAL ? DAY)")
            .bind(days)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

/// Fleet-wide event counts by severity in the last `hours` -- the
/// landing page's summary row.
pub async fn count_by_severity_since(
    pool: &DbPool,
    hours: i64,
) -> anyhow::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*) FROM thanatos_events \
         WHERE occurred_at > (NOW() - INTERVAL ? HOUR) \
         GROUP BY severity",
    )
    .bind(hours)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
