//! Panopticon RADIUS decision records (0.2.9 Q2, `docs/roadmap/0.2.9.md`):
//! every admission decision with what it was based on, and the policy
//! engine's Simulate results.

use std::str::FromStr;

use abyssal_core::{EnforcementKind, PolicySimulation, RadiusDecisionRecord};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

/// Cuts `s` to at most `max` bytes on a character boundary, so a long
/// value can't make the insert fail (and with it the record).
fn cap(s: Option<&str>, max: usize) -> Option<String> {
    let s = s?;
    if s.len() <= max {
        return Some(s.to_string());
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Some(s[..end].to_string())
}

#[derive(FromRow)]
struct DecisionRow {
    id: String,
    decided_at: NaiveDateTime,
    mac_address: Option<String>,
    nas_client_id: Option<String>,
    nas_name: Option<String>,
    nas_address: Option<String>,
    front_end: String,
    admission: String,
    identity: Option<String>,
    outcome: String,
    vlan: Option<u16>,
    role: Option<String>,
    session_timeout: Option<u32>,
    reason: String,
    trust_state: Option<String>,
    enforcement: Option<String>,
    signal_action: Option<String>,
    signal_detail: Option<String>,
    group_rule: Option<String>,
    ad_groups: Option<String>,
}

impl From<DecisionRow> for RadiusDecisionRecord {
    fn from(r: DecisionRow) -> Self {
        RadiusDecisionRecord {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            decided_at: utc(r.decided_at),
            mac_address: r.mac_address,
            nas_client_id: r.nas_client_id.and_then(|s| Uuid::parse_str(&s).ok()),
            nas_name: r.nas_name,
            nas_address: r.nas_address,
            front_end: r.front_end,
            admission: r.admission,
            identity: r.identity,
            outcome: r.outcome,
            vlan: r.vlan,
            role: r.role,
            session_timeout: r.session_timeout,
            reason: r.reason,
            trust_state: r.trust_state,
            enforcement: r.enforcement,
            signal_action: r.signal_action,
            signal_detail: r.signal_detail,
            group_rule: r.group_rule,
            ad_groups: r.ad_groups,
        }
    }
}

/// Records one decision. Over-long values are cut to their column, never
/// rejected.
pub async fn insert(pool: &DbPool, d: &RadiusDecisionRecord) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_radius_decisions \
         (id, decided_at, mac_address, nas_client_id, nas_name, nas_address, front_end, \
          admission, identity, outcome, vlan, role, session_timeout, reason, trust_state, \
          enforcement, signal_action, signal_detail, group_rule, ad_groups) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(d.id.to_string())
    .bind(d.decided_at.naive_utc())
    .bind(cap(d.mac_address.as_deref(), 17))
    .bind(d.nas_client_id.map(|id| id.to_string()))
    .bind(cap(d.nas_name.as_deref(), 128))
    .bind(cap(d.nas_address.as_deref(), 64))
    .bind(cap(Some(&d.front_end), 16))
    .bind(cap(Some(&d.admission), 16))
    .bind(cap(d.identity.as_deref(), 255))
    .bind(cap(Some(&d.outcome), 8))
    .bind(d.vlan)
    .bind(cap(d.role.as_deref(), 64))
    .bind(d.session_timeout)
    .bind(cap(Some(&d.reason), 255))
    .bind(cap(d.trust_state.as_deref(), 16))
    .bind(cap(d.enforcement.as_deref(), 16))
    .bind(cap(d.signal_action.as_deref(), 16))
    .bind(cap(d.signal_detail.as_deref(), 512))
    .bind(cap(d.group_rule.as_deref(), 256))
    .bind(cap(d.ad_groups.as_deref(), 2000))
    .execute(pool)
    .await?;
    Ok(())
}

/// What the Decisions list is filtered by; `None` = any.
#[derive(Debug, Default, Clone)]
pub struct DecisionFilter {
    /// Lowercase colon form.
    pub mac: Option<String>,
    pub nas_client_id: Option<Uuid>,
    /// `accept` | `reject`
    pub outcome: Option<String>,
}

/// The newest decisions matching `filter`, at most `limit`.
pub async fn list(
    pool: &DbPool,
    filter: &DecisionFilter,
    limit: u32,
) -> anyhow::Result<Vec<RadiusDecisionRecord>> {
    let mut sql = String::from("SELECT * FROM panopticon_radius_decisions WHERE 1 = 1");
    if filter.mac.is_some() {
        sql.push_str(" AND mac_address = ?");
    }
    if filter.nas_client_id.is_some() {
        sql.push_str(" AND nas_client_id = ?");
    }
    if filter.outcome.is_some() {
        sql.push_str(" AND outcome = ?");
    }
    sql.push_str(" ORDER BY decided_at DESC LIMIT ?");
    let mut q = sqlx::query_as::<_, DecisionRow>(&sql);
    if let Some(mac) = &filter.mac {
        q = q.bind(mac.to_ascii_lowercase());
    }
    if let Some(id) = filter.nas_client_id {
        q = q.bind(id.to_string());
    }
    if let Some(o) = &filter.outcome {
        q = q.bind(o.clone());
    }
    let rows = q.bind(limit).fetch_all(pool).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Every decision since `since` for any of `macs` (lowercase colon form),
/// newest first, at most `limit`: what the sessions table picks each
/// session's decision from (`abyssal_core::decision_for_session`).
pub async fn for_macs_since(
    pool: &DbPool,
    macs: &[String],
    since: DateTime<Utc>,
    limit: u32,
) -> anyhow::Result<Vec<RadiusDecisionRecord>> {
    if macs.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; macs.len()].join(", ");
    let sql = format!(
        "SELECT * FROM panopticon_radius_decisions \
         WHERE mac_address IN ({placeholders}) AND decided_at >= ? \
         ORDER BY decided_at DESC LIMIT ?"
    );
    let mut q = sqlx::query_as::<_, DecisionRow>(&sql);
    for mac in macs {
        q = q.bind(mac.to_ascii_lowercase());
    }
    let rows = q
        .bind(since.naive_utc())
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// One MAC's newest decisions since `since`, at most `limit`.
pub async fn for_mac_since(
    pool: &DbPool,
    mac: &str,
    since: DateTime<Utc>,
    limit: u32,
) -> anyhow::Result<Vec<RadiusDecisionRecord>> {
    for_macs_since(pool, &[mac.to_string()], since, limit).await
}

/// Deletes decisions made before `cutoff`.
pub async fn prune_older_than(pool: &DbPool, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
    let r = sqlx::query("DELETE FROM panopticon_radius_decisions WHERE decided_at < ?")
        .bind(cutoff.naive_utc())
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

// ---- Policy simulation (Simulate mode, roadmap B6) ----

#[derive(FromRow)]
struct SimulationRow {
    rule_id: String,
    device_id: String,
    rule_name: String,
    device_ip: String,
    mac_address: Option<String>,
    action: String,
    path: String,
    detail: String,
    first_seen_at: NaiveDateTime,
    last_seen_at: NaiveDateTime,
    times_seen: u32,
}

impl SimulationRow {
    fn into_simulation(self) -> Option<PolicySimulation> {
        Some(PolicySimulation {
            rule_id: Uuid::parse_str(&self.rule_id).ok()?,
            device_id: Uuid::parse_str(&self.device_id).ok()?,
            rule_name: self.rule_name,
            device_ip: self.device_ip,
            mac_address: self.mac_address,
            action: EnforcementKind::from_str(&self.action).ok()?,
            path: self.path,
            detail: self.detail,
            first_seen_at: utc(self.first_seen_at),
            last_seen_at: utc(self.last_seen_at),
            times_seen: self.times_seen,
        })
    }
}

/// One simulated match: a new row, or the existing one for this rule and
/// device updated (path, detail, last seen, count).
#[allow(clippy::too_many_arguments)]
pub async fn record_simulation(
    pool: &DbPool,
    rule_id: Uuid,
    rule_name: &str,
    device_id: Uuid,
    device_ip: &str,
    mac_address: Option<&str>,
    action: EnforcementKind,
    path: &str,
    detail: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO panopticon_policy_simulations \
         (rule_id, device_id, rule_name, device_ip, mac_address, action, path, detail) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE rule_name = VALUES(rule_name), device_ip = VALUES(device_ip), \
           mac_address = VALUES(mac_address), action = VALUES(action), path = VALUES(path), \
           detail = VALUES(detail), last_seen_at = CURRENT_TIMESTAMP(6), \
           times_seen = times_seen + 1",
    )
    .bind(rule_id.to_string())
    .bind(device_id.to_string())
    .bind(cap(Some(rule_name), 128))
    .bind(cap(Some(device_ip), 45))
    .bind(cap(mac_address, 17))
    .bind(action.as_str())
    .bind(cap(Some(path), 16))
    .bind(cap(Some(detail), 512))
    .execute(pool)
    .await?;
    Ok(())
}

/// Simulated matches, most recently seen first, at most `limit`.
pub async fn list_simulations(pool: &DbPool, limit: u32) -> anyhow::Result<Vec<PolicySimulation>> {
    let rows: Vec<SimulationRow> = sqlx::query_as(
        "SELECT * FROM panopticon_policy_simulations ORDER BY last_seen_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(SimulationRow::into_simulation)
        .collect())
}

/// Forgets every simulated match (the policy page's "Clear").
pub async fn clear_simulations(pool: &DbPool) -> anyhow::Result<u64> {
    let r = sqlx::query("DELETE FROM panopticon_policy_simulations")
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

/// Deletes simulated matches last seen before `cutoff`.
pub async fn prune_simulations_older_than(
    pool: &DbPool,
    cutoff: DateTime<Utc>,
) -> anyhow::Result<u64> {
    let r = sqlx::query("DELETE FROM panopticon_policy_simulations WHERE last_seen_at < ?")
        .bind(cutoff.naive_utc())
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::cap;

    #[test]
    fn cap_cuts_on_a_character_boundary() {
        assert_eq!(cap(Some("abc"), 5).as_deref(), Some("abc"));
        assert_eq!(cap(Some("abcdef"), 3).as_deref(), Some("abc"));
        // "é" is two bytes: cutting at 2 would split it.
        assert_eq!(cap(Some("aé"), 2).as_deref(), Some("a"));
        assert_eq!(cap(None, 3), None);
    }
}
