//! Persistence for Panopticon NAC auto-enforcement policy rules (phase 4).
//! Ordered by `priority`; the policy sweep (`abyssal_web::panopticon_policy`)
//! evaluates enabled rules in ascending priority and acts on the first match.

use abyssal_core::{DeviceType, EnforcementKind, PolicyRule, PolicyTrigger};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use std::str::FromStr;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(FromRow)]
struct RuleRow {
    id: String,
    priority: i32,
    name: String,
    enabled: bool,
    trigger_kind: String,
    action: String,
    subnet: Option<String>,
    switch_id: Option<String>,
    device_type: Option<String>,
    timeout_minutes: Option<u32>,
    created_by: Option<String>,
    created_at: NaiveDateTime,
}

impl From<RuleRow> for PolicyRule {
    fn from(r: RuleRow) -> Self {
        PolicyRule {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            priority: r.priority,
            name: r.name,
            enabled: r.enabled,
            trigger: r.trigger_kind.parse().unwrap_or(PolicyTrigger::Untrusted),
            action: r.action.parse().unwrap_or(EnforcementKind::Quarantine),
            subnet: r.subnet,
            switch_id: r.switch_id.and_then(|s| Uuid::parse_str(&s).ok()),
            device_type: r
                .device_type
                .as_deref()
                .and_then(|s| DeviceType::from_str(s).ok()),
            timeout_minutes: r.timeout_minutes,
            created_by: r.created_by.and_then(|s| Uuid::parse_str(&s).ok()),
            created_at: utc(r.created_at),
        }
    }
}

/// Fields for creating a rule. `priority` is assigned by `create` (appended to
/// the end), not supplied here.
pub struct NewRule<'a> {
    pub name: &'a str,
    pub trigger: PolicyTrigger,
    pub action: EnforcementKind,
    pub subnet: Option<&'a str>,
    pub switch_id: Option<Uuid>,
    pub device_type: Option<DeviceType>,
    pub timeout_minutes: Option<u32>,
    pub created_by: Option<Uuid>,
}

/// Creates a rule at the end of the list (highest priority number, so it's
/// evaluated last until reordered).
pub async fn create(pool: &DbPool, new: &NewRule<'_>) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    let next_priority: i32 =
        sqlx::query_scalar("SELECT COALESCE(MAX(priority), 0) + 1 FROM panopticon_policy_rules")
            .fetch_one(pool)
            .await?;
    sqlx::query(
        "INSERT INTO panopticon_policy_rules \
         (id, priority, name, enabled, trigger_kind, action, subnet, switch_id, \
          device_type, timeout_minutes, created_by) \
         VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(next_priority)
    .bind(new.name)
    .bind(new.trigger.as_str())
    .bind(new.action.as_str())
    .bind(new.subnet)
    .bind(new.switch_id.map(|u| u.to_string()))
    .bind(new.device_type.map(|d| d.as_str()))
    .bind(new.timeout_minutes)
    .bind(new.created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

/// All rules, ascending priority (evaluation order) -- what both the policy
/// sweep and the management page use.
pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<PolicyRule>> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT * FROM panopticon_policy_rules ORDER BY priority ASC, created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Only enabled rules, ascending priority -- the sweep's working set.
pub async fn list_enabled(pool: &DbPool) -> anyhow::Result<Vec<PolicyRule>> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT * FROM panopticon_policy_rules WHERE enabled = TRUE \
         ORDER BY priority ASC, created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<PolicyRule>> {
    let row: Option<RuleRow> = sqlx::query_as("SELECT * FROM panopticon_policy_rules WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn set_enabled(pool: &DbPool, id: Uuid, enabled: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE panopticon_policy_rules SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM panopticon_policy_rules WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Swaps one rule's priority with its neighbor in the given direction, moving it
/// up (earlier) or down (later) in evaluation order. A no-op if there's no
/// neighbor that way. Done in a transaction so the two rows never collide.
pub async fn reorder(pool: &DbPool, id: Uuid, move_up: bool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let Some(this): Option<RuleRow> =
        sqlx::query_as("SELECT * FROM panopticon_policy_rules WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(());
    };
    // The adjacent rule on the chosen side (the greatest priority below it when
    // moving up, or the least priority above it when moving down).
    let neighbor: Option<RuleRow> = if move_up {
        sqlx::query_as(
            "SELECT * FROM panopticon_policy_rules WHERE priority < ? \
             ORDER BY priority DESC LIMIT 1",
        )
        .bind(this.priority)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query_as(
            "SELECT * FROM panopticon_policy_rules WHERE priority > ? \
             ORDER BY priority ASC LIMIT 1",
        )
        .bind(this.priority)
        .fetch_optional(&mut *tx)
        .await?
    };
    if let Some(neighbor) = neighbor {
        sqlx::query("UPDATE panopticon_policy_rules SET priority = ? WHERE id = ?")
            .bind(neighbor.priority)
            .bind(&this.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE panopticon_policy_rules SET priority = ? WHERE id = ?")
            .bind(this.priority)
            .bind(&neighbor.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
