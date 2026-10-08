//! Persistence for Panopticon NAC enforcement actions (phase 3). Rows are
//! append-mostly: an action is created `Active` (or `ApplyFailed`), then only
//! ever transitions state -- never deleted -- so the table doubles as an
//! enforcement history. The orchestration that pairs these writes with the
//! actual SNMP SETs lives in `abyssal_web::panopticon_enforcement`.

use abyssal_core::{EnforcementAction, EnforcementKind, EnforcementState};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(FromRow)]
struct ActionRow {
    id: String,
    switch_id: String,
    switch_name: String,
    if_index: u32,
    port_label: String,
    kind: String,
    state: String,
    original_admin_status: Option<i64>,
    original_pvid: Option<i64>,
    quarantine_vlan: Option<i64>,
    reason: Option<String>,
    created_by: Option<String>,
    created_by_username: Option<String>,
    created_at: NaiveDateTime,
    expires_at: Option<NaiveDateTime>,
    reverted_at: Option<NaiveDateTime>,
    last_error: Option<String>,
}

impl From<ActionRow> for EnforcementAction {
    fn from(r: ActionRow) -> Self {
        EnforcementAction {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            switch_id: Uuid::parse_str(&r.switch_id).unwrap_or_default(),
            switch_name: r.switch_name,
            if_index: r.if_index,
            port_label: r.port_label,
            kind: r.kind.parse().unwrap_or(EnforcementKind::Disable),
            state: r.state.parse().unwrap_or(EnforcementState::Active),
            original_admin_status: r.original_admin_status,
            original_pvid: r.original_pvid,
            quarantine_vlan: r.quarantine_vlan,
            reason: r.reason,
            created_by: r.created_by.and_then(|s| Uuid::parse_str(&s).ok()),
            created_by_username: r.created_by_username,
            created_at: utc(r.created_at),
            expires_at: r.expires_at.map(utc),
            reverted_at: r.reverted_at.map(utc),
            last_error: r.last_error,
        }
    }
}

/// Everything needed to persist a brand-new action. Grouped into a struct
/// rather than a long positional argument list, since the orchestration layer
/// fills these from a mix of the switch, the port, and the operator's input.
pub struct NewAction<'a> {
    pub switch_id: Uuid,
    pub switch_name: &'a str,
    pub if_index: u32,
    pub port_label: &'a str,
    pub kind: EnforcementKind,
    pub state: EnforcementState,
    pub original_admin_status: Option<i64>,
    pub original_pvid: Option<i64>,
    pub quarantine_vlan: Option<i64>,
    pub reason: Option<&'a str>,
    pub created_by: Option<Uuid>,
    pub created_by_username: Option<&'a str>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_error: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create(pool: &DbPool, new: &NewAction<'_>) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO panopticon_enforcement_actions \
         (id, switch_id, switch_name, if_index, port_label, kind, state, \
          original_admin_status, original_pvid, quarantine_vlan, reason, \
          created_by, created_by_username, expires_at, last_error) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(new.switch_id.to_string())
    .bind(new.switch_name)
    .bind(new.if_index)
    .bind(new.port_label)
    .bind(new.kind.as_str())
    .bind(new.state.as_str())
    .bind(new.original_admin_status)
    .bind(new.original_pvid)
    .bind(new.quarantine_vlan)
    .bind(new.reason)
    .bind(new.created_by.map(|u| u.to_string()))
    .bind(new.created_by_username)
    .bind(new.expires_at.map(|t| t.naive_utc()))
    .bind(new.last_error)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<EnforcementAction>> {
    let row: Option<ActionRow> =
        sqlx::query_as("SELECT * FROM panopticon_enforcement_actions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(row.map(Into::into))
}

/// The in-effect action for a port, if any -- used to block stacking a second
/// enforcement on an already-enforced port, and to find what to release. An
/// `Active` or `RevertFailed` row counts as in-effect; terminal rows don't.
pub async fn find_in_effect_for_port(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
) -> anyhow::Result<Option<EnforcementAction>> {
    let row: Option<ActionRow> = sqlx::query_as(
        "SELECT * FROM panopticon_enforcement_actions \
         WHERE switch_id = ? AND if_index = ? AND state IN ('active', 'revert_failed') \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Every in-effect action across all switches, newest first -- what the
/// enforcement dashboard lists and the Ports page cross-references.
pub async fn list_in_effect(pool: &DbPool) -> anyhow::Result<Vec<EnforcementAction>> {
    let rows: Vec<ActionRow> = sqlx::query_as(
        "SELECT * FROM panopticon_enforcement_actions \
         WHERE state IN ('active', 'revert_failed') ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// In-effect actions on one switch, keyed later by `if_index` to decorate the
/// Ports page.
pub async fn list_in_effect_for_switch(
    pool: &DbPool,
    switch_id: Uuid,
) -> anyhow::Result<Vec<EnforcementAction>> {
    let rows: Vec<ActionRow> = sqlx::query_as(
        "SELECT * FROM panopticon_enforcement_actions \
         WHERE switch_id = ? AND state IN ('active', 'revert_failed') \
         ORDER BY created_at DESC",
    )
    .bind(switch_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Recent actions regardless of state, for the history view (capped).
pub async fn list_recent(pool: &DbPool, limit: u32) -> anyhow::Result<Vec<EnforcementAction>> {
    let rows: Vec<ActionRow> = sqlx::query_as(
        "SELECT * FROM panopticon_enforcement_actions ORDER BY created_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// The auto-revert sweep's work list: timed `Active` actions whose `expires_at`
/// has arrived, plus every `RevertFailed` action regardless of timeout. The
/// latter are always included so a revert that didn't take (including a failed
/// *manual* release of a permanent action) keeps being retried until it sticks
/// -- a failed revert must never silently strand a port.
pub async fn list_due_for_revert(
    pool: &DbPool,
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<EnforcementAction>> {
    let rows: Vec<ActionRow> = sqlx::query_as(
        "SELECT * FROM panopticon_enforcement_actions \
         WHERE (state = 'active' AND expires_at IS NOT NULL AND expires_at <= ?) \
            OR state = 'revert_failed' \
         ORDER BY expires_at ASC",
    )
    .bind(now.naive_utc())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Whether any enforcement action (in any state) was created for this port at
/// or after `since`. The NAC policy engine uses this as a cooldown: it won't
/// re-enforce a port that was recently acted on -- which is what makes an
/// operator's manual release of a policy-applied action "stick" instead of the
/// next sweep immediately re-applying it.
pub async fn has_recent_action_for_port(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    since: DateTime<Utc>,
) -> anyhow::Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM panopticon_enforcement_actions \
         WHERE switch_id = ? AND if_index = ? AND created_at >= ?",
    )
    .bind(switch_id.to_string())
    .bind(if_index)
    .bind(since.naive_utc())
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// Clears an action's auto-revert timeout, making it permanent (stays in
/// effect until manually released). Only meaningful on an in-effect row.
pub async fn make_permanent(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_enforcement_actions SET expires_at = NULL \
         WHERE id = ? AND state IN ('active', 'revert_failed')",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Transitions an action to a terminal/updated state after a revert attempt.
/// On success pass `EnforcementState::Reverted` and `error = None` (stamps
/// `reverted_at`); on a failed revert pass `RevertFailed` and the error, which
/// leaves the action in-effect so the sweep retries it.
pub async fn mark_reverted(
    pool: &DbPool,
    id: Uuid,
    state: EnforcementState,
    error: Option<&str>,
) -> anyhow::Result<()> {
    // Only stamp reverted_at on a successful revert.
    let reverted_at = (state == EnforcementState::Reverted).then(Utc::now);
    sqlx::query(
        "UPDATE panopticon_enforcement_actions \
         SET state = ?, reverted_at = ?, last_error = ? WHERE id = ?",
    )
    .bind(state.as_str())
    .bind(reverted_at.map(|t| t.naive_utc()))
    .bind(error)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}
