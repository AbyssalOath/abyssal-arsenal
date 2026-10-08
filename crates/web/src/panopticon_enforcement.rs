//! Panopticon NAC enforcement orchestration (phase 3) -- the layer that pairs
//! the SNMP SET primitives in `panopticon_snmp` with persistence, gating, and
//! the audit trail. Everything that *writes* to a switch funnels through
//! `apply`/`release` here so the three safety gates (global kill-switch,
//! per-switch opt-in, operator permission) and the audit record can never be
//! bypassed by a route calling the SNMP layer directly.
//!
//! The permission check (`network.manage`) is the caller's responsibility (the
//! route does it before building a request); this module enforces the other two
//! gates and owns the snapshot -> persist -> SET -> schedule-revert flow and the
//! background auto-revert sweep.

use std::sync::Arc;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    PANOPTICON_ENFORCEMENT_ENABLED, PANOPTICON_QUARANTINE_VLAN, PANOPTICON_QUARANTINE_VLAN_DEFAULT,
};
use abyssal_core::{EncryptionKey, EnforcementAction, EnforcementKind, EnforcementState};
use abyssal_database::{DbPool, repo};
use chrono::{Duration, Utc};
use uuid::Uuid;

/// Why an enforcement request was refused before (or while) touching the
/// switch. Separated from a bare string so the route can map each to the right
/// user-facing message and HTTP treatment.
#[derive(Debug)]
pub enum EnforceError {
    /// The global `panopticon.enforcement_enabled` kill-switch is off.
    GloballyDisabled,
    /// This switch hasn't been opted into enforcement.
    SwitchNotOptedIn,
    /// No `ENCRYPTION_KEY`, so the switch's SNMP credentials can't be decrypted.
    NoEncryptionKey,
    /// A quarantine was requested but no quarantine VLAN is configured.
    QuarantineVlanUnset,
    /// The port already has an in-effect action; release it before re-enforcing.
    AlreadyEnforced,
    /// The SNMP SET itself failed (unreachable, read-only community, rejected).
    /// The port was not changed (or may be partially changed for quarantine);
    /// an `ApplyFailed` row is recorded either way.
    Snmp(String),
    /// A database error persisting the action.
    Db(String),
}

impl std::fmt::Display for EnforceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforceError::GloballyDisabled => write!(
                f,
                "NAC enforcement is globally disabled -- turn it on in Settings first."
            ),
            EnforceError::SwitchNotOptedIn => write!(
                f,
                "This switch isn't opted into enforcement -- enable it on the switch's settings \
                 (and make sure its stored SNMP credentials have write access) first."
            ),
            EnforceError::NoEncryptionKey => write!(
                f,
                "ENCRYPTION_KEY isn't configured -- this switch's SNMP credentials can't be \
                 decrypted, so enforcement can't reach it."
            ),
            EnforceError::QuarantineVlanUnset => write!(
                f,
                "No quarantine VLAN is configured -- set one in Settings before quarantining a \
                 port."
            ),
            EnforceError::AlreadyEnforced => write!(
                f,
                "This port already has an active enforcement action -- release it before applying \
                 another."
            ),
            EnforceError::Snmp(msg) => write!(f, "The switch rejected the change: {msg}"),
            EnforceError::Db(msg) => write!(f, "Database error: {msg}"),
        }
    }
}

/// Who/what initiated an enforcement action -- an operator clicking the UI, or
/// the NAC policy engine acting on a matched rule. Drives both attribution
/// (`created_by`) and the audit trail's `by`/`rule` metadata.
pub enum EnforceOrigin {
    Operator { id: Uuid, username: String },
    Policy { rule_name: String },
}

impl EnforceOrigin {
    fn created_by(&self) -> Option<Uuid> {
        match self {
            EnforceOrigin::Operator { id, .. } => Some(*id),
            EnforceOrigin::Policy { .. } => None,
        }
    }

    fn created_by_username(&self) -> Option<&str> {
        match self {
            EnforceOrigin::Operator { username, .. } => Some(username.as_str()),
            EnforceOrigin::Policy { .. } => None,
        }
    }

    fn key(&self) -> &'static str {
        match self {
            EnforceOrigin::Operator { .. } => "operator",
            EnforceOrigin::Policy { .. } => "policy",
        }
    }

    fn rule_name(&self) -> Option<&str> {
        match self {
            EnforceOrigin::Policy { rule_name } => Some(rule_name.as_str()),
            EnforceOrigin::Operator { .. } => None,
        }
    }
}

/// A request to enforce against one port. Built by the route (operator) or the
/// policy sweep (policy); `origin` determines attribution.
pub struct EnforceRequest {
    pub switch: abyssal_core::PanopticonSwitch,
    pub if_index: u32,
    pub port_label: String,
    pub kind: EnforcementKind,
    pub reason: Option<String>,
    /// Minutes until auto-revert; `0` means permanent (no timeout).
    pub timeout_minutes: u32,
    pub origin: EnforceOrigin,
}

/// Who is releasing an action -- an operator (attributed) or the background
/// auto-revert sweep (system).
pub enum ReleaseBy {
    Operator { id: Uuid, username: String },
    AutoRevert,
}

impl ReleaseBy {
    fn key(&self) -> &'static str {
        match self {
            ReleaseBy::Operator { .. } => "operator",
            ReleaseBy::AutoRevert => "auto_revert",
        }
    }
}

/// Applies an enforcement action: checks the gates, snapshots the port's prior
/// state and issues the SNMP SET, then persists the result. On SNMP success an
/// `Active` row is written (with its auto-revert `expires_at`) and the action id
/// returned; on SNMP failure an `ApplyFailed` row is still written for the audit
/// trail and the error returned. The operator's permission must already have
/// been checked by the caller.
pub async fn apply(
    pool: &DbPool,
    encryption_key: Option<&EncryptionKey>,
    req: &EnforceRequest,
) -> Result<Uuid, EnforceError> {
    // --- Gate 1: global kill-switch ---
    if !settings_bool(pool, PANOPTICON_ENFORCEMENT_ENABLED).await {
        return Err(EnforceError::GloballyDisabled);
    }
    // --- Gate 2: per-switch opt-in ---
    if !req.switch.enforcement_enabled {
        return Err(EnforceError::SwitchNotOptedIn);
    }
    // --- Gate 3: a key to decrypt the switch's SNMP credentials with ---
    let key = encryption_key.ok_or(EnforceError::NoEncryptionKey)?;

    // One in-effect action per port at a time.
    if repo::panopticon_enforcement::find_in_effect_for_port(pool, req.switch.id, req.if_index)
        .await
        .map_err(|e| EnforceError::Db(e.to_string()))?
        .is_some()
    {
        return Err(EnforceError::AlreadyEnforced);
    }

    let quarantine_vlan = if req.kind == EnforcementKind::Quarantine {
        let vlan = repo::settings::get_u32(
            pool,
            PANOPTICON_QUARANTINE_VLAN,
            PANOPTICON_QUARANTINE_VLAN_DEFAULT,
        )
        .await
        .unwrap_or(PANOPTICON_QUARANTINE_VLAN_DEFAULT);
        if vlan == 0 {
            return Err(EnforceError::QuarantineVlanUnset);
        }
        Some(vlan)
    } else {
        None
    };

    let expires_at = (req.timeout_minutes > 0)
        .then(|| Utc::now() + Duration::minutes(i64::from(req.timeout_minutes)));

    // --- The actual write to the switch ---
    let snmp_result = match req.kind {
        EnforcementKind::Disable => {
            crate::panopticon_snmp::enforce_disable_port(&req.switch, key, req.if_index)
                .await
                .map(|original_admin| (Some(original_admin), None))
        }
        EnforcementKind::Quarantine => {
            let vlan = quarantine_vlan.expect("quarantine kind always resolves a vlan above");
            crate::panopticon_snmp::enforce_quarantine_port(&req.switch, key, req.if_index, vlan)
                .await
                .map(|original_pvid| (None, Some(original_pvid)))
        }
    };

    match snmp_result {
        Ok((original_admin_status, original_pvid)) => {
            let new = repo::panopticon_enforcement::NewAction {
                switch_id: req.switch.id,
                switch_name: &req.switch.name,
                if_index: req.if_index,
                port_label: &req.port_label,
                kind: req.kind,
                state: EnforcementState::Active,
                original_admin_status,
                original_pvid,
                quarantine_vlan: quarantine_vlan.map(i64::from),
                reason: req.reason.as_deref(),
                created_by: req.origin.created_by(),
                created_by_username: req.origin.created_by_username(),
                expires_at,
                last_error: None,
            };
            let id = repo::panopticon_enforcement::create(pool, &new)
                .await
                .map_err(|e| EnforceError::Db(e.to_string()))?;
            audit_enforced(pool, req, quarantine_vlan, AuditOutcome::Success, None).await;
            Ok(id)
        }
        Err(e) => {
            let msg = e.to_string();
            let new = repo::panopticon_enforcement::NewAction {
                switch_id: req.switch.id,
                switch_name: &req.switch.name,
                if_index: req.if_index,
                port_label: &req.port_label,
                kind: req.kind,
                state: EnforcementState::ApplyFailed,
                original_admin_status: None,
                original_pvid: None,
                quarantine_vlan: quarantine_vlan.map(i64::from),
                reason: req.reason.as_deref(),
                created_by: req.origin.created_by(),
                created_by_username: req.origin.created_by_username(),
                expires_at: None,
                last_error: Some(&msg),
            };
            // Best-effort: even if persisting the failed attempt fails, the
            // original error is what matters to the operator.
            let _ = repo::panopticon_enforcement::create(pool, &new).await;
            audit_enforced(
                pool,
                req,
                quarantine_vlan,
                AuditOutcome::Failure,
                Some(&msg),
            )
            .await;
            Err(EnforceError::Snmp(msg))
        }
    }
}

/// Reverts an in-effect action, restoring the port to its snapshotted prior
/// state. Used both by an operator's "Release" click and by the auto-revert
/// sweep. Ignores the global kill-switch on purpose -- a revert must always be
/// possible, even after enforcement has been turned off. On SNMP failure the
/// action is left `RevertFailed` so the sweep keeps retrying it.
pub async fn release(
    pool: &DbPool,
    encryption_key: Option<&EncryptionKey>,
    action: &EnforcementAction,
    by: ReleaseBy,
) -> Result<(), EnforceError> {
    // A key is required to reach the switch; without it we can't revert, so mark
    // the action for retry rather than silently dropping it.
    let Some(key) = encryption_key else {
        let msg = "ENCRYPTION_KEY isn't configured; cannot reach the switch to revert";
        let _ = repo::panopticon_enforcement::mark_reverted(
            pool,
            action.id,
            EnforcementState::RevertFailed,
            Some(msg),
        )
        .await;
        return Err(EnforceError::NoEncryptionKey);
    };

    // The live switch (for its current SNMP credentials). If it's been removed,
    // there's nothing left to revert on -- close the action out cleanly.
    let switch = match repo::panopticon_switches::find_by_id(pool, action.switch_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            let _ = repo::panopticon_enforcement::mark_reverted(
                pool,
                action.id,
                EnforcementState::Reverted,
                Some("switch no longer exists; nothing to revert on it"),
            )
            .await;
            audit_released(
                pool,
                action,
                &by,
                AuditOutcome::Success,
                Some("switch removed"),
            )
            .await;
            return Ok(());
        }
        Err(e) => return Err(EnforceError::Db(e.to_string())),
    };

    let snmp_result = match action.kind {
        EnforcementKind::Disable => {
            crate::panopticon_snmp::revert_disable_port(
                &switch,
                key,
                action.if_index,
                action.original_admin_status,
            )
            .await
        }
        EnforcementKind::Quarantine => {
            let vlan = action.quarantine_vlan.unwrap_or(0).max(0) as u32;
            crate::panopticon_snmp::revert_quarantine_port(
                &switch,
                key,
                action.if_index,
                action.original_pvid,
                vlan,
            )
            .await
        }
    };

    match snmp_result {
        Ok(()) => {
            repo::panopticon_enforcement::mark_reverted(
                pool,
                action.id,
                EnforcementState::Reverted,
                None,
            )
            .await
            .map_err(|e| EnforceError::Db(e.to_string()))?;
            audit_released(pool, action, &by, AuditOutcome::Success, None).await;
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = repo::panopticon_enforcement::mark_reverted(
                pool,
                action.id,
                EnforcementState::RevertFailed,
                Some(&msg),
            )
            .await;
            audit_released(pool, action, &by, AuditOutcome::Failure, Some(&msg)).await;
            Err(EnforceError::Snmp(msg))
        }
    }
}

async fn settings_bool(pool: &DbPool, key: &str) -> bool {
    repo::settings::get_bool(pool, key, false)
        .await
        .unwrap_or(false)
}

async fn audit_enforced(
    pool: &DbPool,
    req: &EnforceRequest,
    quarantine_vlan: Option<u32>,
    outcome: AuditOutcome,
    error: Option<&str>,
) {
    let resource = format!("{} / {}", req.switch.name, req.port_label);
    let metadata = serde_json::json!({
        "kind": req.kind.as_str(),
        "switch": req.switch.name,
        "switch_id": req.switch.id.to_string(),
        "if_index": req.if_index,
        "port": req.port_label,
        "quarantine_vlan": quarantine_vlan,
        "timeout_minutes": req.timeout_minutes,
        "reason": req.reason,
        "by": req.origin.key(),
        "rule": req.origin.rule_name(),
        "error": error,
    });
    let mut event = AuditEvent::new(AuditAction::NetworkPortEnforced, outcome)
        .resource(&resource)
        .metadata(metadata);
    if let (Some(id), Some(username)) = (req.origin.created_by(), req.origin.created_by_username())
    {
        event = event.actor(Actor {
            user_id: id,
            username,
        });
    }
    if let Err(e) = abyssal_audit::record(pool, event).await {
        tracing::error!(error = %e, "failed to record enforcement audit event");
    }
}

async fn audit_released(
    pool: &DbPool,
    action: &EnforcementAction,
    by: &ReleaseBy,
    outcome: AuditOutcome,
    note: Option<&str>,
) {
    let resource = format!("{} / {}", action.switch_name, action.port_label);
    let metadata = serde_json::json!({
        "kind": action.kind.as_str(),
        "switch": action.switch_name,
        "switch_id": action.switch_id.to_string(),
        "if_index": action.if_index,
        "port": action.port_label,
        "action_id": action.id.to_string(),
        "by": by.key(),
        "note": note,
    });
    let mut event = AuditEvent::new(AuditAction::NetworkPortReleased, outcome)
        .resource(&resource)
        .metadata(metadata);
    if let ReleaseBy::Operator { id, username } = by {
        event = event.actor(Actor {
            user_id: *id,
            username,
        });
    }
    if let Err(e) = abyssal_audit::record(pool, event).await {
        tracing::error!(error = %e, "failed to record release audit event");
    }
}

const REVERT_SWEEP_INTERVAL_SECS: u64 = 60;

/// Background auto-revert sweep: once a minute, restores every enforcement
/// action whose timeout has expired, and retries any that previously failed to
/// revert. This is the safety net behind timed enforcement -- a port disabled
/// "for 30 minutes" comes back on its own even if nobody returns to release it,
/// and a revert that didn't take the first time keeps being retried until the
/// port is confirmed back in service.
pub fn spawn_panopticon_enforcement_revert(
    pool: DbPool,
    encryption_key: Option<Arc<EncryptionKey>>,
    heartbeats: crate::task_health::TaskHeartbeats,
) {
    use crate::task_health::names;
    tokio::spawn(async move {
        heartbeats
            .register(
                names::PANOPTICON_ENFORCEMENT_REVERT,
                REVERT_SWEEP_INTERVAL_SECS,
            )
            .await;
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(REVERT_SWEEP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            heartbeats
                .ok(
                    names::PANOPTICON_ENFORCEMENT_REVERT,
                    REVERT_SWEEP_INTERVAL_SECS,
                )
                .await;

            let due = match repo::panopticon_enforcement::list_due_for_revert(&pool, Utc::now())
                .await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "enforcement revert sweep failed to list due actions");
                    continue;
                }
            };
            for action in due {
                match release(
                    &pool,
                    encryption_key.as_deref(),
                    &action,
                    ReleaseBy::AutoRevert,
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(
                            action_id = %action.id,
                            switch = %action.switch_name,
                            port = %action.port_label,
                            "auto-reverted enforcement action"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            action_id = %action.id,
                            switch = %action.switch_name,
                            port = %action.port_label,
                            error = %e,
                            "auto-revert of enforcement action failed; will retry"
                        );
                    }
                }
            }
        }
    });
}
