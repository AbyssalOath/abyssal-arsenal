//! Enforcement through RADIUS (0.2.7, `docs/roadmap/0.2.7.md`): quarantine or
//! block a *device* without writing to its switch.
//!
//! Port enforcement (`crate::panopticon_enforcement`) needs SNMP write access
//! to the switch and the device located on a port. Where RADIUS controls a
//! device's access instead -- Panopticon's embedded server or FreeRADIUS --
//! a device action does the same job: it's held against the MAC, the RADIUS
//! decision honors it (`panopticon_radius::decide_for_mac`: the quarantine
//! VLAN, or a reject for `Disable`), and a CoA (`crate::panopticon_coa`)
//! makes the NAS re-authorize the device now. Releasing it, by hand or when
//! it expires, sends another CoA.
//!
//! The same gates as port enforcement: the global kill switch, one action in
//! effect per device, a quarantine VLAN for quarantine, an audit record each
//! way. Without CoA on the device's NAS, the action takes effect at the
//! device's next authentication.

use std::sync::Arc;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    PANOPTICON_ENFORCEMENT_ENABLED, PANOPTICON_QUARANTINE_VLAN, PANOPTICON_QUARANTINE_VLAN_DEFAULT,
};
use abyssal_core::{DeviceEnforcement, EncryptionKey, EnforcementKind};
use abyssal_database::{DbPool, repo};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::panopticon_enforcement::{EnforceOrigin, ReleaseBy};

/// Why a device action wasn't applied.
#[derive(Debug, PartialEq, Eq)]
pub enum DeviceEnforceError {
    GloballyDisabled,
    QuarantineVlanUnset,
    AlreadyEnforced,
    Db(String),
}

impl std::fmt::Display for DeviceEnforceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceEnforceError::GloballyDisabled => write!(
                f,
                "NAC enforcement is globally disabled -- turn it on in Settings first."
            ),
            DeviceEnforceError::QuarantineVlanUnset => write!(
                f,
                "No quarantine VLAN is configured, so a device can't be quarantined -- set one in \
                 Settings, or block it instead."
            ),
            DeviceEnforceError::AlreadyEnforced => {
                write!(
                    f,
                    "This device already has an enforcement action in effect."
                )
            }
            DeviceEnforceError::Db(e) => write!(f, "Database error: {e}"),
        }
    }
}

pub struct DeviceEnforceRequest {
    pub mac_address: String,
    pub device_ip: Option<String>,
    pub kind: EnforcementKind,
    pub reason: Option<String>,
    /// Minutes until it's lifted; `0` = permanent.
    pub timeout_minutes: u32,
    pub origin: EnforceOrigin,
}

/// Holds an action against the device and has its NAS re-authorize it.
pub async fn apply(
    pool: &DbPool,
    key: Option<Arc<EncryptionKey>>,
    req: &DeviceEnforceRequest,
) -> Result<Uuid, DeviceEnforceError> {
    if !repo::settings::get_bool(pool, PANOPTICON_ENFORCEMENT_ENABLED, false)
        .await
        .unwrap_or(false)
    {
        return Err(DeviceEnforceError::GloballyDisabled);
    }
    if req.kind == EnforcementKind::Quarantine
        && repo::settings::get_u32(
            pool,
            PANOPTICON_QUARANTINE_VLAN,
            PANOPTICON_QUARANTINE_VLAN_DEFAULT,
        )
        .await
        .unwrap_or(0)
            == 0
    {
        return Err(DeviceEnforceError::QuarantineVlanUnset);
    }
    let expires_at = (req.timeout_minutes > 0)
        .then(|| Utc::now() + Duration::minutes(i64::from(req.timeout_minutes)));
    let id = repo::panopticon_device_enforcement::create(
        pool,
        &repo::panopticon_device_enforcement::NewDeviceAction {
            mac_address: &req.mac_address,
            device_ip: req.device_ip.as_deref(),
            kind: req.kind,
            reason: req.reason.as_deref(),
            created_by: req.origin.created_by(),
            created_by_username: req.origin.created_by_username(),
            expires_at,
        },
    )
    .await
    .map_err(|e| DeviceEnforceError::Db(e.to_string()))?
    .ok_or(DeviceEnforceError::AlreadyEnforced)?;

    let mut event = AuditEvent::new(AuditAction::NetworkDeviceEnforced, AuditOutcome::Success)
        .resource(&req.mac_address)
        .metadata(serde_json::json!({
            "kind": req.kind.as_str(),
            "ip": req.device_ip,
            "by": req.origin.key(),
            "rule": req.origin.rule_name(),
            "reason": req.reason,
            "timeout_minutes": req.timeout_minutes,
            "action_id": id.to_string(),
        }));
    if let EnforceOrigin::Operator { id: uid, username } = &req.origin {
        event = event.actor(Actor {
            user_id: *uid,
            username,
        });
    }
    let _ = abyssal_audit::record(pool, event).await;

    crate::panopticon_coa::spawn_reauthorize_mac(
        pool.clone(),
        key,
        req.mac_address.clone(),
        format!("device {}d", req.kind.as_str()),
        match &req.origin {
            EnforceOrigin::Operator { id, username } => Some((*id, username.clone())),
            EnforceOrigin::Policy { .. } => None,
        },
    );
    Ok(id)
}

/// Lifts an action and has the device's NAS re-authorize it. A release that
/// lost a race (already lifted) does nothing.
pub async fn release(
    pool: &DbPool,
    key: Option<Arc<EncryptionKey>>,
    action: &DeviceEnforcement,
    by: ReleaseBy,
) -> anyhow::Result<()> {
    if !repo::panopticon_device_enforcement::mark_reverted(pool, action.id).await? {
        return Ok(());
    }
    let mut event = AuditEvent::new(AuditAction::NetworkDeviceReleased, AuditOutcome::Success)
        .resource(&action.mac_address)
        .metadata(serde_json::json!({
            "kind": action.kind.as_str(),
            "by": by.key(),
            "action_id": action.id.to_string(),
        }));
    let requester = match &by {
        ReleaseBy::Operator { id, username } => {
            event = event.actor(Actor {
                user_id: *id,
                username,
            });
            Some((*id, username.clone()))
        }
        ReleaseBy::AutoRevert => None,
    };
    let _ = abyssal_audit::record(pool, event).await;
    crate::panopticon_coa::spawn_reauthorize_mac(
        pool.clone(),
        key,
        action.mac_address.clone(),
        format!("device {} lifted", action.kind.as_str()),
        requester,
    );
    Ok(())
}

/// The revert sweep's share: lifts every device action past its expiry.
pub async fn release_due(pool: &DbPool, key: Option<Arc<EncryptionKey>>) {
    let due = match repo::panopticon_device_enforcement::list_due(pool, Utc::now()).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "device enforcement sweep failed to list due actions");
            return;
        }
    };
    for action in due {
        match release(pool, key.clone(), &action, ReleaseBy::AutoRevert).await {
            Ok(()) => {
                tracing::info!(mac = %action.mac_address, "device enforcement expired and lifted")
            }
            Err(e) => {
                tracing::warn!(error = %e, mac = %action.mac_address, "device enforcement lift failed")
            }
        }
    }
}
