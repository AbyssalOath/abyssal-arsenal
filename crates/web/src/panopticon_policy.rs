//! Panopticon NAC auto-enforcement policy engine (phase 4) -- the background
//! sweep that lets enforcement fire without a human in the loop. It is a
//! deliberately decoupled, stateful sweep rather than a hook on the discovery
//! hot path: once a minute-ish it looks at every device the last SNMP poll has
//! *located* (so a resolvable port exists), evaluates the enabled policy rules
//! in priority order, and acts on the first match.
//!
//! Safety composes on top of M3, never around it:
//!   * `PolicyMode::Off` -> the sweep no-ops.
//!   * `PolicyMode::Simulate` -> matches are logged (server log) but nothing is
//!     written -- the recommended way to watch a policy before arming it.
//!   * `PolicyMode::Active` -> the matched action is applied through
//!     `panopticon_enforcement::apply`, which still re-checks every M3 gate
//!     (global kill-switch, per-switch opt-in, resolvable port).
//!   * An already-enforced port is skipped (no stacking), and a port acted on
//!     within the cooldown window is skipped -- so an operator's manual release
//!     of a policy action isn't immediately re-applied on the next sweep.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use abyssal_core::settings::{
    PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES, PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES_DEFAULT,
    PANOPTICON_AUTO_ENFORCE_MODE, PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES,
    PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES_DEFAULT, PANOPTICON_ENFORCEMENT_ENABLED,
    PANOPTICON_ENFORCEMENT_REVERT_MINUTES, PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT,
};
use abyssal_core::{
    EncryptionKey, NetworkDevice, PolicyMode, PolicyRule, PolicyTrigger, TrustState,
};
use abyssal_database::{DbPool, repo};
use chrono::{DateTime, Duration, Utc};

use crate::panopticon_enforcement::{EnforceOrigin, EnforceRequest};

/// Whether a device meets a rule's trigger. `is_new` is computed once per device
/// by the sweep (first-seen within the configured window); passed in rather than
/// recomputed here so this stays a pure, testable decision.
fn trigger_matches(rule: &PolicyRule, device: &NetworkDevice, is_new: bool) -> bool {
    match rule.trigger {
        PolicyTrigger::Untrusted => device.trust_state == TrustState::Untrusted,
        PolicyTrigger::NewUnknown => device.trust_state == TrustState::Unknown && is_new,
    }
}

/// Whether a device falls within a rule's scope filters (all AND-combined; a
/// `None` filter matches anything).
fn scope_matches(rule: &PolicyRule, device: &NetworkDevice) -> bool {
    if let Some(subnet) = &rule.subnet
        && device.network.as_deref() != Some(subnet.as_str())
    {
        return false;
    }
    if let Some(switch_id) = rule.switch_id
        && device.switch_id != Some(switch_id)
    {
        return false;
    }
    if let Some(device_type) = rule.device_type
        && device.device_type != device_type
    {
        return false;
    }
    true
}

/// Whether a rule applies to a device (trigger + scope).
fn rule_matches(rule: &PolicyRule, device: &NetworkDevice, is_new: bool) -> bool {
    trigger_matches(rule, device, is_new) && scope_matches(rule, device)
}

/// The first enabled rule (rules are passed in priority order) that matches.
fn first_match<'a>(
    rules: &'a [PolicyRule],
    device: &NetworkDevice,
    is_new: bool,
) -> Option<&'a PolicyRule> {
    rules.iter().find(|r| rule_matches(r, device, is_new))
}

const POLICY_SWEEP_INTERVAL_SECS: u64 = 120;

/// Spawns the auto-enforcement policy sweep. No-ops cheaply when the mode is
/// `off` or no rules are enabled (one settings read per tick).
pub fn spawn_panopticon_policy_sweep(
    pool: DbPool,
    encryption_key: Option<Arc<EncryptionKey>>,
    heartbeats: crate::task_health::TaskHeartbeats,
) {
    use crate::task_health::names;
    tokio::spawn(async move {
        heartbeats
            .register(names::PANOPTICON_POLICY_SWEEP, POLICY_SWEEP_INTERVAL_SECS)
            .await;
        let mut interval =
            tokio::time::interval(StdDuration::from_secs(POLICY_SWEEP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            heartbeats
                .ok(names::PANOPTICON_POLICY_SWEEP, POLICY_SWEEP_INTERVAL_SECS)
                .await;
            if let Err(e) = run_policy_sweep(&pool, encryption_key.as_deref()).await {
                tracing::error!(error = %e, "NAC policy sweep failed");
            }
        }
    });
}

/// One pass of the policy engine. Factored out of the spawn loop so the control
/// flow is readable and the settings reads happen once per pass.
async fn run_policy_sweep(
    pool: &DbPool,
    encryption_key: Option<&EncryptionKey>,
) -> anyhow::Result<()> {
    let mode: PolicyMode = repo::settings::get_string(pool, PANOPTICON_AUTO_ENFORCE_MODE, "off")
        .await
        .unwrap_or_default()
        .parse()
        .unwrap_or(PolicyMode::Off);
    if mode == PolicyMode::Off {
        return Ok(());
    }

    let rules = repo::panopticon_policy::list_enabled(pool).await?;
    if rules.is_empty() {
        return Ok(());
    }

    let new_window_minutes = repo::settings::get_u32(
        pool,
        PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES,
        PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES_DEFAULT);
    let cooldown_minutes = repo::settings::get_u32(
        pool,
        PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES,
        PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES_DEFAULT);
    let default_timeout = repo::settings::get_u32(
        pool,
        PANOPTICON_ENFORCEMENT_REVERT_MINUTES,
        PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT);
    let global_enforcement = repo::settings::get_bool(pool, PANOPTICON_ENFORCEMENT_ENABLED, false)
        .await
        .unwrap_or(false);

    let now = Utc::now();
    let new_cutoff = now - Duration::minutes(i64::from(new_window_minutes));
    let cooldown_since = now - Duration::minutes(i64::from(cooldown_minutes));

    let devices = repo::network_devices::list_located(pool).await?;
    for device in devices {
        let is_new = device.first_seen_at >= new_cutoff;
        let Some(rule) = first_match(&rules, &device, is_new) else {
            continue;
        };
        // list_located guarantees these are set, but be defensive.
        let (Some(switch_id), Some(port_label)) = (device.switch_id, device.switch_port.clone())
        else {
            continue;
        };

        if let Err(e) = act_on_match(
            pool,
            encryption_key,
            mode,
            global_enforcement,
            rule,
            &device,
            switch_id,
            &port_label,
            default_timeout,
            cooldown_since,
        )
        .await
        {
            tracing::warn!(error = %e, device = %device.ip_address, rule = %rule.name, "policy action failed");
        }
    }
    Ok(())
}

/// Handles one matched (device, rule): resolves the port, applies the skip
/// guards (already-enforced, cooldown), and either simulates (logs) or applies.
#[allow(clippy::too_many_arguments)]
async fn act_on_match(
    pool: &DbPool,
    encryption_key: Option<&EncryptionKey>,
    mode: PolicyMode,
    global_enforcement: bool,
    rule: &PolicyRule,
    device: &NetworkDevice,
    switch_id: uuid::Uuid,
    port_label: &str,
    default_timeout: u32,
    cooldown_since: DateTime<Utc>,
) -> anyhow::Result<()> {
    let Some(switch) = repo::panopticon_switches::find_by_id(pool, switch_id).await? else {
        return Ok(());
    };
    let Some(if_index) =
        repo::panopticon_traffic::find_if_index_by_label(pool, switch_id, port_label).await?
    else {
        tracing::debug!(
            device = %device.ip_address, switch = %switch.name, port = %port_label,
            "policy match but port ifIndex not resolvable yet; skipping"
        );
        return Ok(());
    };

    // Don't stack on an already-enforced port, and respect the post-action
    // cooldown (so a manual release isn't instantly re-applied).
    if repo::panopticon_enforcement::find_in_effect_for_port(pool, switch_id, if_index)
        .await?
        .is_some()
    {
        return Ok(());
    }
    if repo::panopticon_enforcement::has_recent_action_for_port(
        pool,
        switch_id,
        if_index,
        cooldown_since,
    )
    .await?
    {
        return Ok(());
    }

    let timeout_minutes = rule.timeout_minutes.unwrap_or(default_timeout);

    if mode == PolicyMode::Simulate {
        let actionable = global_enforcement && switch.enforcement_enabled;
        tracing::info!(
            rule = %rule.name,
            action = %rule.action.as_str(),
            device = %device.ip_address,
            switch = %switch.name,
            port = %port_label,
            if_index,
            timeout_minutes,
            actionable,
            "NAC policy [simulate]: would enforce (set mode to active to apply)"
        );
        return Ok(());
    }

    // Active mode. Only attempt the write where it could actually land -- apply
    // would refuse otherwise, but pre-checking avoids noisy failed-apply rows
    // for every device on a switch that isn't opted in.
    if !global_enforcement || !switch.enforcement_enabled {
        tracing::debug!(
            rule = %rule.name, device = %device.ip_address, switch = %switch.name,
            "policy match but enforcement not enabled for this switch; skipping"
        );
        return Ok(());
    }

    let req = EnforceRequest {
        switch,
        if_index,
        port_label: port_label.to_string(),
        kind: rule.action,
        reason: Some(format!("Auto-enforced by policy rule \"{}\"", rule.name)),
        timeout_minutes,
        origin: EnforceOrigin::Policy {
            rule_name: rule.name.clone(),
        },
    };
    match crate::panopticon_enforcement::apply(pool, encryption_key, &req).await {
        Ok(id) => {
            tracing::info!(
                rule = %rule.name, device = %device.ip_address, action_id = %id,
                "NAC policy enforced a port"
            );
        }
        Err(e) => {
            tracing::warn!(rule = %rule.name, device = %device.ip_address, error = %e, "NAC policy enforcement failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::{DeviceType, EnforcementKind};
    use chrono::Utc;
    use uuid::Uuid;

    fn device(trust: TrustState) -> NetworkDevice {
        NetworkDevice {
            id: Uuid::new_v4(),
            ip_address: "10.0.9.5".into(),
            network: Some("10.0.9.0/24".into()),
            mac_address: Some("aa:bb:cc:dd:ee:ff".into()),
            hostname: None,
            device_type: DeviceType::Iot,
            trust_state: trust,
            notes: None,
            ports: Vec::new(),
            switch_id: Some(Uuid::nil()),
            switch_port: Some("Gi1/0/5".into()),
            switch_port_seen_at: None,
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
        }
    }

    fn rule(trigger: PolicyTrigger) -> PolicyRule {
        PolicyRule {
            id: Uuid::new_v4(),
            priority: 1,
            name: "r".into(),
            enabled: true,
            trigger,
            action: EnforcementKind::Quarantine,
            subnet: None,
            switch_id: None,
            device_type: None,
            timeout_minutes: None,
            created_by: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn untrusted_trigger_only_matches_untrusted() {
        let r = rule(PolicyTrigger::Untrusted);
        assert!(rule_matches(&r, &device(TrustState::Untrusted), false));
        assert!(!rule_matches(&r, &device(TrustState::Trusted), false));
        assert!(!rule_matches(&r, &device(TrustState::Unknown), true));
    }

    #[test]
    fn new_trigger_requires_unknown_and_new() {
        let r = rule(PolicyTrigger::NewUnknown);
        assert!(rule_matches(&r, &device(TrustState::Unknown), true));
        // Unknown but not new (outside window) -> no match.
        assert!(!rule_matches(&r, &device(TrustState::Unknown), false));
        // New but already classified Trusted -> no match.
        assert!(!rule_matches(&r, &device(TrustState::Trusted), true));
    }

    #[test]
    fn scope_filters_narrow_the_match() {
        let mut r = rule(PolicyTrigger::Untrusted);
        let d = device(TrustState::Untrusted);
        // Matching subnet.
        r.subnet = Some("10.0.9.0/24".into());
        assert!(rule_matches(&r, &d, false));
        // Non-matching subnet.
        r.subnet = Some("10.0.1.0/24".into());
        assert!(!rule_matches(&r, &d, false));
        // Device-type filter.
        r.subnet = None;
        r.device_type = Some(DeviceType::Iot);
        assert!(rule_matches(&r, &d, false));
        r.device_type = Some(DeviceType::Printer);
        assert!(!rule_matches(&r, &d, false));
    }

    #[test]
    fn first_match_respects_priority_order() {
        let mut r1 = rule(PolicyTrigger::Untrusted);
        r1.name = "first".into();
        r1.action = EnforcementKind::Disable;
        let mut r2 = rule(PolicyTrigger::Untrusted);
        r2.name = "second".into();
        let rules = vec![r1, r2];
        let m = first_match(&rules, &device(TrustState::Untrusted), false).unwrap();
        assert_eq!(m.name, "first");
    }
}
