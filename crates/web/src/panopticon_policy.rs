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
//!   * Two guards no rule can get past (0.2.7 N1): the control plane's own
//!     server is never auto-enforced (it would lose the switch access it needs
//!     to undo the action), and neither is a port that looks like an uplink --
//!     one facing another polled switch (LLDP/CDP), or with more located
//!     devices than `panopticon.auto_enforce_max_devices_per_port`.
//!
//! The security-signal triggers (0.2.7 N1) read Scourge alerts (by the flow's
//! source address), open Thanatos events and the latest Cadavault posture
//! score (by the device's managed host, `NetworkDevice::host_id`, falling back
//! to the host's `last_seen_ip`), once per pass -- see [`Signals`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use abyssal_core::settings::{
    PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES, PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES_DEFAULT,
    PANOPTICON_AUTO_ENFORCE_MAX_DEVICES_PER_PORT,
    PANOPTICON_AUTO_ENFORCE_MAX_DEVICES_PER_PORT_DEFAULT, PANOPTICON_AUTO_ENFORCE_MODE,
    PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES, PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES_DEFAULT,
    PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES,
    PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES_DEFAULT, PANOPTICON_ENFORCEMENT_ENABLED,
    PANOPTICON_ENFORCEMENT_REVERT_MINUTES, PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT,
};
use abyssal_core::{
    EncryptionKey, Host, NetworkDevice, PolicyMode, PolicyRule, PolicyTrigger, Severity, TrustState,
};
use abyssal_database::{DbPool, repo};
use chrono::{DateTime, Duration, Utc};

use crate::panopticon_enforcement::{EnforceOrigin, EnforceRequest};
use uuid::Uuid;

/// What the security arsenals currently say, read once per sweep. Host-keyed
/// signals reach a device through [`Signals::host_of`].
#[derive(Debug, Default)]
struct Signals {
    /// Worst Scourge alert severity per flow *source* address, in the window.
    ids: HashMap<String, Severity>,
    /// Worst open Thanatos event severity per host, in the window.
    events: HashMap<Uuid, Severity>,
    /// Latest Cadavault posture score per host (hosts with a score only).
    posture: HashMap<Uuid, u8>,
    /// The source MACs of rogue DHCP servers that answered DHCP themselves
    /// in the window (0.2.9 Q4), lowercase. Not addresses: any device can
    /// name any address as a server.
    rogue_dhcp: HashSet<String>,
    /// Active hosts by the address the control plane sees them at -- the
    /// fallback when a device isn't linked (`host_id`) to its host.
    host_by_ip: HashMap<String, Uuid>,
    /// The control plane's own server: its host(s) and their addresses.
    control_plane_hosts: HashSet<Uuid>,
    control_plane_ips: HashSet<String>,
}

impl Signals {
    fn from_hosts(hosts: &[Host]) -> Self {
        let mut s = Signals::default();
        for h in hosts.iter().filter(|h| h.is_active()) {
            if let Some(ip) = &h.last_seen_ip {
                s.host_by_ip.insert(ip.clone(), h.id);
                if h.is_control_plane {
                    s.control_plane_ips.insert(ip.clone());
                }
            }
            if h.is_control_plane {
                s.control_plane_hosts.insert(h.id);
            }
        }
        s
    }

    /// The managed host a device belongs to: its stored link, else an
    /// active host seen at its address.
    fn host_of(&self, device: &NetworkDevice) -> Option<Uuid> {
        device
            .host_id
            .or_else(|| self.host_by_ip.get(&device.ip_address).copied())
    }

    fn is_control_plane(&self, device: &NetworkDevice) -> bool {
        device
            .host_id
            .is_some_and(|h| self.control_plane_hosts.contains(&h))
            || self.control_plane_ips.contains(&device.ip_address)
    }
}

/// Whether a device meets a rule's trigger. `is_new` is computed once per device
/// by the sweep (first-seen within the configured window); passed in rather than
/// recomputed here so this stays a pure, testable decision.
fn trigger_matches(
    rule: &PolicyRule,
    device: &NetworkDevice,
    is_new: bool,
    signals: &Signals,
) -> bool {
    let host = || signals.host_of(device);
    match rule.trigger {
        PolicyTrigger::Untrusted => device.trust_state == TrustState::Untrusted,
        PolicyTrigger::NewUnknown => device.trust_state == TrustState::Unknown && is_new,
        PolicyTrigger::IdsAlert => signals
            .ids
            .get(&device.ip_address)
            .is_some_and(|s| *s >= rule.effective_min_severity()),
        PolicyTrigger::SecurityEvent => host()
            .and_then(|h| signals.events.get(&h))
            .is_some_and(|s| *s >= rule.effective_min_severity()),
        PolicyTrigger::PostureFailing => host()
            .and_then(|h| signals.posture.get(&h))
            .is_some_and(|score| *score < rule.effective_posture_below()),
        PolicyTrigger::RogueDhcp => device
            .mac_address
            .as_deref()
            .is_some_and(|m| signals.rogue_dhcp.contains(&m.to_ascii_lowercase())),
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
fn rule_matches(
    rule: &PolicyRule,
    device: &NetworkDevice,
    is_new: bool,
    signals: &Signals,
) -> bool {
    trigger_matches(rule, device, is_new, signals) && scope_matches(rule, device)
}

/// The first enabled rule (rules are passed in priority order) that matches.
fn first_match<'a>(
    rules: &'a [PolicyRule],
    device: &NetworkDevice,
    is_new: bool,
    signals: &Signals,
) -> Option<&'a PolicyRule> {
    rules
        .iter()
        .find(|r| rule_matches(r, device, is_new, signals))
}

/// Which switch ports are, as far as Panopticon can tell, uplinks: those
/// with a LLDP/CDP neighbor that is another polled switch (by address or
/// name), and those with more located devices than `max_devices`. Keyed by
/// (switch, port label) -- the label both the FDB location and the neighbor
/// table use.
/// One LLDP/CDP neighbor of a polled switch, as the uplink guard needs it.
#[derive(Debug, Clone)]
struct PortNeighbor {
    switch_id: Uuid,
    local_port: String,
    local_if_index: Option<u32>,
    remote_name: String,
    remote_address: Option<String>,
}

impl PortNeighbor {
    fn from_row(n: abyssal_database::repo::panopticon_topology::Neighbor) -> Option<Self> {
        Some(PortNeighbor {
            switch_id: Uuid::parse_str(&n.switch_id).ok()?,
            local_port: n.local_port,
            local_if_index: n.local_if_index,
            remote_name: n.remote_name,
            remote_address: n.remote_address,
        })
    }
}

#[derive(Debug, Default)]
struct Uplinks {
    switch_facing: HashSet<(Uuid, String)>,
    switch_facing_if_index: HashSet<(Uuid, u32)>,
    devices_per_port: HashMap<(Uuid, String), usize>,
    max_devices: usize,
}

impl Uplinks {
    /// `switches` is every polled switch's (name, address).
    fn build(
        located: &[NetworkDevice],
        neighbors: &[PortNeighbor],
        switches: &[(String, String)],
        max_devices: u32,
    ) -> Self {
        let mut u = Uplinks {
            max_devices: max_devices as usize,
            ..Default::default()
        };
        for d in located {
            if let (Some(sw), Some(port)) = (d.switch_id, &d.switch_port) {
                *u.devices_per_port.entry((sw, port.clone())).or_default() += 1;
            }
        }
        let is_polled_switch = |n: &PortNeighbor| {
            switches.iter().any(|(name, address)| {
                n.remote_address.as_deref() == Some(address.as_str())
                    || (!n.remote_name.is_empty() && n.remote_name.eq_ignore_ascii_case(name))
            })
        };
        for n in neighbors.iter().filter(|n| is_polled_switch(n)) {
            u.switch_facing.insert((n.switch_id, n.local_port.clone()));
            if let Some(idx) = n.local_if_index {
                u.switch_facing_if_index.insert((n.switch_id, idx));
            }
        }
        u
    }

    /// Why this port must not be auto-enforced, if it looks like an uplink.
    fn reason(&self, switch_id: Uuid, port: &str, if_index: Option<u32>) -> Option<String> {
        if self.switch_facing.contains(&(switch_id, port.to_string()))
            || if_index.is_some_and(|i| self.switch_facing_if_index.contains(&(switch_id, i)))
        {
            return Some("the port faces another switch (LLDP/CDP)".into());
        }
        let n = self
            .devices_per_port
            .get(&(switch_id, port.to_string()))
            .copied()
            .unwrap_or(0);
        (n > self.max_devices).then(|| {
            format!(
                "{n} devices are located on the port (more than {}), so it's likely an uplink",
                self.max_devices
            )
        })
    }
}

const POLICY_SWEEP_INTERVAL_SECS: u64 = 120;

/// One policy pass at a time: the sweep and a pass an SNMP trap asks for
/// (0.2.9 Q5) must not both act on the same device at once (each checks
/// "already enforced" before acting).
static PASS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Runs one policy pass now, outside the sweep's schedule (after an SNMP
/// trap's poll, 0.2.9 Q5), waiting for a pass in progress to finish first.
pub(crate) async fn run_policy_pass_now(
    pool: &DbPool,
    encryption_key: Option<&Arc<EncryptionKey>>,
) -> anyhow::Result<()> {
    let _guard = PASS_LOCK.lock().await;
    run_policy_sweep(pool, encryption_key).await
}

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
            if let Err(e) = run_policy_pass_now(&pool, encryption_key.as_ref()).await {
                tracing::error!(error = %e, "NAC policy sweep failed");
            }
        }
    });
}

/// Settings and lookups shared by every device in one pass.
struct Pass<'a> {
    pool: &'a DbPool,
    encryption_key: Option<&'a Arc<EncryptionKey>>,
    mode: PolicyMode,
    global_enforcement: bool,
    default_timeout: u32,
    cooldown_since: DateTime<Utc>,
    signal_since: DateTime<Utc>,
    signals: Signals,
    uplinks: Uplinks,
    /// MACs with an open RADIUS session: devices whose access RADIUS
    /// controls, enforceable without SNMP.
    radius_macs: HashSet<String>,
    /// MACs already under a device action.
    radius_enforced: HashSet<String>,
}

/// One pass of the policy engine. Factored out of the spawn loop so the control
/// flow is readable and the settings reads happen once per pass.
async fn run_policy_sweep(
    pool: &DbPool,
    encryption_key: Option<&Arc<EncryptionKey>>,
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

    let setting = |key: &'static str, default: u32| async move {
        repo::settings::get_u32(pool, key, default)
            .await
            .unwrap_or(default)
    };
    let new_window_minutes = setting(
        PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES,
        PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES_DEFAULT,
    )
    .await;
    let cooldown_minutes = setting(
        PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES,
        PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES_DEFAULT,
    )
    .await;
    let default_timeout = setting(
        PANOPTICON_ENFORCEMENT_REVERT_MINUTES,
        PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT,
    )
    .await;
    let signal_window_minutes = setting(
        PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES,
        PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES_DEFAULT,
    )
    .await;
    let max_devices_per_port = setting(
        PANOPTICON_AUTO_ENFORCE_MAX_DEVICES_PER_PORT,
        PANOPTICON_AUTO_ENFORCE_MAX_DEVICES_PER_PORT_DEFAULT,
    )
    .await;
    let global_enforcement = repo::settings::get_bool(pool, PANOPTICON_ENFORCEMENT_ENABLED, false)
        .await
        .unwrap_or(false);

    let now = Utc::now();
    let new_cutoff = now - Duration::minutes(i64::from(new_window_minutes));
    let signal_since = now - Duration::minutes(i64::from(signal_window_minutes));

    // Signals are read only when a rule needs them. The host list is always
    // read: the control-plane guard needs it whatever the trigger.
    let wants = |pred: fn(PolicyTrigger) -> bool| rules.iter().any(|r| pred(r.trigger));
    let mut signals = Signals::from_hosts(&repo::hosts::list(pool).await?);
    if wants(|t| t == PolicyTrigger::IdsAlert) {
        signals.ids = repo::panopticon_signals::ids_alert_severities(pool, signal_since).await?;
    }
    if wants(|t| t == PolicyTrigger::SecurityEvent) {
        signals.events =
            repo::panopticon_signals::open_event_severities(pool, signal_since).await?;
    }
    if wants(|t| t == PolicyTrigger::PostureFailing) {
        signals.posture = repo::panopticon_signals::latest_posture_scores(pool).await?;
    }
    if wants(|t| t == PolicyTrigger::RogueDhcp) {
        signals.rogue_dhcp =
            crate::panopticon_rogue_dhcp::rogue_macs_since(pool, signal_since).await?;
    }

    // Every recent device with a MAC: located ones can be enforced at their
    // port, and any whose access RADIUS controls, through RADIUS.
    let devices = repo::network_devices::list_recent_with_mac(pool).await?;
    let located: Vec<NetworkDevice> = devices
        .iter()
        .filter(|d| d.switch_id.is_some() && d.switch_port.is_some())
        .cloned()
        .collect();
    let neighbors: Vec<PortNeighbor> = repo::panopticon_topology::list_neighbors(pool)
        .await?
        .into_iter()
        .filter_map(PortNeighbor::from_row)
        .collect();
    let switches: Vec<(String, String)> = repo::panopticon_switches::list(pool)
        .await?
        .into_iter()
        .map(|s| (s.name, s.ip_address))
        .collect();
    let uplinks = Uplinks::build(&located, &neighbors, &switches, max_devices_per_port);

    let pass = Pass {
        pool,
        encryption_key,
        mode,
        global_enforcement,
        default_timeout,
        cooldown_since: now - Duration::minutes(i64::from(cooldown_minutes)),
        signal_since,
        signals,
        uplinks,
        radius_macs: repo::panopticon_radius::macs_with_open_sessions(pool).await?,
        radius_enforced: repo::panopticon_device_enforcement::macs_in_effect(pool).await?,
    };
    for device in &devices {
        let is_new = device.first_seen_at >= new_cutoff;
        let Some(rule) = first_match(&rules, device, is_new, &pass.signals) else {
            continue;
        };
        if let Err(e) = act_on_match(&pass, rule, device).await {
            tracing::warn!(error = %e, device = %device.ip_address, rule = %rule.name, "policy action failed");
        }
    }
    Ok(())
}

/// Why a signal rule fired, for the enforcement reason and the audit log,
/// e.g. `Scourge high alert "ET MALWARE ..."`. `None` for the trust-state
/// triggers, whose reason is the rule alone.
async fn signal_detail(
    pass: &Pass<'_>,
    rule: &PolicyRule,
    device: &NetworkDevice,
) -> Option<String> {
    let host = pass.signals.host_of(device);
    let min = rule.effective_min_severity();
    match rule.trigger {
        PolicyTrigger::Untrusted | PolicyTrigger::NewUnknown => None,
        PolicyTrigger::IdsAlert => repo::panopticon_signals::top_ids_alert(
            pass.pool,
            &device.ip_address,
            pass.signal_since,
            min,
        )
        .await
        .ok()
        .flatten()
        .map(|(sev, sig)| format!("Scourge {sev} alert \"{sig}\"")),
        PolicyTrigger::SecurityEvent => {
            repo::panopticon_signals::top_open_event(pass.pool, host?, pass.signal_since, min)
                .await
                .ok()
                .flatten()
                .map(|(sev, label)| format!("open Thanatos {sev} event \"{label}\""))
        }
        PolicyTrigger::PostureFailing => {
            let score = pass.signals.posture.get(&host?)?;
            Some(format!(
                "Cadavault posture score {score} (below {})",
                rule.effective_posture_below()
            ))
        }
        PolicyTrigger::RogueDhcp => Some(format!(
            "rogue DHCP server: answered DHCP from {} (not an allowed server)",
            device.mac_address.as_deref().unwrap_or("its MAC")
        )),
    }
}

/// `what`, and the signal behind the match if there is one.
fn with_signal(what: String, detail: &Option<String>) -> String {
    match detail {
        Some(d) => format!("{what}: {d}"),
        None => what,
    }
}

/// Stores a simulated match for the policy page (0.2.9 Q2, B6). A failure
/// is only logged: the server log has it too.
async fn record_simulation(
    pass: &Pass<'_>,
    rule: &PolicyRule,
    device: &NetworkDevice,
    path: &str,
    detail: &str,
) {
    if let Err(e) = repo::panopticon_radius_decisions::record_simulation(
        pass.pool,
        rule.id,
        &rule.name,
        device.id,
        &device.ip_address,
        device.mac_address.as_deref(),
        rule.action,
        path,
        detail,
    )
    .await
    {
        tracing::warn!(error = %e, rule = %rule.name, "couldn't record a simulated policy match");
    }
}

/// What the port (SNMP) path made of a match.
enum PortPath {
    /// Enforced, simulated, or deliberately left alone (already enforced,
    /// cooldown): nothing more to do for this device.
    Done,
    /// The port can't be enforced (not located, uplink, port not resolvable,
    /// SNMP enforcement not enabled for the switch): try RADIUS.
    Unavailable(String),
}

fn policy_reason(rule: &PolicyRule, detail: &Option<String>) -> String {
    match detail {
        Some(d) => format!("Auto-enforced by policy rule \"{}\": {d}", rule.name),
        None => format!("Auto-enforced by policy rule \"{}\"", rule.name),
    }
}

/// Handles one matched (device, rule): the control-plane guard, then the
/// port's SNMP path, then -- where that isn't available -- RADIUS, for a
/// device with an open RADIUS session. Simulate mode logs what it would do.
async fn act_on_match(
    pass: &Pass<'_>,
    rule: &PolicyRule,
    device: &NetworkDevice,
) -> anyhow::Result<()> {
    let simulate = pass.mode == PolicyMode::Simulate;
    let skip = |why: String| async move {
        // Visible while an admin is watching a simulated policy; quiet once
        // it's active (it would repeat every sweep).
        if simulate {
            tracing::info!(rule = %rule.name, device = %device.ip_address,
                "NAC policy [simulate]: matched, but not enforced: {why}");
            record_simulation(pass, rule, device, "skipped", &why).await;
        } else {
            tracing::debug!(rule = %rule.name, device = %device.ip_address,
                "NAC policy: matched, but not enforced: {why}");
        }
    };
    if pass.signals.is_control_plane(device) {
        skip("it's the control plane's own server".into()).await;
        return Ok(());
    }
    let why_not_port = match try_port(pass, rule, device).await? {
        PortPath::Done => return Ok(()),
        PortPath::Unavailable(why) => why,
    };
    match radius_target(device, &pass.radius_macs) {
        Ok(mac) => try_radius(pass, rule, device, &mac).await,
        Err(why_not_radius) => {
            skip(format!("{why_not_port}, and {why_not_radius}")).await;
            Ok(())
        }
    }
}

/// Why a located device's port can't be enforced over SNMP, if it can't:
/// it looks like an uplink, its ifIndex isn't known yet, or SNMP enforcement
/// isn't enabled for its switch (or at all). In that order: an uplink is
/// never enforced, whatever the settings.
fn port_unavailable(
    uplink: Option<String>,
    if_index: Option<u32>,
    snmp_enabled: bool,
    switch_name: &str,
) -> Option<String> {
    if let Some(why) = uplink {
        return Some(format!("{why} (port not enforced)"));
    }
    if if_index.is_none() {
        return Some("its port's ifIndex isn't resolved yet".into());
    }
    (!snmp_enabled).then(|| format!("SNMP enforcement isn't enabled for {switch_name}"))
}

/// The MAC to enforce through RADIUS -- the device has one and an open
/// RADIUS session, so RADIUS controls its access -- or why not.
fn radius_target(
    device: &NetworkDevice,
    radius_macs: &HashSet<String>,
) -> Result<String, &'static str> {
    let mac = device
        .mac_address
        .as_ref()
        .map(|m| m.to_ascii_lowercase())
        .ok_or("it has no MAC for RADIUS")?;
    if radius_macs.contains(&mac) {
        Ok(mac)
    } else {
        Err("it has no open RADIUS session")
    }
}

/// The SNMP path: enforce the device's switch port.
async fn try_port(
    pass: &Pass<'_>,
    rule: &PolicyRule,
    device: &NetworkDevice,
) -> anyhow::Result<PortPath> {
    let pool = pass.pool;
    let simulate = pass.mode == PolicyMode::Simulate;
    let (Some(switch_id), Some(port_label)) = (device.switch_id, device.switch_port.as_deref())
    else {
        return Ok(PortPath::Unavailable("its switch port isn't known".into()));
    };
    let Some(switch) = repo::panopticon_switches::find_by_id(pool, switch_id).await? else {
        return Ok(PortPath::Unavailable("its switch was removed".into()));
    };
    let if_index =
        repo::panopticon_traffic::find_if_index_by_label(pool, switch_id, port_label).await?;
    let snmp_enabled = pass.global_enforcement && switch.enforcement_enabled;
    if let Some(why) = port_unavailable(
        pass.uplinks.reason(switch_id, port_label, if_index),
        if_index,
        snmp_enabled,
        &switch.name,
    ) {
        return Ok(PortPath::Unavailable(why));
    }
    let Some(if_index) = if_index else {
        return Ok(PortPath::Done); // unreachable: port_unavailable checks it
    };

    // Don't stack on an already-enforced port, and respect the post-action
    // cooldown (so a manual release isn't instantly re-applied).
    if repo::panopticon_enforcement::find_in_effect_for_port(pool, switch_id, if_index)
        .await?
        .is_some()
        || repo::panopticon_enforcement::has_recent_action_for_port(
            pool,
            switch_id,
            if_index,
            pass.cooldown_since,
        )
        .await?
    {
        return Ok(PortPath::Done);
    }

    let timeout_minutes = rule.timeout_minutes.unwrap_or(pass.default_timeout);
    let detail = signal_detail(pass, rule, device).await;
    if simulate {
        tracing::info!(
            rule = %rule.name,
            action = %rule.action.as_str(),
            device = %device.ip_address,
            switch = %switch.name,
            port = %port_label,
            if_index,
            timeout_minutes,
            signal = detail.as_deref().unwrap_or(""),
            "NAC policy [simulate]: would enforce the port over SNMP (set mode to active to apply)"
        );
        let what = format!("{} port {port_label}", switch.name);
        record_simulation(pass, rule, device, "port", &with_signal(what, &detail)).await;
        return Ok(PortPath::Done);
    }

    let req = EnforceRequest {
        switch,
        if_index,
        port_label: port_label.to_string(),
        kind: rule.action,
        reason: Some(policy_reason(rule, &detail)),
        timeout_minutes,
        origin: EnforceOrigin::Policy {
            rule_name: rule.name.clone(),
        },
    };
    match crate::panopticon_enforcement::apply(pool, pass.encryption_key, &req).await {
        Ok(id) => tracing::info!(
            rule = %rule.name, device = %device.ip_address, action_id = %id,
            "NAC policy enforced a port"
        ),
        Err(e) => tracing::warn!(
            rule = %rule.name, device = %device.ip_address, error = %e,
            "NAC policy port enforcement failed"
        ),
    }
    Ok(PortPath::Done)
}

/// The RADIUS path: a device action, which the RADIUS decision honors and a
/// CoA applies -- no switch write.
async fn try_radius(
    pass: &Pass<'_>,
    rule: &PolicyRule,
    device: &NetworkDevice,
    mac: &str,
) -> anyhow::Result<()> {
    let pool = pass.pool;
    if pass.radius_enforced.contains(mac)
        || repo::panopticon_device_enforcement::has_recent_for_mac(pool, mac, pass.cooldown_since)
            .await?
    {
        return Ok(());
    }
    let timeout_minutes = rule.timeout_minutes.unwrap_or(pass.default_timeout);
    let detail = signal_detail(pass, rule, device).await;
    if pass.mode == PolicyMode::Simulate {
        tracing::info!(
            rule = %rule.name,
            action = %rule.action.as_str(),
            device = %device.ip_address,
            mac,
            timeout_minutes,
            actionable = pass.global_enforcement,
            signal = detail.as_deref().unwrap_or(""),
            "NAC policy [simulate]: would enforce the device through RADIUS (set mode to active to apply)"
        );
        let what = if pass.global_enforcement {
            format!("MAC {mac}")
        } else {
            format!("MAC {mac} (enforcement is turned off globally, so not even when active)")
        };
        record_simulation(pass, rule, device, "radius", &with_signal(what, &detail)).await;
        return Ok(());
    }
    if !pass.global_enforcement {
        tracing::debug!(rule = %rule.name, device = %device.ip_address,
            "policy match but enforcement is globally disabled; skipping");
        return Ok(());
    }
    let req = crate::panopticon_device_enforcement::DeviceEnforceRequest {
        mac_address: mac.to_string(),
        device_ip: Some(device.ip_address.clone()),
        kind: rule.action,
        reason: Some(policy_reason(rule, &detail)),
        timeout_minutes,
        origin: EnforceOrigin::Policy {
            rule_name: rule.name.clone(),
        },
    };
    match crate::panopticon_device_enforcement::apply(pool, pass.encryption_key.cloned(), &req)
        .await
    {
        Ok(id) => tracing::info!(
            rule = %rule.name, device = %device.ip_address, action_id = %id,
            "NAC policy enforced a device through RADIUS"
        ),
        Err(e) => tracing::warn!(
            rule = %rule.name, device = %device.ip_address, error = %e,
            "NAC policy RADIUS enforcement failed"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::{DeviceType, EnforcementKind};
    use chrono::Utc;

    fn device(trust: TrustState) -> NetworkDevice {
        NetworkDevice {
            id: Uuid::new_v4(),
            ip_address: "10.0.9.5".into(),
            network: Some("10.0.9.0/24".into()),
            mac_address: Some("aa:bb:cc:dd:ee:ff".into()),
            hostname: None,
            device_type: DeviceType::Iot,
            device_type_auto: false,
            trust_state: trust,
            host_id: None,
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
            min_severity: None,
            posture_below: None,
            subnet: None,
            switch_id: None,
            device_type: None,
            timeout_minutes: None,
            created_by: None,
            created_at: Utc::now(),
        }
    }

    fn none() -> Signals {
        Signals::default()
    }

    #[test]
    fn untrusted_trigger_only_matches_untrusted() {
        let r = rule(PolicyTrigger::Untrusted);
        assert!(rule_matches(
            &r,
            &device(TrustState::Untrusted),
            false,
            &none()
        ));
        assert!(!rule_matches(
            &r,
            &device(TrustState::Trusted),
            false,
            &none()
        ));
        assert!(!rule_matches(
            &r,
            &device(TrustState::Unknown),
            true,
            &none()
        ));
    }

    #[test]
    fn new_trigger_requires_unknown_and_new() {
        let r = rule(PolicyTrigger::NewUnknown);
        assert!(rule_matches(
            &r,
            &device(TrustState::Unknown),
            true,
            &none()
        ));
        // Unknown but not new (outside window) -> no match.
        assert!(!rule_matches(
            &r,
            &device(TrustState::Unknown),
            false,
            &none()
        ));
        // New but already classified Trusted -> no match.
        assert!(!rule_matches(
            &r,
            &device(TrustState::Trusted),
            true,
            &none()
        ));
    }

    #[test]
    fn scope_filters_narrow_the_match() {
        let mut r = rule(PolicyTrigger::Untrusted);
        let d = device(TrustState::Untrusted);
        // Matching subnet.
        r.subnet = Some("10.0.9.0/24".into());
        assert!(rule_matches(&r, &d, false, &none()));
        // Non-matching subnet.
        r.subnet = Some("10.0.1.0/24".into());
        assert!(!rule_matches(&r, &d, false, &none()));
        // Device-type filter.
        r.subnet = None;
        r.device_type = Some(DeviceType::Iot);
        assert!(rule_matches(&r, &d, false, &none()));
        r.device_type = Some(DeviceType::Printer);
        assert!(!rule_matches(&r, &d, false, &none()));
    }

    #[test]
    fn first_match_respects_priority_order() {
        let mut r1 = rule(PolicyTrigger::Untrusted);
        r1.name = "first".into();
        r1.action = EnforcementKind::Disable;
        let mut r2 = rule(PolicyTrigger::Untrusted);
        r2.name = "second".into();
        let rules = vec![r1, r2];
        let m = first_match(&rules, &device(TrustState::Untrusted), false, &none()).unwrap();
        assert_eq!(m.name, "first");
    }

    #[test]
    fn ids_alerts_match_the_source_at_or_above_the_minimum() {
        let d = device(TrustState::Trusted);
        let mut signals = none();
        signals.ids.insert("10.0.9.5".into(), Severity::Medium);
        let mut r = rule(PolicyTrigger::IdsAlert);
        // Default minimum is high: a medium alert doesn't fire it.
        assert!(!rule_matches(&r, &d, false, &signals));
        r.min_severity = Some(Severity::Medium);
        assert!(rule_matches(&r, &d, false, &signals));
        // Another address's alert never counts.
        let mut other = none();
        other.ids.insert("10.0.9.6".into(), Severity::Critical);
        assert!(!rule_matches(&r, &d, false, &other));
    }

    #[test]
    fn security_events_reach_the_device_through_its_host() {
        let host = Uuid::new_v4();
        let mut signals = none();
        signals.events.insert(host, Severity::High);
        let r = rule(PolicyTrigger::SecurityEvent);

        // Unlinked device, no host at its address: no match.
        let mut d = device(TrustState::Trusted);
        assert!(!rule_matches(&r, &d, false, &signals));
        // Linked by host_id.
        d.host_id = Some(host);
        assert!(rule_matches(&r, &d, false, &signals));
        // Or found by the host's last_seen_ip.
        d.host_id = None;
        signals.host_by_ip.insert("10.0.9.5".into(), host);
        assert!(rule_matches(&r, &d, false, &signals));
        // The stored link wins over the address fallback.
        d.host_id = Some(Uuid::new_v4());
        assert!(!rule_matches(&r, &d, false, &signals));
    }

    #[test]
    fn posture_fails_strictly_below_the_threshold() {
        let host = Uuid::new_v4();
        let mut d = device(TrustState::Trusted);
        d.host_id = Some(host);
        let mut signals = none();
        let mut r = rule(PolicyTrigger::PostureFailing);
        signals.posture.insert(host, 59);
        assert!(
            rule_matches(&r, &d, false, &signals),
            "default threshold 60"
        );
        signals.posture.insert(host, 60);
        assert!(!rule_matches(&r, &d, false, &signals));
        r.posture_below = Some(80);
        assert!(rule_matches(&r, &d, false, &signals));
        // A host with no score isn't failing.
        signals.posture.clear();
        assert!(!rule_matches(&r, &d, false, &signals));
    }

    #[test]
    fn a_rogue_dhcp_server_matches_by_the_mac_it_answered_from() {
        let mut d = device(TrustState::Trusted);
        d.mac_address = Some("AA:BB:CC:00:00:06".into());
        let r = rule(PolicyTrigger::RogueDhcp);
        let mut signals = none();
        assert!(!rule_matches(&r, &d, false, &signals));
        signals.rogue_dhcp.insert("aa:bb:cc:00:00:06".into());
        assert!(rule_matches(&r, &d, false, &signals));
        // Its address being named as a server isn't enough.
        signals.rogue_dhcp = [d.ip_address.clone()].into_iter().collect();
        assert!(!rule_matches(&r, &d, false, &signals));
        d.mac_address = None;
        signals.rogue_dhcp.insert("aa:bb:cc:00:00:06".into());
        assert!(!rule_matches(&r, &d, false, &signals));
        assert_eq!(
            "rogue_dhcp".parse::<PolicyTrigger>(),
            Ok(PolicyTrigger::RogueDhcp)
        );
        assert!(PolicyTrigger::ALL.contains(&PolicyTrigger::RogueDhcp));
    }

    #[test]
    fn the_control_plane_is_recognized_by_link_or_address() {
        let cp = Uuid::new_v4();
        let mut signals = none();
        signals.control_plane_hosts.insert(cp);
        let mut d = device(TrustState::Untrusted);
        assert!(!signals.is_control_plane(&d));
        d.host_id = Some(cp);
        assert!(signals.is_control_plane(&d));
        d.host_id = None;
        signals.control_plane_ips.insert("10.0.9.5".into());
        assert!(signals.is_control_plane(&d));
    }

    fn neighbor(switch: Uuid, port: &str, name: &str, addr: Option<&str>) -> PortNeighbor {
        PortNeighbor {
            switch_id: switch,
            local_port: port.into(),
            local_if_index: None,
            remote_name: name.into(),
            remote_address: addr.map(str::to_string),
        }
    }

    #[test]
    fn uplinks_are_ports_facing_a_polled_switch_or_crowded() {
        let sw = Uuid::new_v4();
        let core = ("core-sw".to_string(), "10.0.0.2".to_string());
        let mut located: Vec<NetworkDevice> = (0..5)
            .map(|i| {
                let mut d = device(TrustState::Unknown);
                d.ip_address = format!("10.0.9.{i}");
                d.switch_id = Some(sw);
                d.switch_port = Some("Gi1/0/48".into());
                d
            })
            .collect();
        let mut desk = device(TrustState::Unknown);
        desk.switch_id = Some(sw);
        desk.switch_port = Some("Gi1/0/5".into());
        located.push(desk);
        let neighbors = vec![
            neighbor(sw, "Gi1/0/47", "CORE-SW", None),
            neighbor(sw, "Gi1/0/6", "phone-1234", Some("10.0.9.200")),
        ];
        let u = Uplinks::build(&located, &neighbors, &[core], 4);

        assert!(
            u.reason(sw, "Gi1/0/47", None)
                .unwrap()
                .contains("another switch")
        );
        assert!(
            u.reason(sw, "Gi1/0/48", None)
                .unwrap()
                .contains("5 devices")
        );
        // A desk port, and a port whose neighbor is a phone, are fine.
        assert_eq!(u.reason(sw, "Gi1/0/5", None), None);
        assert_eq!(u.reason(sw, "Gi1/0/6", None), None);
        // The same port on another switch isn't an uplink.
        assert_eq!(u.reason(Uuid::new_v4(), "Gi1/0/47", None), None);
    }

    #[test]
    fn a_switch_neighbor_is_matched_by_address_and_if_index() {
        let sw = Uuid::new_v4();
        let mut n = neighbor(sw, "TenGig1/1/1", "", Some("10.0.0.2"));
        n.local_if_index = Some(49);
        let switches = vec![("core-sw".to_string(), "10.0.0.2".to_string())];
        let u = Uplinks::build(&[], &[n], &switches, 4);
        // Found by ifIndex even when the device's port label differs.
        assert!(u.reason(sw, "Te1/1/1", Some(49)).is_some());
        assert!(u.reason(sw, "Te1/1/1", Some(50)).is_none());
    }

    #[test]
    fn ports_are_skipped_for_uplinks_unresolved_ports_and_snmp_off() {
        // A resolvable port on an opted-in switch: SNMP.
        assert_eq!(port_unavailable(None, Some(5), true, "sw1"), None);
        // An uplink wins over everything else.
        let why = port_unavailable(Some("faces another switch".into()), Some(5), true, "sw1");
        assert!(why.unwrap().contains("faces another switch"));
        assert!(
            port_unavailable(None, None, true, "sw1")
                .unwrap()
                .contains("ifIndex")
        );
        assert!(
            port_unavailable(None, Some(5), false, "sw1")
                .unwrap()
                .contains("isn't enabled for sw1")
        );
    }

    #[test]
    fn radius_takes_over_only_for_devices_with_a_radius_session() {
        let mut d = device(TrustState::Untrusted);
        d.mac_address = Some("AA:BB:CC:DD:EE:FF".into());
        let mut sessions = HashSet::new();
        assert_eq!(
            radius_target(&d, &sessions),
            Err("it has no open RADIUS session")
        );
        sessions.insert("aa:bb:cc:dd:ee:ff".to_string());
        // The MAC is matched case-insensitively and returned lowercase.
        assert_eq!(radius_target(&d, &sessions), Ok("aa:bb:cc:dd:ee:ff".into()));
        d.mac_address = None;
        assert_eq!(
            radius_target(&d, &sessions),
            Err("it has no MAC for RADIUS")
        );
    }

    #[test]
    fn condition_labels_show_the_threshold() {
        let mut r = rule(PolicyTrigger::IdsAlert);
        assert!(r.condition_label().ends_with("high or worse"));
        r.trigger = PolicyTrigger::PostureFailing;
        r.posture_below = Some(75);
        assert!(r.condition_label().ends_with("score below 75"));
        r.trigger = PolicyTrigger::Untrusted;
        assert_eq!(r.condition_label(), "Untrusted device");
    }
}
