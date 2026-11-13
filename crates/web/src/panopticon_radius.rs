//! Panopticon's embedded RADIUS server (NAC phase 5): MAC Auth Bypass with
//! dynamic VLAN assignment, plus accounting ingest for the "who authenticated
//! where" identity. It makes Panopticon the access-control decision point --
//! switches/APs point their 802.1X/MAB RADIUS config at it, and the device's
//! `TrustState` (plus a small policy of settings) decides accept / reject /
//! quarantine-VLAN.
//!
//! Scope: MAB (MAC-based) only. There is no RADIUS user credential store, so
//! the server cannot verify a password -- a request carrying User-Password,
//! CHAP-Password, or EAP-Message is *rejected* rather than silently authorized
//! on its MAC (authorizing a credentialed request without checking the
//! credential would be an authentication bypass). Real user auth (PAP against a
//! credential store, or EAP-TLS/PEAP) belongs with a dedicated stack like
//! FreeRADIUS, which `deploy/freeradius` provides (EAP-TLS, and PEAP against
//! Active Directory). The wire codec lives in `crate::radius`.

use std::net::IpAddr;
use std::sync::Arc;

use abyssal_core::settings::{
    PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES,
    PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES_DEFAULT, PANOPTICON_PORTAL_VLAN,
    PANOPTICON_PORTAL_VLAN_DEFAULT, PANOPTICON_QUARANTINE_VLAN, PANOPTICON_QUARANTINE_VLAN_DEFAULT,
    PANOPTICON_RADIUS_ACCT_PORT, PANOPTICON_RADIUS_ACCT_PORT_DEFAULT, PANOPTICON_RADIUS_AUTH_PORT,
    PANOPTICON_RADIUS_AUTH_PORT_DEFAULT, PANOPTICON_RADIUS_DECISION_RETENTION_DAYS,
    PANOPTICON_RADIUS_DECISION_RETENTION_DAYS_DEFAULT, PANOPTICON_RADIUS_GUEST_VLAN,
    PANOPTICON_RADIUS_GUEST_VLAN_DEFAULT, PANOPTICON_RADIUS_ROLE_GUEST,
    PANOPTICON_RADIUS_ROLE_QUARANTINE, PANOPTICON_RADIUS_ROLE_REGISTRATION,
    PANOPTICON_RADIUS_ROLE_TRUSTED, PANOPTICON_RADIUS_ROLE_UNKNOWN,
    PANOPTICON_RADIUS_SIGNAL_EVENT_ACTION, PANOPTICON_RADIUS_SIGNAL_EVENT_MIN_SEVERITY,
    PANOPTICON_RADIUS_SIGNAL_IDS_ACTION, PANOPTICON_RADIUS_SIGNAL_IDS_MIN_SEVERITY,
    PANOPTICON_RADIUS_SIGNAL_POSTURE_ACTION, PANOPTICON_RADIUS_SIGNAL_POSTURE_BELOW,
    PANOPTICON_RADIUS_TIMEOUT_GUEST_MINUTES, PANOPTICON_RADIUS_TIMEOUT_MAX_MINUTES,
    PANOPTICON_RADIUS_TIMEOUT_QUARANTINE_MINUTES, PANOPTICON_RADIUS_TIMEOUT_REGISTRATION_MINUTES,
    PANOPTICON_RADIUS_TIMEOUT_TRUSTED_MINUTES, PANOPTICON_RADIUS_TIMEOUT_UNKNOWN_MINUTES,
    PANOPTICON_RADIUS_TRUSTED_VLAN, PANOPTICON_RADIUS_TRUSTED_VLAN_DEFAULT,
    PANOPTICON_RADIUS_UNKNOWN_ACTION, PANOPTICON_RADIUS_UNTRUSTED_ACTION,
};
use abyssal_core::{
    EncryptionKey, EnforcementKind, NetworkDevice, RadiusClient, RadiusGroupRule, Severity,
    TrustState, first_matching_group_rule, network_of, parse_cidr,
};
use abyssal_database::{DbPool, repo};

use crate::radius::{self, Packet};

const MAX_PACKET: usize = 4096;

/// Per-trust-state admission policy, read from settings once per packet (cheap).
pub(crate) struct RadiusPolicy {
    trusted_vlan: u32,
    quarantine_vlan: u32,
    /// "quarantine" | "reject"
    untrusted_action: String,
    /// "accept" | "guest" | "register" | "reject"
    unknown_action: String,
    guest_vlan: u32,
    /// The registration VLAN, for `unknown_action = register` (0 = unset).
    registration_vlan: u32,
    /// Roles per outcome (0.2.8 P2); `None` = no role.
    role_trusted: Option<String>,
    role_quarantine: Option<String>,
    role_unknown: Option<String>,
    role_guest: Option<String>,
    role_registration: Option<String>,
    /// Session-Timeout per outcome, in seconds (0.2.8 P4); 0 = none.
    timeout_trusted: u32,
    timeout_quarantine: u32,
    timeout_unknown: u32,
    timeout_guest: u32,
    timeout_registration: u32,
}

/// How the device got this far: MAC authentication only, or a real 802.1X
/// login (EAP, through FreeRADIUS). The registration portal is for devices
/// that can't authenticate, so an authenticated one never goes there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    Mab,
    Authenticated,
}

/// The MAB authorization outcome.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Access-Accept, optionally with a VLAN assignment.
    Accept(Option<u32>),
    /// Access-Reject.
    Reject,
}

/// The core MAB decision: maps a device's trust state (or its absence) to an
/// admission outcome under the configured policy. Pure and table-tested.
///
/// `enforced` is the enforcement action in effect on the device's switch port
/// (0.2.7 N2), and it wins over trust: a quarantined port's device goes to the
/// quarantine VLAN (or is rejected if none is configured), a disabled port's
/// is rejected. Without this, a device re-authenticating on a quarantined port
/// -- which a CoA now makes happen at once -- would get its trusted VLAN back
/// and walk straight out of quarantine.
///
/// `registered` is whether the device has an approved, unexpired guest
/// registration (only read when `unknown_action = register`, 0.2.7 N5).
///
/// `group_vlan` is the VLAN of the first AD group rule the login matched
/// (0.2.8 P1). It only ever chooses *which VLAN an admitted device gets*:
/// enforcement and an Untrusted device still win, an unknown device under
/// `reject` is still rejected, and it's ignored unless the device passed a
/// real 802.1X login.
///
/// The VLAN-only view of [`decide_full`] (no roles, a NAS that doesn't apply
/// them), which the VLAN tests are written against.
#[cfg(test)]
fn decide(
    trust: Option<TrustState>,
    enforced: Option<EnforcementKind>,
    registered: bool,
    admission: Admission,
    group_vlan: Option<u32>,
    p: &RadiusPolicy,
) -> Decision {
    decide_full(
        &DecisionInputs {
            trust,
            enforced,
            registered,
            admission,
            group_vlan,
            group_role: None,
            nas_applies_roles: false,
            signal: None,
            registration_expires_in: None,
        },
        p,
    )
    .decision
}

/// Everything a decision depends on besides the policy settings.
pub(crate) struct DecisionInputs {
    pub trust: Option<TrustState>,
    pub enforced: Option<EnforcementKind>,
    pub registered: bool,
    pub admission: Admission,
    /// The first matching AD group rule's VLAN (0.2.8 P1).
    pub group_vlan: Option<u32>,
    /// ... and its role (0.2.8 P2).
    pub group_role: Option<String>,
    /// Whether the NAS asking applies roles (its role attribute isn't
    /// `None`). Quarantine by role alone, without a quarantine VLAN, is only
    /// safe then: a NAS that ignores the role would admit the device
    /// unrestricted.
    pub nas_applies_roles: bool,
    /// The strictest security signal that fired for the device (0.2.8 P3).
    pub signal: Option<SignalAction>,
    /// Seconds left on the device's approved guest registration, when it
    /// has one (0.2.8 P4: a guest session ends no later than that).
    pub registration_expires_in: Option<u32>,
}

/// A decision plus the role (ACL / user role name) and Session-Timeout for
/// an Accept.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub decision: Decision,
    pub role: Option<String>,
    /// Seconds until the NAS re-authenticates the session (0.2.8 P4).
    pub session_timeout: Option<u32>,
}

/// The shortest Session-Timeout sent, so an almost-expired registration
/// doesn't make a NAS re-authenticate in a tight loop.
const MIN_SESSION_TIMEOUT_SECS: u32 = 60;

/// [`decide`] with roles (0.2.8 P2). Each admitting outcome has its own
/// role setting (trusted, quarantine, unknown, guest, registration); an AD
/// group rule's role replaces it wherever the group rule's VLAN would apply.
/// A reject never carries a role. Quarantine needs the quarantine VLAN, or
/// a quarantine role on a NAS that applies roles; with neither it rejects
/// (fail closed).
///
/// A security signal (0.2.8 P3) comes below port and device enforcement
/// and above everything else, and only ever tightens: it turns an admitting
/// outcome into quarantine or a reject, never a reject into anything else.
///
/// Each admitting outcome also has its own Session-Timeout (0.2.8 P4), so
/// a NAS without CoA re-asks: short for quarantine and registration, long
/// for trusted. An approved guest's session ends no later than its
/// registration, where a guest timeout is set.
#[cfg(test)]
fn decide_full(i: &DecisionInputs, p: &RadiusPolicy) -> Verdict {
    decide_explained(i, p).0
}

/// [`decide_full`], and what it was based on, for the decision record and
/// the log (0.2.9 Q2): "trusted device", "security signal: quarantine
/// (otherwise: trusted device)", ...
fn decide_explained(i: &DecisionInputs, p: &RadiusPolicy) -> (Verdict, String) {
    let authenticated = i.admission == Admission::Authenticated;
    let group_vlan = i.group_vlan.filter(|v| *v > 0 && authenticated);
    let group_role = i.group_role.clone().filter(|_| authenticated);
    let by_group = if group_vlan.is_some() || group_role.is_some() {
        ", by AD group rule"
    } else {
        ""
    };
    let accept = |vlan: Option<u32>, role: Option<String>, timeout: u32| Verdict {
        decision: Decision::Accept(vlan),
        role,
        session_timeout: (timeout > 0).then(|| timeout.max(MIN_SESSION_TIMEOUT_SECS)),
    };
    let reject = || Verdict {
        decision: Decision::Reject,
        role: None,
        session_timeout: None,
    };
    let quarantine = |why: &str| {
        if p.quarantine_vlan > 0 {
            (
                accept(
                    Some(p.quarantine_vlan),
                    p.role_quarantine.clone(),
                    p.timeout_quarantine,
                ),
                why.to_string(),
            )
        } else if i.nas_applies_roles && p.role_quarantine.is_some() {
            (
                accept(None, p.role_quarantine.clone(), p.timeout_quarantine),
                format!("{why} (by role)"),
            )
        } else {
            (
                reject(),
                format!("{why}, but no quarantine VLAN (or role this NAS applies): rejected"),
            )
        }
    };
    let registered_guest_timeout = match i.registration_expires_in {
        Some(left) if p.timeout_guest > 0 => p.timeout_guest.min(left),
        _ => p.timeout_guest,
    };
    let vlan_or = |fallback: u32| group_vlan.or((fallback > 0).then_some(fallback));

    match i.enforced {
        Some(EnforcementKind::Disable) => {
            return (reject(), "disabled by enforcement (port or device)".into());
        }
        Some(EnforcementKind::Quarantine) => {
            return quarantine("quarantined by enforcement (port or device)");
        }
        None => {}
    }
    let base = match i.trust {
        Some(TrustState::Trusted) => (
            accept(
                vlan_or(p.trusted_vlan),
                group_role.or_else(|| p.role_trusted.clone()),
                p.timeout_trusted,
            ),
            format!("trusted device{by_group}"),
        ),
        Some(TrustState::Untrusted) => match p.untrusted_action.as_str() {
            "reject" => (reject(), "untrusted device: reject".into()),
            // "quarantine": isolate onto the quarantine VLAN (or role).
            _ => quarantine("untrusted device: quarantine"),
        },
        // Unknown trust, or a device not in inventory at all.
        _ => match p.unknown_action.as_str() {
            "reject" => (reject(), "unknown device: reject".into()),
            "guest" => (
                accept(
                    vlan_or(p.guest_vlan),
                    group_role.or_else(|| p.role_guest.clone()),
                    p.timeout_guest,
                ),
                format!("unknown device: guest VLAN{by_group}"),
            ),
            // The registration portal: registered guests to the guest VLAN,
            // everyone else to the registration VLAN -- or, with none
            // configured, nowhere (fail closed).
            // An 802.1X-authenticated device that isn't classified yet is
            // admitted plainly, as before the portal existed.
            "register" if authenticated => (
                accept(
                    group_vlan,
                    group_role.or_else(|| p.role_unknown.clone()),
                    p.timeout_unknown,
                ),
                format!("unknown device, 802.1X login: admitted{by_group}"),
            ),
            "register" if i.registered => (
                accept(
                    (p.guest_vlan > 0).then_some(p.guest_vlan),
                    p.role_guest.clone(),
                    registered_guest_timeout,
                ),
                "unknown device, approved registration: guest VLAN".into(),
            ),
            "register" if p.registration_vlan > 0 => (
                accept(
                    Some(p.registration_vlan),
                    p.role_registration.clone(),
                    p.timeout_registration,
                ),
                "unknown device, not registered: registration VLAN".into(),
            ),
            "register" => (
                reject(),
                "unknown device, not registered, and no registration VLAN: reject".into(),
            ),
            // "accept" (the safe default): admit with no VLAN assignment
            // (or the AD group's).
            _ => (
                accept(
                    group_vlan,
                    group_role.or_else(|| p.role_unknown.clone()),
                    p.timeout_unknown,
                ),
                format!("unknown device: admitted{by_group}"),
            ),
        },
    };
    match i.signal {
        _ if base.0.decision == Decision::Reject => base,
        None => base,
        Some(SignalAction::Reject) => (
            reject(),
            format!("security signal: reject (otherwise: {})", base.1),
        ),
        Some(SignalAction::Quarantine) => quarantine(&format!(
            "security signal: quarantine (otherwise: {})",
            base.1
        )),
    }
}

/// What a security signal at login does to the device (0.2.8 P3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SignalAction {
    Quarantine,
    Reject,
}

impl SignalAction {
    /// `reject`, else quarantine (the setting's default).
    pub(crate) fn from_setting(s: &str) -> Self {
        if s == "reject" {
            SignalAction::Reject
        } else {
            SignalAction::Quarantine
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SignalAction::Quarantine => "quarantine",
            SignalAction::Reject => "reject",
        }
    }
}

/// Which security signals are checked at login, and what each does.
#[derive(Debug, Clone, Default)]
pub(crate) struct SignalPolicy {
    /// Latest Cadavault posture score strictly below this.
    pub posture_below: Option<(u8, SignalAction)>,
    /// An open Thanatos event at or above this severity.
    pub event_min: Option<(Severity, SignalAction)>,
    /// A Scourge alert from the device's address at or above this severity.
    pub ids_min: Option<(Severity, SignalAction)>,
    /// How far back events and alerts count.
    pub window_minutes: u32,
}

impl SignalPolicy {
    pub(crate) fn any(&self) -> bool {
        self.posture_below.is_some() || self.event_min.is_some() || self.ids_min.is_some()
    }
}

/// A security signal that fired at login, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoginSignal {
    pub action: SignalAction,
    /// For the log, e.g. `Cadavault posture score 42 (below 60)`.
    pub detail: String,
}

/// The strictest of the signals that fired (a reject over a quarantine; the
/// first of equals, in check order: posture, Thanatos, Scourge).
fn strictest(fired: Vec<LoginSignal>) -> Option<LoginSignal> {
    fired.into_iter().rev().max_by_key(|s| s.action)
}

/// The security signals for one device at login (0.2.8 P3). Host-keyed
/// signals (posture, Thanatos) need the device's managed host -- its link,
/// else an active host at its address; Scourge's go by the device's address.
/// The control plane's own server is never restricted by a signal (as in
/// the policy engine: it would lose the access it needs to undo it). A
/// database error skips that signal, logged: the signals only add
/// restrictions, so the login is decided as without it.
async fn login_signal(
    pool: &DbPool,
    device: &NetworkDevice,
    policy: &SignalPolicy,
) -> Option<LoginSignal> {
    fn ok<T>(r: anyhow::Result<T>, what: &str, mac: &str) -> Option<T> {
        r.map_err(|e| {
            tracing::error!(error = %e, mac, signal = what, "RADIUS: couldn't read a security signal; deciding without it");
        })
        .ok()
    }
    use repo::panopticon_signals as sig;
    let mac = device.mac_address.as_deref().unwrap_or("");
    let ip = device.ip_address.as_str();
    let host = if policy.posture_below.is_some() || policy.event_min.is_some() {
        ok(
            sig::host_for_device(pool, device.host_id, ip).await,
            "host",
            mac,
        )
        .flatten()
    } else {
        None
    };
    let control_plane = host.is_some_and(|(_, cp)| cp)
        || ok(sig::is_control_plane_ip(pool, ip).await, "host", mac).unwrap_or(false);
    if control_plane {
        tracing::debug!(
            mac,
            "RADIUS: the control plane's own server; security signals not checked"
        );
        return None;
    }
    let host = host.map(|(id, _)| id);
    let since = chrono::Utc::now() - chrono::Duration::minutes(i64::from(policy.window_minutes));
    let mut fired = Vec::new();
    if let (Some((below, action)), Some(h)) = (policy.posture_below, host)
        && let Some(score) = ok(sig::latest_posture_score(pool, h).await, "posture", mac).flatten()
        && score < below
    {
        fired.push(LoginSignal {
            action,
            detail: format!("Cadavault posture score {score} (below {below})"),
        });
    }
    if let (Some((min, action)), Some(h)) = (policy.event_min, host)
        && let Some((sev, label)) = ok(
            sig::top_open_event(pool, h, since, min).await,
            "thanatos",
            mac,
        )
        .flatten()
    {
        fired.push(LoginSignal {
            action,
            detail: format!("open Thanatos {sev} event \"{label}\""),
        });
    }
    if let Some((min, action)) = policy.ids_min
        && !ip.is_empty()
        && let Some((sev, signature)) = ok(
            sig::top_ids_alert(pool, ip, since, min).await,
            "scourge",
            mac,
        )
        .flatten()
    {
        fired.push(LoginSignal {
            action,
            detail: format!("Scourge {sev} alert \"{signature}\""),
        });
    }
    strictest(fired)
}

async fn load_signal_policy(pool: &DbPool) -> SignalPolicy {
    let string = |k: &'static str| {
        let pool = pool.clone();
        async move {
            repo::settings::get_string(&pool, k, "")
                .await
                .unwrap_or_default()
        }
    };
    let posture_below = repo::settings::get_u32(pool, PANOPTICON_RADIUS_SIGNAL_POSTURE_BELOW, 0)
        .await
        .unwrap_or(0)
        .min(100);
    let action = |raw: String| SignalAction::from_setting(&raw);
    SignalPolicy {
        posture_below: (posture_below > 0).then_some((
            posture_below as u8,
            action(string(PANOPTICON_RADIUS_SIGNAL_POSTURE_ACTION).await),
        )),
        event_min: match Severity::from_key(
            &string(PANOPTICON_RADIUS_SIGNAL_EVENT_MIN_SEVERITY).await,
        ) {
            Some(sev) => Some((
                sev,
                action(string(PANOPTICON_RADIUS_SIGNAL_EVENT_ACTION).await),
            )),
            None => None,
        },
        ids_min: match Severity::from_key(&string(PANOPTICON_RADIUS_SIGNAL_IDS_MIN_SEVERITY).await)
        {
            Some(sev) => Some((
                sev,
                action(string(PANOPTICON_RADIUS_SIGNAL_IDS_ACTION).await),
            )),
            None => None,
        },
        window_minutes: repo::settings::get_u32(
            pool,
            PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES,
            PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES_DEFAULT,
        )
        .await
        .unwrap_or(PANOPTICON_AUTO_ENFORCE_SIGNAL_WINDOW_MINUTES_DEFAULT),
    }
}

/// Normalizes a MAC from whatever punctuation a NAS used (`aa-bb-..`,
/// `aabb.ccdd.eeff`, `AABBCCDDEEFF`, `aa:bb:..`) to lowercase colon form, or
/// `None` if it isn't 12 hex digits.
pub(crate) fn normalize_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    let pairs: Vec<&str> = (0..12).step_by(2).map(|i| &hex[i..i + 2]).collect();
    Some(pairs.join(":"))
}

/// Outcome of resolving the MAC a MAB request authenticates as.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MacResolution {
    /// A single, consistent MAC to authorize.
    Resolved(String),
    /// User-Name and Calling-Station-Id are both MACs but disagree -- a request
    /// trying to assert a different identity than its observed source MAC.
    Conflict,
    /// No MAC present at all -- nothing to MAB-authorize.
    Missing,
}

/// Resolves the MAB MAC from the (already normalized) Calling-Station-Id and
/// User-Name values. Calling-Station-Id (the switch-observed source MAC) is the
/// anchor; a User-Name MAC, if present, must match it.
pub(crate) fn resolve_mab_mac(
    calling: Option<String>,
    username_mac: Option<String>,
) -> MacResolution {
    match (calling, username_mac) {
        (Some(c), Some(u)) => {
            if c == u {
                MacResolution::Resolved(c)
            } else {
                MacResolution::Conflict
            }
        }
        (Some(c), None) => MacResolution::Resolved(c),
        (None, Some(u)) => MacResolution::Resolved(u),
        (None, None) => MacResolution::Missing,
    }
}

/// Whether a RADIUS client entry (bare IP or CIDR) matches a source address.
fn client_matches(nas_address: &str, src: IpAddr) -> bool {
    let nas_address = nas_address.trim();
    if let Some((net_addr, prefix)) = parse_cidr(nas_address) {
        let src_net = network_of(&src.to_string(), prefix, prefix);
        let cidr_net = network_of(&net_addr.to_string(), prefix, prefix);
        src_net.is_some() && src_net == cidr_net
    } else {
        nas_address == src.to_string()
    }
}

/// Finds the enabled RADIUS client matching a source address and returns its
/// decrypted shared secret, or `None` if no client matches / decryption fails.
/// Also how the CoA sender (`crate::panopticon_coa`) finds a session's NAS.
/// The enabled NAS client a source address belongs to, without its secret.
pub(crate) async fn client_by_ip(pool: &DbPool, src: IpAddr) -> Option<RadiusClient> {
    repo::panopticon_radius::list_enabled_clients(pool)
        .await
        .ok()?
        .into_iter()
        .find(|c| client_matches(&c.nas_address, src))
}

pub(crate) async fn client_for(
    pool: &DbPool,
    key: &EncryptionKey,
    src: IpAddr,
) -> Option<(RadiusClient, zeroize::Zeroizing<String>)> {
    let client = client_by_ip(pool, src).await?;
    match key.decrypt(&client.shared_secret_encrypted) {
        Ok(secret) => Some((client, secret)),
        Err(e) => {
            tracing::warn!(error = %e, client = %client.name, "RADIUS: failed to decrypt client secret");
            None
        }
    }
}

/// The admission decision for a MAC -- the device's trust state, unless an
/// enforcement action is in effect on the port it was last located on, or
/// on the device itself (enforcement through RADIUS) -- and
/// what it was based on. Shared by the embedded server and the FreeRADIUS
/// front end (`crate::panopticon_freeradius`), so the two can't drift apart.
pub(crate) async fn decide_for_mac(
    pool: &DbPool,
    mac: &str,
    admission: Admission,
    nas: Option<&RadiusClient>,
) -> LoginDecision {
    decide_for_login(pool, mac, admission, nas, &[]).await
}

/// What [`decide_for_login`] decided, and what it was based on.
pub(crate) struct LoginDecision {
    pub decision: Decision,
    /// The role (ACL / user role) for an Accept, 0.2.8 P2. Sent only to a
    /// NAS with a role attribute.
    pub role: Option<String>,
    pub trust: Option<TrustState>,
    pub enforced: Option<EnforcementKind>,
    /// The AD group rule that matched (0.2.8 P1).
    pub group_rule: Option<RadiusGroupRule>,
    /// The security signal that restricted the device (0.2.8 P3).
    pub signal: Option<LoginSignal>,
    /// Session-Timeout for an Accept, in seconds (0.2.8 P4).
    pub session_timeout: Option<u32>,
    /// What the decision was based on (0.2.9 Q2).
    pub reason: String,
    /// The login's AD groups that have a rule, as given (0.2.9 Q2).
    pub groups: Vec<String>,
}

/// Prunes decision records, simulated policy matches and accounted
/// sessions not seen for `panopticon.radius_decision_retention_days`
/// (0.2.9 Q2, Q3), every six hours.
pub fn spawn_radius_decision_retention(
    pool: DbPool,
    task_health: crate::task_health::TaskHeartbeats,
) {
    use crate::task_health::names::PANOPTICON_RADIUS_RETENTION as NAME;
    const INTERVAL_SECS: u64 = 6 * 60 * 60;
    tokio::spawn(async move {
        task_health.register(NAME, INTERVAL_SECS).await;
        tokio::time::sleep(std::time::Duration::from_secs(90)).await;
        loop {
            let days = repo::settings::get_u32(
                &pool,
                PANOPTICON_RADIUS_DECISION_RETENTION_DAYS,
                PANOPTICON_RADIUS_DECISION_RETENTION_DAYS_DEFAULT,
            )
            .await
            .unwrap_or(PANOPTICON_RADIUS_DECISION_RETENTION_DAYS_DEFAULT);
            let result = if days == 0 {
                Ok(())
            } else {
                let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(days));
                prune_decisions(&pool, cutoff).await
            };
            match result {
                Ok(()) => task_health.ok(NAME, INTERVAL_SECS).await,
                Err(e) => {
                    tracing::error!(error = %e, "RADIUS decision retention failed");
                    task_health.error(NAME, INTERVAL_SECS, e.to_string()).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(INTERVAL_SECS)).await;
        }
    });
}

async fn prune_decisions(
    pool: &DbPool,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    use repo::panopticon_radius_decisions as decisions;
    let n = decisions::prune_older_than(pool, cutoff).await?;
    let m = decisions::prune_simulations_older_than(pool, cutoff).await?;
    // Accounted sessions not seen for as long (0.2.9 Q3): nothing pruned
    // them before. An open one that old is a NAS that never sent Stop.
    let k = repo::panopticon_radius::prune_sessions_older_than(pool, cutoff).await?;
    if n + m + k > 0 {
        tracing::info!(
            decisions = n,
            simulations = m,
            sessions = k,
            "RADIUS retention pruned old records"
        );
    }
    Ok(())
}

/// Which front end made a decision, for its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrontEnd {
    Embedded,
    FreeRadius,
}

impl FrontEnd {
    fn as_str(self) -> &'static str {
        match self {
            FrontEnd::Embedded => "embedded",
            FrontEnd::FreeRadius => "freeradius",
        }
    }
}

/// Where a decision was asked from, for its record.
pub(crate) struct DecisionContext<'a> {
    pub front_end: FrontEnd,
    pub admission: Admission,
    /// Lowercase colon form, or empty when the login had none.
    pub mac: &'a str,
    pub identity: Option<&'a str>,
    pub nas: Option<&'a RadiusClient>,
    /// The address the request came from (the NAS).
    pub nas_address: Option<String>,
}

/// Records a decision (0.2.9 Q2) without holding up the reply: written in
/// the background, and a failure is only logged. A record is for people,
/// never part of the decision.
pub(crate) fn record(pool: &DbPool, d: &LoginDecision, ctx: DecisionContext<'_>) {
    let rec = d.to_record(&ctx);
    let pool = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = repo::panopticon_radius_decisions::insert(&pool, &rec).await {
            tracing::warn!(error = %e, "RADIUS: couldn't record a decision");
        }
    });
}

impl LoginDecision {
    /// The record of this decision, as asked in `ctx`. The role is the one
    /// actually sent: none to a NAS without a role attribute.
    pub(crate) fn to_record(
        &self,
        ctx: &DecisionContext<'_>,
    ) -> abyssal_core::RadiusDecisionRecord {
        let (outcome, vlan) = match self.decision {
            Decision::Accept(vlan) => ("accept", vlan.and_then(|v| u16::try_from(v).ok())),
            Decision::Reject => ("reject", None),
        };
        let applies_roles = ctx.nas.is_some_and(|c| c.role_attribute.sends_roles());
        abyssal_core::RadiusDecisionRecord {
            id: uuid::Uuid::new_v4(),
            decided_at: chrono::Utc::now(),
            mac_address: (!ctx.mac.is_empty()).then(|| ctx.mac.to_ascii_lowercase()),
            nas_client_id: ctx.nas.map(|c| c.id),
            nas_name: ctx.nas.map(|c| c.name.clone()),
            nas_address: ctx.nas_address.clone(),
            front_end: ctx.front_end.as_str().into(),
            admission: match ctx.admission {
                Admission::Mab => "mab",
                Admission::Authenticated => "dot1x",
            }
            .into(),
            identity: ctx.identity.filter(|s| !s.is_empty()).map(str::to_string),
            outcome: outcome.into(),
            vlan,
            role: self.role.clone().filter(|_| applies_roles),
            session_timeout: self.session_timeout,
            reason: self.reason.clone(),
            trust_state: self.trust.map(|t| t.as_str().to_string()),
            enforcement: self.enforced.map(|k| k.as_str().to_string()),
            signal_action: self.signal.as_ref().map(|s| s.action.as_str().to_string()),
            signal_detail: self.signal.as_ref().map(|s| s.detail.clone()),
            group_rule: self.group_rule.as_ref().map(|r| r.group_name.clone()),
            ad_groups: (!self.groups.is_empty()).then(|| {
                self.groups
                    .join(&abyssal_core::GROUP_LIST_SEPARATOR.to_string())
            }),
        }
    }

    /// The signal for the log: `"quarantine: Cadavault posture ..."`.
    pub(crate) fn signal_label(&self) -> String {
        self.signal
            .as_ref()
            .map(|s| format!("{}: {}", s.action.as_str(), s.detail))
            .unwrap_or_else(|| "none".into())
    }
}

/// [`decide_for_mac`] for an 802.1X login that brought its AD groups along
/// (PEAP through FreeRADIUS, 0.2.8 P1): the first matching group rule
/// chooses the VLAN (and role) where the device is admitted. A rule lookup
/// that fails counts as no match: the device then gets its non-group
/// decision, which a group rule could only have changed the VLAN or role
/// of, never turned from a reject into an accept.
///
/// `nas` is the NAS client asking, when known: it decides whether a role
/// can stand in for a missing quarantine VLAN (0.2.8 P2).
pub(crate) async fn decide_for_login(
    pool: &DbPool,
    mac: &str,
    admission: Admission,
    nas: Option<&RadiusClient>,
    groups: &[String],
) -> LoginDecision {
    let device = repo::network_devices::find_by_mac(pool, mac)
        .await
        .ok()
        .flatten();
    let trust = device.as_ref().map(|d| d.trust_state);
    let enforced = match device
        .as_ref()
        .and_then(|d| Some((d.switch_id?, d.switch_port.clone()?)))
    {
        Some((switch_id, port)) => {
            repo::panopticon_enforcement::find_in_effect_for_port_label(pool, switch_id, &port)
                .await
                .ok()
                .flatten()
                .map(|a| a.kind)
        }
        None => None,
    };
    // No port action: a device action (enforcement through RADIUS) instead.
    let enforced = match enforced {
        Some(kind) => Some(kind),
        None if !mac.is_empty() => {
            repo::panopticon_device_enforcement::find_in_effect_for_mac(pool, mac)
                .await
                .ok()
                .flatten()
                .map(|a| a.kind)
        }
        None => None,
    };
    let policy = load_policy(pool).await;
    // A registration only matters for a device that isn't classified.
    let now = chrono::Utc::now();
    let registration = if policy.unknown_action == "register"
        && !matches!(trust, Some(TrustState::Trusted | TrustState::Untrusted))
        && !mac.is_empty()
    {
        repo::panopticon_registrations::find(pool, mac)
            .await
            .ok()
            .flatten()
            .filter(|r| r.grants_access(now))
    } else {
        None
    };
    let registered = registration.is_some();
    let registration_expires_in = registration
        .and_then(|r| r.expires_at)
        .map(|e| u32::try_from((e - now).num_seconds().max(0)).unwrap_or(u32::MAX));
    let group_rule = if groups.is_empty() || admission != Admission::Authenticated {
        None
    } else {
        match repo::panopticon_radius::list_group_rules(pool).await {
            Ok(rules) => first_matching_group_rule(&rules, groups).cloned(),
            Err(e) => {
                tracing::error!(error = %e, "couldn't read the RADIUS group rules; deciding without them");
                None
            }
        }
    };
    // Security signals (0.2.8 P3): only for a device in the inventory, and
    // not read at all where enforcement already decides.
    let signal = match &device {
        Some(d) if enforced.is_none() => {
            let signals = load_signal_policy(pool).await;
            if signals.any() {
                login_signal(pool, d, &signals).await
            } else {
                None
            }
        }
        _ => None,
    };
    let (verdict, reason) = decide_explained(
        &DecisionInputs {
            trust,
            enforced,
            registered,
            admission,
            group_vlan: group_rule.as_ref().map(|r| u32::from(r.vlan)),
            group_role: group_rule.as_ref().and_then(|r| r.role.clone()),
            nas_applies_roles: nas.is_some_and(|c| c.role_attribute.sends_roles()),
            signal: signal.as_ref().map(|s| s.action),
            registration_expires_in,
        },
        &policy,
    );
    LoginDecision {
        decision: verdict.decision,
        role: verdict.role,
        trust,
        enforced,
        group_rule,
        signal,
        session_timeout: verdict.session_timeout,
        reason,
        groups: groups.to_vec(),
    }
}

async fn load_policy(pool: &DbPool) -> RadiusPolicy {
    let g = |k: &'static str, d: u32| {
        let pool = pool.clone();
        async move { repo::settings::get_u32(&pool, k, d).await.unwrap_or(d) }
    };
    RadiusPolicy {
        trusted_vlan: g(
            PANOPTICON_RADIUS_TRUSTED_VLAN,
            PANOPTICON_RADIUS_TRUSTED_VLAN_DEFAULT,
        )
        .await,
        quarantine_vlan: g(
            PANOPTICON_QUARANTINE_VLAN,
            PANOPTICON_QUARANTINE_VLAN_DEFAULT,
        )
        .await,
        untrusted_action: repo::settings::get_string(
            pool,
            PANOPTICON_RADIUS_UNTRUSTED_ACTION,
            "quarantine",
        )
        .await
        .unwrap_or_else(|_| "quarantine".to_string()),
        unknown_action: repo::settings::get_string(
            pool,
            PANOPTICON_RADIUS_UNKNOWN_ACTION,
            "accept",
        )
        .await
        .unwrap_or_else(|_| "accept".to_string()),
        guest_vlan: g(
            PANOPTICON_RADIUS_GUEST_VLAN,
            PANOPTICON_RADIUS_GUEST_VLAN_DEFAULT,
        )
        .await,
        registration_vlan: g(PANOPTICON_PORTAL_VLAN, PANOPTICON_PORTAL_VLAN_DEFAULT).await,
        role_trusted: role(pool, PANOPTICON_RADIUS_ROLE_TRUSTED).await,
        role_quarantine: role(pool, PANOPTICON_RADIUS_ROLE_QUARANTINE).await,
        role_unknown: role(pool, PANOPTICON_RADIUS_ROLE_UNKNOWN).await,
        role_guest: role(pool, PANOPTICON_RADIUS_ROLE_GUEST).await,
        role_registration: role(pool, PANOPTICON_RADIUS_ROLE_REGISTRATION).await,
        timeout_trusted: timeout(pool, PANOPTICON_RADIUS_TIMEOUT_TRUSTED_MINUTES).await,
        timeout_quarantine: timeout(pool, PANOPTICON_RADIUS_TIMEOUT_QUARANTINE_MINUTES).await,
        timeout_unknown: timeout(pool, PANOPTICON_RADIUS_TIMEOUT_UNKNOWN_MINUTES).await,
        timeout_guest: timeout(pool, PANOPTICON_RADIUS_TIMEOUT_GUEST_MINUTES).await,
        timeout_registration: timeout(pool, PANOPTICON_RADIUS_TIMEOUT_REGISTRATION_MINUTES).await,
    }
}

/// A Session-Timeout setting (minutes) in seconds; 0 when unset, and
/// capped at [`abyssal_core::settings::PANOPTICON_RADIUS_TIMEOUT_MAX_MINUTES`].
async fn timeout(pool: &DbPool, key: &'static str) -> u32 {
    let minutes = repo::settings::get_u32(pool, key, 0).await.unwrap_or(0);
    minutes.min(PANOPTICON_RADIUS_TIMEOUT_MAX_MINUTES) * 60
}

/// A role setting: `None` when unset, empty, or (somehow) not a valid role
/// name -- an invalid name is never sent to a NAS.
async fn role(pool: &DbPool, key: &'static str) -> Option<String> {
    let raw = repo::settings::get_string(pool, key, "").await.ok()?;
    abyssal_core::validate_role_name(&raw).ok().flatten()
}

/// Handles one Access-Request datagram, returning the response bytes to send
/// back (or `None` to silently drop -- unknown NAS, bad secret, parse failure).
async fn handle_auth(
    pool: &DbPool,
    key: &EncryptionKey,
    src: IpAddr,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let packet = Packet::parse(buf)?;
    if packet.code != radius::CODE_ACCESS_REQUEST {
        return None;
    }
    let (client, secret) = client_for(pool, key, src).await?;
    let secret = secret.as_bytes();

    // Integrity: if the request carries a Message-Authenticator it must validate.
    if !packet.verify_message_authenticator(secret) {
        tracing::warn!(client = %client.name, "RADIUS: Access-Request Message-Authenticator mismatch (wrong shared secret?)");
        return None;
    }

    let include_msg_auth = packet.has(radius::ATTR_MESSAGE_AUTHENTICATOR);

    let reject = |reason: &str| {
        tracing::debug!(client = %client.name, reason, "RADIUS: Access-Reject");
        Some(radius::build_response(
            radius::CODE_ACCESS_REJECT,
            packet.id,
            &packet.authenticator,
            &[],
            secret,
            include_msg_auth,
        ))
    };

    // We don't speak EAP -- reject a real 802.1X supplicant so it can fall back
    // to MAB or a guest flow rather than hanging.
    if packet.has(radius::ATTR_EAP_MESSAGE) {
        return reject("EAP request (MAB only)");
    }

    // This server authenticates by MAC (MAB) only -- there is no RADIUS user
    // credential store, so it cannot verify a password. A request carrying
    // User-Password or CHAP-Password is a real credentialed auth attempt;
    // authorizing it on MAC alone would be an authentication bypass (the
    // credential would be silently ignored). Reject it rather than MAB-accept.
    if packet.has(radius::ATTR_USER_PASSWORD) || packet.has(radius::ATTR_CHAP_PASSWORD) {
        return reject("password-bearing request (PAP/CHAP not supported; MAB only)");
    }

    // Resolve the MAB MAC. The switch-observed source MAC (Calling-Station-Id)
    // is the identity anchor; if User-Name is also a MAC it must agree, so a
    // request can't assert one MAC as its source and a different (trusted) MAC
    // as its name. A request with no identifiable MAC can't be MAB-authorized
    // and is rejected rather than falling through to the "unknown" default.
    let calling = packet
        .get_string(radius::ATTR_CALLING_STATION_ID)
        .and_then(|s| normalize_mac(&s));
    let username_mac = packet
        .get_string(radius::ATTR_USER_NAME)
        .and_then(|s| normalize_mac(&s));
    let mac = match resolve_mab_mac(calling, username_mac) {
        MacResolution::Resolved(m) => m,
        MacResolution::Conflict => {
            return reject("User-Name MAC disagrees with Calling-Station-Id");
        }
        MacResolution::Missing => return reject("no MAC to authorize (MAB only)"),
    };

    let d = decide_for_mac(pool, &mac, Admission::Mab, Some(&client)).await;
    record(
        pool,
        &d,
        DecisionContext {
            front_end: FrontEnd::Embedded,
            admission: Admission::Mab,
            mac: &mac,
            identity: packet.get_string(radius::ATTR_USER_NAME).as_deref(),
            nas: Some(&client),
            // As accounting files the session (handle_acct).
            nas_address: Some(
                packet
                    .get_ipv4(radius::ATTR_NAS_IP_ADDRESS)
                    .unwrap_or_else(|| src.to_string()),
            ),
        },
    );

    let (code, attrs) = match &d.decision {
        Decision::Accept(vlan) => {
            let mut attrs = vlan.map(radius::vlan_attributes).unwrap_or_default();
            if let Some(role) = &d.role {
                attrs.extend(radius::role_attributes(client.role_attribute, role));
            }
            if let Some(secs) = d.session_timeout {
                attrs.extend(radius::session_timeout_attributes(secs));
            }
            (radius::CODE_ACCESS_ACCEPT, attrs)
        }
        Decision::Reject => (radius::CODE_ACCESS_REJECT, Vec::new()),
    };
    tracing::info!(
        client = %client.name,
        mac = %mac,
        trust = d.trust.map(|t| t.as_str()).unwrap_or("unknown/none"),
        enforced = d.enforced.map(|k| k.as_str()).unwrap_or("none"),
        signal = %d.signal_label(),
        reason = %d.reason,
        decision = ?d.decision,
        role = d.role.as_deref().filter(|_| client.role_attribute.sends_roles()).unwrap_or("none"),
        session_timeout = d.session_timeout.unwrap_or(0),
        "RADIUS MAB decision"
    );
    Some(radius::build_response(
        code,
        packet.id,
        &packet.authenticator,
        &attrs,
        secret,
        include_msg_auth,
    ))
}

/// Handles one Accounting-Request datagram: verifies it, records/updates the
/// session, and returns the Accounting-Response bytes.
async fn handle_acct(
    pool: &DbPool,
    key: &EncryptionKey,
    src: IpAddr,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let packet = Packet::parse(buf)?;
    if packet.code != radius::CODE_ACCOUNTING_REQUEST {
        return None;
    }
    let (client, secret) = client_for(pool, key, src).await?;
    let secret = secret.as_bytes();

    if !packet.verify_accounting_authenticator(secret) {
        tracing::warn!(client = %client.name, "RADIUS: Accounting-Request authenticator mismatch (wrong shared secret?)");
        return None;
    }

    let status = packet.get_u32(radius::ATTR_ACCT_STATUS_TYPE);
    let is_stop = status == Some(radius::ACCT_STATUS_STOP);
    let mac = packet
        .get_string(radius::ATTR_CALLING_STATION_ID)
        .and_then(|s| normalize_mac(&s));
    let nas_ip = packet
        .get_ipv4(radius::ATTR_NAS_IP_ADDRESS)
        .unwrap_or_else(|| src.to_string());
    let nas_port = packet
        .get_string(radius::ATTR_NAS_PORT_ID)
        .or_else(|| packet.get_string(radius::ATTR_CALLED_STATION_ID));
    let username = packet.get_string(radius::ATTR_USER_NAME);
    let framed_ip = packet.get_ipv4(radius::ATTR_FRAMED_IP_ADDRESS);
    let acct_session_id = packet.get_string(radius::ATTR_ACCT_SESSION_ID);
    let terminate_cause = packet
        .get_u32(radius::ATTR_ACCT_TERMINATE_CAUSE)
        .map(|c| c.to_string());

    let update = repo::panopticon_radius::SessionUpdate {
        username: username.as_deref(),
        mac_address: mac.as_deref(),
        nas_ip: Some(nas_ip.as_str()),
        nas_port: nas_port.as_deref(),
        framed_ip: framed_ip.as_deref(),
        acct_session_id: acct_session_id.as_deref(),
        auth_method: Some("accounting"),
        stop: is_stop,
        terminate_cause: terminate_cause.as_deref(),
    };
    if let Err(e) = repo::panopticon_radius::upsert_session(pool, &update).await {
        tracing::warn!(error = %e, "RADIUS: failed to record accounting session");
    }

    // Accounting-Response carries no attributes; just a signed acknowledgement.
    Some(radius::build_response(
        radius::CODE_ACCOUNTING_RESPONSE,
        packet.id,
        &packet.authenticator,
        &[],
        secret,
        false,
    ))
}

/// Spawns the RADIUS auth (1812) and accounting (1813) listeners if enabled.
/// No-ops when disabled or when no `ENCRYPTION_KEY` is configured (client shared
/// secrets are stored encrypted and couldn't be decrypted without it).
pub async fn spawn_panopticon_radius(pool: DbPool, encryption_key: Option<Arc<EncryptionKey>>) {
    let enabled = repo::settings::get_bool(
        &pool,
        abyssal_core::settings::PANOPTICON_RADIUS_ENABLED,
        false,
    )
    .await
    .unwrap_or(false);
    if !enabled {
        return;
    }
    // With FreeRADIUS in front (it shares this container's network and owns
    // UDP 1812/1813), binding here would fight it for the ports.
    if crate::panopticon_freeradius::enabled() {
        tracing::warn!(
            "Panopticon RADIUS is enabled, but FREERADIUS_API_TOKEN is set, so FreeRADIUS answers \
             RADIUS; the embedded listener isn't started"
        );
        return;
    }
    let Some(key) = encryption_key else {
        tracing::warn!("Panopticon RADIUS is enabled but ENCRYPTION_KEY isn't set; not starting");
        return;
    };
    let auth_port = repo::settings::get_u32(
        &pool,
        PANOPTICON_RADIUS_AUTH_PORT,
        PANOPTICON_RADIUS_AUTH_PORT_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_RADIUS_AUTH_PORT_DEFAULT) as u16;
    let acct_port = repo::settings::get_u32(
        &pool,
        PANOPTICON_RADIUS_ACCT_PORT,
        PANOPTICON_RADIUS_ACCT_PORT_DEFAULT,
    )
    .await
    .unwrap_or(PANOPTICON_RADIUS_ACCT_PORT_DEFAULT) as u16;

    spawn_listener(pool.clone(), key.clone(), auth_port, Handler::Auth);
    spawn_listener(pool, key, acct_port, Handler::Acct);
}

#[derive(Clone, Copy)]
enum Handler {
    Auth,
    Acct,
}

fn spawn_listener(pool: DbPool, key: Arc<EncryptionKey>, port: u16, handler: Handler) {
    tokio::spawn(async move {
        let socket = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, port, "Panopticon RADIUS listener failed to bind");
                return;
            }
        };
        let kind = match handler {
            Handler::Auth => "auth",
            Handler::Acct => "accounting",
        };
        tracing::info!(port, kind, "Panopticon RADIUS listener started");
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, kind, "RADIUS recv error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let datagram = buf[..n].to_vec();
            let pool = pool.clone();
            let key = key.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                let response = match handler {
                    Handler::Auth => handle_auth(&pool, &key, src.ip(), &datagram).await,
                    Handler::Acct => handle_acct(&pool, &key, src.ip(), &datagram).await,
                };
                if let Some(bytes) = response
                    && let Err(e) = socket.send_to(&bytes, src).await
                {
                    tracing::warn!(error = %e, kind, "RADIUS failed to send response");
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RadiusPolicy {
        RadiusPolicy {
            trusted_vlan: 10,
            quarantine_vlan: 999,
            untrusted_action: "quarantine".into(),
            unknown_action: "accept".into(),
            guest_vlan: 50,
            registration_vlan: 99,
            role_trusted: None,
            role_quarantine: None,
            role_unknown: None,
            role_guest: None,
            role_registration: None,
            timeout_trusted: 0,
            timeout_quarantine: 0,
            timeout_unknown: 0,
            timeout_guest: 0,
            timeout_registration: 0,
        }
    }

    fn inputs(trust: Option<TrustState>) -> DecisionInputs {
        DecisionInputs {
            trust,
            enforced: None,
            registered: false,
            admission: Admission::Mab,
            group_vlan: None,
            group_role: None,
            nas_applies_roles: true,
            signal: None,
            registration_expires_in: None,
        }
    }

    fn roles(mut p: RadiusPolicy) -> RadiusPolicy {
        p.role_trusted = Some("EMPLOYEE".into());
        p.role_quarantine = Some("QUARANTINE".into());
        p.role_unknown = Some("UNKNOWN".into());
        p.role_guest = Some("GUEST".into());
        p.role_registration = Some("REGISTER".into());
        p
    }

    fn verdict(vlan: Option<u32>, role: &str) -> Verdict {
        Verdict {
            decision: Decision::Accept(vlan),
            role: Some(role.into()),
            session_timeout: None,
        }
    }

    #[test]
    fn a_signal_tightens_every_admitting_outcome() {
        let p = roles(policy());
        let with = |trust, signal| DecisionInputs {
            signal: Some(signal),
            ..inputs(trust)
        };
        for trust in [Some(TrustState::Trusted), Some(TrustState::Unknown), None] {
            assert_eq!(
                decide_full(&with(trust, SignalAction::Quarantine), &p),
                verdict(Some(999), "QUARANTINE"),
                "{trust:?}"
            );
            assert_eq!(
                decide_full(&with(trust, SignalAction::Reject), &p).decision,
                Decision::Reject
            );
        }
        // An AD group's VLAN doesn't get a quarantined login out of it.
        let mut i = with(Some(TrustState::Trusted), SignalAction::Quarantine);
        i.admission = Admission::Authenticated;
        i.group_vlan = Some(30);
        i.group_role = Some("FINANCE".into());
        assert_eq!(decide_full(&i, &p), verdict(Some(999), "QUARANTINE"));
    }

    #[test]
    fn a_signal_never_loosens_a_reject_or_overrides_enforcement() {
        let mut p = roles(policy());
        p.untrusted_action = "reject".into();
        let mut i = inputs(Some(TrustState::Untrusted));
        i.signal = Some(SignalAction::Quarantine);
        assert_eq!(decide_full(&i, &p).decision, Decision::Reject);
        p.unknown_action = "reject".into();
        let mut i = inputs(None);
        i.signal = Some(SignalAction::Quarantine);
        assert_eq!(decide_full(&i, &p).decision, Decision::Reject);
        // Port quarantine stays quarantine, even with a reject signal
        // (enforcement wins, and signals aren't read under it anyway).
        let mut i = inputs(Some(TrustState::Trusted));
        i.enforced = Some(EnforcementKind::Quarantine);
        i.signal = Some(SignalAction::Reject);
        assert_eq!(decide_full(&i, &p), verdict(Some(999), "QUARANTINE"));
    }

    #[test]
    fn signal_quarantine_without_a_vlan_follows_the_nas() {
        let mut p = roles(policy());
        p.quarantine_vlan = 0;
        let mut i = inputs(Some(TrustState::Trusted));
        i.signal = Some(SignalAction::Quarantine);
        assert_eq!(decide_full(&i, &p), verdict(None, "QUARANTINE"));
        i.nas_applies_roles = false;
        assert_eq!(decide_full(&i, &p).decision, Decision::Reject);
    }

    #[test]
    fn strictest_signal_wins_then_the_first() {
        let s = |action, detail: &str| LoginSignal {
            action,
            detail: detail.into(),
        };
        assert_eq!(strictest(Vec::new()), None);
        assert_eq!(
            strictest(vec![
                s(SignalAction::Quarantine, "posture"),
                s(SignalAction::Reject, "thanatos"),
                s(SignalAction::Quarantine, "scourge"),
            ]),
            Some(s(SignalAction::Reject, "thanatos"))
        );
        assert_eq!(
            strictest(vec![
                s(SignalAction::Quarantine, "posture"),
                s(SignalAction::Quarantine, "scourge"),
            ]),
            Some(s(SignalAction::Quarantine, "posture"))
        );
    }

    #[test]
    fn signal_action_setting_defaults_to_quarantine() {
        assert_eq!(SignalAction::from_setting("reject"), SignalAction::Reject);
        assert_eq!(
            SignalAction::from_setting("quarantine"),
            SignalAction::Quarantine
        );
        assert_eq!(SignalAction::from_setting(""), SignalAction::Quarantine);
        assert!(SignalAction::Reject > SignalAction::Quarantine);
    }

    fn timeouts(mut p: RadiusPolicy) -> RadiusPolicy {
        p.timeout_trusted = 8 * 3600;
        p.timeout_quarantine = 600;
        p.timeout_unknown = 1800;
        p.timeout_guest = 3600;
        p.timeout_registration = 300;
        p
    }

    fn timeout_of(i: &DecisionInputs, p: &RadiusPolicy) -> Option<u32> {
        decide_full(i, p).session_timeout
    }

    #[test]
    fn each_outcome_carries_its_session_timeout() {
        let mut p = timeouts(policy());
        assert_eq!(
            timeout_of(&inputs(Some(TrustState::Trusted)), &p),
            Some(8 * 3600)
        );
        assert_eq!(
            timeout_of(&inputs(Some(TrustState::Untrusted)), &p),
            Some(600)
        );
        assert_eq!(timeout_of(&inputs(None), &p), Some(1800));
        // Port quarantine and a security signal use the quarantine timeout.
        let mut i = inputs(Some(TrustState::Trusted));
        i.enforced = Some(EnforcementKind::Quarantine);
        assert_eq!(timeout_of(&i, &p), Some(600));
        let mut i = inputs(Some(TrustState::Trusted));
        i.signal = Some(SignalAction::Quarantine);
        assert_eq!(timeout_of(&i, &p), Some(600));
        p.unknown_action = "guest".into();
        assert_eq!(timeout_of(&inputs(None), &p), Some(3600));
        p.unknown_action = "register".into();
        assert_eq!(timeout_of(&inputs(None), &p), Some(300));
        // A reject carries none.
        p.untrusted_action = "reject".into();
        assert_eq!(timeout_of(&inputs(Some(TrustState::Untrusted)), &p), None);
        // None configured: none sent (0.2.7 replies unchanged).
        assert_eq!(
            timeout_of(&inputs(Some(TrustState::Trusted)), &policy()),
            None
        );
    }

    #[test]
    fn a_registered_guest_session_ends_with_its_registration() {
        let mut p = timeouts(policy());
        p.unknown_action = "register".into();
        let mut i = inputs(None);
        i.registered = true;
        i.registration_expires_in = Some(1200);
        assert_eq!(timeout_of(&i, &p), Some(1200));
        i.registration_expires_in = Some(7200);
        assert_eq!(timeout_of(&i, &p), Some(3600));
        // Almost expired: not shorter than the floor.
        i.registration_expires_in = Some(5);
        assert_eq!(timeout_of(&i, &p), Some(MIN_SESSION_TIMEOUT_SECS));
        // No guest timeout set: nothing sent (off until configured).
        p.timeout_guest = 0;
        assert_eq!(timeout_of(&i, &p), None);
    }

    fn reason(i: &DecisionInputs, p: &RadiusPolicy) -> String {
        decide_explained(i, p).1
    }

    #[test]
    fn every_decision_says_what_it_was_based_on() {
        let mut p = roles(policy());
        assert_eq!(
            reason(&inputs(Some(TrustState::Trusted)), &p),
            "trusted device"
        );
        assert_eq!(
            reason(&inputs(Some(TrustState::Untrusted)), &p),
            "untrusted device: quarantine"
        );
        assert_eq!(reason(&inputs(None), &p), "unknown device: admitted");
        let mut i = inputs(Some(TrustState::Trusted));
        i.enforced = Some(EnforcementKind::Disable);
        assert_eq!(reason(&i, &p), "disabled by enforcement (port or device)");
        let mut i = inputs(Some(TrustState::Trusted));
        i.signal = Some(SignalAction::Quarantine);
        assert_eq!(
            reason(&i, &p),
            "security signal: quarantine (otherwise: trusted device)"
        );
        let mut i = inputs(Some(TrustState::Trusted));
        i.admission = Admission::Authenticated;
        i.group_vlan = Some(30);
        assert_eq!(reason(&i, &p), "trusted device, by AD group rule");
        // Quarantine by role alone, and its fail-closed reject, say so.
        p.quarantine_vlan = 0;
        assert_eq!(
            reason(&inputs(Some(TrustState::Untrusted)), &p),
            "untrusted device: quarantine (by role)"
        );
        let mut i = inputs(Some(TrustState::Untrusted));
        i.nas_applies_roles = false;
        assert_eq!(
            reason(&i, &p),
            "untrusted device: quarantine, but no quarantine VLAN (or role this NAS applies): rejected"
        );
        p.unknown_action = "register".into();
        p.registration_vlan = 0;
        assert_eq!(
            reason(&inputs(None), &p),
            "unknown device, not registered, and no registration VLAN: reject"
        );
    }

    fn client(attr: abyssal_core::RoleAttribute) -> RadiusClient {
        RadiusClient {
            id: uuid::Uuid::new_v4(),
            name: "lab-sw".into(),
            nas_address: "10.0.0.1".into(),
            shared_secret_encrypted: String::new(),
            enabled: true,
            coa_mode: abyssal_core::CoaMode::Disconnect,
            coa_port: 3799,
            role_attribute: attr,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn the_record_holds_what_was_sent_and_why() {
        let d = LoginDecision {
            decision: Decision::Accept(Some(999)),
            role: Some("QUARANTINE.in".into()),
            trust: Some(TrustState::Trusted),
            enforced: None,
            group_rule: None,
            signal: Some(LoginSignal {
                action: SignalAction::Quarantine,
                detail: "Cadavault posture score 40 (below 60)".into(),
            }),
            session_timeout: Some(600),
            reason: "security signal: quarantine (otherwise: trusted device)".into(),
            groups: vec!["CORP\\Finance".into(), "Staff".into()],
        };
        let filter_id = client(abyssal_core::RoleAttribute::FilterId);
        let ctx = |nas| DecisionContext {
            front_end: FrontEnd::FreeRadius,
            admission: Admission::Authenticated,
            mac: "AA:BB:CC:00:00:01",
            identity: Some("alice"),
            nas,
            nas_address: Some("10.0.0.1".into()),
        };
        let r = d.to_record(&ctx(Some(&filter_id)));
        assert_eq!(r.mac_address.as_deref(), Some("aa:bb:cc:00:00:01"));
        assert_eq!((r.outcome.as_str(), r.vlan), ("accept", Some(999)));
        assert_eq!(r.role.as_deref(), Some("QUARANTINE.in"));
        assert_eq!(r.session_timeout, Some(600));
        assert_eq!(
            (r.front_end.as_str(), r.admission.as_str()),
            ("freeradius", "dot1x")
        );
        assert_eq!(r.nas_name.as_deref(), Some("lab-sw"));
        assert_eq!(r.signal_action.as_deref(), Some("quarantine"));
        assert_eq!(r.ad_groups.as_deref(), Some("CORP\\Finance;Staff"));
        // A NAS without a role attribute was sent no role: none recorded.
        let none = client(abyssal_core::RoleAttribute::None);
        assert_eq!(d.to_record(&ctx(Some(&none))).role, None);
        assert_eq!(d.to_record(&ctx(None)).role, None);
    }

    #[test]
    fn each_outcome_carries_its_role() {
        let mut p = roles(policy());
        assert_eq!(
            decide_full(&inputs(Some(TrustState::Trusted)), &p),
            verdict(Some(10), "EMPLOYEE")
        );
        assert_eq!(
            decide_full(&inputs(Some(TrustState::Untrusted)), &p),
            verdict(Some(999), "QUARANTINE")
        );
        assert_eq!(decide_full(&inputs(None), &p), verdict(None, "UNKNOWN"));
        p.unknown_action = "guest".into();
        assert_eq!(decide_full(&inputs(None), &p), verdict(Some(50), "GUEST"));
        p.unknown_action = "register".into();
        assert_eq!(
            decide_full(&inputs(None), &p),
            verdict(Some(99), "REGISTER")
        );
        let mut registered = inputs(None);
        registered.registered = true;
        assert_eq!(decide_full(&registered, &p), verdict(Some(50), "GUEST"));
        // Enforcement: quarantine carries the quarantine role, even for a
        // trusted device; a reject never carries a role.
        let mut i = inputs(Some(TrustState::Trusted));
        i.enforced = Some(EnforcementKind::Quarantine);
        assert_eq!(decide_full(&i, &p), verdict(Some(999), "QUARANTINE"));
        i.enforced = Some(EnforcementKind::Disable);
        assert_eq!(
            decide_full(&i, &p),
            Verdict {
                decision: Decision::Reject,
                role: None,
                session_timeout: None,
            }
        );
        // No roles configured: the same decisions, no roles.
        let plain = policy();
        assert_eq!(
            decide_full(&inputs(Some(TrustState::Trusted)), &plain),
            Verdict {
                decision: Decision::Accept(Some(10)),
                role: None,
                session_timeout: None,
            }
        );
    }

    #[test]
    fn quarantine_by_role_alone_only_where_the_nas_applies_roles() {
        let mut p = roles(policy());
        p.quarantine_vlan = 0;
        let mut i = inputs(Some(TrustState::Untrusted));
        // A NAS that applies roles: admitted on its VLAN, restricted by role.
        assert_eq!(decide_full(&i, &p), verdict(None, "QUARANTINE"));
        // One that doesn't would let the device in unrestricted: reject.
        i.nas_applies_roles = false;
        assert_eq!(decide_full(&i, &p).decision, Decision::Reject);
        // No quarantine role either: reject, wherever.
        i.nas_applies_roles = true;
        p.role_quarantine = None;
        assert_eq!(decide_full(&i, &p).decision, Decision::Reject);
        // Same for an enforced quarantine.
        p.role_quarantine = Some("QUARANTINE".into());
        let mut e = inputs(Some(TrustState::Trusted));
        e.enforced = Some(EnforcementKind::Quarantine);
        assert_eq!(decide_full(&e, &p), verdict(None, "QUARANTINE"));
        e.nas_applies_roles = false;
        assert_eq!(decide_full(&e, &p).decision, Decision::Reject);
    }

    #[test]
    fn ad_group_role_replaces_the_outcome_role_where_its_vlan_would_apply() {
        let p = roles(policy());
        let mut i = inputs(Some(TrustState::Trusted));
        i.admission = Admission::Authenticated;
        i.group_role = Some("FINANCE".into());
        // A role-only rule: the trusted VLAN, the group's role.
        assert_eq!(decide_full(&i, &p), verdict(Some(10), "FINANCE"));
        i.group_vlan = Some(30);
        assert_eq!(decide_full(&i, &p), verdict(Some(30), "FINANCE"));
        // A rule without a role keeps the outcome's role.
        i.group_role = None;
        assert_eq!(decide_full(&i, &p), verdict(Some(30), "EMPLOYEE"));
        // Never over quarantine.
        i.group_role = Some("FINANCE".into());
        i.trust = Some(TrustState::Untrusted);
        assert_eq!(decide_full(&i, &p), verdict(Some(999), "QUARANTINE"));
        // Ignored for MAB.
        i.trust = Some(TrustState::Trusted);
        i.admission = Admission::Mab;
        assert_eq!(decide_full(&i, &p), verdict(Some(10), "EMPLOYEE"));
    }

    #[test]
    fn ad_group_vlan_only_chooses_among_admitting_outcomes() {
        let auth = Admission::Authenticated;
        let g = Some(30);
        let mut p = policy();
        // Trusted: the group's VLAN instead of the trusted VLAN.
        assert_eq!(
            decide(Some(TrustState::Trusted), None, false, auth, g, &p),
            Decision::Accept(Some(30))
        );
        // Enforcement and Untrusted always win.
        for kind in [EnforcementKind::Quarantine, EnforcementKind::Disable] {
            assert_eq!(
                decide(Some(TrustState::Trusted), Some(kind), false, auth, g, &p),
                decide(Some(TrustState::Trusted), Some(kind), false, auth, None, &p),
            );
        }
        assert_eq!(
            decide(Some(TrustState::Untrusted), None, false, auth, g, &p),
            Decision::Accept(Some(999))
        );
        p.untrusted_action = "reject".into();
        assert_eq!(
            decide(Some(TrustState::Untrusted), None, false, auth, g, &p),
            Decision::Reject
        );
        // Unknown devices: accept, guest and register take the group's VLAN;
        // reject stays a reject.
        for (action, want) in [
            ("accept", Decision::Accept(Some(30))),
            ("guest", Decision::Accept(Some(30))),
            ("register", Decision::Accept(Some(30))),
            ("reject", Decision::Reject),
        ] {
            p.unknown_action = action.into();
            assert_eq!(decide(None, None, false, auth, g, &p), want, "{action}");
            assert_eq!(
                decide(Some(TrustState::Unknown), None, false, auth, g, &p),
                want,
                "{action}"
            );
        }
        // Ignored for MAB (no login), and a VLAN of 0 means no group VLAN.
        p.unknown_action = "accept".into();
        assert_eq!(
            decide(
                Some(TrustState::Trusted),
                None,
                false,
                Admission::Mab,
                g,
                &p
            ),
            Decision::Accept(Some(10))
        );
        assert_eq!(
            decide(Some(TrustState::Trusted), None, false, auth, Some(0), &p),
            Decision::Accept(Some(10))
        );
    }

    #[test]
    fn trusted_device_is_accepted_with_its_vlan() {
        assert_eq!(
            decide(
                Some(TrustState::Trusted),
                None,
                false,
                Admission::Mab,
                None,
                &policy()
            ),
            Decision::Accept(Some(10))
        );
    }

    #[test]
    fn untrusted_device_is_quarantined_or_rejected() {
        let mut p = policy();
        assert_eq!(
            decide(
                Some(TrustState::Untrusted),
                None,
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Accept(Some(999))
        );
        p.untrusted_action = "reject".into();
        assert_eq!(
            decide(
                Some(TrustState::Untrusted),
                None,
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Reject
        );
        // Quarantine with no VLAN configured fails closed.
        p.untrusted_action = "quarantine".into();
        p.quarantine_vlan = 0;
        assert_eq!(
            decide(
                Some(TrustState::Untrusted),
                None,
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Reject
        );
    }

    #[test]
    fn unknown_device_follows_unknown_action() {
        let mut p = policy();
        // Default "accept" admits with no VLAN.
        assert_eq!(
            decide(None, None, false, Admission::Mab, None, &p),
            Decision::Accept(None)
        );
        assert_eq!(
            decide(
                Some(TrustState::Unknown),
                None,
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Accept(None)
        );
        p.unknown_action = "guest".into();
        assert_eq!(
            decide(None, None, false, Admission::Mab, None, &p),
            Decision::Accept(Some(50))
        );
        p.unknown_action = "reject".into();
        assert_eq!(
            decide(None, None, false, Admission::Mab, None, &p),
            Decision::Reject
        );
    }

    #[test]
    fn registration_portal_sends_unregistered_devices_to_register() {
        let mut p = policy();
        p.unknown_action = "register".into();
        assert_eq!(
            decide(None, None, false, Admission::Mab, None, &p),
            Decision::Accept(Some(99))
        );
        assert_eq!(
            decide(None, None, true, Admission::Mab, None, &p),
            Decision::Accept(Some(50))
        );
        assert_eq!(
            decide(
                Some(TrustState::Unknown),
                None,
                true,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Accept(Some(50))
        );
        // Classified devices don't go through the portal.
        assert_eq!(
            decide(
                Some(TrustState::Trusted),
                None,
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Accept(Some(10))
        );
        // A registered guest on a quarantined port is still quarantined.
        assert_eq!(
            decide(
                None,
                Some(EnforcementKind::Quarantine),
                true,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Accept(Some(999))
        );
        // No registration VLAN configured: fail closed.
        p.registration_vlan = 0;
        assert_eq!(
            decide(None, None, false, Admission::Mab, None, &p),
            Decision::Reject
        );
        // A device that passed 802.1X never needs the portal.
        assert_eq!(
            decide(None, None, false, Admission::Authenticated, None, &p),
            Decision::Accept(None)
        );
        // No guest VLAN: a registered guest is accepted without one.
        p.guest_vlan = 0;
        assert_eq!(
            decide(None, None, true, Admission::Mab, None, &p),
            Decision::Accept(None)
        );
    }

    #[test]
    fn port_enforcement_wins_over_trust() {
        let mut p = policy();
        let trusted = Some(TrustState::Trusted);
        // A trusted device on a quarantined port stays quarantined.
        assert_eq!(
            decide(
                trusted,
                Some(EnforcementKind::Quarantine),
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Accept(Some(999))
        );
        assert_eq!(
            decide(
                trusted,
                Some(EnforcementKind::Disable),
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Reject
        );
        // No quarantine VLAN: fail closed rather than admit.
        p.quarantine_vlan = 0;
        assert_eq!(
            decide(
                trusted,
                Some(EnforcementKind::Quarantine),
                false,
                Admission::Mab,
                None,
                &p
            ),
            Decision::Reject
        );
    }

    #[test]
    fn normalize_mac_handles_common_formats() {
        let want = Some("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), want);
        assert_eq!(normalize_mac("AABBCCDDEEFF"), want);
        assert_eq!(normalize_mac("aabb.ccdd.eeff"), want);
        assert_eq!(normalize_mac("AA:BB:CC:DD:EE:FF"), want);
        assert_eq!(normalize_mac("nope"), None);
    }

    #[test]
    fn resolve_mab_mac_requires_consistency() {
        let m = "aa:bb:cc:dd:ee:ff".to_string();
        let other = "11:22:33:44:55:66".to_string();
        // Calling-Station-Id alone, or agreeing User-Name, resolve.
        assert_eq!(
            resolve_mab_mac(Some(m.clone()), None),
            MacResolution::Resolved(m.clone())
        );
        assert_eq!(
            resolve_mab_mac(Some(m.clone()), Some(m.clone())),
            MacResolution::Resolved(m.clone())
        );
        // User-Name MAC disagreeing with the source MAC is a conflict.
        assert_eq!(
            resolve_mab_mac(Some(m.clone()), Some(other)),
            MacResolution::Conflict
        );
        // No MAC at all -> nothing to authorize.
        assert_eq!(resolve_mab_mac(None, None), MacResolution::Missing);
        // User-Name MAC only (no Calling-Station-Id) still resolves.
        assert_eq!(
            resolve_mab_mac(None, Some(m.clone())),
            MacResolution::Resolved(m)
        );
    }

    #[test]
    fn client_matches_ip_and_cidr() {
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        assert!(client_matches("10.0.0.7", ip));
        assert!(client_matches("10.0.0.0/24", ip));
        assert!(!client_matches("10.0.1.0/24", ip));
        assert!(!client_matches("10.0.0.8", ip));
    }
}
