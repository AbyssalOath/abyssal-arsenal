//! Panopticon NAC phase 5 (embedded RADIUS server) model types -- the network
//! access servers (switches/APs) allowed to talk to the RADIUS listener, and
//! the authenticated sessions it has accounted. The wire protocol and the
//! server itself live in `abyssal_web::radius` / `abyssal_web::panopticon_radius`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A RADIUS client (a "NAS": a switch or AP) permitted to send Access/Accounting
/// requests. Matched by source address, keyed to a shared secret. The secret is
/// stored encrypted at rest (`abyssal_core::crypto::EncryptionKey`); callers
/// decrypt it only at the point of verifying/signing a packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusClient {
    pub id: Uuid,
    pub name: String,
    /// The NAS source address this client matches: either a bare IP
    /// ("10.0.0.2") or a CIDR ("10.0.0.0/24") covering a range of NAS devices.
    pub nas_address: String,
    pub shared_secret_encrypted: String,
    pub enabled: bool,
    /// How to push a re-authorization to this NAS (RFC 5176), 0.2.7 N2.
    pub coa_mode: CoaMode,
    /// UDP port the NAS listens on for CoA/Disconnect (RFC 5176 default 3799).
    pub coa_port: u16,
    /// Which attribute carries a role name in an Access-Accept (0.2.8 P2).
    pub role_attribute: RoleAttribute,
    pub created_at: DateTime<Utc>,
}

/// How a NAS is told which role (ACL, user role) an admitted device gets
/// (0.2.8 P2). The role or ACL itself is defined on the NAS; Panopticon only
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RoleAttribute {
    /// No role is sent (the default, and what every NAS got before 0.2.8).
    #[default]
    None,
    /// RFC 2865 `Filter-Id`: Cisco IOS named ACLs (`NAME.in`), Juniper,
    /// HPE/Aruba switches, and most others.
    FilterId,
    /// `Aruba-User-Role` (vendor 14823, type 1): Aruba controllers and
    /// AOS-CX/AOS-S switches with local user roles.
    ArubaUserRole,
}

impl RoleAttribute {
    pub const ALL: &'static [RoleAttribute] = &[
        RoleAttribute::None,
        RoleAttribute::FilterId,
        RoleAttribute::ArubaUserRole,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RoleAttribute::None => "none",
            RoleAttribute::FilterId => "filter_id",
            RoleAttribute::ArubaUserRole => "aruba_role",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            RoleAttribute::None => "None (VLAN only)",
            RoleAttribute::FilterId => "Filter-Id (Cisco ACL, most vendors)",
            RoleAttribute::ArubaUserRole => "Aruba-User-Role",
        }
    }

    /// Whether this NAS applies a role at all.
    pub const fn sends_roles(self) -> bool {
        !matches!(self, RoleAttribute::None)
    }
}

impl std::str::FromStr for RoleAttribute {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RoleAttribute::ALL
            .iter()
            .copied()
            .find(|m| m.as_str() == s)
            .ok_or(())
    }
}

/// Longest role name accepted (the column is VARCHAR(64)).
pub const ROLE_NAME_MAX_LEN: usize = 64;

/// Checks and trims a role (ACL / user role) name: 1 to
/// [`ROLE_NAME_MAX_LEN`] characters of letters, digits and `_ - . :`.
/// Strict on purpose: it goes verbatim into a RADIUS attribute that the NAS
/// matches against its own configuration. An empty input means "no role"
/// (`Ok(None)`).
pub fn validate_role_name(raw: &str) -> Result<Option<String>, &'static str> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.len() > ROLE_NAME_MAX_LEN {
        return Err("A role name can be 64 characters at most.");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err("A role name can only contain letters, digits, '_', '-', '.' and ':'.");
    }
    Ok(Some(name.to_string()))
}

/// How Panopticon asks a NAS to re-authorize a session after a device's trust
/// or quarantine changes (RFC 5176 Dynamic Authorization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CoaMode {
    /// Never: changes take effect at the device's next authentication.
    #[default]
    Off,
    /// Disconnect-Request: the NAS ends the session and the device
    /// re-authenticates, getting the new decision. Works on most switches and
    /// controllers; the device briefly loses access.
    Disconnect,
    /// CoA-Request carrying Cisco's `subscriber:command=reauthenticate`: the
    /// switch re-runs authorization without dropping the link. Cisco IOS/IOS-XE
    /// (and some others that copy it).
    CiscoReauth,
}

impl CoaMode {
    pub const ALL: &'static [CoaMode] = &[CoaMode::Off, CoaMode::Disconnect, CoaMode::CiscoReauth];

    pub const fn as_str(self) -> &'static str {
        match self {
            CoaMode::Off => "off",
            CoaMode::Disconnect => "disconnect",
            CoaMode::CiscoReauth => "cisco_reauth",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            CoaMode::Off => "Off",
            CoaMode::Disconnect => "Disconnect (RFC 5176)",
            CoaMode::CiscoReauth => "Reauthenticate (Cisco CoA)",
        }
    }
}

impl std::str::FromStr for CoaMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CoaMode::ALL
            .iter()
            .copied()
            .find(|m| m.as_str() == s)
            .ok_or(())
    }
}

/// One accounted RADIUS session, from the NAS's accounting stream -- the
/// "richer identity" record tying an authenticated user/MAC to where and when
/// it was on the network. Keyed uniquely by (`nas_ip`, `acct_session_id`);
/// Interim-Update refreshes `last_seen_at`, Stop sets `stopped_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusSession {
    pub id: Uuid,
    /// The authenticated identity: a real username for an EAP session, or the
    /// MAC for a MAB session.
    pub username: Option<String>,
    /// Device MAC (from Calling-Station-Id), normalized lower-colon where
    /// possible -- what ties a session back to an inventory device.
    pub mac_address: Option<String>,
    pub nas_ip: Option<String>,
    /// Switch port the session is on (Called-Station-Id / NAS-Port-Id).
    pub nas_port: Option<String>,
    pub framed_ip: Option<String>,
    pub acct_session_id: Option<String>,
    /// How Panopticon authorized it: "mab", "pap", or "accounting" (a session
    /// first seen via an accounting packet we didn't authorize ourselves).
    pub auth_method: Option<String>,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub terminate_cause: Option<String>,
    /// The latest CoA/Disconnect sent for this session and the NAS's answer.
    pub last_coa_at: Option<DateTime<Utc>>,
    pub last_coa_result: Option<String>,
}

impl RadiusSession {
    /// Whether this session is still open (no Stop recorded).
    pub fn is_active(&self) -> bool {
        self.stopped_at.is_none()
    }
}

/// An Active Directory group -> VLAN rule for 802.1X logins that passed PEAP
/// against AD (0.2.8 P1, `docs/roadmap/0.2.8.md`). Rules are ordered by
/// `position` (then age); the first whose group the login is in wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusGroupRule {
    pub id: Uuid,
    /// `DOMAIN\Group`, or a plain `Group` matching that name in any domain.
    pub group_name: String,
    /// 0 = keep the device's VLAN (the rule only sets a role).
    pub vlan: u16,
    /// The role (ACL / user role) the login gets, 0.2.8 P2.
    pub role: Option<String>,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

/// Longest group name accepted (the column is VARCHAR(256)).
pub const GROUP_NAME_MAX_LEN: usize = 256;

/// Separates group names on their way through FreeRADIUS
/// (`Abyssal-AD-Group-Candidates`, `Abyssal-AD-Groups`). AD doesn't allow it
/// in a group's pre-Windows 2000 name, which is the name winbind reports.
pub const GROUP_LIST_SEPARATOR: char = ';';

/// Checks and trims a group name for a rule: non-empty, at most
/// [`GROUP_NAME_MAX_LEN`] characters, no [`GROUP_LIST_SEPARATOR`], no
/// control characters, and at most one `DOMAIN\` prefix with both sides
/// non-empty.
pub fn validate_group_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("The group name is required.");
    }
    if name.chars().count() > GROUP_NAME_MAX_LEN {
        return Err("The group name is too long (256 characters at most).");
    }
    if name.contains(GROUP_LIST_SEPARATOR) || name.chars().any(char::is_control) {
        return Err("The group name can't contain ';' or control characters.");
    }
    if let Some((domain, group)) = name.split_once('\\')
        && (domain.trim().is_empty() || group.trim().is_empty() || group.contains('\\'))
    {
        return Err("Write the group as DOMAIN\\Group, or just Group.");
    }
    Ok(name.to_string())
}

/// Whether a login's group (`DOMAIN\Group` or `Group`, as FreeRADIUS reports
/// it) is the group a rule names. Case-insensitive; a rule without a domain
/// matches the name in any domain.
pub fn group_matches(rule_group: &str, login_group: &str) -> bool {
    let rule = rule_group.trim().to_lowercase();
    let login = login_group.trim().to_lowercase();
    if rule.is_empty() || login.is_empty() {
        return false;
    }
    if rule == login {
        return true;
    }
    match (rule.contains('\\'), login.rsplit_once('\\')) {
        // A plain rule name matches the login group's name in any domain.
        (false, Some((_, name))) => rule == name,
        _ => false,
    }
}

/// The first rule (in the given order: callers pass rules sorted by
/// position) whose group is one of the login's groups.
pub fn first_matching_group_rule<'a>(
    rules: &'a [RadiusGroupRule],
    groups: &[String],
) -> Option<&'a RadiusGroupRule> {
    rules
        .iter()
        .find(|r| groups.iter().any(|g| group_matches(&r.group_name, g)))
}

/// Splits a `;`-separated group list from FreeRADIUS, dropping empty items.
pub fn split_group_list(raw: &str) -> Vec<String> {
    raw.split(GROUP_LIST_SEPARATOR)
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .map(str::to_string)
        .collect()
}

/// One RADIUS admission decision as recorded (0.2.9 Q2,
/// `docs/roadmap/0.2.9.md`): what was decided, for whom, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusDecisionRecord {
    pub id: Uuid,
    pub decided_at: DateTime<Utc>,
    pub mac_address: Option<String>,
    pub nas_client_id: Option<Uuid>,
    pub nas_name: Option<String>,
    pub nas_address: Option<String>,
    /// `embedded` | `freeradius`
    pub front_end: String,
    /// `mab` | `dot1x`
    pub admission: String,
    pub identity: Option<String>,
    /// `accept` | `reject`
    pub outcome: String,
    pub vlan: Option<u16>,
    /// The role sent, if any.
    pub role: Option<String>,
    pub session_timeout: Option<u32>,
    /// What it was based on, e.g. "security signal: quarantine".
    pub reason: String,
    pub trust_state: Option<String>,
    pub enforcement: Option<String>,
    pub signal_action: Option<String>,
    pub signal_detail: Option<String>,
    pub group_rule: Option<String>,
    /// The login's AD groups that have a rule, `;`-separated.
    pub ad_groups: Option<String>,
}

impl RadiusDecisionRecord {
    pub fn accepted(&self) -> bool {
        self.outcome == "accept"
    }

    /// One line for a table: "accept, VLAN 10, role EMPLOYEE.in, 8 h" or
    /// "reject".
    pub fn summary(&self) -> String {
        if !self.accepted() {
            return "reject".into();
        }
        let mut parts = vec!["accept".to_string()];
        if let Some(v) = self.vlan {
            parts.push(format!("VLAN {v}"));
        }
        if let Some(r) = &self.role {
            parts.push(format!("role {r}"));
        }
        if let Some(t) = self.session_timeout {
            parts.push(format!("re-auth {}", duration_label(t)));
        }
        parts.join(", ")
    }

    /// The reasons for a table: the reason, then the signal and group rule.
    pub fn why(&self) -> String {
        let mut parts = vec![self.reason.clone()];
        if let Some(d) = &self.signal_detail {
            parts.push(d.clone());
        }
        if let Some(g) = &self.group_rule {
            parts.push(format!("AD group rule {g}"));
        }
        parts.join("; ")
    }
}

/// "45 s", "10 min", "8 h", "1 h 30 min".
pub fn duration_label(secs: u32) -> String {
    match secs {
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min", s / 60),
        s if s % 3600 < 60 => format!("{} h", s / 3600),
        s => format!("{} h {} min", s / 3600, (s % 3600) / 60),
    }
}

/// How long before a session's accounting Start its Access-Accept can be:
/// the Accept always comes first, by seconds.
pub const DECISION_BEFORE_SESSION_SLACK_SECS: i64 = 300;

/// The decision a session is running on (0.2.9 Q2): of `decisions` (one
/// MAC's, any order), the latest made between shortly before the session
/// started and when it stopped (if it has), preferring those from the
/// session's own NAS address. Re-authentications make new decisions, so
/// the latest is the one in force.
pub fn decision_for_session<'a>(
    session: &RadiusSession,
    decisions: &'a [RadiusDecisionRecord],
) -> Option<&'a RadiusDecisionRecord> {
    let from = session.started_at - chrono::Duration::seconds(DECISION_BEFORE_SESSION_SLACK_SECS);
    let mac = session.mac_address.as_deref()?.to_ascii_lowercase();
    let in_window = |d: &&RadiusDecisionRecord| {
        d.mac_address
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
            == Some(mac.as_str())
            && d.decided_at >= from
            && session.stopped_at.is_none_or(|stop| d.decided_at <= stop)
    };
    let same_nas = |d: &&RadiusDecisionRecord| {
        session.nas_ip.is_some() && d.nas_address.as_deref() == session.nas_ip.as_deref()
    };
    decisions
        .iter()
        .filter(in_window)
        .filter(same_nas)
        .max_by_key(|d| d.decided_at)
        .or_else(|| {
            decisions
                .iter()
                .filter(in_window)
                .max_by_key(|d| d.decided_at)
        })
}

#[cfg(test)]
mod group_rule_tests {
    use super::*;

    fn rule(group: &str, vlan: u16) -> RadiusGroupRule {
        RadiusGroupRule {
            id: Uuid::new_v4(),
            group_name: group.into(),
            vlan,
            role: None,
            position: 0,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn group_names_are_validated() {
        assert_eq!(
            validate_group_name("  CORP\\WiFi Users ").unwrap(),
            "CORP\\WiFi Users"
        );
        assert_eq!(validate_group_name("Finance").unwrap(), "Finance");
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name("   ").is_err());
        assert!(validate_group_name("a;b").is_err());
        assert!(validate_group_name("a\nb").is_err());
        assert!(validate_group_name("\\Finance").is_err());
        assert!(validate_group_name("CORP\\").is_err());
        assert!(validate_group_name("A\\B\\C").is_err());
        assert!(validate_group_name(&"x".repeat(257)).is_err());
        assert!(validate_group_name(&"x".repeat(256)).is_ok());
    }

    #[test]
    fn matching_is_case_insensitive_and_domain_aware() {
        assert!(group_matches("CORP\\Finance", "corp\\finance"));
        assert!(group_matches("Finance", "CORP\\Finance"));
        assert!(group_matches("Finance", "finance"));
        assert!(!group_matches("CORP\\Finance", "OTHER\\Finance"));
        assert!(!group_matches("CORP\\Finance", "Finance"));
        assert!(!group_matches("Finance", "CORP\\Finance-Admins"));
        assert!(!group_matches("", "Finance"));
        assert!(!group_matches("Finance", ""));
    }

    #[test]
    fn first_rule_in_order_wins() {
        let rules = vec![
            rule("CORP\\Admins", 10),
            rule("Staff", 20),
            rule("Finance", 30),
        ];
        let groups = vec!["CORP\\Finance".to_string(), "CORP\\Staff".to_string()];
        assert_eq!(first_matching_group_rule(&rules, &groups).unwrap().vlan, 20);
        assert!(first_matching_group_rule(&rules, &[]).is_none());
        assert!(first_matching_group_rule(&[], &groups).is_none());
        let none = vec!["CORP\\Sales".to_string()];
        assert!(first_matching_group_rule(&rules, &none).is_none());
    }

    #[test]
    fn role_names_are_validated() {
        assert_eq!(
            validate_role_name(" QUARANTINE.in ").unwrap().as_deref(),
            Some("QUARANTINE.in")
        );
        assert_eq!(
            validate_role_name("guest-role_1:a").unwrap().as_deref(),
            Some("guest-role_1:a")
        );
        assert_eq!(validate_role_name("  ").unwrap(), None);
        assert!(validate_role_name("has space").is_err());
        assert!(validate_role_name("semi;colon").is_err());
        assert!(validate_role_name("%{User-Name}").is_err());
        assert!(validate_role_name("ünicode").is_err());
        assert!(validate_role_name(&"r".repeat(65)).is_err());
        assert!(validate_role_name(&"r".repeat(64)).is_ok());
    }

    #[test]
    fn role_attributes_round_trip() {
        for a in RoleAttribute::ALL {
            assert_eq!(a.as_str().parse::<RoleAttribute>(), Ok(*a));
        }
        assert!("cisco".parse::<RoleAttribute>().is_err());
        assert!(!RoleAttribute::None.sends_roles());
        assert!(RoleAttribute::FilterId.sends_roles());
    }

    #[test]
    fn group_lists_split_on_semicolons() {
        assert_eq!(
            split_group_list("CORP\\WiFi Users; Staff;;"),
            vec!["CORP\\WiFi Users".to_string(), "Staff".to_string()]
        );
        assert!(split_group_list("").is_empty());
        assert!(split_group_list(" ; ").is_empty());
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn at(min: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap() + Duration::minutes(min)
    }

    fn decision(min: i64, mac: &str, nas: &str, vlan: u16) -> RadiusDecisionRecord {
        RadiusDecisionRecord {
            id: Uuid::new_v4(),
            decided_at: at(min),
            mac_address: Some(mac.into()),
            nas_client_id: None,
            nas_name: None,
            nas_address: Some(nas.into()),
            front_end: "embedded".into(),
            admission: "mab".into(),
            identity: None,
            outcome: "accept".into(),
            vlan: Some(vlan),
            role: None,
            session_timeout: None,
            reason: "trusted device".into(),
            trust_state: None,
            enforcement: None,
            signal_action: None,
            signal_detail: None,
            group_rule: None,
            ad_groups: None,
        }
    }

    fn session(started: i64, stopped: Option<i64>, nas: &str) -> RadiusSession {
        RadiusSession {
            id: Uuid::new_v4(),
            username: None,
            mac_address: Some("AA:BB:CC:00:00:01".into()),
            nas_ip: Some(nas.into()),
            nas_port: None,
            framed_ip: None,
            acct_session_id: None,
            auth_method: None,
            started_at: at(started),
            last_seen_at: at(started),
            stopped_at: stopped.map(at),
            terminate_cause: None,
            last_coa_at: None,
            last_coa_result: None,
        }
    }

    #[test]
    fn a_session_runs_on_its_latest_decision() {
        let mac = "aa:bb:cc:00:00:01";
        let ds = vec![
            decision(-60, mac, "10.0.0.1", 1),  // long before: another session
            decision(0, mac, "10.0.0.1", 10),   // its Accept
            decision(30, mac, "10.0.0.1", 999), // a re-authentication
            decision(31, "aa:bb:cc:00:00:02", "10.0.0.1", 5),
        ];
        let s = session(0, None, "10.0.0.1");
        assert_eq!(
            decision_for_session(&s, &ds).and_then(|d| d.vlan),
            Some(999)
        );
        // Stopped before the re-authentication.
        let s = session(0, Some(20), "10.0.0.1");
        assert_eq!(decision_for_session(&s, &ds).and_then(|d| d.vlan), Some(10));
        // The Accept a little before accounting Start counts.
        let s = session(3, Some(20), "10.0.0.1");
        assert_eq!(decision_for_session(&s, &ds).and_then(|d| d.vlan), Some(10));
        // Nothing in the window.
        let s = session(-200, Some(-100), "10.0.0.1");
        assert!(decision_for_session(&s, &ds).is_none());
    }

    #[test]
    fn the_sessions_own_nas_is_preferred() {
        let mac = "aa:bb:cc:00:00:01";
        let ds = vec![
            decision(1, mac, "10.0.0.1", 10),
            decision(2, mac, "10.0.0.2", 20),
        ];
        let s = session(0, None, "10.0.0.1");
        assert_eq!(decision_for_session(&s, &ds).and_then(|d| d.vlan), Some(10));
        // A NAS that reports another address than it sends from: any NAS.
        let s = session(0, None, "192.0.2.9");
        assert_eq!(decision_for_session(&s, &ds).and_then(|d| d.vlan), Some(20));
    }

    #[test]
    fn summaries_and_durations() {
        let mut d = decision(0, "aa:bb:cc:00:00:01", "10.0.0.1", 10);
        d.role = Some("EMPLOYEE.in".into());
        d.session_timeout = Some(8 * 3600);
        assert_eq!(
            d.summary(),
            "accept, VLAN 10, role EMPLOYEE.in, re-auth 8 h"
        );
        d.signal_detail = Some("Cadavault posture score 40 (below 60)".into());
        d.group_rule = Some("CORP\\Finance".into());
        assert_eq!(
            d.why(),
            "trusted device; Cadavault posture score 40 (below 60); AD group rule CORP\\Finance"
        );
        d.outcome = "reject".into();
        assert_eq!(d.summary(), "reject");
        assert_eq!(duration_label(45), "45 s");
        assert_eq!(duration_label(600), "10 min");
        assert_eq!(duration_label(1197), "19 min");
        assert_eq!(duration_label(3600), "1 h");
        assert_eq!(duration_label(5400), "1 h 30 min");
    }
}
