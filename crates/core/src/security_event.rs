use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// How serious a Thanatos security event is. Ordered (`Low` < `Medium` <
/// `High` < `Critical`) so a correlation sweep can threshold on it
/// directly. `Critical` is reserved for the control plane's own
/// correlation findings -- individual classified log lines from an agent
/// are never more than `High` (see `AgentOperation::ScanSecurityEvents`'s
/// doc comment), so seeing `Critical` in the event log always means "the
/// correlation sweep raised this," never "one log line looked this bad."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_key(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_key())
    }
}

/// An event's place in its (manual, analyst-driven) lifecycle -- Thanatos
/// SIEM/EDR build-out, Phase 3, the first real use of
/// `Permission::SecurityManage`. Every event starts `Open`; nothing here
/// ever transitions a status automatically (a re-scan matching the same
/// content hash is a no-op via `INSERT IGNORE`, not a "reopen").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EventStatus {
    #[default]
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
}

impl EventStatus {
    pub const fn as_key(self) -> &'static str {
        match self {
            EventStatus::Open => "open",
            EventStatus::Acknowledged => "acknowledged",
            EventStatus::Resolved => "resolved",
            EventStatus::Suppressed => "suppressed",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "open" => Some(EventStatus::Open),
            "acknowledged" => Some(EventStatus::Acknowledged),
            "resolved" => Some(EventStatus::Resolved),
            "suppressed" => Some(EventStatus::Suppressed),
            _ => None,
        }
    }

    /// Whether a view that's hiding "settled" events should show this one
    /// -- `Open`/`Acknowledged` are still active, `Resolved`/`Suppressed`
    /// are done with.
    pub const fn is_active(self) -> bool {
        matches!(self, EventStatus::Open | EventStatus::Acknowledged)
    }
}

impl std::fmt::Display for EventStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_key())
    }
}

/// One classified security-relevant log line (or, when `source` is
/// `"correlation"`, one threshold finding the control plane itself
/// raised) persisted by Thanatos. `line_hash` is what the database
/// actually deduplicates on -- re-scanning the same tail window on every
/// sweep is expected and harmless, not something this type needs to
/// prevent itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub host_id: Uuid,
    pub source: String,
    pub severity: Severity,
    pub label: String,
    /// MITRE ATT&CK technique ID this finding maps to (e.g. `T1003.001`), or
    /// empty when none is mapped. Annotated control-plane-side from the
    /// finding's label (see `thanatos_ops::technique_for`), not sent by the
    /// agent, so it can be refined without an agent rebuild.
    pub technique: String,
    pub raw_line: String,
    pub occurred_at: DateTime<Utc>,
    pub status: EventStatus,
    /// Who last changed `status` away from `Open` -- `None` for an event
    /// still in its default state, or one from before Phase 3.
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// A free-text note attached at resolve/suppress time -- optional
    /// even then, and always `None` for a merely-acknowledged event.
    pub resolution_note: Option<String>,
}

/// A Thanatos suppression / allowlist rule (M4): matched against each incoming
/// classified finding at ingest, and any finding it matches is dropped (never
/// persisted, never alerted). One mechanism serves both "suppress this class of
/// finding" (match by `label`/`source`/`technique`) and "allowlist this
/// known-good indicator" (match by `text_contains`, e.g. a monitoring box's IP
/// or a service account). Every set criterion must match (AND); an unset
/// criterion doesn't constrain. A rule with no criteria set would match
/// everything and is rejected at creation (`has_criteria`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRule {
    pub id: Uuid,
    /// Restrict to one host; `None` applies fleet-wide.
    pub host_id: Option<Uuid>,
    pub source: Option<String>,
    pub label: Option<String>,
    pub technique: Option<String>,
    /// A substring that must appear in the finding's `raw_line` (the allowlist
    /// pivot: an IP, username, hash, process name, ...).
    pub text_contains: Option<String>,
    pub reason: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    /// Optional expiry -- a temporary suppression that stops applying after this
    /// instant. `None` never expires.
    pub expires_at: Option<DateTime<Utc>>,
}

impl SuppressionRule {
    /// Whether at least one matching criterion is set -- a rule with none would
    /// match (and drop) every finding, so creation rejects it.
    pub fn has_criteria(&self) -> bool {
        self.host_id.is_some()
            || self.source.is_some()
            || self.label.is_some()
            || self.technique.is_some()
            || self.text_contains.is_some()
    }

    /// Whether this rule matches a finding. Every set criterion must match; an
    /// unset (`None`) criterion is a wildcard. Expiry is handled by the caller
    /// (active rules are loaded already-filtered), so this is pure criteria.
    ///
    /// `text_contains` is matched on **token boundaries**, not as a raw
    /// substring: the value must equal a whole token of `raw_line` (tokens split
    /// on anything that isn't alphanumeric/`.`/`-`/`_`). This is deliberate --
    /// an allowlist indicator like the IP `10.0.0.5` must not be satisfied by an
    /// attacker embedding it inside `210.0.0.59`, a different username, or
    /// arbitrary attacker-controlled free text in the line, which a plain
    /// substring match would allow (a detection-evasion bypass). Operators are
    /// encouraged to pair a `text_contains` allowlist with a `source`/`label` so
    /// a single token can't silence unrelated finding classes.
    pub fn matches(
        &self,
        host_id: Uuid,
        source: &str,
        label: &str,
        technique: &str,
        raw_line: &str,
    ) -> bool {
        self.host_id.is_none_or(|h| h == host_id)
            && self.source.as_deref().is_none_or(|s| s == source)
            && self.label.as_deref().is_none_or(|l| l == label)
            && self.technique.as_deref().is_none_or(|t| t == technique)
            && self
                .text_contains
                .as_deref()
                .is_none_or(|t| contains_token(raw_line, t))
    }
}

/// Whether `needle` equals a whole token of `haystack`. Tokens are maximal runs
/// of characters that make up an indicator -- alphanumerics plus `.`/`-`/`_`
/// (so IPv4 addresses, hostnames, usernames and `name.exe` stay intact) --
/// separated by anything else (spaces, `=`, `\`, tabs, `:`...). Used so an
/// allowlist value matches an indicator exactly, never as an embedded substring.
fn contains_token(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack
        .split(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-' || c == '_'))
        .any(|token| token == needle)
}

/// The dedup key `thanatos_events` uniquely constrains on. Stable across
/// repeated scans of the same log tail window -- that's the point:
/// re-scanning is expected, and this is what makes it a harmless no-op
/// via `INSERT IGNORE` rather than a duplicate row -- but distinct per
/// host and per source, so the same raw line from two different hosts, or
/// two different log sources on the same host, never collides.
pub fn hash_event_line(host_id: Uuid, source: &str, raw_line: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(host_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(source.as_bytes());
    hasher.update(b"\0");
    hasher.update(raw_line.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_round_trips_through_its_key() {
        for s in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::from_key(s.as_key()), Some(s));
        }
    }

    #[test]
    fn event_status_round_trips_through_its_key() {
        for s in [
            EventStatus::Open,
            EventStatus::Acknowledged,
            EventStatus::Resolved,
            EventStatus::Suppressed,
        ] {
            assert_eq!(EventStatus::from_key(s.as_key()), Some(s));
        }
    }

    #[test]
    fn unknown_event_status_key_resolves_to_none() {
        assert_eq!(EventStatus::from_key("not-a-status"), None);
    }

    #[test]
    fn event_status_defaults_to_open() {
        assert_eq!(EventStatus::default(), EventStatus::Open);
    }

    #[test]
    fn open_and_acknowledged_are_active_resolved_and_suppressed_are_not() {
        assert!(EventStatus::Open.is_active());
        assert!(EventStatus::Acknowledged.is_active());
        assert!(!EventStatus::Resolved.is_active());
        assert!(!EventStatus::Suppressed.is_active());
    }

    #[test]
    fn unknown_severity_key_resolves_to_none() {
        assert_eq!(Severity::from_key("not-a-severity"), None);
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    fn rule(
        host_id: Option<Uuid>,
        source: Option<&str>,
        label: Option<&str>,
        technique: Option<&str>,
        text_contains: Option<&str>,
    ) -> SuppressionRule {
        SuppressionRule {
            id: Uuid::new_v4(),
            host_id,
            source: source.map(str::to_string),
            label: label.map(str::to_string),
            technique: technique.map(str::to_string),
            text_contains: text_contains.map(str::to_string),
            reason: None,
            created_by: None,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn suppression_rule_requires_at_least_one_criterion() {
        assert!(!rule(None, None, None, None, None).has_criteria());
        assert!(rule(None, Some("sysmon"), None, None, None).has_criteria());
        assert!(rule(None, None, None, None, Some("10.0.0.5")).has_criteria());
    }

    #[test]
    fn suppression_rule_matches_all_set_criteria_and_wildcards_the_rest() {
        let host = Uuid::new_v4();
        let other = Uuid::new_v4();
        // Allowlist a known-good IP anywhere in the raw line.
        let r = rule(None, None, None, None, Some("10.0.0.5"));
        assert!(r.matches(
            host,
            "security",
            "Windows failed logon",
            "T1110",
            "... from 10.0.0.5 ..."
        ));
        assert!(!r.matches(
            host,
            "security",
            "Windows failed logon",
            "T1110",
            "... from 10.0.0.9 ..."
        ));
        // Suppress a class on one host only.
        let r = rule(Some(host), Some("posture"), None, None, None);
        assert!(r.matches(
            host,
            "posture",
            "SMBv1 protocol enabled",
            "",
            "EnableSMB1Protocol=true"
        ));
        assert!(!r.matches(
            other,
            "posture",
            "SMBv1 protocol enabled",
            "",
            "EnableSMB1Protocol=true"
        ));
        assert!(!r.matches(host, "security", "SMBv1 protocol enabled", "", "x"));
        // Match by technique.
        let r = rule(None, None, None, Some("T1003.001"), None);
        assert!(r.matches(
            host,
            "sysmon",
            "Possible LSASS memory access (credential theft)",
            "T1003.001",
            "x"
        ));
        assert!(!r.matches(host, "sysmon", "x", "T1055", "x"));
    }

    #[test]
    fn text_allowlist_matches_whole_tokens_not_embedded_substrings() {
        let host = Uuid::new_v4();
        let r = rule(None, None, None, None, Some("10.0.0.5"));
        // Exact token in various delimiter contexts matches.
        assert!(r.matches(host, "security", "x", "", "from 10.0.0.5 port 22"));
        assert!(r.matches(host, "security", "x", "", "remote_addr=10.0.0.5\tproto=tcp"));
        // Embedded in a larger number / different address must NOT match
        // (the detection-evasion bypass a raw substring match would allow).
        assert!(!r.matches(host, "security", "x", "", "from 210.0.0.59 port 22"));
        assert!(!r.matches(host, "security", "x", "", "from 10.0.0.50 port 22"));
        // Username token allowlist.
        let r = rule(None, None, None, None, Some("svc_scanner"));
        assert!(r.matches(host, "security", "x", "", "Account=svc_scanner logged on"));
        assert!(!r.matches(
            host,
            "security",
            "x",
            "",
            "Account=svc_scanner_admin logged on"
        ));
    }

    #[test]
    fn event_hash_is_deterministic_and_distinguishes_source_and_host() {
        let host_a = Uuid::new_v4();
        let host_b = Uuid::new_v4();
        assert_eq!(
            hash_event_line(host_a, "auth.log", "Failed password for root"),
            hash_event_line(host_a, "auth.log", "Failed password for root")
        );
        assert_ne!(
            hash_event_line(host_a, "auth.log", "Failed password for root"),
            hash_event_line(host_b, "auth.log", "Failed password for root")
        );
        assert_ne!(
            hash_event_line(host_a, "auth.log", "Failed password for root"),
            hash_event_line(host_a, "secure", "Failed password for root")
        );
    }
}
