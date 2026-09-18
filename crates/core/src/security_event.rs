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
    pub raw_line: String,
    pub occurred_at: DateTime<Utc>,
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
    fn unknown_severity_key_resolves_to_none() {
        assert_eq!(Severity::from_key("not-a-severity"), None);
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
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
