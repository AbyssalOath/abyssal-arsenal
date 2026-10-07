use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::security_event::Severity;

/// The kind of indicator a threat-intel IOC is (M5). Determines how a finding's
/// text is matched: IPs and hashes by exact token, domains by token or any
/// subdomain of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    Ip,
    Domain,
    Hash,
}

impl IocType {
    pub const fn as_key(self) -> &'static str {
        match self {
            IocType::Ip => "ip",
            IocType::Domain => "domain",
            IocType::Hash => "hash",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "ip" => Some(IocType::Ip),
            "domain" => Some(IocType::Domain),
            "hash" => Some(IocType::Hash),
            _ => None,
        }
    }

    /// Normalizes a raw operator-entered value for this type: domains and hashes
    /// are lowercased (case-insensitive indicators), IPs are left as-is. Trims
    /// surrounding whitespace in all cases. Returns `None` for an empty value.
    pub fn normalize(self, raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        Some(match self {
            IocType::Ip => trimmed.to_string(),
            IocType::Domain | IocType::Hash => trimmed.to_ascii_lowercase(),
        })
    }
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_key())
    }
}

/// One threat-intel indicator of compromise (M5). Matched against every stored
/// finding's text at ingest; a match raises a dedicated high-signal `ioc`
/// finding. `value` is already normalized (see `IocType::normalize`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub id: Uuid,
    pub ioc_type: IocType,
    pub value: String,
    /// Severity to raise on a match.
    pub severity: Severity,
    /// Where this indicator came from (a feed name), shown in the match finding.
    pub label: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Ioc {
    /// Whether this indicator appears in `text`. Matching is **token-based**, not
    /// a raw substring, so an IP `10.0.0.5` never matches inside `210.0.0.59`
    /// and a domain `evil.com` never matches inside `notevil.com`. Tokens are
    /// maximal runs of alphanumerics plus `.`/`-`/`_` (so IPs, hashes and
    /// `host.domain.tld` stay intact), split on everything else (`/`, `:`, `=`,
    /// spaces, tabs...). A domain also matches any subdomain of itself.
    pub fn matches(&self, text: &str) -> bool {
        text.split(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-' || c == '_'))
            .filter(|t| !t.is_empty())
            .any(|token| match self.ioc_type {
                IocType::Ip => token == self.value,
                IocType::Hash => token.eq_ignore_ascii_case(&self.value),
                IocType::Domain => {
                    let token = token.to_ascii_lowercase();
                    token == self.value || token.ends_with(&format!(".{}", self.value))
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ioc(ioc_type: IocType, value: &str) -> Ioc {
        Ioc {
            id: Uuid::new_v4(),
            ioc_type,
            value: ioc_type.normalize(value).unwrap(),
            severity: Severity::High,
            label: None,
            created_by: None,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn ioc_type_round_trips() {
        for t in [IocType::Ip, IocType::Domain, IocType::Hash] {
            assert_eq!(IocType::from_key(t.as_key()), Some(t));
        }
        assert_eq!(IocType::from_key("nope"), None);
    }

    #[test]
    fn ip_matches_whole_token_only() {
        let i = ioc(IocType::Ip, "203.0.113.9");
        assert!(i.matches("remote_addr=203.0.113.9\tproto=tcp"));
        assert!(i.matches("connection from 203.0.113.9 refused"));
        assert!(!i.matches("remote_addr=203.0.113.90"));
        assert!(!i.matches("remote_addr=1203.0.113.9"));
    }

    #[test]
    fn domain_matches_itself_and_subdomains_case_insensitively() {
        let i = ioc(IocType::Domain, "Evil.com");
        assert_eq!(i.value, "evil.com");
        assert!(i.matches("GET http://evil.com/payload"));
        assert!(i.matches("lookup c2.evil.com ok"));
        assert!(i.matches("beacon to EVIL.COM"));
        assert!(!i.matches("notevil.com is fine"));
        assert!(!i.matches("evil.command.example"));
    }

    #[test]
    fn hash_matches_case_insensitively_as_token() {
        let i = ioc(IocType::Hash, "ABCDEF0123");
        assert!(i.matches("/etc/x hash changed to abcdef0123"));
        assert!(i.matches("Hashes=SHA256=ABCDEF0123"));
        assert!(!i.matches("abcdef01234"));
    }

    #[test]
    fn normalize_rejects_empty_and_lowercases() {
        assert_eq!(IocType::Domain.normalize("  "), None);
        assert_eq!(
            IocType::Hash.normalize(" DEADBEEF "),
            Some("deadbeef".to_string())
        );
        assert_eq!(
            IocType::Ip.normalize(" 10.0.0.5 "),
            Some("10.0.0.5".to_string())
        );
    }
}
