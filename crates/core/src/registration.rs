//! Guest registrations from Panopticon's registration portal (0.2.7 N5, see
//! `docs/roadmap/0.2.7.md`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationStatus {
    Pending,
    Approved,
    Denied,
    Revoked,
    Expired,
}

impl RegistrationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            RegistrationStatus::Pending => "pending",
            RegistrationStatus::Approved => "approved",
            RegistrationStatus::Denied => "denied",
            RegistrationStatus::Revoked => "revoked",
            RegistrationStatus::Expired => "expired",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            RegistrationStatus::Pending => "Waiting for approval",
            RegistrationStatus::Approved => "Approved",
            RegistrationStatus::Denied => "Denied",
            RegistrationStatus::Revoked => "Revoked",
            RegistrationStatus::Expired => "Expired",
        }
    }
}

impl std::str::FromStr for RegistrationStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "pending" => RegistrationStatus::Pending,
            "approved" => RegistrationStatus::Approved,
            "denied" => RegistrationStatus::Denied,
            "revoked" => RegistrationStatus::Revoked,
            "expired" => RegistrationStatus::Expired,
            _ => return Err(()),
        })
    }
}

/// How the portal grants access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortalMode {
    /// A guest who accepts the terms is approved at once.
    SelfService,
    /// Staff approve each request on the registrations page.
    #[default]
    Sponsor,
}

impl PortalMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            PortalMode::SelfService => "self",
            PortalMode::Sponsor => "sponsor",
        }
    }

    pub fn parse(s: &str) -> Self {
        if s == "self" {
            PortalMode::SelfService
        } else {
            PortalMode::Sponsor
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub mac_address: String,
    pub name: String,
    pub email: Option<String>,
    pub status: RegistrationStatus,
    pub requested_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Registration {
    /// Whether the device has guest access right now.
    pub fn grants_access(&self, now: DateTime<Utc>) -> bool {
        self.status == RegistrationStatus::Approved && self.expires_at.is_some_and(|e| e > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn only_unexpired_approvals_grant_access() {
        let now = Utc::now();
        let mut r = Registration {
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            name: "Guest".into(),
            email: None,
            status: RegistrationStatus::Approved,
            requested_at: now,
            decided_at: Some(now),
            decided_by: None,
            expires_at: Some(now + Duration::hours(1)),
        };
        assert!(r.grants_access(now));
        assert!(!r.grants_access(now + Duration::hours(2)));
        r.status = RegistrationStatus::Pending;
        assert!(!r.grants_access(now));
        r.status = RegistrationStatus::Approved;
        r.expires_at = None;
        assert!(!r.grants_access(now));
    }

    #[test]
    fn statuses_round_trip() {
        for s in [
            RegistrationStatus::Pending,
            RegistrationStatus::Approved,
            RegistrationStatus::Denied,
            RegistrationStatus::Revoked,
            RegistrationStatus::Expired,
        ] {
            assert_eq!(s.as_str().parse::<RegistrationStatus>(), Ok(s));
        }
        assert_eq!(PortalMode::parse("self"), PortalMode::SelfService);
        assert_eq!(PortalMode::parse("anything"), PortalMode::Sponsor);
    }
}
