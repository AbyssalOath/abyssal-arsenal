use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Who can see and use a saved macro -- `Personal` is visible only to its
/// owner, `Role` to every member of `Macro::role_id`. Stored as its
/// `as_str()` key rather than a database `ENUM`, same reasoning as
/// `SnmpVersion` and friends: adding a scope later never needs a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacroScope {
    Personal,
    Role,
}

impl MacroScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            MacroScope::Personal => "personal",
            MacroScope::Role => "role",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            MacroScope::Personal => "Personal",
            MacroScope::Role => "Role",
        }
    }

    pub const ALL: &'static [MacroScope] = &[MacroScope::Personal, MacroScope::Role];
}

impl std::str::FromStr for MacroScope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "personal" => Ok(MacroScope::Personal),
            "role" => Ok(MacroScope::Role),
            _ => Err(()),
        }
    }
}

/// Which of `Macro`'s two payload shapes is populated. `CronJob` was the
/// first (GitHub issue #7): a saved Grimoire scheduled-task template.
/// `CommunityString` is the second: a saved SNMP community string for
/// Panopticon's "add managed switch" form. Exactly one of the two field
/// groups on `Macro` is populated, per this discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MacroType {
    CronJob,
    CommunityString,
}

impl MacroType {
    pub const fn as_str(self) -> &'static str {
        match self {
            MacroType::CronJob => "cron_job",
            MacroType::CommunityString => "community_string",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            MacroType::CronJob => "Scheduled task",
            MacroType::CommunityString => "SNMP community string",
        }
    }

    pub const ALL: &'static [MacroType] = &[MacroType::CronJob, MacroType::CommunityString];
}

impl std::str::FromStr for MacroType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cron_job" => Ok(MacroType::CronJob),
            "community_string" => Ok(MacroType::CommunityString),
            _ => Err(()),
        }
    }
}

/// A saved, reusable value or action template -- GitHub issue #7. A
/// `Personal` macro (`scope`) is visible only to `owner_user_id`; a
/// `Role` macro is visible to every member of `role_id` (`None` iff
/// `scope` is `Personal`). `macro_type` picks which payload is populated:
/// `CronJob` uses `job_name`/`schedule`/`run_as_user`/`command` (the exact
/// fields `AgentOperation::SetCronJob` needs, minus a target host, since a
/// macro is reused across hosts rather than tied to one);
/// `CommunityString` uses `secret_value_encrypted` (AES-256-GCM
/// ciphertext, `abyssal_core::crypto::EncryptionKey` -- same key already
/// used for a Panopticon switch's own stored SNMP credentials). Extending
/// macros to a third payload later is the same additive shape this second
/// one was -- see `ARCHITECTURE.md#authorization-rbac`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macro {
    pub id: Uuid,
    pub name: String,
    pub owner_user_id: Uuid,
    pub scope: MacroScope,
    pub role_id: Option<Uuid>,
    pub macro_type: MacroType,
    pub job_name: Option<String>,
    pub schedule: Option<String>,
    pub run_as_user: Option<String>,
    pub command: Option<String>,
    pub secret_value_encrypted: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_scope_through_as_str_and_from_str() {
        for scope in MacroScope::ALL {
            assert_eq!(scope.as_str().parse::<MacroScope>().unwrap(), *scope);
        }
    }

    #[test]
    fn rejects_unrecognized_strings() {
        assert!("".parse::<MacroScope>().is_err());
        assert!("everyone".parse::<MacroScope>().is_err());
    }

    #[test]
    fn round_trips_every_macro_type_through_as_str_and_from_str() {
        for t in MacroType::ALL {
            assert_eq!(t.as_str().parse::<MacroType>().unwrap(), *t);
        }
    }
}
