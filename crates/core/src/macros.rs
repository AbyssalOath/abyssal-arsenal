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

/// A saved, reusable Grimoire scheduled-task ("cron job") template --
/// GitHub issue #7's first (and, for now, only) macro payload: the exact
/// fields `AgentOperation::SetCronJob` needs, minus a target host, since a
/// macro is reused across hosts rather than tied to one. A `Personal`
/// macro (`scope`) is visible only to `owner_user_id`; a `Role` macro is
/// visible to every member of `role_id` (`None` iff `scope` is
/// `Personal`). Extending macros to a second action type later is an
/// additive change (a discriminator column plus new payload fields), not
/// something this shape tries to anticipate -- see
/// `ARCHITECTURE.md#macros` for why v1 is scoped to just this one action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macro {
    pub id: Uuid,
    pub name: String,
    pub owner_user_id: Uuid,
    pub scope: MacroScope,
    pub role_id: Option<Uuid>,
    pub job_name: String,
    pub schedule: String,
    pub run_as_user: String,
    pub command: String,
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
}
