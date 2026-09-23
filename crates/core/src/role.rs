use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A max nesting depth of 3 (root -> child -> grandchild) keeps a
/// delegated hierarchy legible -- deep enough for "Network Admin ->
/// Network Tech -> Network Tech (read-only)"-style delegation, shallow
/// enough that "whose permissions actually apply here" never needs more
/// than two hops to answer by eye. Enforced in
/// `repo::roles::create`/`set_parent`, not the schema (MariaDB can't
/// express a bounded-depth tree constraint declaratively).
pub const MAX_ROLE_DEPTH: u8 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// System roles (seeded at startup) cannot be deleted or renamed, and
    /// are always root roles (`parent_role_id` is always `None`) --
    /// delegated sub-roles are a custom-role-only concept. Their
    /// permission set can still be adjusted by a Super Admin, same as
    /// today.
    pub is_system: bool,
    /// `None` for a root role (every system role, and any custom role
    /// created directly under no parent). `Some` makes this role a
    /// delegated sub-role: GitHub issue #8 -- see
    /// `repo::roles::effective_permissions_for_role`.
    pub parent_role_id: Option<Uuid>,
    /// The user who created this role -- `None` for the five seeded
    /// system roles (nothing "created" them, `seed_core_defaults` just
    /// ensures they exist) and for any custom role whose creator was
    /// later deleted (`ON DELETE SET NULL`).
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub const SUPER_ADMIN: &str = "Super Admin";
pub const SYSTEM_ADMIN: &str = "System Admin";
pub const NETWORK_ADMIN: &str = "Network Admin";
pub const SECURITY_ADMIN: &str = "Security / OPSEC Admin";
pub const REGULAR_USER: &str = "Regular User";

pub const BUILT_IN_ROLES: &[&str] = &[
    SUPER_ADMIN,
    SYSTEM_ADMIN,
    NETWORK_ADMIN,
    SECURITY_ADMIN,
    REGULAR_USER,
];
