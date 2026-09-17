use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// System roles (seeded at startup) cannot be deleted, only have their
    /// permission set adjusted.
    pub is_system: bool,
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
