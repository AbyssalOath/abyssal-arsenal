use std::collections::HashSet;

use abyssal_core::{Permission, User};
use abyssal_database::{DbPool, repo};

/// The fully-resolved authorization context for one authenticated request:
/// the user, and the union of permissions granted by every role they hold.
/// Always built fresh from the database — never cached across requests — so a
/// role change takes effect on the user's very next action.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: User,
    pub permissions: HashSet<Permission>,
}

impl AuthContext {
    pub fn has(&self, perm: Permission) -> bool {
        self.permissions.contains(&perm)
    }

    /// Loads a fresh authorization context for `user`. Any database failure
    /// here must be treated as "cannot authorize" by the caller, not "allow
    /// everything" — see `AppError::Forbidden`'s fail-closed contract.
    pub async fn load(pool: &DbPool, user: User) -> anyhow::Result<Self> {
        let permissions = repo::roles::effective_permissions(pool, user.id)
            .await?
            .into_iter()
            .collect();
        Ok(Self { user, permissions })
    }
}
