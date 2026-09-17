use abyssal_core::{AppError, Permission};

use crate::AuthContext;

/// Explicit, per-handler permission check. Deliberately not hidden behind
/// middleware: every protected handler calls this itself so it's obvious at
/// the call site what's being enforced, and so there's no shared layer whose
/// misconfiguration could silently let a route through. Always fails closed.
pub fn ensure(ctx: &AuthContext, perm: Permission) -> Result<(), AppError> {
    if ctx.has(perm) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub fn ensure_any(ctx: &AuthContext, perms: &[Permission]) -> Result<(), AppError> {
    if perms.iter().any(|p| ctx.has(*p)) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::{AuthProviderKind, User};
    use chrono::Utc;
    use std::collections::HashSet;
    use uuid::Uuid;

    fn user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "test".into(),
            email: "test@example.com".into(),
            password_hash: None,
            auth_provider: AuthProviderKind::local(),
            is_active: true,
            must_change_password: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: None,
            timezone: "UTC".into(),
        }
    }

    #[test]
    fn super_admin_style_context_passes_every_check() {
        let ctx = AuthContext {
            user: user(),
            permissions: Permission::ALL.iter().copied().collect(),
        };
        for perm in Permission::ALL {
            assert!(ensure(&ctx, *perm).is_ok());
        }
    }

    #[test]
    fn regular_user_denied_on_admin_permission() {
        let mut permissions = HashSet::new();
        permissions.insert(Permission::SystemsView);
        let ctx = AuthContext {
            user: user(),
            permissions,
        };

        assert!(ensure(&ctx, Permission::SystemsView).is_ok());
        assert!(matches!(
            ensure(&ctx, Permission::UsersDelete),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn empty_permission_set_denies_everything() {
        let ctx = AuthContext {
            user: user(),
            permissions: HashSet::new(),
        };
        for perm in Permission::ALL {
            assert!(matches!(ensure(&ctx, *perm), Err(AppError::Forbidden)));
        }
    }
}
