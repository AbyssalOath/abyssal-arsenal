use abyssal_core::User;
use abyssal_database::{repo, DbPool};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("account is disabled")]
    AccountDisabled,
    #[error("too many failed attempts, try again later")]
    RateLimited,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Abstraction over "how a set of credentials gets turned into a `User`". This
/// exists so an OIDC/SAML provider can be added later without touching session
/// issuance, RBAC, or any handler that just wants "give me an authenticated
/// user" — SSO users resolve to the same `User`/role model as local accounts.
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(
        &self,
        pool: &DbPool,
        username: &str,
        password: &str,
    ) -> Result<User, AuthError>;
}

pub struct LocalAuthProvider;

#[async_trait::async_trait]
impl AuthProvider for LocalAuthProvider {
    async fn authenticate(
        &self,
        pool: &DbPool,
        username: &str,
        password: &str,
    ) -> Result<User, AuthError> {
        let user = repo::users::find_by_username(pool, username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if !user.is_active {
            return Err(AuthError::AccountDisabled);
        }

        let hash = user
            .password_hash
            .as_deref()
            .ok_or(AuthError::InvalidCredentials)?;

        if !crate::password::verify_password(password, hash) {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(user)
    }
}
