use abyssal_core::Session;
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_database::{DbPool, repo};
use chrono::{Duration, Utc};
use uuid::Uuid;

/// Issues a new session, returning the raw token (to be set in a cookie — never
/// persisted anywhere) alongside the stored `Session` record.
pub async fn issue(
    pool: &DbPool,
    user_id: Uuid,
    ttl: Duration,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> anyhow::Result<(String, Session)> {
    let token = generate_token();
    let hash = hash_token(&token);
    let expires_at = Utc::now() + ttl;
    let session =
        repo::sessions::create(pool, user_id, &hash, expires_at, ip_address, user_agent).await?;
    Ok((token, session))
}

/// Validates a presented raw token against the stored hash, returning the
/// session only if it exists, isn't revoked, and hasn't expired.
pub async fn validate(pool: &DbPool, token: &str) -> anyhow::Result<Option<Session>> {
    let hash = hash_token(token);
    let Some(session) = repo::sessions::find_by_token_hash(pool, &hash).await? else {
        return Ok(None);
    };
    if session.is_valid(Utc::now()) {
        Ok(Some(session))
    } else {
        Ok(None)
    }
}

pub async fn revoke(pool: &DbPool, session_id: Uuid) -> anyhow::Result<()> {
    repo::sessions::revoke(pool, session_id).await
}

pub async fn revoke_all_for_user(pool: &DbPool, user_id: Uuid) -> anyhow::Result<()> {
    repo::sessions::revoke_all_for_user(pool, user_id).await
}
