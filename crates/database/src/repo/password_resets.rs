use chrono::Duration;
use uuid::Uuid;

use crate::DbPool;

pub async fn create(
    pool: &DbPool,
    user_id: Uuid,
    token_hash: &str,
    ttl: Duration,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + ttl;
    sqlx::query(
        "INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(user_id.to_string())
    .bind(token_hash)
    .bind(expires_at.naive_utc())
    .execute(pool)
    .await?;
    Ok(())
}

/// Whether this user already has a reset request from within the last
/// `minutes` -- checked before sending another one, so repeatedly
/// submitting "forgot password" for the same account can't be used to
/// spam their inbox.
pub async fn has_recent_request(
    pool: &DbPool,
    user_id: Uuid,
    minutes: i64,
) -> anyhow::Result<bool> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM password_resets \
         WHERE user_id = ? AND created_at >= CURRENT_TIMESTAMP(6) - INTERVAL ? MINUTE",
    )
    .bind(user_id.to_string())
    .bind(minutes)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// Looks up which user an unused, unexpired token belongs to, without
/// consuming it -- used to render the "set a new password" form before
/// the token is actually spent.
pub async fn find_valid_user_id(pool: &DbPool, token_hash: &str) -> anyhow::Result<Option<Uuid>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT user_id FROM password_resets \
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP(6)",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(id,)| Uuid::parse_str(&id).ok()))
}

/// Atomically marks an unused, unexpired token as used and returns which
/// user it belonged to -- same race-avoidance shape as
/// `host_enrollment_tokens::consume` (the check and the mark-as-used
/// happen in one `UPDATE`, so two concurrent submissions of the same
/// token can't both succeed), plus a follow-up lookup for the user id
/// since MySQL/MariaDB has no `UPDATE ... RETURNING`.
pub async fn consume(pool: &DbPool, token_hash: &str) -> anyhow::Result<Option<Uuid>> {
    let result = sqlx::query(
        "UPDATE password_resets SET used_at = CURRENT_TIMESTAMP(6) \
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP(6)",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Ok(None);
    }

    let row: Option<(String,)> =
        sqlx::query_as("SELECT user_id FROM password_resets WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(id,)| Uuid::parse_str(&id).ok()))
}
