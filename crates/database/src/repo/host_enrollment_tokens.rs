use chrono::Duration;
use uuid::Uuid;

use crate::DbPool;

pub async fn create(
    pool: &DbPool,
    token_hash: &str,
    created_by: Option<Uuid>,
    ttl: Duration,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + ttl;
    sqlx::query(
        "INSERT INTO host_enrollment_tokens (id, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(token_hash)
    .bind(created_by.map(|u| u.to_string()))
    .bind(expires_at.naive_utc())
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically marks an unused, unexpired token as used and reports whether
/// that succeeded. Doing the check and the mark-as-used in one `UPDATE`
/// (rather than a separate `SELECT` then `UPDATE`) means two concurrent
/// enrollment attempts with the same token can't both succeed.
pub async fn consume(pool: &DbPool, token_hash: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE host_enrollment_tokens SET used_at = CURRENT_TIMESTAMP(6) \
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP(6)",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
