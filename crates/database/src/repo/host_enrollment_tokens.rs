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

/// A single-use token that flags the host enrolling with it as the control
/// plane's own server -- what `install.sh` uses to enroll the server's own
/// agent. Short-lived: it's used within seconds of being minted.
pub async fn create_control_plane(
    pool: &DbPool,
    token_hash: &str,
    ttl: Duration,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + ttl;
    sqlx::query(
        "INSERT INTO host_enrollment_tokens (id, token_hash, expires_at, control_plane) \
         VALUES (?, ?, ?, 1)",
    )
    .bind(id.to_string())
    .bind(token_hash)
    .bind(expires_at.naive_utc())
    .execute(pool)
    .await?;
    Ok(())
}

/// What kind of token a (already [`consume`]d) token is.
pub struct TokenKind {
    pub id: Uuid,
    /// Minted by `install.sh` for the control plane's own server.
    pub control_plane: bool,
}

pub async fn kind(pool: &DbPool, token_hash: &str) -> anyhow::Result<Option<TokenKind>> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT id, control_plane FROM host_enrollment_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(id, control_plane)| TokenKind {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        control_plane,
    }))
}

/// Atomically validates and burns a single-use token, reporting whether it
/// succeeded. One `UPDATE` (not a separate `SELECT` then `UPDATE`) so two
/// concurrent enrollments can't both slip the same token through. Legacy
/// reusable deployment tokens (`reusable = 1`, from before install tokens)
/// no longer enroll anything: install tokens replaced them in 0.2.4.
pub async fn consume(pool: &DbPool, token_hash: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE host_enrollment_tokens \
         SET use_count = use_count + 1, used_at = CURRENT_TIMESTAMP(6) \
         WHERE token_hash = ? \
           AND reusable = 0 \
           AND revoked_at IS NULL \
           AND expires_at > CURRENT_TIMESTAMP(6) \
           AND used_at IS NULL",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
