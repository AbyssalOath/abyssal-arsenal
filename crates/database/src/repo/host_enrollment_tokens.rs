use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use sqlx::FromRow;
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

/// Whether a token (already [`consume`]d) was minted for the control
/// plane's own server.
pub async fn is_control_plane(pool: &DbPool, token_hash: &str) -> anyhow::Result<bool> {
    let flag: Option<(bool,)> =
        sqlx::query_as("SELECT control_plane FROM host_enrollment_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(pool)
            .await?;
    Ok(flag.is_some_and(|(f,)| f))
}

/// Creates a reusable deployment token (Wazuh-style registration key): it can
/// enroll many hosts until it expires or is revoked, with an optional label to
/// identify it. Returns its id so the UI can offer a revoke button immediately.
pub async fn create_deployment(
    pool: &DbPool,
    token_hash: &str,
    created_by: Option<Uuid>,
    ttl: Duration,
    label: Option<&str>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + ttl;
    sqlx::query(
        "INSERT INTO host_enrollment_tokens (id, token_hash, created_by, expires_at, reusable, label) \
         VALUES (?, ?, ?, ?, 1, ?)",
    )
    .bind(id.to_string())
    .bind(token_hash)
    .bind(created_by.map(|u| u.to_string()))
    .bind(expires_at.naive_utc())
    .bind(label)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Atomically validates and records one use of a token, reporting whether it
/// succeeded. One `UPDATE` (not a separate `SELECT` then `UPDATE`) so two
/// concurrent enrollments can't both slip a single-use token through. Handles
/// both kinds: a single-use token matches only while unused and is then burned
/// (`used_at` set); a reusable deployment token matches while unexpired and
/// unrevoked, incrementing `use_count` and leaving `used_at` NULL so it keeps
/// working for the next host.
pub async fn consume(pool: &DbPool, token_hash: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE host_enrollment_tokens \
         SET use_count = use_count + 1, \
             used_at = CASE WHEN reusable = 1 THEN used_at ELSE CURRENT_TIMESTAMP(6) END \
         WHERE token_hash = ? \
           AND revoked_at IS NULL \
           AND expires_at > CURRENT_TIMESTAMP(6) \
           AND (reusable = 1 OR used_at IS NULL)",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// One active (not revoked, not expired) reusable deployment token, for the
/// admin UI's management list. The raw token is never returned -- only hashed
/// metadata -- so the command string is shown once, at creation.
pub struct DeploymentToken {
    pub id: Uuid,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub use_count: i64,
}

#[derive(FromRow)]
struct DeploymentTokenRow {
    id: String,
    label: Option<String>,
    created_at: NaiveDateTime,
    expires_at: NaiveDateTime,
    use_count: i64,
}

/// Active deployment tokens (reusable, unexpired, unrevoked), newest first.
pub async fn list_active_deployment(pool: &DbPool) -> anyhow::Result<Vec<DeploymentToken>> {
    let rows: Vec<DeploymentTokenRow> = sqlx::query_as(
        "SELECT id, label, created_at, expires_at, use_count FROM host_enrollment_tokens \
         WHERE reusable = 1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP(6) \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DeploymentToken {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            label: r.label,
            created_at: DateTime::from_naive_utc_and_offset(r.created_at, Utc),
            expires_at: DateTime::from_naive_utc_and_offset(r.expires_at, Utc),
            use_count: r.use_count,
        })
        .collect())
}

/// Revokes a deployment token by id (idempotent). A revoked token stops
/// enrolling new hosts immediately; already-enrolled hosts keep their own
/// per-host credentials and are unaffected.
pub async fn revoke(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE host_enrollment_tokens SET revoked_at = CURRENT_TIMESTAMP(6) \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}
