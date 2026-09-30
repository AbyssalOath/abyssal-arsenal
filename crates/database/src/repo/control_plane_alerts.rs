//! Firing state for control-plane self-alerts (see `web::self_monitor`). One
//! row per alert key; an alert fires on the transition into "firing" and
//! clears on the transition out, rather than re-notifying every sweep tick.
//! Mirrors `repo::monitoring`'s host-metric firing state, but keyed by a plain
//! string since control-plane alerts aren't per-host.

use crate::DbPool;

/// Whether the given alert key is currently in the firing state.
pub async fn is_firing(pool: &DbPool, key: &str) -> anyhow::Result<bool> {
    let firing: Option<i64> =
        sqlx::query_scalar("SELECT firing FROM control_plane_alert_state WHERE alert_key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(firing.unwrap_or(0) != 0)
}

/// Sets (upserts) the firing state for an alert key.
pub async fn set_firing(pool: &DbPool, key: &str, firing: bool) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO control_plane_alert_state (alert_key, firing, updated_at) \
         VALUES (?, ?, CURRENT_TIMESTAMP(6)) \
         ON DUPLICATE KEY UPDATE firing = VALUES(firing), updated_at = VALUES(updated_at)",
    )
    .bind(key)
    .bind(i8::from(firing))
    .execute(pool)
    .await?;
    Ok(())
}
