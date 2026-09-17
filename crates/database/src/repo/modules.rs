use crate::DbPool;

/// Ensures every statically known arsenal key has a row in `modules`, defaulting
/// newly-seen modules to enabled. Existing rows (and any admin's enabled/disabled
/// choice) are left untouched.
pub async fn ensure_seeded(pool: &DbPool, keys: &[&str]) -> anyhow::Result<()> {
    for key in keys {
        sqlx::query("INSERT IGNORE INTO modules (`key`, enabled) VALUES (?, TRUE)")
            .bind(key)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn is_enabled(pool: &DbPool, key: &str) -> anyhow::Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as("SELECT enabled FROM modules WHERE `key` = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(e,)| e).unwrap_or(true))
}

pub async fn enabled_keys(pool: &DbPool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT `key` FROM modules WHERE enabled = TRUE")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(k,)| k).collect())
}

pub async fn set_enabled(pool: &DbPool, key: &str, enabled: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE modules SET enabled = ? WHERE `key` = ?")
        .bind(enabled)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}
