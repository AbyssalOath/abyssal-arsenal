use serde_json::Value;
use uuid::Uuid;

use crate::DbPool;

pub async fn get(pool: &DbPool, key: &str) -> anyhow::Result<Option<Value>> {
    let row: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE `key` = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(v,)| v))
}

pub async fn get_bool(pool: &DbPool, key: &str, default: bool) -> anyhow::Result<bool> {
    Ok(get(pool, key)
        .await?
        .and_then(|v| v.as_bool())
        .unwrap_or(default))
}

pub async fn set(
    pool: &DbPool,
    key: &str,
    value: Value,
    updated_by: Option<Uuid>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO settings (`key`, value, updated_by) VALUES (?, ?, ?) \
         ON DUPLICATE KEY UPDATE value = VALUES(value), updated_by = VALUES(updated_by)",
    )
    .bind(key)
    .bind(value)
    .bind(updated_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(())
}
