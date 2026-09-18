use uuid::Uuid;

use crate::DbPool;

pub async fn list_for_user(pool: &DbPool, user_id: Uuid) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT module_key FROM user_pinned_modules WHERE user_id = ?")
            .bind(user_id.to_string())
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(k,)| k).collect())
}

pub async fn pin(pool: &DbPool, user_id: Uuid, module_key: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT IGNORE INTO user_pinned_modules (user_id, module_key) VALUES (?, ?)")
        .bind(user_id.to_string())
        .bind(module_key)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn unpin(pool: &DbPool, user_id: Uuid, module_key: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM user_pinned_modules WHERE user_id = ? AND module_key = ?")
        .bind(user_id.to_string())
        .bind(module_key)
        .execute(pool)
        .await?;
    Ok(())
}
