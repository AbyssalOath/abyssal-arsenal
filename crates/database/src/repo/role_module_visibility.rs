use std::collections::HashSet;

use uuid::Uuid;

use crate::DbPool;

/// The module keys explicitly allowed by a role's dashboard-visibility
/// customization, or `None` if the role has no customization at all --
/// meaning it imposes no restriction beyond whatever permissions already
/// allow. Distinguishing "no rows" from "empty set" this way is what lets
/// a brand new/uncustomized role keep showing everything its permissions
/// already allow, rather than an admin having to explicitly re-select
/// every arsenal before a role shows anything.
pub async fn visibility_for_role(
    pool: &DbPool,
    role_id: Uuid,
) -> anyhow::Result<Option<HashSet<String>>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT module_key FROM role_module_visibility WHERE role_id = ?")
            .bind(role_id.to_string())
            .fetch_all(pool)
            .await?;
    if rows.is_empty() {
        Ok(None)
    } else {
        Ok(Some(rows.into_iter().map(|(k,)| k).collect()))
    }
}

/// A user's effective dashboard-visibility restriction across every role
/// assigned to them: `None` if any one of their roles is uncustomized
/// (that role alone already permits everything permissions allow, so
/// nothing is restricted overall -- mirrors how permissions themselves
/// already union across a user's roles, most-permissive-wins), or
/// `Some(set)` of every module key allowed by any of their roles when
/// every role they have is customized.
pub async fn effective_restriction_for_user(
    pool: &DbPool,
    user_id: Uuid,
) -> anyhow::Result<Option<HashSet<String>>> {
    let (unrestricted_role_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM user_roles ur \
         WHERE ur.user_id = ? AND ur.role_id NOT IN (SELECT DISTINCT role_id FROM role_module_visibility)",
    )
    .bind(user_id.to_string())
    .fetch_one(pool)
    .await?;
    if unrestricted_role_count > 0 {
        return Ok(None);
    }

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT rmv.module_key FROM role_module_visibility rmv \
         INNER JOIN user_roles ur ON ur.role_id = rmv.role_id \
         WHERE ur.user_id = ?",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(Some(rows.into_iter().map(|(k,)| k).collect()))
}

/// Replaces a role's entire dashboard-visibility customization. Passing an
/// empty slice clears the customization entirely (back to "uncustomized",
/// not "show nothing") -- see `visibility_for_role`.
pub async fn set_visible_modules(
    pool: &DbPool,
    role_id: Uuid,
    module_keys: &[String],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_module_visibility WHERE role_id = ?")
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await?;
    for key in module_keys {
        sqlx::query("INSERT INTO role_module_visibility (role_id, module_key) VALUES (?, ?)")
            .bind(role_id.to_string())
            .bind(key)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
