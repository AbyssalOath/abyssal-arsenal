use abyssal_core::{Permission, Role};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct RoleRow {
    id: String,
    name: String,
    description: String,
    is_system: bool,
}

impl From<RoleRow> for Role {
    fn from(row: RoleRow) -> Self {
        Role {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            name: row.name,
            description: row.description,
            is_system: row.is_system,
        }
    }
}

pub async fn find_by_name(pool: &DbPool, name: &str) -> anyhow::Result<Option<Role>> {
    let row: Option<RoleRow> = sqlx::query_as("SELECT * FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<Role>> {
    let row: Option<RoleRow> = sqlx::query_as("SELECT * FROM roles WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<Role>> {
    let rows: Vec<RoleRow> = sqlx::query_as("SELECT * FROM roles ORDER BY name ASC")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn create(
    pool: &DbPool,
    name: &str,
    description: &str,
    is_system: bool,
) -> anyhow::Result<Role> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO roles (id, name, description, is_system) VALUES (?, ?, ?, ?)")
        .bind(id.to_string())
        .bind(name)
        .bind(description)
        .bind(is_system)
        .execute(pool)
        .await?;
    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("role vanished immediately after insert"))
}

pub async fn set_permissions(
    pool: &DbPool,
    role_id: Uuid,
    permissions: &[Permission],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
        .bind(role_id.to_string())
        .execute(&mut *tx)
        .await?;
    for perm in permissions {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)")
            .bind(role_id.to_string())
            .bind(perm.as_key())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn permissions_for_role(pool: &DbPool, role_id: Uuid) -> anyhow::Result<Vec<Permission>> {
    let keys: Vec<(String,)> =
        sqlx::query_as("SELECT permission_key FROM role_permissions WHERE role_id = ?")
            .bind(role_id.to_string())
            .fetch_all(pool)
            .await?;
    Ok(keys
        .into_iter()
        .filter_map(|(key,)| Permission::from_key(&key))
        .collect())
}

pub async fn assign_role_to_user(
    pool: &DbPool,
    user_id: Uuid,
    role_id: Uuid,
) -> anyhow::Result<()> {
    sqlx::query("INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)")
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn remove_role_from_user(
    pool: &DbPool,
    user_id: Uuid,
    role_id: Uuid,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?")
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn roles_for_user(pool: &DbPool, user_id: Uuid) -> anyhow::Result<Vec<Role>> {
    let rows: Vec<RoleRow> = sqlx::query_as(
        "SELECT r.* FROM roles r \
         INNER JOIN user_roles ur ON ur.role_id = r.id \
         WHERE ur.user_id = ? ORDER BY r.name ASC",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Resolves the union of permissions across every role assigned to a user via a
/// fresh database lookup — never a cached/long-lived claim set.
pub async fn effective_permissions(
    pool: &DbPool,
    user_id: Uuid,
) -> anyhow::Result<Vec<Permission>> {
    let keys: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT rp.permission_key FROM role_permissions rp \
         INNER JOIN user_roles ur ON ur.role_id = rp.role_id \
         WHERE ur.user_id = ?",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(keys
        .into_iter()
        .filter_map(|(key,)| Permission::from_key(&key))
        .collect())
}
