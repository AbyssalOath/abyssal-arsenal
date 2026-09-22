use abyssal_core::{Macro, MacroScope};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct MacroRow {
    id: String,
    name: String,
    owner_user_id: String,
    scope: String,
    role_id: Option<String>,
    job_name: String,
    schedule: String,
    run_as_user: String,
    command: String,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<MacroRow> for Macro {
    fn from(row: MacroRow) -> Self {
        Macro {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            name: row.name,
            owner_user_id: Uuid::parse_str(&row.owner_user_id).unwrap_or_default(),
            // A row can't actually have an unrecognized scope (only this
            // module ever writes one), but falling back to `Personal`
            // rather than panicking keeps a future bad value from taking
            // the whole macro list down.
            scope: row.scope.parse().unwrap_or(MacroScope::Personal),
            role_id: row
                .role_id
                .map(|id| Uuid::parse_str(&id).unwrap_or_default()),
            job_name: row.job_name,
            schedule: row.schedule,
            run_as_user: row.run_as_user,
            command: row.command,
            created_at: utc(row.created_at),
            updated_at: utc(row.updated_at),
        }
    }
}

/// Everything `create`/`update` need for a macro's own fields (not its
/// id/timestamps) -- bundled into one struct rather than a long parameter
/// list, following `NewAuditEntry`'s precedent.
pub struct MacroFields<'a> {
    pub name: &'a str,
    pub owner_user_id: Uuid,
    pub scope: MacroScope,
    pub role_id: Option<Uuid>,
    pub job_name: &'a str,
    pub schedule: &'a str,
    pub run_as_user: &'a str,
    pub command: &'a str,
}

pub async fn create(pool: &DbPool, fields: MacroFields<'_>) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO macros \
         (id, name, owner_user_id, scope, role_id, job_name, schedule, run_as_user, command) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(fields.name)
    .bind(fields.owner_user_id.to_string())
    .bind(fields.scope.as_str())
    .bind(fields.role_id.map(|id| id.to_string()))
    .bind(fields.job_name)
    .bind(fields.schedule)
    .bind(fields.run_as_user)
    .bind(fields.command)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<Macro>> {
    let row: Option<MacroRow> = sqlx::query_as("SELECT * FROM macros WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

async fn list_personal(pool: &DbPool, owner_user_id: Uuid) -> anyhow::Result<Vec<Macro>> {
    let rows: Vec<MacroRow> =
        sqlx::query_as("SELECT * FROM macros WHERE scope = 'personal' AND owner_user_id = ?")
            .bind(owner_user_id.to_string())
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

async fn list_for_roles(pool: &DbPool, role_ids: &[Uuid]) -> anyhow::Result<Vec<Macro>> {
    if role_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; role_ids.len()].join(", ");
    let sql = format!("SELECT * FROM macros WHERE scope = 'role' AND role_id IN ({placeholders})");
    let mut query = sqlx::query_as(&sql);
    for role_id in role_ids {
        query = query.bind(role_id.to_string());
    }
    let rows: Vec<MacroRow> = query.fetch_all(pool).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Every macro `user_id` can see: their own personal macros, plus every
/// role macro for a role in `role_ids` (that user's own roles -- the
/// caller resolves this via `repo::roles::roles_for_user` first, since
/// this layer has no `AuthContext` of its own). Sorted by name for a
/// stable, predictable list.
pub async fn list_visible_to_user(
    pool: &DbPool,
    user_id: Uuid,
    role_ids: &[Uuid],
) -> anyhow::Result<Vec<Macro>> {
    let mut macros = list_personal(pool, user_id).await?;
    macros.extend(list_for_roles(pool, role_ids).await?);
    macros.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(macros)
}

pub async fn update(pool: &DbPool, id: Uuid, fields: MacroFields<'_>) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE macros SET name = ?, scope = ?, role_id = ?, job_name = ?, schedule = ?, \
         run_as_user = ?, command = ? WHERE id = ?",
    )
    .bind(fields.name)
    .bind(fields.scope.as_str())
    .bind(fields.role_id.map(|id| id.to_string()))
    .bind(fields.job_name)
    .bind(fields.schedule)
    .bind(fields.run_as_user)
    .bind(fields.command)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM macros WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
