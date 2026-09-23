use abyssal_core::{Macro, MacroScope, MacroType};
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
    macro_type: String,
    role_id: Option<String>,
    job_name: Option<String>,
    schedule: Option<String>,
    run_as_user: Option<String>,
    command: Option<String>,
    secret_value_encrypted: Option<String>,
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
            // A row can't actually have an unrecognized scope/type (only
            // this module ever writes one), but falling back rather than
            // panicking keeps a future bad value from taking the whole
            // macro list down.
            scope: row.scope.parse().unwrap_or(MacroScope::Personal),
            role_id: row
                .role_id
                .map(|id| Uuid::parse_str(&id).unwrap_or_default()),
            macro_type: row.macro_type.parse().unwrap_or(MacroType::CronJob),
            job_name: row.job_name,
            schedule: row.schedule,
            run_as_user: row.run_as_user,
            command: row.command,
            secret_value_encrypted: row.secret_value_encrypted,
            created_at: utc(row.created_at),
            updated_at: utc(row.updated_at),
        }
    }
}

/// Everything `create`/`update` need for a macro's own fields (not its
/// id/timestamps) -- bundled into one struct rather than a long parameter
/// list, following `NewAuditEntry`'s precedent. Which of the payload
/// fields are actually meaningful depends on `macro_type` -- the caller
/// (`routes/grimoire.rs` for `CronJob`, `routes/panopticon.rs` and
/// `routes/account.rs` for `CommunityString`) leaves the other type's
/// fields `None`; this layer just persists whatever it's handed.
pub struct MacroFields<'a> {
    pub name: &'a str,
    pub owner_user_id: Uuid,
    pub scope: MacroScope,
    pub role_id: Option<Uuid>,
    pub macro_type: MacroType,
    pub job_name: Option<&'a str>,
    pub schedule: Option<&'a str>,
    pub run_as_user: Option<&'a str>,
    pub command: Option<&'a str>,
    pub secret_value_encrypted: Option<&'a str>,
}

pub async fn create(pool: &DbPool, fields: MacroFields<'_>) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO macros \
         (id, name, owner_user_id, scope, macro_type, role_id, job_name, schedule, \
          run_as_user, command, secret_value_encrypted) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(fields.name)
    .bind(fields.owner_user_id.to_string())
    .bind(fields.scope.as_str())
    .bind(fields.macro_type.as_str())
    .bind(fields.role_id.map(|id| id.to_string()))
    .bind(fields.job_name)
    .bind(fields.schedule)
    .bind(fields.run_as_user)
    .bind(fields.command)
    .bind(fields.secret_value_encrypted)
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

async fn list_personal(
    pool: &DbPool,
    owner_user_id: Uuid,
    macro_type: MacroType,
) -> anyhow::Result<Vec<Macro>> {
    let rows: Vec<MacroRow> = sqlx::query_as(
        "SELECT * FROM macros WHERE scope = 'personal' AND owner_user_id = ? AND macro_type = ?",
    )
    .bind(owner_user_id.to_string())
    .bind(macro_type.as_str())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

async fn list_for_roles(
    pool: &DbPool,
    role_ids: &[Uuid],
    macro_type: MacroType,
) -> anyhow::Result<Vec<Macro>> {
    if role_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = vec!["?"; role_ids.len()].join(", ");
    let sql = format!(
        "SELECT * FROM macros WHERE scope = 'role' AND macro_type = ? AND role_id IN ({placeholders})"
    );
    let mut query = sqlx::query_as(&sql).bind(macro_type.as_str());
    for role_id in role_ids {
        query = query.bind(role_id.to_string());
    }
    let rows: Vec<MacroRow> = query.fetch_all(pool).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Every macro of `macro_type` that `user_id` can see: their own personal
/// macros of that type, plus every role macro of that type for a role in
/// `role_ids` (that user's own roles -- the caller resolves this via
/// `repo::roles::roles_for_user` first, since this layer has no
/// `AuthContext` of its own). Sorted by name for a stable, predictable
/// list.
pub async fn list_visible_to_user(
    pool: &DbPool,
    user_id: Uuid,
    role_ids: &[Uuid],
    macro_type: MacroType,
) -> anyhow::Result<Vec<Macro>> {
    let mut macros = list_personal(pool, user_id, macro_type).await?;
    macros.extend(list_for_roles(pool, role_ids, macro_type).await?);
    macros.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(macros)
}

/// Every macro of `macro_type` this user owns (personal or role, doesn't
/// matter -- ownership, not visibility) -- the Account page's "manage the
/// macros I created" list, distinct from `list_visible_to_user`'s "every
/// macro I can currently use," which for a role macro also includes ones
/// a role-mate created.
pub async fn list_owned_by(
    pool: &DbPool,
    owner_user_id: Uuid,
    macro_type: MacroType,
) -> anyhow::Result<Vec<Macro>> {
    let rows: Vec<MacroRow> = sqlx::query_as(
        "SELECT * FROM macros WHERE owner_user_id = ? AND macro_type = ? ORDER BY name ASC",
    )
    .bind(owner_user_id.to_string())
    .bind(macro_type.as_str())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn update(pool: &DbPool, id: Uuid, fields: MacroFields<'_>) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE macros SET name = ?, scope = ?, role_id = ?, job_name = ?, schedule = ?, \
         run_as_user = ?, command = ?, secret_value_encrypted = ? WHERE id = ?",
    )
    .bind(fields.name)
    .bind(fields.scope.as_str())
    .bind(fields.role_id.map(|id| id.to_string()))
    .bind(fields.job_name)
    .bind(fields.schedule)
    .bind(fields.run_as_user)
    .bind(fields.command)
    .bind(fields.secret_value_encrypted)
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
