use abyssal_core::MacroScope;
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct ProfileRow {
    id: String,
    name: String,
    owner_user_id: String,
    scope: String,
    role_id: Option<String>,
}

/// A named, reusable bundle of declarative config settings. Scoping mirrors
/// `macros`: personal (owner-only) or role (shared with a role's members).
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub owner_user_id: Uuid,
    pub scope: MacroScope,
    pub role_id: Option<Uuid>,
}

impl From<ProfileRow> for Profile {
    fn from(row: ProfileRow) -> Self {
        Profile {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            name: row.name,
            owner_user_id: Uuid::parse_str(&row.owner_user_id).unwrap_or_default(),
            scope: row.scope.parse().unwrap_or(MacroScope::Personal),
            role_id: row.role_id.and_then(|id| Uuid::parse_str(&id).ok()),
        }
    }
}

#[derive(FromRow)]
struct ProfileEntryRow {
    id: String,
    kind: String,
    entry_key: String,
    entry_value: String,
}

/// One config setting within a profile.
pub struct ProfileEntry {
    pub id: Uuid,
    pub kind: String,
    pub key: String,
    pub value: String,
}

impl From<ProfileEntryRow> for ProfileEntry {
    fn from(row: ProfileEntryRow) -> Self {
        ProfileEntry {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            kind: row.kind,
            key: row.entry_key,
            value: row.entry_value,
        }
    }
}

pub async fn create_profile(
    pool: &DbPool,
    name: &str,
    owner_user_id: Uuid,
    scope: MacroScope,
    role_id: Option<Uuid>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO grimoire_profiles (id, name, owner_user_id, scope, role_id) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(owner_user_id.to_string())
    .bind(scope.as_str())
    .bind(role_id.map(|r| r.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<Profile>> {
    let row: Option<ProfileRow> = sqlx::query_as(
        "SELECT id, name, owner_user_id, scope, role_id FROM grimoire_profiles WHERE id = ?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

pub async fn delete_profile(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM grimoire_profiles WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Every profile visible to this user: their own personal ones plus the role
/// ones for roles they belong to. Mirrors `macros::list_visible_to_user`.
pub async fn list_visible_to_user(
    pool: &DbPool,
    user_id: Uuid,
    role_ids: &[Uuid],
) -> anyhow::Result<Vec<Profile>> {
    let personal: Vec<ProfileRow> = sqlx::query_as(
        "SELECT id, name, owner_user_id, scope, role_id FROM grimoire_profiles \
         WHERE scope = 'personal' AND owner_user_id = ?",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;

    let mut profiles: Vec<Profile> = personal.into_iter().map(Into::into).collect();

    for role_id in role_ids {
        let role_rows: Vec<ProfileRow> = sqlx::query_as(
            "SELECT id, name, owner_user_id, scope, role_id FROM grimoire_profiles \
             WHERE scope = 'role' AND role_id = ?",
        )
        .bind(role_id.to_string())
        .fetch_all(pool)
        .await?;
        profiles.extend(role_rows.into_iter().map(Into::into));
    }

    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(profiles)
}

pub async fn list_entries(pool: &DbPool, profile_id: Uuid) -> anyhow::Result<Vec<ProfileEntry>> {
    let rows: Vec<ProfileEntryRow> = sqlx::query_as(
        "SELECT id, kind, entry_key, entry_value FROM grimoire_profile_entries \
         WHERE profile_id = ? ORDER BY position ASC, id ASC",
    )
    .bind(profile_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn add_entry(
    pool: &DbPool,
    profile_id: Uuid,
    kind: &str,
    key: &str,
    value: &str,
) -> anyhow::Result<()> {
    // Append at the end: position = current count.
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM grimoire_profile_entries WHERE profile_id = ?")
            .bind(profile_id.to_string())
            .fetch_one(pool)
            .await?;
    sqlx::query(
        "INSERT INTO grimoire_profile_entries (id, profile_id, kind, entry_key, entry_value, position) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(profile_id.to_string())
    .bind(kind)
    .bind(key)
    .bind(value)
    .bind(count)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes one entry, scoped to its profile so a mismatched pair is a no-op.
pub async fn remove_entry(pool: &DbPool, profile_id: Uuid, entry_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM grimoire_profile_entries WHERE id = ? AND profile_id = ?")
        .bind(entry_id.to_string())
        .bind(profile_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
