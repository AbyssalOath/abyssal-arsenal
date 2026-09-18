use abyssal_core::{AuthProviderKind, User};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct UserRow {
    id: String,
    username: String,
    email: String,
    password_hash: Option<String>,
    auth_provider: String,
    is_active: bool,
    must_change_password: bool,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
    last_login_at: Option<NaiveDateTime>,
    timezone: String,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            username: row.username,
            email: row.email,
            password_hash: row.password_hash,
            auth_provider: AuthProviderKind(row.auth_provider),
            is_active: row.is_active,
            must_change_password: row.must_change_password,
            created_at: utc(row.created_at),
            updated_at: utc(row.updated_at),
            last_login_at: row.last_login_at.map(utc),
            timezone: row.timezone,
        }
    }
}

pub async fn count(pool: &DbPool) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

pub async fn create(
    pool: &DbPool,
    username: &str,
    email: &str,
    password_hash: Option<&str>,
    auth_provider: &str,
    must_change_password: bool,
) -> anyhow::Result<User> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, must_change_password) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(auth_provider)
    .bind(must_change_password)
    .execute(pool)
    .await?;

    find_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user vanished immediately after insert"))
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<User>> {
    let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_username(pool: &DbPool, username: &str) -> anyhow::Result<Option<User>> {
    let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_email(pool: &DbPool, email: &str) -> anyhow::Result<Option<User>> {
    let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(Into::into))
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<User>> {
    let rows: Vec<UserRow> = sqlx::query_as("SELECT * FROM users ORDER BY created_at ASC")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn set_active(pool: &DbPool, id: Uuid, active: bool) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET is_active = ? WHERE id = ?")
        .bind(active)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_password(
    pool: &DbPool,
    id: Uuid,
    password_hash: &str,
    must_change_password: bool,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?")
        .bind(password_hash)
        .bind(must_change_password)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn touch_last_login(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET last_login_at = CURRENT_TIMESTAMP(6) WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Sets a user's own display timezone. Callers are expected to have already
/// validated `timezone` against a real IANA name (see
/// `crates/web/src/routes/account.rs`) -- this layer just persists it.
pub async fn set_timezone(pool: &DbPool, id: Uuid, timezone: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET timezone = ? WHERE id = ?")
        .bind(timezone)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}
