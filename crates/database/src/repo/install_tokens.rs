//! Additional install tokens: AAT-format, reusable enrollment secrets with a
//! label, optional expiry, use count, approval setting and revoke. The
//! default token (the AAT) lives in `settings`; see `abyssal_web::aat` and
//! `abyssal_web::install_tokens` for the sealing and the rules.

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

pub struct NewInstallToken<'a> {
    pub label: &'a str,
    pub token_sealed: &'a str,
    pub token_hash: &'a str,
    pub key_id: &'a str,
    pub require_approval: bool,
    pub created_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn create(pool: &DbPool, new: &NewInstallToken<'_>) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO install_tokens \
         (id, label, token_sealed, token_hash, key_id, require_approval, created_by, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(new.label)
    .bind(new.token_sealed)
    .bind(new.token_hash)
    .bind(new.key_id)
    .bind(new.require_approval)
    .bind(new.created_by.map(|u| u.to_string()))
    .bind(new.expires_at.map(|t| t.naive_utc()))
    .execute(pool)
    .await?;
    Ok(id)
}

#[derive(Debug, Clone)]
pub struct InstallToken {
    pub id: Uuid,
    pub label: String,
    pub token_sealed: String,
    pub require_approval: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub use_count: i64,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl InstallToken {
    /// Not revoked and not expired: it still enrolls hosts.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|t| t > now)
    }
}

#[derive(FromRow)]
struct Row {
    id: String,
    label: String,
    token_sealed: String,
    require_approval: bool,
    created_at: NaiveDateTime,
    expires_at: Option<NaiveDateTime>,
    revoked_at: Option<NaiveDateTime>,
    use_count: i64,
    last_used_at: Option<NaiveDateTime>,
}

fn utc(t: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(t, Utc)
}

impl From<Row> for InstallToken {
    fn from(r: Row) -> Self {
        InstallToken {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            label: r.label,
            token_sealed: r.token_sealed,
            require_approval: r.require_approval,
            created_at: utc(r.created_at),
            expires_at: r.expires_at.map(utc),
            revoked_at: r.revoked_at.map(utc),
            use_count: r.use_count,
            last_used_at: r.last_used_at.map(utc),
        }
    }
}

const COLUMNS: &str = "id, label, token_sealed, require_approval, created_at, expires_at, \
                       revoked_at, use_count, last_used_at";

/// Every install token, revoked and expired ones included (the Hosts page
/// still names them as what enrolled a host), newest first.
pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<InstallToken>> {
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM install_tokens ORDER BY created_at DESC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<InstallToken>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM install_tokens WHERE id = ?"
    ))
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// The active token with this hash, if any (what enrollment checks).
pub async fn find_active_by_hash(
    pool: &DbPool,
    token_hash: &str,
) -> anyhow::Result<Option<InstallToken>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM install_tokens WHERE token_hash = ? AND revoked_at IS NULL \
         AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))"
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// The active token with this key ID, if any (what the CA proof uses).
pub async fn find_active_by_key_id(
    pool: &DbPool,
    key_id: &str,
) -> anyhow::Result<Option<InstallToken>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM install_tokens WHERE key_id = ? AND revoked_at IS NULL \
         AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))"
    ))
    .bind(key_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Counts one enrollment with the token.
pub async fn record_use(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE install_tokens SET use_count = use_count + 1, \
         last_used_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Stops the token enrolling hosts (idempotent). Hosts it enrolled keep
/// their own credentials.
pub async fn revoke(pool: &DbPool, id: Uuid) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE install_tokens SET revoked_at = CURRENT_TIMESTAMP(6) \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
