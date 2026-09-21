use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;

use crate::DbPool;

#[derive(FromRow)]
struct TrustedKeyRow {
    fingerprint: String,
}

/// The fingerprint (`SHA256:<base64>`) already trusted for this IP, if
/// any -- `None` means this is the first time a deploy has ever touched
/// this address, so the host-key review step has nothing to compare
/// against and must ask the admin to confirm it (see
/// `ssh_deploy.rs::probe_host_key`).
pub async fn trusted_fingerprint(
    pool: &DbPool,
    ip_address: &str,
) -> anyhow::Result<Option<String>> {
    let row: Option<TrustedKeyRow> =
        sqlx::query_as("SELECT fingerprint FROM ssh_trusted_host_keys WHERE ip_address = ?")
            .bind(ip_address)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.fingerprint))
}

/// Records a fingerprint as trusted -- only ever called after the admin
/// has explicitly confirmed it (first sighting) or it already matched
/// what's on file (an unremarkable re-confirmation, just refreshing
/// `last_seen_at`). Never called to silently overwrite a *different*
/// previously-trusted fingerprint for the same IP -- that's a hard stop
/// handled entirely in `ssh_deploy.rs`, not here.
pub async fn trust(pool: &DbPool, ip_address: &str, fingerprint: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO ssh_trusted_host_keys (ip_address, fingerprint) VALUES (?, ?) \
         ON DUPLICATE KEY UPDATE \
             fingerprint = VALUES(fingerprint), \
             last_seen_at = CURRENT_TIMESTAMP(6)",
    )
    .bind(ip_address)
    .bind(fingerprint)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(FromRow)]
struct TrustedRowFull {
    ip_address: String,
    fingerprint: String,
    first_seen_at: NaiveDateTime,
    last_seen_at: NaiveDateTime,
}

pub struct TrustedHostKey {
    pub ip_address: String,
    pub fingerprint: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<TrustedHostKey>> {
    let rows: Vec<TrustedRowFull> =
        sqlx::query_as("SELECT * FROM ssh_trusted_host_keys ORDER BY ip_address ASC")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|r| TrustedHostKey {
            ip_address: r.ip_address,
            fingerprint: r.fingerprint,
            first_seen_at: DateTime::from_naive_utc_and_offset(r.first_seen_at, Utc),
            last_seen_at: DateTime::from_naive_utc_and_offset(r.last_seen_at, Utc),
        })
        .collect())
}

/// Removes a stored trust decision -- e.g. an admin deliberately
/// re-imaged a host and wants its next deploy to prompt fresh rather than
/// hard-stop on what now looks like a changed key.
pub async fn forget(pool: &DbPool, ip_address: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM ssh_trusted_host_keys WHERE ip_address = ?")
        .bind(ip_address)
        .execute(pool)
        .await?;
    Ok(())
}
