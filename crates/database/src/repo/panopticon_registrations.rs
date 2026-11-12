//! Guest registrations from Panopticon's registration portal (0.2.7 N5).

use abyssal_core::{Registration, RegistrationStatus};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(FromRow)]
struct Row {
    mac_address: String,
    name: String,
    email: Option<String>,
    status: String,
    requested_at: NaiveDateTime,
    decided_at: Option<NaiveDateTime>,
    decided_by: Option<String>,
    expires_at: Option<NaiveDateTime>,
}

impl From<Row> for Registration {
    fn from(r: Row) -> Self {
        Registration {
            mac_address: r.mac_address,
            name: r.name,
            email: r.email,
            status: r.status.parse().unwrap_or(RegistrationStatus::Expired),
            requested_at: utc(r.requested_at),
            decided_at: r.decided_at.map(utc),
            decided_by: r.decided_by,
            expires_at: r.expires_at.map(utc),
        }
    }
}

/// Records a guest's request: pending, or (self-service) approved until
/// `approved_until`. A device asking again replaces its earlier request,
/// unless that one still grants access or was denied (a denial sticks, so a
/// refused device can't refill the queue; staff can still approve it).
///
/// MariaDB applies the assignments left to right, so `status` must stay
/// last: every condition before it reads the old status.
pub async fn request(
    pool: &DbPool,
    mac: &str,
    name: &str,
    email: Option<&str>,
    approved_until: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    let status = if approved_until.is_some() {
        RegistrationStatus::Approved
    } else {
        RegistrationStatus::Pending
    };
    let decided_by = approved_until.map(|_| "self-registration");
    sqlx::query(
        "INSERT INTO panopticon_registrations \
         (mac_address, name, email, status, decided_at, decided_by, expires_at) \
         VALUES (LOWER(?), ?, ?, ?, IF(? IS NULL, NULL, CURRENT_TIMESTAMP(6)), ?, ?) \
         ON DUPLICATE KEY UPDATE \
             name = IF((status = 'approved' AND expires_at > UTC_TIMESTAMP(6)) OR status = 'denied', name, VALUES(name)), \
             email = IF((status = 'approved' AND expires_at > UTC_TIMESTAMP(6)) OR status = 'denied', email, VALUES(email)), \
             requested_at = IF((status = 'approved' AND expires_at > UTC_TIMESTAMP(6)) OR status = 'denied', requested_at, CURRENT_TIMESTAMP(6)), \
             decided_at = IF((status = 'approved' AND expires_at > UTC_TIMESTAMP(6)) OR status = 'denied', decided_at, VALUES(decided_at)), \
             decided_by = IF((status = 'approved' AND expires_at > UTC_TIMESTAMP(6)) OR status = 'denied', decided_by, VALUES(decided_by)), \
             expires_at = IF((status = 'approved' AND expires_at > UTC_TIMESTAMP(6)) OR status = 'denied', expires_at, VALUES(expires_at)), \
             status = IF((status = 'approved' AND expires_at > UTC_TIMESTAMP(6)) OR status = 'denied', status, VALUES(status))",
    )
    .bind(mac)
    .bind(name)
    .bind(email)
    .bind(status.as_str())
    .bind(decided_by)
    .bind(decided_by)
    .bind(approved_until.map(|t| t.naive_utc()))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find(pool: &DbPool, mac: &str) -> anyhow::Result<Option<Registration>> {
    let row: Option<Row> =
        sqlx::query_as("SELECT * FROM panopticon_registrations WHERE mac_address = LOWER(?)")
            .bind(mac)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(Into::into))
}

/// Pending first (they need someone), then newest.
pub async fn list(pool: &DbPool, limit: u32) -> anyhow::Result<Vec<Registration>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT * FROM panopticon_registrations \
         ORDER BY status = 'pending' DESC, requested_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// A staff decision, only from the states it makes sense from (checked in
/// the UPDATE).
/// Returns whether anything changed.
pub async fn decide(
    pool: &DbPool,
    mac: &str,
    to: RegistrationStatus,
    by: &str,
    expires_at: Option<DateTime<Utc>>,
) -> anyhow::Result<bool> {
    // Approve a pending or denied request; deny a pending one; revoke a
    // live approval.
    let (from_a, from_b) = match to {
        RegistrationStatus::Approved => ("pending", "denied"),
        RegistrationStatus::Denied => ("pending", "pending"),
        RegistrationStatus::Revoked => ("approved", "approved"),
        _ => return Ok(false),
    };
    let result = sqlx::query(
        "UPDATE panopticon_registrations \
         SET status = ?, decided_at = CURRENT_TIMESTAMP(6), decided_by = ?, expires_at = ? \
         WHERE mac_address = LOWER(?) AND status IN (?, ?)",
    )
    .bind(to.as_str())
    .bind(by)
    .bind(expires_at.map(|t| t.naive_utc()))
    .bind(mac)
    .bind(from_a)
    .bind(from_b)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Marks approvals past their expiry as expired, returning their MACs (to
/// re-authorize: they go back to the registration VLAN).
pub async fn expire_due(pool: &DbPool) -> anyhow::Result<Vec<String>> {
    let now = Utc::now().naive_utc();
    let macs: Vec<(String,)> = sqlx::query_as(
        "SELECT mac_address FROM panopticon_registrations \
         WHERE status = 'approved' AND expires_at <= ?",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;
    let mut expired = Vec::new();
    for (mac,) in macs {
        let r = sqlx::query(
            "UPDATE panopticon_registrations SET status = 'expired' \
             WHERE mac_address = ? AND status = 'approved' AND expires_at <= ?",
        )
        .bind(&mac)
        .bind(now)
        .execute(pool)
        .await?;
        if r.rows_affected() > 0 {
            expired.push(mac);
        }
    }
    Ok(expired)
}
