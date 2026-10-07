//! Threat-intel IOCs (M5) -- see `abyssal_core::Ioc`. A finding whose text
//! matches any active IOC raises a dedicated `ioc` finding. The ingest path
//! loads all active IOCs once per scan and matches in memory.

use abyssal_core::{Ioc, IocType, Severity};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(FromRow)]
struct IocRow {
    id: String,
    ioc_type: String,
    value: String,
    severity: String,
    label: Option<String>,
    created_by: Option<String>,
    created_at: NaiveDateTime,
    expires_at: Option<NaiveDateTime>,
}

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

impl TryFrom<IocRow> for Ioc {
    type Error = ();
    fn try_from(row: IocRow) -> Result<Self, ()> {
        Ok(Ioc {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            // A row with an unrecognized type (shouldn't happen) is skipped by
            // the caller rather than mislabeled.
            ioc_type: IocType::from_key(&row.ioc_type).ok_or(())?,
            value: row.value,
            severity: Severity::from_key(&row.severity).unwrap_or(Severity::High),
            label: row.label,
            created_by: row.created_by.and_then(|s| Uuid::parse_str(&s).ok()),
            created_at: utc(row.created_at),
            expires_at: row.expires_at.map(utc),
        })
    }
}

/// Active (unexpired) IOCs -- the ingest path's input.
pub async fn list_active(pool: &DbPool) -> anyhow::Result<Vec<Ioc>> {
    let rows: Vec<IocRow> = sqlx::query_as(
        "SELECT * FROM thanatos_iocs \
         WHERE expires_at IS NULL OR expires_at > NOW() \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().filter_map(|r| r.try_into().ok()).collect())
}

/// Every IOC, active or expired -- the management page's list.
pub async fn list_all(pool: &DbPool) -> anyhow::Result<Vec<Ioc>> {
    let rows: Vec<IocRow> = sqlx::query_as("SELECT * FROM thanatos_iocs ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().filter_map(|r| r.try_into().ok()).collect())
}

/// Inserts one IOC, ignoring a duplicate `(ioc_type, value)` (returns whether a
/// new row was actually added). `value` must already be normalized
/// (`IocType::normalize`).
pub async fn create(
    pool: &DbPool,
    ioc_type: IocType,
    value: &str,
    severity: Severity,
    label: Option<&str>,
    created_by: Option<Uuid>,
    expires_at: Option<DateTime<Utc>>,
) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "INSERT IGNORE INTO thanatos_iocs \
         (id, ioc_type, value, severity, label, created_by, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ioc_type.as_key())
    .bind(value)
    .bind(severity.as_key())
    .bind(label)
    .bind(created_by.map(|u| u.to_string()))
    .bind(expires_at.map(|d| d.naive_utc()))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Deletes one IOC by id. Returns whether a row matched.
pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM thanatos_iocs WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
