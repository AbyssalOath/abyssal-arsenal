use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(Debug, Clone)]
pub struct NewAuditEntry<'a> {
    pub user_id: Option<Uuid>,
    pub username_snapshot: &'a str,
    pub action: &'a str,
    pub resource: Option<&'a str>,
    pub result: &'a str,
    pub source_ip: Option<&'a str>,
    pub auth_method: Option<&'a str>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditEntry {
    pub id: String,
    pub occurred_at: NaiveDateTime,
    pub user_id: Option<String>,
    pub username_snapshot: String,
    pub action: String,
    pub resource: Option<String>,
    pub result: String,
    pub source_ip: Option<String>,
    pub auth_method: Option<String>,
    pub metadata: Option<Value>,
}

impl AuditEntry {
    pub fn occurred_at_utc(&self) -> DateTime<Utc> {
        DateTime::from_naive_utc_and_offset(self.occurred_at, Utc)
    }
}

pub async fn record(pool: &DbPool, entry: NewAuditEntry<'_>) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_log \
         (id, user_id, username_snapshot, action, resource, result, source_ip, auth_method, metadata) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(entry.user_id.map(|u| u.to_string()))
    .bind(entry.username_snapshot)
    .bind(entry.action)
    .bind(entry.resource)
    .bind(entry.result)
    .bind(entry.source_ip)
    .bind(entry.auth_method)
    .bind(entry.metadata)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    pub action: Option<String>,
    pub username: Option<String>,
}

pub async fn list(
    pool: &DbPool,
    filter: &AuditFilter,
    page: i64,
    page_size: i64,
) -> anyhow::Result<Vec<AuditEntry>> {
    let offset = page.max(0) * page_size;
    let rows: Vec<AuditEntry> = sqlx::query_as(
        "SELECT * FROM audit_log \
         WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username_snapshot = ?) \
         ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
    )
    .bind(&filter.action)
    .bind(&filter.action)
    .bind(&filter.username)
    .bind(&filter.username)
    .bind(page_size)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn count(pool: &DbPool, filter: &AuditFilter) -> anyhow::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log \
         WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username_snapshot = ?)",
    )
    .bind(&filter.action)
    .bind(&filter.action)
    .bind(&filter.username)
    .bind(&filter.username)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// A position in the audit log's `(occurred_at, id)` total order -- `id`
/// (a UUID) is the tiebreaker for rows sharing the same microsecond
/// timestamp, which `datetime(6)` makes rare but not impossible (e.g. a
/// batch of audit events written from one request). Opaque to callers
/// outside this module: encode/decode round-trip through a query param,
/// never constructed from anything but a row this module itself returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCursor {
    occurred_at_micros: i64,
    id: String,
}

impl AuditCursor {
    fn of(entry: &AuditEntry) -> Self {
        Self {
            occurred_at_micros: entry.occurred_at.and_utc().timestamp_micros(),
            id: entry.id.clone(),
        }
    }

    pub fn encode(&self) -> String {
        format!("{}_{}", self.occurred_at_micros, self.id)
    }

    /// `None` for anything that isn't a `<micros>_<uuid>` pair this module
    /// itself produced -- a hand-edited or stale cursor query param falls
    /// back to the first page rather than erroring.
    pub fn decode(s: &str) -> Option<Self> {
        let (micros, id) = s.split_once('_')?;
        Some(Self {
            occurred_at_micros: micros.parse().ok()?,
            id: id.to_string(),
        })
    }

    fn occurred_at(&self) -> NaiveDateTime {
        DateTime::from_timestamp_micros(self.occurred_at_micros)
            .unwrap_or_default()
            .naive_utc()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorDirection {
    /// Paging toward more recent entries (the "Newer" link). Meaningless
    /// without a cursor -- `list_keyset` treats `cursor: None` as "first
    /// page" regardless of `direction`.
    Newer,
    /// Paging toward older entries (the "Older" link), or the initial
    /// unbounded fetch.
    Older,
}

/// One keyset page -- no `total`/`total_pages`, since a keyset page
/// deliberately never runs the `COUNT(*)` a numbered pager would need.
#[derive(Debug, Clone)]
pub struct KeysetPage<T> {
    pub items: Vec<T>,
    pub newer_cursor: Option<String>,
    pub older_cursor: Option<String>,
}

/// One keyset page of the audit log -- no `COUNT(*)` over the whole
/// table, and no `OFFSET` (which gets linearly slower the deeper a page
/// is, since MariaDB still has to walk and discard every skipped row).
/// `limit + 1` rows are fetched and the extra trimmed off, purely to know
/// whether there's a further page in the direction just paged.
pub async fn list_keyset(
    pool: &DbPool,
    filter: &AuditFilter,
    cursor: Option<&AuditCursor>,
    direction: CursorDirection,
    limit: i64,
) -> anyhow::Result<KeysetPage<AuditEntry>> {
    let fetch_limit = limit + 1;
    let paging_newer = cursor.is_some() && direction == CursorDirection::Newer;

    let mut rows: Vec<AuditEntry> = match cursor {
        None => {
            sqlx::query_as(
                "SELECT * FROM audit_log \
                 WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username_snapshot = ?) \
                 ORDER BY occurred_at DESC, id DESC LIMIT ?",
            )
            .bind(&filter.action)
            .bind(&filter.action)
            .bind(&filter.username)
            .bind(&filter.username)
            .bind(fetch_limit)
            .fetch_all(pool)
            .await?
        }
        Some(c) if !paging_newer => {
            sqlx::query_as(
                "SELECT * FROM audit_log \
                 WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username_snapshot = ?) \
                   AND (occurred_at, id) < (?, ?) \
                 ORDER BY occurred_at DESC, id DESC LIMIT ?",
            )
            .bind(&filter.action)
            .bind(&filter.action)
            .bind(&filter.username)
            .bind(&filter.username)
            .bind(c.occurred_at())
            .bind(&c.id)
            .bind(fetch_limit)
            .fetch_all(pool)
            .await?
        }
        Some(c) => {
            // Fetched ascending (the rows immediately above the cursor,
            // closest first), then reversed below to restore the page's
            // newest-first display order.
            let mut rows: Vec<AuditEntry> = sqlx::query_as(
                "SELECT * FROM audit_log \
                 WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username_snapshot = ?) \
                   AND (occurred_at, id) > (?, ?) \
                 ORDER BY occurred_at ASC, id ASC LIMIT ?",
            )
            .bind(&filter.action)
            .bind(&filter.action)
            .bind(&filter.username)
            .bind(&filter.username)
            .bind(c.occurred_at())
            .bind(&c.id)
            .bind(fetch_limit)
            .fetch_all(pool)
            .await?;
            rows.reverse();
            rows
        }
    };

    // The probe row proving "there's more in this direction" lands at
    // whichever end of `rows` is farthest from the cursor: the last
    // element for the initial fetch/`Older` (plain `ORDER BY ... DESC`),
    // but the *first* element for `Newer` (reversed back from ascending).
    let has_more = rows.len() as i64 > limit;
    if has_more {
        if paging_newer {
            rows.remove(0);
        } else {
            rows.truncate(limit as usize);
        }
    }

    let newer_cursor = if rows.is_empty() || cursor.is_none() {
        None // empty page, or already the first/newest page
    } else if paging_newer {
        has_more.then(|| AuditCursor::of(&rows[0]))
    } else {
        // Came from Older: the row we paged from is always still there to
        // page back Newer toward.
        Some(AuditCursor::of(&rows[0]))
    };
    let older_cursor = if rows.is_empty() {
        None
    } else if paging_newer {
        // Paging Newer always has somewhere to go back Older to: the
        // cursor we arrived from.
        Some(AuditCursor::of(rows.last().unwrap()))
    } else {
        has_more.then(|| AuditCursor::of(rows.last().unwrap()))
    };

    Ok(KeysetPage {
        items: rows,
        newer_cursor: newer_cursor.map(|c| c.encode()),
        older_cursor: older_cursor.map(|c| c.encode()),
    })
}

/// Streams the *entire* filtered audit log in fixed-size keyset batches,
/// calling `on_batch` for each one -- the export path's answer to "never
/// truncated by page limits" without ever holding more than one batch in
/// memory at a time (unlike the old `list(pool, filter, 0, 10_000)`, which
/// silently dropped everything past row 10,000).
pub async fn for_each_batch<F>(
    pool: &DbPool,
    filter: &AuditFilter,
    batch_size: i64,
    mut on_batch: F,
) -> anyhow::Result<()>
where
    F: FnMut(&[AuditEntry]) -> anyhow::Result<()>,
{
    let mut cursor: Option<AuditCursor> = None;
    loop {
        let batch = list_keyset(
            pool,
            filter,
            cursor.as_ref(),
            CursorDirection::Older,
            batch_size,
        )
        .await?;
        if batch.items.is_empty() {
            break;
        }
        on_batch(&batch.items)?;
        if batch.older_cursor.is_none() {
            break;
        }
        cursor = batch.items.last().map(AuditCursor::of);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips_through_encode_and_decode() {
        let c = AuditCursor {
            occurred_at_micros: 1_700_000_000_123_456,
            id: "3fa85f64-5717-4562-b3fc-2c963f66afa6".to_string(),
        };
        let decoded = AuditCursor::decode(&c.encode()).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn cursor_decode_rejects_malformed_input() {
        assert!(AuditCursor::decode("not-a-cursor").is_none());
        assert!(AuditCursor::decode("abc_uuid").is_none());
        assert!(AuditCursor::decode("").is_none());
    }
}
