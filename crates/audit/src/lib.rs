mod action;
mod writer;

pub use action::{AuditAction, AuditOutcome};
pub use writer::{Actor, AuditEvent, record};

pub use abyssal_database::repo::audit::{
    AuditCursor, AuditEntry, AuditFilter, CursorDirection, KeysetPage,
};

use abyssal_database::DbPool;

/// Paginated read access for the audit viewer. Kept here (rather than callers
/// reaching into `abyssal-database` directly) so this crate stays the single
/// entry point for both writing and reading audit history.
///
/// Offset-based, so it re-runs a `COUNT(*)` and pays an `OFFSET` scan on
/// every page -- fine for the dashboard's small "recent activity" fetch
/// (`routes/dashboard.rs`, always page 0), but the audit viewer itself
/// (`routes/audit.rs`) uses [`list_keyset`] instead (GitHub issue #10:
/// keyset pagination for append-heavy/huge tables).
pub async fn list(
    pool: &DbPool,
    filter: &AuditFilter,
    page: i64,
    page_size: i64,
) -> anyhow::Result<Vec<AuditEntry>> {
    abyssal_database::repo::audit::list(pool, filter, page, page_size).await
}

pub async fn count(pool: &DbPool, filter: &AuditFilter) -> anyhow::Result<i64> {
    abyssal_database::repo::audit::count(pool, filter).await
}

/// Keyset (cursor) read access -- see
/// `abyssal_database::repo::audit::list_keyset`'s doc comment for the
/// `(occurred_at, id)` cursor design.
pub async fn list_keyset(
    pool: &DbPool,
    filter: &AuditFilter,
    cursor: Option<&AuditCursor>,
    direction: CursorDirection,
    limit: i64,
) -> anyhow::Result<KeysetPage<AuditEntry>> {
    abyssal_database::repo::audit::list_keyset(pool, filter, cursor, direction, limit).await
}

/// Streams the entire filtered audit log in bounded batches -- the export
/// path's way of returning every matching row without ever loading them
/// all into memory at once or silently truncating past some fixed cap.
pub async fn for_each_batch<F>(
    pool: &DbPool,
    filter: &AuditFilter,
    batch_size: i64,
    on_batch: F,
) -> anyhow::Result<()>
where
    F: FnMut(&[AuditEntry]) -> anyhow::Result<()>,
{
    abyssal_database::repo::audit::for_each_batch(pool, filter, batch_size, on_batch).await
}
