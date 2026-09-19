mod action;
mod writer;

pub use action::{AuditAction, AuditOutcome};
pub use writer::{Actor, AuditEvent, record};

pub use abyssal_database::repo::audit::{AuditEntry, AuditFilter};

use abyssal_database::DbPool;

/// Paginated read access for the audit viewer. Kept here (rather than callers
/// reaching into `abyssal-database` directly) so this crate stays the single
/// entry point for both writing and reading audit history.
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
