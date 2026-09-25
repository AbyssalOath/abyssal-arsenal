//! Platform-wide audit-trail-to-syslog export sweep (Phase 12 of the
//! Thanatos SIEM/EDR build-out, the "platform-wide audit trail" scope
//! chosen over "Thanatos-only"). Unlike Thanatos's own per-event export
//! (`thanatos_ops::maybe_export_persisted_event`), this doesn't hook into
//! any specific write path -- `abyssal_audit::record` is called from
//! hundreds of sites across the whole app (logins, RBAC changes,
//! backups, every arsenal's containment actions, ...), and retrofitting
//! every one of them to also push a notification would be exactly the
//! kind of invasive, easy-to-miss-one-call-site refactor this codebase
//! avoids elsewhere. Instead this sweep tails the append-only
//! `audit_log` table itself from a persisted watermark (`abyssal_
//! database::repo::audit::list_after`/`AuditCursor`) -- the same
//! "poll on an interval, advance a cursor" shape `spawn_thanatos_sweep`
//! already established, applied to a table instead of a live agent.

use std::time::Duration;

use abyssal_core::settings::{AUDIT_SYSLOG_EXPORT_CURSOR, AUDIT_SYSLOG_EXPORT_ENABLED};
use abyssal_database::repo::audit::AuditCursor;
use abyssal_database::{DbPool, repo};
use abyssal_notifications::{NotificationDispatcher, NotificationMessage, Severity};

/// How often the sweep polls for new audit rows. Fixed, not
/// Settings-tunable like Thanatos's own sweep interval -- polling the
/// audit table is cheap (an indexed keyset query), so there's no real
/// tradeoff here worth exposing as a knob the way Thanatos's real
/// per-host network round trip is.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// How many rows to export per tick -- bounded so one enormous backlog
/// (e.g. re-enabling this after a long time off) can't hold the sweep's
/// loop iteration open indefinitely; the next tick just picks up where
/// this one left off.
const BATCH_SIZE: i64 = 500;

pub fn spawn_audit_syslog_sweep(
    pool: DbPool,
    notifications: std::sync::Arc<NotificationDispatcher>,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;

            let enabled =
                match repo::settings::get_bool(&pool, AUDIT_SYSLOG_EXPORT_ENABLED, false).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read audit syslog export setting");
                        continue;
                    }
                };
            if !enabled {
                continue;
            }

            if let Err(e) = export_one_batch(&pool, &notifications).await {
                tracing::error!(error = %e, "audit syslog export tick failed");
            }
        }
    });
}

async fn export_one_batch(
    pool: &DbPool,
    notifications: &NotificationDispatcher,
) -> anyhow::Result<()> {
    let stored_cursor = repo::settings::get_string(pool, AUDIT_SYSLOG_EXPORT_CURSOR, "").await?;
    let cursor = if stored_cursor.is_empty() {
        // First run: silently baseline at "now" rather than exporting
        // this whole (potentially long) audit history the instant an
        // admin opts in -- the same "a host's first-ever scan never
        // alerts" principle Thanatos's own FIM/port/module baselines
        // already established, applied here to "don't retroactively
        // export pre-existing history."
        let newest = repo::audit::latest_cursor(pool).await?;
        if let Some(newest) = &newest {
            repo::settings::set(
                pool,
                AUDIT_SYSLOG_EXPORT_CURSOR,
                serde_json::json!(newest.encode()),
                None,
            )
            .await?;
        }
        return Ok(());
    } else {
        AuditCursor::decode(&stored_cursor)
    };

    let rows = repo::audit::list_after(pool, cursor.as_ref(), BATCH_SIZE).await?;
    let Some(last) = rows.last() else {
        return Ok(());
    };
    let new_cursor = AuditCursor::of(last);

    for entry in &rows {
        let severity = if entry.result == "FAILURE" {
            Severity::Warning
        } else {
            Severity::Info
        };
        let subject = format!("[Audit] {}", entry.action);
        let body = format!(
            "actor={} result={} resource={} source_ip={}{}",
            entry.username_snapshot,
            entry.result,
            entry.resource.as_deref().unwrap_or("-"),
            entry.source_ip.as_deref().unwrap_or("-"),
            entry
                .metadata
                .as_ref()
                .map(|m| format!(" metadata={m}"))
                .unwrap_or_default(),
        );
        notifications
            .dispatch(&NotificationMessage {
                subject,
                body,
                severity,
                recipients: Vec::new(),
            })
            .await;
    }

    repo::settings::set(
        pool,
        AUDIT_SYSLOG_EXPORT_CURSOR,
        serde_json::json!(new_cursor.encode()),
        None,
    )
    .await?;
    Ok(())
}
