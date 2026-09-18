//! Thanatos's control-plane-side logic: parsing and persisting a scan's
//! classified events, and the correlation check that turns a burst of
//! high-severity events into an alert. Shared by both the on-demand,
//! admin-triggered scan (`routes/thanatos.rs`) and the unattended
//! periodic sweep (`crates/app/src/main.rs`) -- the only difference
//! between them is *how* `AgentOperation::ScanSecurityEvents` gets
//! dispatched (through `Executor::execute_on_host` with a real
//! `AuthContext` for the former, directly through
//! `HostConnectionRegistry::dispatch` for the latter, which has no user
//! to check permissions against -- the same split
//! `spawn_elevation_expiry_sweep` already establishes for system-
//! initiated work).

use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_core::settings::{THANATOS_ALERT_RECIPIENTS, THANATOS_MONITORING_ENABLED};
use abyssal_core::Severity;
use abyssal_database::{repo, DbPool};
use abyssal_notifications::{NotificationDispatcher, NotificationMessage};
use uuid::Uuid;

use crate::state::AppState;

/// How far back a correlation check looks, and how long a raised alert
/// suppresses another one for the same host -- the same window serves
/// both purposes, so an alert's own cooldown is exactly as long as the
/// burst window that triggered it.
const CORRELATION_WINDOW_MINUTES: i64 = 5;
/// High-or-above events within the window that constitute a "burst"
/// worth alerting on. Matches the seeded default abyssal-seclog itself
/// uses for its own repeated-SSH-failure rule.
const CORRELATION_THRESHOLD: i64 = 5;

/// Parses `stdout` from `AgentOperation::ScanSecurityEvents` (either
/// tab-separated `severity\tlabel\tsource\traw_line` event lines, or a
/// single plain-English informational line when nothing was found/
/// nothing matched) and persists every event, deduplicating by content
/// hash. Returns the number of genuinely *new* events persisted (not the
/// number of lines the agent reported -- re-scanning the same tail
/// window reports the same lines again every time) and, when the output
/// wasn't event data at all, the informational message to show instead.
pub async fn persist_scan_output(
    pool: &DbPool,
    host_id: Uuid,
    stdout: &str,
) -> anyhow::Result<(usize, Option<String>)> {
    let mut persisted = 0usize;
    let mut saw_any_event_line = false;

    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        let [severity_str, label, source, raw_line] = parts.as_slice() else {
            continue;
        };
        let Some(severity) = Severity::from_key(severity_str) else {
            continue;
        };
        saw_any_event_line = true;
        if repo::security_events::insert_if_new(pool, host_id, source, severity, label, raw_line)
            .await?
        {
            persisted += 1;
        }
    }

    if saw_any_event_line {
        Ok((persisted, None))
    } else {
        let message = stdout.trim();
        Ok((
            0,
            if message.is_empty() {
                None
            } else {
                Some(message.to_string())
            },
        ))
    }
}

/// Checks whether this host has crossed the high-severity burst
/// threshold within the correlation window and, if so and it hasn't
/// already been alerted on within that same window, raises a `Critical`
/// correlation finding and notifies `recipients` (a no-op if empty or if
/// no notification provider is configured -- the finding is still
/// persisted and visible in the UI either way). Returns whether an alert
/// was raised.
pub async fn check_and_raise_alert(
    pool: &DbPool,
    notifications: &NotificationDispatcher,
    recipients: &[String],
    host_id: Uuid,
    host_name: &str,
) -> anyhow::Result<bool> {
    let recent_high =
        repo::security_events::count_high_severity_since(pool, host_id, CORRELATION_WINDOW_MINUTES)
            .await?;
    if recent_high < CORRELATION_THRESHOLD {
        return Ok(false);
    }
    if repo::security_events::has_recent_correlation_event(
        pool,
        host_id,
        CORRELATION_WINDOW_MINUTES,
    )
    .await?
    {
        return Ok(false);
    }

    let label = "Repeated high-severity security events";
    let raw_line = format!(
        "{recent_high} high-or-critical security event(s) on \"{host_name}\" within the last \
         {CORRELATION_WINDOW_MINUTES} minutes (threshold: {CORRELATION_THRESHOLD})."
    );

    repo::security_events::insert_if_new(
        pool,
        host_id,
        "correlation",
        Severity::Critical,
        label,
        &raw_line,
    )
    .await?;

    if !recipients.is_empty() {
        let message = NotificationMessage {
            subject: format!("[Thanatos] Security alert on {host_name}"),
            body: raw_line.clone(),
            severity: abyssal_notifications::Severity::Critical,
            recipients: recipients.to_vec(),
        };
        notifications.dispatch(&message).await;
    }

    Ok(true)
}

/// Parses a comma-separated recipient list the way
/// `THANATOS_ALERT_RECIPIENTS` stores it.
pub fn parse_recipients(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Runs the persist-then-correlate pipeline for one host's scan output --
/// the shared tail end of both the on-demand and the periodic-sweep
/// paths.
pub async fn ingest_scan(
    pool: &DbPool,
    notifications: &NotificationDispatcher,
    recipients: &[String],
    host_id: Uuid,
    host_name: &str,
    stdout: &str,
) -> anyhow::Result<(usize, Option<String>, bool)> {
    let (persisted, informational) = persist_scan_output(pool, host_id, stdout).await?;
    let alerted =
        check_and_raise_alert(pool, notifications, recipients, host_id, host_name).await?;
    Ok((persisted, informational, alerted))
}

/// Fleet-wide severity counts over the last `hours`, rendered as
/// `(label, count)` pairs in a fixed Low/Medium/High/Critical order
/// (rather than whatever order the database happened to return) for the
/// landing page summary.
pub async fn severity_summary(pool: &DbPool, hours: i64) -> anyhow::Result<Vec<(Severity, i64)>> {
    let rows = repo::security_events::count_by_severity_since(pool, hours).await?;
    let mut counts = [0i64; 4];
    for (severity_key, count) in rows {
        if let Some(severity) = Severity::from_key(&severity_key) {
            counts[severity as usize] = count;
        }
    }
    Ok(vec![
        (Severity::Low, counts[0]),
        (Severity::Medium, counts[1]),
        (Severity::High, counts[2]),
        (Severity::Critical, counts[3]),
    ])
}

/// Spawns Thanatos's unattended periodic sweep -- the counterpart to
/// `spawn_elevation_expiry_sweep` in `crates/app/src/main.rs`, following
/// the same shape (a `tokio::spawn`'d fixed-interval loop, system-
/// initiated so it bypasses `Executor::execute_on_host` and dispatches
/// directly through `HostConnectionRegistry`, since there's no
/// `AuthContext` to check permissions against). Does nothing on a tick
/// where `THANATOS_MONITORING_ENABLED` is off, checked fresh every tick
/// so toggling the setting takes effect on the next tick, not after a
/// restart.
pub fn spawn_thanatos_sweep(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;

            let enabled =
                match repo::settings::get_bool(&state.pool, THANATOS_MONITORING_ENABLED, false)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read Thanatos monitoring setting");
                        continue;
                    }
                };
            if !enabled {
                continue;
            }

            let recipients_raw = match repo::settings::get_string(
                &state.pool,
                THANATOS_ALERT_RECIPIENTS,
                "",
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "failed to read Thanatos alert recipients");
                    String::new()
                }
            };
            let recipients = parse_recipients(&recipients_raw);

            let hosts = match repo::hosts::list(&state.pool).await {
                Ok(hosts) => hosts,
                Err(e) => {
                    tracing::error!(error = %e, "Thanatos sweep failed to list hosts");
                    continue;
                }
            };

            for host in hosts {
                if !host.is_active() || !state.hosts.is_connected(host.id) {
                    continue;
                }

                let outcome = state
                    .hosts
                    .dispatch(
                        host.id,
                        AgentOperation::ScanSecurityEvents,
                        Duration::from_secs(30),
                    )
                    .await;

                let stdout = match outcome {
                    Ok(CommandOutcome::Ok(output)) => output.stdout,
                    Ok(CommandOutcome::Err(message)) => {
                        tracing::warn!(host = %host.name, error = %message, "Thanatos sweep scan failed");
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(host = %host.name, error = %e, "Thanatos sweep dispatch failed");
                        continue;
                    }
                };

                if let Err(e) = ingest_scan(
                    &state.pool,
                    &state.notifications,
                    &recipients,
                    host.id,
                    &host.name,
                    &stdout,
                )
                .await
                {
                    tracing::error!(host = %host.name, error = %e, "Thanatos sweep failed to ingest scan results");
                }
            }
        }
    });
}
