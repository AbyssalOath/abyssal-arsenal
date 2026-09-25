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

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::Severity;
use abyssal_core::settings::{
    THANATOS_ALERT_RECIPIENTS, THANATOS_CORRELATION_THRESHOLD,
    THANATOS_CORRELATION_THRESHOLD_DEFAULT, THANATOS_CORRELATION_WINDOW_MINUTES,
    THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT, THANATOS_CROSS_HOST_THRESHOLD,
    THANATOS_CROSS_HOST_THRESHOLD_DEFAULT, THANATOS_MONITORING_ENABLED,
    THANATOS_SWEEP_INTERVAL_SECONDS, THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT,
};
use abyssal_database::{DbPool, repo};
use abyssal_notifications::{NotificationDispatcher, NotificationMessage};
use uuid::Uuid;

use crate::state::AppState;

/// Reads `THANATOS_CORRELATION_THRESHOLD`/`_WINDOW_MINUTES`, falling back
/// to their defaults on a read error rather than failing the scan that
/// needs them -- correlation is a nice-to-have layered on top of a scan
/// that already succeeded, never something worth aborting the scan over.
async fn correlation_settings(pool: &DbPool) -> (i64, i64) {
    let threshold = repo::settings::get_u32(
        pool,
        THANATOS_CORRELATION_THRESHOLD,
        THANATOS_CORRELATION_THRESHOLD_DEFAULT,
    )
    .await
    .unwrap_or(THANATOS_CORRELATION_THRESHOLD_DEFAULT);
    let window_minutes = repo::settings::get_u32(
        pool,
        THANATOS_CORRELATION_WINDOW_MINUTES,
        THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT,
    )
    .await
    .unwrap_or(THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT);
    (i64::from(threshold), i64::from(window_minutes))
}

/// The synthetic label/severity for a file-integrity watch-list change --
/// never emitted by the agent's own `RULES` table (that's reserved for
/// `critical`-free classified log lines), so this is the one place a
/// `source = "fim"` row's shape is defined.
const FIM_CHANGE_LABEL: &str = "File-integrity watch-list change";

/// Parses `stdout` from `AgentOperation::ScanSecurityEvents` -- three
/// explicitly tagged line shapes (see `crates/agent/src/thanatos.rs`'s
/// module doc comment): `severity\tlabel\tsource\traw_line` for a
/// classified event, `fim\t<path>\t<hash>` for a file-integrity
/// watch-list entry, `info\t<message>` for anything else worth surfacing
/// (no readable log sources, or nothing matched). Any line matching none
/// of these shapes is silently ignored rather than guessed at.
///
/// Persists every classified event (deduplicated by content hash) and
/// compares every FIM hash against the last one recorded for that
/// host+path (`repo::thanatos_file_hashes`), inserting a synthetic
/// `high`-severity event when one has actually changed since a prior
/// observation (never on the first sighting of a path, which only
/// establishes the baseline). Returns the number of genuinely *new*
/// events persisted (classified + FIM-drift combined -- not the number of
/// lines the agent reported, since re-scanning the same tail window
/// reports the same lines again every time) and, when the agent sent an
/// `info` line, that message to show instead.
pub async fn persist_scan_output(
    pool: &DbPool,
    host_id: Uuid,
    stdout: &str,
) -> anyhow::Result<(usize, Option<String>)> {
    let mut persisted = 0usize;
    let mut informational_lines: Vec<&str> = Vec::new();

    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("fim\t") {
            let Some((path, hash)) = rest.split_once('\t') else {
                continue;
            };
            if repo::thanatos_file_hashes::upsert_if_changed(pool, host_id, path, hash).await? {
                let raw_line = format!("{path} hash changed to {hash}");
                if repo::security_events::insert_if_new(
                    pool,
                    host_id,
                    "fim",
                    Severity::High,
                    FIM_CHANGE_LABEL,
                    &raw_line,
                )
                .await?
                {
                    persisted += 1;
                }
            }
            continue;
        }

        if let Some(message) = line.strip_prefix("info\t") {
            informational_lines.push(message);
            continue;
        }

        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        let [severity_str, label, source, raw_line] = parts.as_slice() else {
            continue;
        };
        let Some(severity) = Severity::from_key(severity_str) else {
            continue;
        };
        if repo::security_events::insert_if_new(pool, host_id, source, severity, label, raw_line)
            .await?
        {
            persisted += 1;
        }
    }

    let informational = (!informational_lines.is_empty()).then(|| informational_lines.join("\n"));
    Ok((persisted, informational))
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
    let (threshold, window_minutes) = correlation_settings(pool).await;

    let recent_high =
        repo::security_events::count_high_severity_since(pool, host_id, window_minutes).await?;
    if recent_high < threshold {
        return Ok(false);
    }
    if repo::security_events::has_recent_correlation_event(pool, host_id, window_minutes).await? {
        return Ok(false);
    }

    let label = "Repeated high-severity security events";
    let raw_line = format!(
        "{recent_high} high-or-critical security event(s) on \"{host_name}\" within the last \
         {window_minutes} minutes (threshold: {threshold})."
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

    // System-attributed (no actor) regardless of whether this correlation
    // check ran off an on-demand scan or the unattended sweep -- the
    // finding itself is a computed detection, not something either a user
    // or the sweep "did"; the scan action that triggered it is audited
    // separately (`SecurityEventScanRun`, via `Executor`'s `HostOpKind` on
    // the on-demand path, or directly below in the sweep loop).
    if let Err(e) = abyssal_audit::record(
        pool,
        AuditEvent::new(AuditAction::SecurityAlertRaised, AuditOutcome::Success)
            .resource(host_name)
            .metadata(serde_json::json!({
                "recent_high_severity_count": recent_high,
                "threshold": threshold,
                "window_minutes": window_minutes,
            })),
    )
    .await
    {
        tracing::error!(error = %e, host = %host_name, "failed to write audit record for Thanatos correlation alert");
    }

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

/// Best-effort extraction of a `from <ip>` token from a raw auth-log line
/// (e.g. `"Failed password for invalid user root from 203.0.113.5 port 22
/// ssh2"`) -- every SSH auth failure/success rule this app's own `RULES`
/// table (`crates/agent/src/thanatos.rs`) matches follows this shape.
/// Returns the first whitespace-delimited token that parses as an IPv4 or
/// IPv6 address, `None` if none does (a rule matched by coincidence on a
/// line with no address at all, e.g. a `sudo:`/systemd-unit-failure line).
fn extract_source_ip(raw_line: &str) -> Option<IpAddr> {
    raw_line.split_whitespace().find_map(|tok| tok.parse().ok())
}

const CROSS_HOST_LABEL: &str = "Cross-host credential-stuffing pattern";

/// Looks for one source IP that's triggered high-or-above severity events
/// on several distinct hosts within the correlation window -- a pattern a
/// per-host threshold alone can't see (Thanatos SIEM/EDR build-out,
/// Phase 2). Shares `source = "correlation"` with the per-host alert
/// (distinguished by `label` instead) so it shows up in the same "Recent
/// Alerts" fleet view and fleet-wide alert count with no changes needed
/// there; as a side effect, a host that already has a fresh per-host
/// correlation finding this window is also treated as already covered for
/// this check (`has_recent_correlation_event` doesn't distinguish which
/// kind raised it) -- an accepted, documented tradeoff: both alerts
/// describe the same underlying incident already being surfaced, not two
/// unrelated things silently suppressing each other. One row is inserted
/// per affected host still missing a fresh correlation finding, so it
/// appears on each of their own event histories, not just an arbitrarily-
/// chosen one.
///
/// Called once per host's `ingest_scan` (both the on-demand and sweep
/// paths), so an *N*-host sweep tick runs this fleet-wide query *N* times
/// rather than once -- an accepted simplicity tradeoff at the scale this
/// app targets (a homelab/small-org fleet, not thousands of hosts), not
/// something worth a separate "run once per sweep tick" code path for.
async fn check_cross_host_burst(
    pool: &DbPool,
    notifications: &NotificationDispatcher,
    recipients: &[String],
    window_minutes: i64,
) -> anyhow::Result<bool> {
    let host_threshold = repo::settings::get_u32(
        pool,
        THANATOS_CROSS_HOST_THRESHOLD,
        THANATOS_CROSS_HOST_THRESHOLD_DEFAULT,
    )
    .await
    .unwrap_or(THANATOS_CROSS_HOST_THRESHOLD_DEFAULT);

    let rows =
        repo::security_events::list_recent_high_severity_all_hosts(pool, window_minutes).await?;
    let mut hosts_by_ip: HashMap<IpAddr, HashSet<Uuid>> = HashMap::new();
    for (host_id, raw_line) in &rows {
        if let Some(ip) = extract_source_ip(raw_line) {
            hosts_by_ip.entry(ip).or_default().insert(*host_id);
        }
    }

    let mut alerted = false;
    for (ip, affected_hosts) in hosts_by_ip {
        if (affected_hosts.len() as u32) < host_threshold {
            continue;
        }
        let raw_line = format!(
            "{ip} triggered high-or-critical security events on {} distinct host(s) within the \
             last {window_minutes} minutes (threshold: {host_threshold}).",
            affected_hosts.len()
        );

        for host_id in &affected_hosts {
            if repo::security_events::has_recent_correlation_event(pool, *host_id, window_minutes)
                .await?
            {
                continue;
            }
            let inserted = repo::security_events::insert_if_new(
                pool,
                *host_id,
                "correlation",
                Severity::Critical,
                CROSS_HOST_LABEL,
                &raw_line,
            )
            .await?;
            if !inserted {
                continue;
            }
            alerted = true;

            if let Err(e) = abyssal_audit::record(
                pool,
                AuditEvent::new(AuditAction::SecurityAlertRaised, AuditOutcome::Success)
                    .resource(&host_id.to_string())
                    .metadata(serde_json::json!({
                        "source_ip": ip.to_string(),
                        "affected_host_count": affected_hosts.len(),
                        "threshold": host_threshold,
                        "window_minutes": window_minutes,
                        "kind": "cross_host",
                    })),
            )
            .await
            {
                tracing::error!(error = %e, host_id = %host_id, "failed to write audit record for Thanatos cross-host alert");
            }

            if !recipients.is_empty() {
                let message = NotificationMessage {
                    subject: "[Thanatos] Cross-host security alert".to_string(),
                    body: raw_line.clone(),
                    severity: abyssal_notifications::Severity::Critical,
                    recipients: recipients.to_vec(),
                };
                notifications.dispatch(&message).await;
            }
        }
    }

    Ok(alerted)
}

/// Runs the persist-then-correlate pipeline for one host's scan output --
/// the shared tail end of both the on-demand and the periodic-sweep
/// paths. `alerted` is true if either the per-host burst check or the
/// fleet-wide cross-host check raised a finding.
pub async fn ingest_scan(
    pool: &DbPool,
    notifications: &NotificationDispatcher,
    recipients: &[String],
    host_id: Uuid,
    host_name: &str,
    stdout: &str,
) -> anyhow::Result<(usize, Option<String>, bool)> {
    let (persisted, informational) = persist_scan_output(pool, host_id, stdout).await?;
    let per_host_alerted =
        check_and_raise_alert(pool, notifications, recipients, host_id, host_name).await?;
    let (_, window_minutes) = correlation_settings(pool).await;
    let cross_host_alerted =
        check_cross_host_burst(pool, notifications, recipients, window_minutes).await?;
    Ok((
        persisted,
        informational,
        per_host_alerted || cross_host_alerted,
    ))
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
/// the same shape (a `tokio::spawn`'d loop, system-initiated so it
/// bypasses `Executor::execute_on_host` and dispatches directly through
/// `HostConnectionRegistry`, since there's no `AuthContext` to check
/// permissions against). Does nothing on a tick where
/// `THANATOS_MONITORING_ENABLED` is off, checked fresh every tick so
/// toggling the setting takes effect on the next tick, not after a
/// restart. Unlike a fixed `tokio::time::interval`, the sleep duration
/// itself is re-read from `THANATOS_SWEEP_INTERVAL_SECONDS` before every
/// sleep -- a lowered interval takes effect after at most one old-length
/// sleep, never a restart.
pub fn spawn_thanatos_sweep(state: AppState) {
    tokio::spawn(async move {
        loop {
            let interval_secs = repo::settings::get_u32(
                &state.pool,
                THANATOS_SWEEP_INTERVAL_SECONDS,
                THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT,
            )
            .await
            .unwrap_or(THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT);
            tokio::time::sleep(Duration::from_secs(u64::from(interval_secs))).await;

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

                match ingest_scan(
                    &state.pool,
                    &state.notifications,
                    &recipients,
                    host.id,
                    &host.name,
                    &stdout,
                )
                .await
                {
                    Ok((persisted, _informational, alerted)) => {
                        // System-attributed -- this is the sweep's only
                        // audit trail today (it bypasses
                        // `Executor::execute_on_host` entirely, since
                        // there's no `AuthContext` to check permissions
                        // against, and so gets none of that path's
                        // automatic auditing for free).
                        if let Err(e) = abyssal_audit::record(
                            &state.pool,
                            AuditEvent::new(
                                AuditAction::SecurityEventScanRun,
                                AuditOutcome::Success,
                            )
                            .resource(&host.name)
                            .metadata(serde_json::json!({
                                "persisted_count": persisted,
                                "alerted": alerted,
                                "trigger": "sweep",
                            })),
                        )
                        .await
                        {
                            tracing::error!(host = %host.name, error = %e, "failed to write audit record for Thanatos sweep scan");
                        }
                    }
                    Err(e) => {
                        tracing::error!(host = %host.name, error = %e, "Thanatos sweep failed to ingest scan results");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_source_ip_from_an_ssh_failure_line() {
        assert_eq!(
            extract_source_ip(
                "Failed password for invalid user root from 203.0.113.5 port 22 ssh2"
            ),
            Some("203.0.113.5".parse().unwrap())
        );
    }

    #[test]
    fn extracts_an_ipv6_source_address_too() {
        assert_eq!(
            extract_source_ip("Failed password for admin from 2001:db8::1 port 22 ssh2"),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn returns_none_when_no_token_is_an_ip_address() {
        assert_eq!(
            extract_source_ip("sudo: pam_unix(sudo:auth): session opened"),
            None
        );
        assert_eq!(extract_source_ip(""), None);
    }

    #[test]
    fn parse_recipients_splits_and_trims_and_drops_empties() {
        assert_eq!(
            parse_recipients(" a@example.com, b@example.com ,, "),
            vec!["a@example.com".to_string(), "b@example.com".to_string()]
        );
    }
}
