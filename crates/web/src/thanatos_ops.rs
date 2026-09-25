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

use abyssal_agent_protocol::{
    AgentOperation, CommandOutcome, is_protected_account_name, is_protected_windows_account_name,
    is_valid_absolute_path, is_valid_account_name, is_valid_windows_absolute_path,
    is_valid_windows_account_name,
};
use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::Severity;
use abyssal_core::settings::{
    THANATOS_ALERT_RECIPIENTS, THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED,
    THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED, THANATOS_CORRELATION_THRESHOLD,
    THANATOS_CORRELATION_THRESHOLD_DEFAULT, THANATOS_CORRELATION_WINDOW_MINUTES,
    THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT, THANATOS_CROSS_HOST_THRESHOLD,
    THANATOS_CROSS_HOST_THRESHOLD_DEFAULT, THANATOS_EXTRA_FIM_PATHS, THANATOS_MONITORING_ENABLED,
    THANATOS_SWEEP_INTERVAL_SECONDS, THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT,
};
use abyssal_database::{DbPool, repo};
use abyssal_hosts::HostConnectionRegistry;
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

/// Same role as `FIM_CHANGE_LABEL`, for a newly-appearing listening
/// port (`source = "network"`) -- see
/// `repo::thanatos_network_baseline::record_seen_ports`.
const NEW_LISTENING_PORT_LABEL: &str = "New listening port";

/// Same role again, for a newly-loaded kernel module/driver (Phase 9,
/// `source = "kernel_module"`) -- see `repo::
/// thanatos_kernel_module_baseline::record_seen_modules`.
const NEW_KERNEL_MODULE_LABEL: &str = "New kernel module/driver loaded";

/// Parses `stdout` from `AgentOperation::ScanSecurityEvents` -- five
/// explicitly tagged line shapes (see `crates/agent/src/thanatos.rs`'s
/// module doc comment): `severity\tlabel\tsource\traw_line` for a
/// classified event, `fim\t<path>\t<hash>` for a file-integrity
/// watch-list entry, `port\t<proto>:<port>` for a currently-listening
/// port (Phase 7a), `module\t<name>` for a currently-loaded kernel
/// module/driver (Phase 9), `info\t<message>` for anything else worth
/// surfacing (no readable log sources, or nothing matched). Any line
/// matching none of these shapes is silently ignored rather than
/// guessed at.
///
/// Persists every classified event (deduplicated by content hash) and
/// compares every FIM hash against the last one recorded for that
/// host+path (`repo::thanatos_file_hashes`), inserting a synthetic
/// `high`-severity event when one has actually changed since a prior
/// observation (never on the first sighting of a path, which only
/// establishes the baseline). Every reported port and every reported
/// module are each reconciled in their own batch, after the line-by-line
/// loop, against `repo::thanatos_network_baseline`/`repo::
/// thanatos_kernel_module_baseline` respectively -- genuinely new ones
/// (never on a host's first-ever scan) each become a synthetic
/// `high`-severity event too. Returns the number of genuinely *new*
/// events persisted (classified + FIM-drift + new-port + new-module
/// combined -- not the number of lines the agent reported, since
/// re-scanning the same tail window reports the same lines again every
/// time) and, when the agent sent an `info` line, that message to show
/// instead.
pub async fn persist_scan_output(
    pool: &DbPool,
    hosts: &HostConnectionRegistry,
    notifications: &NotificationDispatcher,
    host_id: Uuid,
    host_name: &str,
    stdout: &str,
) -> anyhow::Result<(usize, Option<String>)> {
    let mut persisted = 0usize;
    let mut informational_lines: Vec<&str> = Vec::new();
    let mut current_ports: Vec<String> = Vec::new();
    let mut current_modules: Vec<String> = Vec::new();

    for line in stdout.lines() {
        if let Some(port_key) = line.strip_prefix("port\t") {
            if !port_key.is_empty() {
                current_ports.push(port_key.to_string());
            }
            continue;
        }

        if let Some(module_key) = line.strip_prefix("module\t") {
            if !module_key.is_empty() {
                current_modules.push(module_key.to_string());
            }
            continue;
        }

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
                    export_event_to_syslog(
                        notifications,
                        host_name,
                        Severity::High,
                        "fim",
                        FIM_CHANGE_LABEL,
                        &raw_line,
                    )
                    .await;
                }
                if is_per_user_ssh_authorized_keys(path) {
                    maybe_auto_quarantine_ssh_key(pool, hosts, host_id, path).await;
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
            export_event_to_syslog(notifications, host_name, severity, source, label, raw_line)
                .await;
        }
    }

    if !current_ports.is_empty() {
        let new_ports =
            repo::thanatos_network_baseline::record_seen_ports(pool, host_id, &current_ports)
                .await?;
        for port_key in new_ports {
            let raw_line = format!("New listening port: {port_key}");
            if repo::security_events::insert_if_new(
                pool,
                host_id,
                "network",
                Severity::High,
                NEW_LISTENING_PORT_LABEL,
                &raw_line,
            )
            .await?
            {
                persisted += 1;
                export_event_to_syslog(
                    notifications,
                    host_name,
                    Severity::High,
                    "network",
                    NEW_LISTENING_PORT_LABEL,
                    &raw_line,
                )
                .await;
            }
        }
    }

    if !current_modules.is_empty() {
        let new_modules = repo::thanatos_kernel_module_baseline::record_seen_modules(
            pool,
            host_id,
            &current_modules,
        )
        .await?;
        for module_key in new_modules {
            let raw_line = format!("New kernel module/driver loaded: {module_key}");
            if repo::security_events::insert_if_new(
                pool,
                host_id,
                "kernel_module",
                Severity::High,
                NEW_KERNEL_MODULE_LABEL,
                &raw_line,
            )
            .await?
            {
                persisted += 1;
                export_event_to_syslog(
                    notifications,
                    host_name,
                    Severity::High,
                    "kernel_module",
                    NEW_KERNEL_MODULE_LABEL,
                    &raw_line,
                )
                .await;
            }
        }
    }

    let informational = (!informational_lines.is_empty()).then(|| informational_lines.join("\n"));
    Ok((persisted, informational))
}

/// Maps a Thanatos finding's `Severity` to the coarser three-level
/// `abyssal_notifications::Severity` -- `Low`/`Medium` both fold to
/// `Info` (a real SIEM's own rules can re-derive finer severity from the
/// forwarded `source`/label text if it wants to), `High` maps to
/// `Warning`, and `Critical` (reserved for correlation alerts, per this
/// file's own convention) maps to `Critical`.
fn notification_severity(severity: Severity) -> abyssal_notifications::Severity {
    match severity {
        Severity::Low | Severity::Medium => abyssal_notifications::Severity::Info,
        Severity::High => abyssal_notifications::Severity::Warning,
        Severity::Critical => abyssal_notifications::Severity::Critical,
    }
}

/// Phase 12 (external SIEM/syslog export), the "every persisted
/// classified event" scope chosen over "alerts only": forwards *every*
/// genuinely new Thanatos finding (not just correlation alerts, which
/// already went through `notifications.dispatch` before this phase) to
/// whatever `NotificationProvider`s are registered. `recipients` is
/// deliberately empty -- unlike an alert email, nobody should get an
/// inbox message for every classified log line, only a syslog
/// destination that's set up to receive a firehose of these
/// (`SmtpProvider::send` is a no-op on an empty recipient list, so this
/// naturally reaches only the syslog provider when both are configured).
async fn export_event_to_syslog(
    notifications: &NotificationDispatcher,
    host_name: &str,
    severity: Severity,
    source: &str,
    label: &str,
    raw_line: &str,
) {
    notifications
        .dispatch(&NotificationMessage {
            subject: format!("[Thanatos] {host_name}: {label}"),
            body: format!("source={source} severity={} {raw_line}", severity.as_key()),
            severity: notification_severity(severity),
            recipients: Vec::new(),
        })
        .await;
}

/// True only for a per-user OpenSSH `authorized_keys` file, matched on
/// exact basename (not a suffix check) so Windows' fixed, admin-wide
/// `administrators_authorized_keys` (which happens to end with the same
/// substring) is deliberately excluded -- see
/// `THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED`'s doc comment for why
/// auto-quarantine is scoped this narrowly rather than to "any FIM
/// drift." Splits on both separators since a path here may be either
/// Linux- or Windows-shaped depending on the reporting host.
fn is_per_user_ssh_authorized_keys(path: &str) -> bool {
    path.rsplit(['/', '\\']).next() == Some("authorized_keys")
}

/// Phase 11: if `THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED` is on,
/// dispatches `AgentOperation::QuarantineFile` against `host_id` for a
/// per-user `authorized_keys` file this scan just found had changed --
/// no human in the loop. Best-effort: any failure (setting read, path
/// validation, dispatch) is logged and recorded in the audit trail as a
/// failure rather than propagated, since this runs inside the middle of
/// ingesting an otherwise-successful scan and a misfired automation
/// should never take the scan itself down.
async fn maybe_auto_quarantine_ssh_key(
    pool: &DbPool,
    hosts: &HostConnectionRegistry,
    host_id: Uuid,
    path: &str,
) {
    match repo::settings::get_bool(pool, THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED, false).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            tracing::error!(error = %e, "failed to read auto-quarantine-ssh-keys setting");
            return;
        }
    }

    let host = match repo::hosts::find_by_id(pool, host_id).await {
        Ok(Some(host)) => host,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(error = %e, host_id = %host_id, "failed to load host for auto-quarantine");
            return;
        }
    };
    let is_windows = host.os.as_deref() == Some("windows");
    let path_valid = if is_windows {
        is_valid_windows_absolute_path(path)
    } else {
        is_valid_absolute_path(path)
    };
    if !path_valid {
        tracing::warn!(host_id = %host_id, path, "auto-quarantine skipped: path failed validation");
        return;
    }

    let outcome = hosts
        .dispatch(
            host_id,
            AgentOperation::QuarantineFile {
                path: path.to_string(),
            },
            Duration::from_secs(30),
        )
        .await;

    let (audit_outcome, detail) = match outcome {
        Ok(CommandOutcome::Ok(_)) => (AuditOutcome::Success, None),
        Ok(CommandOutcome::Err(message)) => (AuditOutcome::Failure, Some(message)),
        Err(e) => (AuditOutcome::Failure, Some(e.to_string())),
    };
    if let Some(detail) = &detail {
        tracing::warn!(host_id = %host_id, path, error = detail, "auto-quarantine dispatch did not succeed");
    }

    if let Err(e) = abyssal_audit::record(
        pool,
        AuditEvent::new(AuditAction::AutomatedResponseTriggered, audit_outcome)
            .resource(&host_id.to_string())
            .metadata(serde_json::json!({
                "action": "quarantine_file",
                "host_id": host_id,
                "path": path,
                "trigger": "authorized_keys_fim_drift",
                "detail": detail,
            })),
    )
    .await
    {
        tracing::error!(error = %e, host_id = %host_id, "failed to write audit record for auto-quarantine");
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

/// Parses `THANATOS_EXTRA_FIM_PATHS` the way it's stored -- comma- or
/// newline-separated, same permissive split-trim-filter shape
/// `parse_recipients` uses for its own comma-separated setting (a
/// second separator here since multi-line paths are more natural to
/// paste one-per-line than comma-joined).
pub fn parse_extra_fim_paths(raw: &str) -> Vec<String> {
    raw.split([',', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Filters `all_paths` down to the ones valid for `os` (`Host.os`) --
/// an entry meant for one platform is silently dropped for a host on the
/// other rather than sent anyway and failing/being ignored agent-side.
/// `None` or anything other than `"windows"` is treated as Unix,
/// matching `routes::thanatos::os_label`'s own default branch.
pub fn extra_fim_paths_for(all_paths: &[String], os: Option<&str>) -> Vec<String> {
    let is_valid: fn(&str) -> bool = if os == Some("windows") {
        abyssal_agent_protocol::is_valid_windows_absolute_path
    } else {
        abyssal_agent_protocol::is_valid_absolute_path
    };
    all_paths
        .iter()
        .filter(|path| is_valid(path))
        .cloned()
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

/// Best-effort extraction of the targeted username from a raw SSH
/// auth-log line, for the same family of rules `extract_source_ip`
/// already parses (`crates/agent/src/thanatos.rs`'s SSH-related `RULES`
/// entries) -- the OpenSSH/PAM message phrasing this depends on is
/// stable and non-localized (`sshd` never localizes its own log output),
/// unlike Windows Security-log messages (see that `RULES` table's own
/// doc comment for why this is deliberately Linux-only, Phase 7d).
/// Checked in this specific order because it matters:
/// - `"invalid user "` first, so `"Failed password for invalid user
///   root from ..."` extracts `"root"`, not the literal word `"invalid"`.
/// - `"for user "` second, so `"session opened for user root"` (PAM's
///   own distinct phrasing, no `"invalid user"` involved) extracts
///   `"root"` rather than the literal word `"user"` a naive `"for "`
///   split would grab instead.
/// - a plain `" for "` last, for `"Failed password for admin from ..."`/
///   `"Accepted publickey for admin from ..."`/`"Accepted password for
///   admin from ..."`.
///
/// Lines with no `for`-shaped clause at all (`"FAILED su"`, generic PAM
/// `"authentication failure"` without a `user=`/`for` token) return
/// `None` -- a coverage gap, not a wrong answer, the same "best-effort,
/// not exhaustive" character `extract_source_ip` already has.
fn extract_username(raw_line: &str) -> Option<String> {
    if let Some((_, rest)) = raw_line.split_once("invalid user ") {
        return rest.split_whitespace().next().map(str::to_string);
    }
    if let Some((_, rest)) = raw_line.split_once("for user ") {
        return rest.split_whitespace().next().map(str::to_string);
    }
    if let Some((_, rest)) = raw_line.split_once(" for ") {
        return rest.split_whitespace().next().map(str::to_string);
    }
    None
}

const CROSS_HOST_LABEL: &str = "Cross-host credential-stuffing pattern";
const CROSS_HOST_USERNAME_LABEL: &str = "Cross-host account-targeting pattern";

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

/// Same shape and reasoning as `check_cross_host_burst` above, grouping
/// by *targeted username* instead of *source IP* (Phase 7d) -- a
/// same-account-across-many-hosts pattern a per-host or per-IP check
/// alone can't see (an attacker rotating source IPs while retrying the
/// same credential fleet-wide, or a compromised credential being tried
/// against every host that might accept it). Shares the same
/// `source = "correlation"` row shape, the same
/// `THANATOS_CROSS_HOST_THRESHOLD` setting (one "how many hosts is
/// suspicious" knob for both cross-host rules, not two to tune
/// separately), and the same already-covered-this-window suppression via
/// `has_recent_correlation_event`. Linux-only in practice, since
/// `extract_username` only recognizes the OpenSSH/PAM message shapes
/// Windows event log lines don't share -- see that function's own doc
/// comment.
/// Phase 11: if `THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED` is on,
/// dispatches `AgentOperation::LockUserAccount` for `username` against
/// `host_id` right after the cross-host account-targeting correlation
/// rule has just raised a fresh finding naming it -- no human in the
/// loop. Same best-effort error handling as
/// `maybe_auto_quarantine_ssh_key`: any failure is logged/audited, never
/// propagated. Branches validation by `Host.os` the same way the
/// Inquest disable-account route (Phase 7c) already does; the agent's
/// own protected-account checks (`root`/`Administrator`/...) are the
/// real backstop, but checking here too avoids a wasted dispatch and
/// lets the audit trail say plainly that it was skipped rather than
/// merely failed.
async fn maybe_auto_disable_account(
    pool: &DbPool,
    hosts: &HostConnectionRegistry,
    host_id: Uuid,
    username: &str,
) {
    match repo::settings::get_bool(pool, THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED, false).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            tracing::error!(error = %e, "failed to read auto-disable-account setting");
            return;
        }
    }

    let host = match repo::hosts::find_by_id(pool, host_id).await {
        Ok(Some(host)) => host,
        Ok(None) => return,
        Err(e) => {
            tracing::error!(error = %e, host_id = %host_id, "failed to load host for auto-disable-account");
            return;
        }
    };
    let is_windows = host.os.as_deref() == Some("windows");
    let (name_valid, is_protected) = if is_windows {
        (
            is_valid_windows_account_name(username),
            is_protected_windows_account_name(username),
        )
    } else {
        (
            is_valid_account_name(username),
            is_protected_account_name(username),
        )
    };
    if !name_valid || is_protected {
        tracing::warn!(host_id = %host_id, username, "auto-disable-account skipped: invalid or protected account name");
        return;
    }

    let outcome = hosts
        .dispatch(
            host_id,
            AgentOperation::LockUserAccount {
                username: username.to_string(),
            },
            Duration::from_secs(30),
        )
        .await;

    let (audit_outcome, detail) = match outcome {
        Ok(CommandOutcome::Ok(_)) => (AuditOutcome::Success, None),
        Ok(CommandOutcome::Err(message)) => (AuditOutcome::Failure, Some(message)),
        Err(e) => (AuditOutcome::Failure, Some(e.to_string())),
    };
    if let Some(detail) = &detail {
        tracing::warn!(host_id = %host_id, username, error = detail, "auto-disable-account dispatch did not succeed");
    }

    if let Err(e) = abyssal_audit::record(
        pool,
        AuditEvent::new(AuditAction::AutomatedResponseTriggered, audit_outcome)
            .resource(&host_id.to_string())
            .metadata(serde_json::json!({
                "action": "disable_account",
                "host_id": host_id,
                "username": username,
                "trigger": "cross_host_account_targeting",
                "detail": detail,
            })),
    )
    .await
    {
        tracing::error!(error = %e, host_id = %host_id, "failed to write audit record for auto-disable-account");
    }
}

async fn check_cross_host_username_reuse(
    pool: &DbPool,
    hosts: &HostConnectionRegistry,
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
    let mut hosts_by_username: HashMap<String, HashSet<Uuid>> = HashMap::new();
    for (host_id, raw_line) in &rows {
        if let Some(username) = extract_username(raw_line) {
            hosts_by_username
                .entry(username)
                .or_default()
                .insert(*host_id);
        }
    }

    let mut alerted = false;
    for (username, affected_hosts) in hosts_by_username {
        if (affected_hosts.len() as u32) < host_threshold {
            continue;
        }
        let raw_line = format!(
            "Account \"{username}\" was targeted by high-or-critical security events on {} \
             distinct host(s) within the last {window_minutes} minutes (threshold: \
             {host_threshold}).",
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
                CROSS_HOST_USERNAME_LABEL,
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
                        "username": username,
                        "affected_host_count": affected_hosts.len(),
                        "threshold": host_threshold,
                        "window_minutes": window_minutes,
                        "kind": "cross_host_username",
                    })),
            )
            .await
            {
                tracing::error!(error = %e, host_id = %host_id, "failed to write audit record for Thanatos cross-host account-targeting alert");
            }

            maybe_auto_disable_account(pool, hosts, *host_id, &username).await;

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
/// paths. `alerted` is true if the per-host burst check or either
/// fleet-wide cross-host check (by source IP or by targeted username,
/// Phase 7d) raised a finding.
pub async fn ingest_scan(
    pool: &DbPool,
    hosts: &HostConnectionRegistry,
    notifications: &NotificationDispatcher,
    recipients: &[String],
    host_id: Uuid,
    host_name: &str,
    stdout: &str,
) -> anyhow::Result<(usize, Option<String>, bool)> {
    let (persisted, informational) =
        persist_scan_output(pool, hosts, notifications, host_id, host_name, stdout).await?;
    let per_host_alerted =
        check_and_raise_alert(pool, notifications, recipients, host_id, host_name).await?;
    let (_, window_minutes) = correlation_settings(pool).await;
    let cross_host_ip_alerted =
        check_cross_host_burst(pool, notifications, recipients, window_minutes).await?;
    let cross_host_username_alerted =
        check_cross_host_username_reuse(pool, hosts, notifications, recipients, window_minutes)
            .await?;
    Ok((
        persisted,
        informational,
        per_host_alerted || cross_host_ip_alerted || cross_host_username_alerted,
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

            let extra_fim_paths_raw =
                match repo::settings::get_string(&state.pool, THANATOS_EXTRA_FIM_PATHS, "").await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read Thanatos extra FIM paths");
                        String::new()
                    }
                };
            let extra_fim_paths_all = parse_extra_fim_paths(&extra_fim_paths_raw);

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

                let extra_fim_paths = extra_fim_paths_for(&extra_fim_paths_all, host.os.as_deref());
                let outcome = state
                    .hosts
                    .dispatch(
                        host.id,
                        AgentOperation::ScanSecurityEvents { extra_fim_paths },
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
                    &state.hosts,
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
    fn maps_thanatos_severity_to_notification_severity() {
        assert_eq!(
            notification_severity(Severity::Low),
            abyssal_notifications::Severity::Info
        );
        assert_eq!(
            notification_severity(Severity::Medium),
            abyssal_notifications::Severity::Info
        );
        assert_eq!(
            notification_severity(Severity::High),
            abyssal_notifications::Severity::Warning
        );
        assert_eq!(
            notification_severity(Severity::Critical),
            abyssal_notifications::Severity::Critical
        );
    }

    #[test]
    fn recognizes_a_per_user_authorized_keys_path_on_both_platforms() {
        assert!(is_per_user_ssh_authorized_keys(
            "/home/alice/.ssh/authorized_keys"
        ));
        assert!(is_per_user_ssh_authorized_keys(
            "/root/.ssh/authorized_keys"
        ));
        assert!(is_per_user_ssh_authorized_keys(
            r"C:\Users\alice\.ssh\authorized_keys"
        ));
    }

    #[test]
    fn excludes_the_windows_admin_wide_authorized_keys_file() {
        // Ends with the same substring ("authorized_keys") as the
        // per-user file, but is a different, system-wide file that
        // backs every admin login -- must never be treated the same.
        assert!(!is_per_user_ssh_authorized_keys(
            r"C:\ProgramData\ssh\administrators_authorized_keys"
        ));
    }

    #[test]
    fn excludes_unrelated_fim_watchlist_paths() {
        assert!(!is_per_user_ssh_authorized_keys("/etc/passwd"));
        assert!(!is_per_user_ssh_authorized_keys("/etc/ssh/sshd_config"));
    }

    #[test]
    fn extracts_username_from_invalid_user_lines() {
        assert_eq!(
            extract_username("Failed password for invalid user root from 203.0.113.5 port 22 ssh2"),
            Some("root".to_string())
        );
    }

    #[test]
    fn extracts_username_from_plain_for_lines() {
        assert_eq!(
            extract_username("Failed password for admin from 203.0.113.5 port 22 ssh2"),
            Some("admin".to_string())
        );
        assert_eq!(
            extract_username("Accepted publickey for deploy from 203.0.113.5 port 22 ssh2"),
            Some("deploy".to_string())
        );
    }

    #[test]
    fn extracts_username_from_session_opened_lines_not_the_word_user() {
        // Regression check: a naive `" for "` split would grab the
        // literal word "user" here instead of the real username.
        assert_eq!(
            extract_username("pam_unix(sshd:session): session opened for user root by (uid=0)"),
            Some("root".to_string())
        );
    }

    #[test]
    fn returns_none_when_no_for_clause_is_present() {
        assert_eq!(
            extract_username(
                "pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 \
                 tty=/dev/pts/0 ruser=dschwartzad rhost=  user=root"
            ),
            None
        );
        assert_eq!(extract_username(""), None);
    }

    #[test]
    fn parse_recipients_splits_and_trims_and_drops_empties() {
        assert_eq!(
            parse_recipients(" a@example.com, b@example.com ,, "),
            vec!["a@example.com".to_string(), "b@example.com".to_string()]
        );
    }

    #[test]
    fn parse_extra_fim_paths_splits_on_commas_and_newlines() {
        assert_eq!(
            parse_extra_fim_paths(" /etc/foo,\n /etc/bar \n\n, ,C:\\Users\\bad.exe"),
            vec![
                "/etc/foo".to_string(),
                "/etc/bar".to_string(),
                "C:\\Users\\bad.exe".to_string(),
            ]
        );
    }

    #[test]
    fn extra_fim_paths_for_filters_by_platform() {
        let paths = vec![
            "/etc/foo".to_string(),
            "C:\\Users\\bad.exe".to_string(),
            "relative/path".to_string(),
        ];
        assert_eq!(
            extra_fim_paths_for(&paths, None),
            vec!["/etc/foo".to_string()]
        );
        assert_eq!(
            extra_fim_paths_for(&paths, Some("linux")),
            vec!["/etc/foo".to_string()]
        );
        assert_eq!(
            extra_fim_paths_for(&paths, Some("windows")),
            vec!["C:\\Users\\bad.exe".to_string()]
        );
    }
}
