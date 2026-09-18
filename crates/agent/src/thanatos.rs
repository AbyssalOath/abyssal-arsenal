//! Security telemetry collection and threat detection ("Thanatos"): tails
//! this host's security-relevant logs and classifies each line against a
//! fixed, ordered rule table. Deliberately narrow compared to a full
//! EDR/SIEM shipper -- no continuous push telemetry, no eBPF, no log-file
//! offset tracking. The control plane pulls this on demand (or on its own
//! periodic sweep, see `crates/web/src/thanatos_ops.rs`) and does its own
//! deduplication by content hash, so re-scanning the same tail window
//! repeatedly is harmless, just slightly redundant -- a deliberate
//! simplicity trade-off consistent with every other arsenal in this
//! codebase never needing host-side state files.
//!
//! Output is tab-separated (`severity\tlabel\tsource\traw_line`) rather
//! than free text: the control plane needs to parse and persist each
//! matched line as its own row for correlation to work, and `OperationOutput`
//! has no structured variant -- this is the same reasoning Reliquary's and
//! Inquest's listing operations already use `find -printf` tab-separated
//! output for.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::command_exists;

const TAIL_LINES: &str = "500";
const JOURNAL_LINES: &str = "200";

/// `(path, source label)` -- tried in order; the first one that's a
/// readable, non-empty file wins. Debian/Ubuntu vs. RHEL/Fedora-family
/// naming, the two layouts flat security logs actually appear under.
const LOG_CANDIDATES: &[(&str, &str)] = &[
    ("/var/log/auth.log", "auth.log"),
    ("/var/log/secure", "secure"),
];

/// A journal source to fall back to when neither flat log candidate
/// above exists or is readable (e.g. a systemd-journal-only host with no
/// rsyslog forwarding configured). `sshd` and `systemd-logind` are real
/// systemd units (`journalctl -u`), but `sudo`/`su` are one-off child
/// processes, not services -- they have no unit at all, so `-u sudo`
/// silently returns nothing. Their PAM messages (including the
/// "authentication failure" line this arsenal's rules match on) are
/// tagged with the syslog identifier `sudo`/`su` instead, which needs
/// `journalctl -t`, a genuinely different flag.
enum JournalSource {
    Unit(&'static str),
    Identifier(&'static str),
}

const JOURNAL_SOURCES: &[JournalSource] = &[
    JournalSource::Unit("sshd"),
    JournalSource::Identifier("sudo"),
    JournalSource::Identifier("su"),
    JournalSource::Unit("systemd-logind"),
];

/// Ordered, first-match-wins classification rules: (substring, severity,
/// label). Order is load-bearing -- specific patterns before general ones,
/// e.g. "Failed password for invalid user" before the plain "Failed
/// password for", so an invalid-user attempt is never under-classified as
/// an ordinary failed login. `severity` is always `low`/`medium`/`high`
/// here -- `critical` is reserved for the control plane's own correlation
/// findings (see the `AgentOperation::ScanSecurityEvents` doc comment).
const RULES: &[(&str, &str, &str)] = &[
    (
        "Failed password for invalid user",
        "high",
        "SSH invalid-user login attempt",
    ),
    ("Failed password for", "medium", "SSH failed login"),
    (
        "Invalid user",
        "medium",
        "SSH login attempt for nonexistent user",
    ),
    (
        "Accepted publickey for",
        "low",
        "SSH successful login (key)",
    ),
    (
        "Accepted password for",
        "low",
        "SSH successful login (password)",
    ),
    (
        "session opened for user root",
        "high",
        "Root session opened",
    ),
    ("session opened for user", "low", "Session opened"),
    ("authentication failure", "high", "Authentication failure"),
    ("FAILED su", "high", "su authentication failure"),
    ("sudo:", "low", "Sudo activity"),
    ("password changed", "medium", "Password changed"),
    ("new group:", "medium", "Group created"),
    ("new user:", "medium", "User created"),
    (
        "Connection closed",
        "low",
        "SSH connection closed before authentication",
    ),
    ("segfault", "medium", "Process segfault"),
    ("New session", "low", "New login session"),
];

fn classify(line: &str) -> Option<(&'static str, &'static str)> {
    RULES
        .iter()
        .find(|(needle, _, _)| line.contains(needle))
        .map(|(_, severity, label)| (*severity, *label))
}

pub async fn scan_security_events(elevation: &ElevationState) -> CommandOutcome {
    let mut lines_with_source: Vec<(&'static str, String)> = Vec::new();

    for (path, source) in LOG_CANDIDATES {
        match elevation
            .run_allow_failure("tail", &["-n", TAIL_LINES, path])
            .await
        {
            Ok(output) if output.exit_code == Some(0) && !output.stdout.trim().is_empty() => {
                for line in output.stdout.lines() {
                    lines_with_source.push((source, line.to_string()));
                }
            }
            _ => {}
        }
    }

    if lines_with_source.is_empty() && command_exists("journalctl").await {
        for source in JOURNAL_SOURCES {
            let (flag, value) = match source {
                JournalSource::Unit(u) => ("-u", *u),
                JournalSource::Identifier(i) => ("-t", *i),
            };
            match elevation
                .run_allow_failure(
                    "journalctl",
                    &[flag, value, "-n", JOURNAL_LINES, "--no-pager", "-o", "cat"],
                )
                .await
            {
                Ok(output) if output.exit_code == Some(0) => {
                    for line in output.stdout.lines() {
                        if !line.trim().is_empty() {
                            lines_with_source.push(("journal", line.to_string()));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if lines_with_source.is_empty() {
        return CommandOutcome::Ok(OperationOutput {
            stdout: "No readable security log sources found (checked /var/log/auth.log, \
                     /var/log/secure, and journalctl for sshd/sudo/systemd-logind)."
                .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    let scanned = lines_with_source.len();
    let mut matched = String::new();
    let mut matched_count = 0usize;
    for (source, line) in &lines_with_source {
        if let Some((severity, label)) = classify(line) {
            matched_count += 1;
            matched.push_str(&format!("{severity}\t{label}\t{source}\t{line}\n"));
        }
    }

    if matched_count == 0 {
        return CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Scanned {scanned} line(s); nothing matched the current detection rules."
            ),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    CommandOutcome::Ok(OperationOutput {
        stdout: matched,
        stderr: String::new(),
        exit_code: Some(0),
    })
}
