//! Security telemetry collection and threat detection ("Thanatos"): on
//! Linux, tails this host's security-relevant logs (auth/login, the
//! kernel ring buffer, and systemd unit failures); on Windows, queries
//! the Security and System event logs for an analogous set of signals
//! (failed/successful logons, account creation, privileged group
//! membership changes, service failures, unexpected shutdowns). Either
//! way, each line/event is classified against a fixed, ordered rule
//! table. Deliberately narrow compared to a full EDR/SIEM shipper -- no
//! continuous push telemetry, no eBPF/ETW, no log-file offset tracking.
//! The control plane pulls this on demand (or on its own periodic sweep,
//! see `crates/web/src/thanatos_ops.rs`) and does its own deduplication
//! by content hash, so re-scanning the same tail window repeatedly is
//! harmless, just slightly redundant -- a deliberate simplicity
//! trade-off consistent with every other arsenal in this codebase never
//! needing host-side state files.
//!
//! Output is tab-separated (`severity\tlabel\tsource\traw_line` for a
//! classified event, `fim\t<path>\t<hash>` for a file-integrity watch-list
//! entry, `info\t<message>` for anything else worth surfacing) rather
//! than free text: the control plane needs to parse and persist each
//! matched line as its own row for correlation to work, and `OperationOutput`
//! has no structured variant -- this is the same reasoning Reliquary's and
//! Inquest's listing operations already use `find -printf` tab-separated
//! output for. Identical on both platforms -- the control plane's ingest,
//! correlation, and UI code needs zero changes either way.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
#[cfg(unix)]
use crate::process::command_exists;

#[cfg(unix)]
const TAIL_LINES: &str = "500";
#[cfg(unix)]
const JOURNAL_LINES: &str = "200";

/// `(path, source label)` -- tried in order; the first one that's a
/// readable, non-empty file wins. Debian/Ubuntu vs. RHEL/Fedora-family
/// naming, the two layouts flat security logs actually appear under.
#[cfg(unix)]
const LOG_CANDIDATES: &[(&str, &str)] = &[
    ("/var/log/auth.log", "auth.log"),
    ("/var/log/secure", "secure"),
];

/// Same "flat file first" shape as `LOG_CANDIDATES`, for the kernel ring
/// buffer -- `/var/log/kern.log` exists on Debian/Ubuntu by default (RHEL/
/// Fedora fold kernel messages into the journal instead, so there's no
/// equivalent flat-file candidate to add for that family). Independent of
/// the auth sources above: gathered and classified regardless of whether
/// auth.log/secure/journal turned up anything, since OOM-kills and
/// hardware errors are never auth-related.
#[cfg(unix)]
const KERNEL_LOG_CANDIDATES: &[(&str, &str)] = &[("/var/log/kern.log", "kern.log")];

/// Small, fixed set of security-sensitive files hashed on every scan --
/// lightweight file-integrity monitoring, not a general-purpose file
/// scanner. Kept as a hardcoded list rather than control-plane-configurable
/// for now: doing that properly would mean carrying a path list on the
/// wire (`AgentOperation::ScanSecurityEvents` is a bare unit variant
/// today), which bumps `PROTOCOL_VERSION` and touches both dispatch call
/// sites -- a bigger change than this pass's scope. The agent stays
/// stateless either way; comparison against the last-known hash happens
/// entirely control-plane-side (`repo::thanatos_file_hashes`).
#[cfg(unix)]
const FIM_WATCHLIST: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
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
#[cfg(unix)]
enum JournalSource {
    Unit(&'static str),
    Identifier(&'static str),
}

#[cfg(unix)]
const JOURNAL_SOURCES: &[JournalSource] = &[
    JournalSource::Unit("sshd"),
    JournalSource::Identifier("sudo"),
    JournalSource::Identifier("su"),
    JournalSource::Unit("systemd-logind"),
];

/// Windows Security-log event IDs Thanatos watches for, chosen to mirror
/// what the Linux auth-log path already watches: failed/successful
/// logons, account creation, and privileged group membership changes.
/// 4688 (process creation) is deliberately not queried by ID at all --
/// see the `RULES` doc comment below for why.
#[cfg(windows)]
const WINDOWS_SECURITY_EVENT_IDS: &[u32] = &[4624, 4625, 4720, 4732];

/// Windows System-log signals: repeated service-start failures/hangs and
/// an unexpected shutdown -- the closest analog available from the event
/// log alone to Linux's "systemd unit failed"/kernel-crash rules. Windows
/// has no OOM killer, so there's no direct analog to that specific rule;
/// 6008 (unexpected shutdown) is the nearest "something crashed hard"
/// signal.
#[cfg(windows)]
const WINDOWS_SYSTEM_EVENT_IDS: &[u32] = &[6008, 7000, 7009, 7011];

/// Hashed on every scan, mirroring Linux's `FIM_WATCHLIST`. Windows has
/// no single flat-file analog to /etc/passwd or /etc/sudoers -- local
/// account/group state lives in the binary, normally-locked SAM
/// database, not a hashable text file -- so this is deliberately just
/// the one genuine equivalent: the hosts file, a classic tampering
/// target for traffic redirection, same as /etc/hosts would be if
/// Linux's own watch-list included it.
#[cfg(windows)]
const WINDOWS_FIM_WATCHLIST: &str = r"C:\Windows\System32\drivers\etc\hosts";

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
    // Kernel ring buffer (source "kern.log"/"kernel") and systemd unit
    // failures (source "systemd") -- added alongside the auth-oriented
    // rules above rather than in a separate table, since classification
    // is one global first-match-wins pass regardless of which source a
    // line came from.
    ("invoked oom-killer", "high", "OOM killer invoked"),
    (
        "Out of memory: Killed process",
        "high",
        "OOM killer invoked",
    ),
    (
        "Machine Check Event",
        "high",
        "Hardware machine-check event",
    ),
    ("I/O error", "medium", "Disk I/O error"),
    // `systemctl --failed`'s default column layout always repeats the
    // ACTIVE and SUB state back to back for a failed unit ("... loaded
    // failed failed ..."), a distinctive enough pair of words that it's
    // very unlikely to appear in an unrelated log line.
    ("failed failed", "medium", "systemd unit failed"),
    // ---- Windows Security/System event log signals (Phase 4). Matched
    // on the `EventID=<n>` marker the Windows scan path embeds in each
    // line, never on the event's own message text: that text is
    // localized per the host's display language, so an English-wording
    // substring rule would silently stop matching on a non-English
    // host, while the numeric event ID is stable across every locale.
    // 4688 (process creation, audited only if the host's policy enables
    // it) is deliberately NOT classified by event ID at all -- on a host
    // where it's enabled it fires on every process launch, almost all
    // benign, and this arsenal only ever persists rows a rule actually
    // matched. Instead, only a command line containing a known
    // obfuscation/LOLBin pattern is flagged below, the same
    // "specific signal, not the whole category" approach
    // `segfault`/`invoked oom-killer` already take on the Linux side.
    ("EventID=4625", "high", "Windows failed logon"),
    ("EventID=4624", "low", "Windows successful logon"),
    ("EventID=4720", "medium", "Windows user account created"),
    (
        "EventID=4732",
        "high",
        "Windows account added to a security group",
    ),
    (
        "-EncodedCommand",
        "high",
        "Suspicious encoded PowerShell command",
    ),
    (
        "FromBase64String",
        "high",
        "Suspicious base64-decode-and-execute pattern",
    ),
    ("EventID=6008", "high", "Unexpected system shutdown"),
    ("EventID=7000", "medium", "Windows service failed to start"),
    ("EventID=7009", "medium", "Windows service failed to start"),
    ("EventID=7011", "medium", "Windows service control timeout"),
];

fn classify(line: &str) -> Option<(&'static str, &'static str)> {
    RULES
        .iter()
        .find(|(needle, _, _)| line.contains(needle))
        .map(|(_, severity, label)| (*severity, *label))
}

#[cfg(unix)]
pub async fn scan_security_events(elevation: &ElevationState) -> CommandOutcome {
    let mut lines_with_source: Vec<(&'static str, String)> = Vec::new();

    // ---- Auth/login sources: a flat log file, or journalctl only if
    // neither flat candidate was readable at all. ----
    let mut auth_found = false;
    for (path, source) in LOG_CANDIDATES {
        match elevation
            .run_allow_failure("tail", &["-n", TAIL_LINES, path])
            .await
        {
            Ok(output) if output.exit_code == Some(0) && !output.stdout.trim().is_empty() => {
                auth_found = true;
                for line in output.stdout.lines() {
                    lines_with_source.push((source, line.to_string()));
                }
            }
            _ => {}
        }
    }

    if !auth_found && command_exists("journalctl").await {
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

    // ---- Kernel ring buffer: independent of the auth sources above --
    // OOM-kills/hardware errors/segfault bursts aren't auth-related, so
    // this is gathered regardless of whether `auth_found` came up empty.
    // Same "flat file first, journal/dmesg fallback" shape. A permission
    // failure here (e.g. `kernel.dmesg_restrict=1` and no elevation)
    // still returns `Ok` with the error text as stdout -- harmless, since
    // `classify` below only ever emits lines that actually match a rule,
    // never surfaces raw command output verbatim the way a read-only
    // display arsenal does.
    let mut kernel_found = false;
    for (path, source) in KERNEL_LOG_CANDIDATES {
        match elevation
            .run_allow_failure("tail", &["-n", TAIL_LINES, path])
            .await
        {
            Ok(output) if output.exit_code == Some(0) && !output.stdout.trim().is_empty() => {
                kernel_found = true;
                for line in output.stdout.lines() {
                    lines_with_source.push((source, line.to_string()));
                }
            }
            _ => {}
        }
    }
    if !kernel_found {
        let kernel_output = if command_exists("journalctl").await {
            elevation
                .run_allow_failure(
                    "journalctl",
                    &["-k", "-n", JOURNAL_LINES, "--no-pager", "-o", "cat"],
                )
                .await
        } else {
            elevation.run_allow_failure("dmesg", &["-T"]).await
        };
        if let Ok(output) = kernel_output
            && output.exit_code == Some(0)
        {
            for line in output.stdout.lines() {
                if !line.trim().is_empty() {
                    lines_with_source.push(("kernel", line.to_string()));
                }
            }
        }
    }

    // ---- systemd unit failures: independent of everything above. ----
    if command_exists("systemctl").await
        && let Ok(output) = elevation
            .run_allow_failure("systemctl", &["--failed", "--no-pager", "--no-legend"])
            .await
        && output.exit_code == Some(0)
    {
        for line in output.stdout.lines() {
            if !line.trim().is_empty() {
                lines_with_source.push(("systemd", line.to_string()));
            }
        }
    }

    let scanned = lines_with_source.len();
    let mut stdout = String::new();
    let mut matched_count = 0usize;
    for (source, line) in &lines_with_source {
        if let Some((severity, label)) = classify(line) {
            matched_count += 1;
            stdout.push_str(&format!("{severity}\t{label}\t{source}\t{line}\n"));
        }
    }

    // File-integrity watch-list -- always attempted, independent of
    // whether any log source above was readable at all (hashing a file
    // has nothing to do with log availability).
    for path in FIM_WATCHLIST {
        if let Ok(output) = elevation.run_allow_failure("sha256sum", &[path]).await
            && output.exit_code == Some(0)
            && let Some(hash) = output.stdout.split_whitespace().next()
        {
            stdout.push_str(&format!("fim\t{path}\t{hash}\n"));
        }
    }

    if matched_count == 0 {
        let note = if scanned == 0 {
            "No readable security log sources found (checked /var/log/auth.log, \
             /var/log/secure, journalctl for sshd/sudo/systemd-logind, the kernel ring \
             buffer, and systemd unit status)."
                .to_string()
        } else {
            format!("Scanned {scanned} line(s); nothing matched the current detection rules.")
        };
        stdout.push_str(&format!("info\t{note}\n"));
    }

    CommandOutcome::Ok(OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// Windows equivalent of the Unix `scan_security_events` above -- same
/// wire format, same classify()/RULES pass, different gathering. Reads
/// via `Get-WinEvent` (shelled out through `powershell.exe`) rather than
/// the raw Win32 EventLog API: this agent has no Windows machine in its
/// own test/CI loop to verify unsafe FFI against, and every other
/// platform-specific data source in this crate already goes through a
/// CLI tool and text parsing rather than a native API, so this keeps
/// that same, independently-verifiable shape. `_elevation` is unused --
/// unlike Linux's sudo-gated reads, the service always runs as
/// `LocalSystem` (see `crates/agent/src/winservice.rs`), which already
/// has full Event Log read access.
#[cfg(windows)]
pub async fn scan_security_events(_elevation: &ElevationState) -> CommandOutcome {
    let mut lines_with_source: Vec<(&'static str, String)> = Vec::new();

    for (log_name, source, ids) in [
        ("Security", "security", WINDOWS_SECURITY_EVENT_IDS),
        ("System", "system", WINDOWS_SYSTEM_EVENT_IDS),
    ] {
        let id_list = ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        // `-replace '\r?\n', ' '` flattens the (often multi-line)
        // Message property to one line, since the outer wire format is
        // itself newline-delimited; the 300-char cap keeps a handful of
        // very long templates from dwarfing everything else in the
        // scan's output. `EventID=$($_.Id)` is prepended as a stable,
        // non-localized marker `classify()` matches on -- see the
        // `RULES` doc comment for why matching on the message text
        // itself would be unreliable.
        let script = format!(
            "Get-WinEvent -FilterHashtable @{{LogName='{log_name}';Id={id_list}}} \
             -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object {{ \
             $m = ($_.Message -replace '\\r?\\n', ' ').Trim(); \
             if ($m.Length -gt 300) {{ $m = $m.Substring(0, 300) }}; \
             \"EventID=$($_.Id)`tTime=$($_.TimeCreated.ToString('o'))`t$m\" }}"
        );
        if let Ok(output) = crate::process::run_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )
        .await
        {
            for line in output.stdout.lines() {
                if !line.trim().is_empty() {
                    lines_with_source.push((source, line.to_string()));
                }
            }
        }
    }

    let scanned = lines_with_source.len();
    let mut stdout = String::new();
    let mut matched_count = 0usize;
    for (source, line) in &lines_with_source {
        if let Some((severity, label)) = classify(line) {
            matched_count += 1;
            stdout.push_str(&format!("{severity}\t{label}\t{source}\t{line}\n"));
        }
    }

    // File-integrity watch-list -- see `WINDOWS_FIM_WATCHLIST`'s doc
    // comment for why this is just the one path, unlike Linux's four.
    let hash_script = format!(
        "(Get-FileHash -Algorithm SHA256 -Path '{WINDOWS_FIM_WATCHLIST}' \
         -ErrorAction SilentlyContinue).Hash"
    );
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &hash_script],
    )
    .await
    {
        let hash = output.stdout.trim();
        if !hash.is_empty() {
            // Lowercased to match Linux's `sha256sum` output convention
            // (Get-FileHash returns uppercase hex) -- purely cosmetic
            // consistency, since each host's baseline is compared only
            // against its own prior scans, never cross-host.
            stdout.push_str(&format!(
                "fim\t{WINDOWS_FIM_WATCHLIST}\t{}\n",
                hash.to_lowercase()
            ));
        }
    }

    if matched_count == 0 {
        let note = if scanned == 0 {
            "No Security/System event log entries were readable for the watched event IDs \
             (4624/4625/4720/4732 in Security, 6008/7000/7009/7011 in System)."
                .to_string()
        } else {
            format!("Scanned {scanned} event(s); nothing matched the current detection rules.")
        };
        stdout.push_str(&format!("info\t{note}\n"));
    }

    CommandOutcome::Ok(OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_oom_killer_invocations_as_high() {
        assert_eq!(
            classify("kernel: [12345.678] myproc invoked oom-killer: gfp_mask=0x..."),
            Some(("high", "OOM killer invoked"))
        );
        assert_eq!(
            classify("Out of memory: Killed process 1234 (myproc) total-vm:..."),
            Some(("high", "OOM killer invoked"))
        );
    }

    #[test]
    fn classifies_hardware_and_io_errors() {
        assert_eq!(
            classify("mce: [Hardware Error]: Machine Check Event"),
            Some(("high", "Hardware machine-check event"))
        );
        assert_eq!(
            classify("Buffer I/O error on device sda1, logical block 12345"),
            Some(("medium", "Disk I/O error"))
        );
    }

    #[test]
    fn classifies_failed_systemd_units() {
        assert_eq!(
            classify("myapp.service loaded failed failed My App"),
            Some(("medium", "systemd unit failed"))
        );
    }

    #[test]
    fn segfault_still_classifies_after_the_new_rules_were_added() {
        // Regression check: the new kernel/systemd rules were appended
        // after the existing ones, not inserted in the middle -- make
        // sure that didn't silently reorder anything load-bearing.
        assert_eq!(
            classify("kernel: myproc[1234]: segfault at 0 ip 0000 sp 0000 error 4"),
            Some(("medium", "Process segfault"))
        );
    }

    #[test]
    fn unrelated_lines_do_not_classify() {
        assert_eq!(classify("systemd[1]: Started My App."), None);
        assert_eq!(classify("kernel: [1.0] Linux version 6.1.0"), None);
    }

    #[test]
    fn classifies_windows_event_log_signals_by_stable_event_id_marker() {
        assert_eq!(
            classify("EventID=4625\tTime=2026-01-01T00:00:00.000Z\tAn account failed to log on."),
            Some(("high", "Windows failed logon"))
        );
        assert_eq!(
            classify(
                "EventID=4624\tTime=2026-01-01T00:00:00.000Z\tAn account was successfully logged on."
            ),
            Some(("low", "Windows successful logon"))
        );
        assert_eq!(
            classify("EventID=4720\tTime=2026-01-01T00:00:00.000Z\tA user account was created."),
            Some(("medium", "Windows user account created"))
        );
        assert_eq!(
            classify(
                "EventID=4732\tTime=2026-01-01T00:00:00.000Z\tA member was added to a security-enabled local group."
            ),
            Some(("high", "Windows account added to a security group"))
        );
    }

    #[test]
    fn classifies_windows_system_log_signals() {
        assert_eq!(
            classify(
                "EventID=6008\tTime=2026-01-01T00:00:00.000Z\tThe previous system shutdown was unexpected."
            ),
            Some(("high", "Unexpected system shutdown"))
        );
        assert_eq!(
            classify(
                "EventID=7000\tTime=2026-01-01T00:00:00.000Z\tThe Foo service failed to start."
            ),
            Some(("medium", "Windows service failed to start"))
        );
    }

    #[test]
    fn classifies_suspicious_process_creation_command_lines_regardless_of_event_id() {
        // 4688 (process creation) is deliberately not matched by EventID
        // alone -- see the RULES doc comment. Only a command line
        // containing a known obfuscation/LOLBin pattern should classify.
        assert_eq!(
            classify(
                "EventID=4688\tTime=2026-01-01T00:00:00.000Z\tpowershell.exe -EncodedCommand SQBFAFgA"
            ),
            Some(("high", "Suspicious encoded PowerShell command"))
        );
        assert_eq!(
            classify("EventID=4688\tTime=2026-01-01T00:00:00.000Z\tcmd.exe /c whoami /priv"),
            None
        );
    }
}
