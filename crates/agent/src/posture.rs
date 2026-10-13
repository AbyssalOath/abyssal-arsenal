//! `PostureFacts` (protocol 46): gathers every fact Cadavault's posture
//! checks read, as one `PostureFactsReport`. Read-only. The checks
//! themselves (pass, fail, not applicable) live control-plane side in
//! `abyssal-posture`, so this only reports what it finds: a fact it can't
//! read is left out, with a note saying why where there's one.
//!
//! The parsers are plain functions over command output, tested below on
//! recorded samples.

use std::collections::BTreeMap;

use abyssal_agent_protocol::{CommandOutcome, OperationOutput, PostureFactsReport};

use crate::elevation::ElevationState;

type Facts = BTreeMap<String, String>;

fn ok(report: &PostureFactsReport) -> CommandOutcome {
    match serde_json::to_string(report) {
        Ok(stdout) => CommandOutcome::Ok(OperationOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(format!("couldn't encode the posture facts: {e}")),
    }
}

// ---------------------------------------------------------------- parsers --

/// `sshd -T`: one `key value...` per line, keys already lower-case.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_sshd_t(dump: &str, facts: &mut Facts) {
    for line in dump.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let value = parts.collect::<Vec<_>>().join(" ");
        facts.insert(format!("sshd.{}", key.to_lowercase()), value);
    }
}

/// `/etc/login.defs`: `KEY value`, `#` comments.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_login_defs(text: &str, facts: &mut Facts) {
    const KEYS: &[&str] = &[
        "PASS_MAX_DAYS",
        "PASS_MIN_DAYS",
        "PASS_WARN_AGE",
        "ENCRYPT_METHOD",
        "UMASK",
    ];
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let (Some(key), Some(value)) = (parts.next(), parts.next())
            && KEYS.contains(&key)
        {
            facts.insert(format!("logindefs.{key}"), value.to_string());
        }
    }
}

/// A `key = value` file (`pwquality.conf`, `faillock.conf`): the last
/// uncommented setting of `key` wins, as it does for the PAM modules.
#[cfg_attr(not(unix), allow(dead_code))]
fn conf_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim().to_string())
        .next_back()
}

/// A `key=value` argument on a PAM line (`pam_pwquality.so minlen=14`).
#[cfg_attr(not(unix), allow(dead_code))]
fn pam_arg(pam_text: &str, module: &str, key: &str) -> Option<String> {
    pam_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && l.contains(module))
        .flat_map(|l| l.split_whitespace())
        .filter_map(|word| word.split_once('='))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
        .next_back()
}

/// `/etc/passwd`: accounts other than root with UID 0.
#[cfg_attr(not(unix), allow(dead_code))]
fn extra_uid0(passwd: &str) -> Vec<String> {
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 2 && f[2] == "0" && f[0] != "root").then(|| f[0].to_string())
        })
        .collect()
}

/// `/etc/shadow`: accounts whose password field is empty (log in with no
/// password). Only names are reported, never hashes.
#[cfg_attr(not(unix), allow(dead_code))]
fn empty_password_accounts(shadow: &str) -> Vec<String> {
    shadow
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let hash = f.next()?;
            (!name.is_empty() && hash.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// `ufw status verbose`: active, and the incoming default.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_ufw(text: &str) -> (bool, Option<String>) {
    let active = text
        .lines()
        .any(|l| l.trim().eq_ignore_ascii_case("Status: active"));
    // "Default: deny (incoming), allow (outgoing), disabled (routed)"
    let default = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Default:"))
        .and_then(|rest| {
            rest.split(',')
                .find(|p| p.contains("(incoming)"))
                .and_then(|p| p.split_whitespace().next())
                .map(str::to_lowercase)
        });
    (active, default)
}

/// `nft list ruleset`: the policy of input-hook chains (`drop` if any is
/// drop), or `None` with no input chain.
#[cfg_attr(not(unix), allow(dead_code))]
fn nft_input_policy(ruleset: &str) -> Option<String> {
    let policies: Vec<String> = ruleset
        .lines()
        .filter(|l| l.contains("hook input"))
        .filter_map(|l| {
            l.split("policy")
                .nth(1)
                .and_then(|p| {
                    p.split(|c: char| c == ';' || c.is_whitespace())
                        .find(|w| !w.is_empty())
                })
                .map(str::to_lowercase)
        })
        .collect();
    if policies.is_empty() {
        None
    } else if policies.iter().any(|p| p == "drop") {
        Some("drop".into())
    } else {
        Some(policies[0].clone())
    }
}

/// `iptables -S INPUT`: the chain's `-P INPUT <policy>` line.
#[cfg_attr(not(unix), allow(dead_code))]
fn iptables_input_policy(rules: &str) -> Option<String> {
    rules
        .lines()
        .find_map(|l| l.trim().strip_prefix("-P INPUT "))
        .map(|p| p.trim().to_lowercase())
}

/// Whether iptables INPUT has rules beyond its policy line.
#[cfg_attr(not(unix), allow(dead_code))]
fn iptables_has_rules(rules: &str) -> bool {
    rules.lines().any(|l| l.trim().starts_with("-A INPUT"))
}

/// `/proc/mounts`: the options of the filesystem mounted exactly at
/// `target`, if it's a separate mount.
#[cfg_attr(not(unix), allow(dead_code))]
fn mount_options(mounts: &str, target: &str) -> Option<String> {
    mounts
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 4 && f[1] == target).then(|| f[3].to_string())
        })
        .next_back()
}

// ------------------------------------------------------------------ linux --

#[cfg(unix)]
mod linux {
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use crate::process::{command_exists, run_command_allow_failure};

    /// The kernel parameters the checks read, from `/proc/sys`.
    const SYSCTLS: &[&str] = &[
        "kernel.randomize_va_space",
        "kernel.dmesg_restrict",
        "kernel.kptr_restrict",
        "kernel.yama.ptrace_scope",
        "kernel.unprivileged_bpf_disabled",
        "fs.protected_hardlinks",
        "fs.protected_symlinks",
        "fs.suid_dumpable",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.default.accept_redirects",
        "net.ipv4.conf.all.secure_redirects",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.default.log_martians",
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.icmp_ignore_bogus_error_responses",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ip_forward",
        "net.ipv6.conf.all.accept_redirects",
        "net.ipv6.conf.default.accept_redirects",
    ];

    /// Services that send credentials in clear or shouldn't be on a server.
    const LEGACY_UNITS: &[&str] = &[
        "telnet.socket",
        "telnetd.service",
        "rsh.socket",
        "rlogin.socket",
        "rexec.socket",
        "tftp.socket",
        "tftp.service",
        "xinetd.service",
        "vsftpd.service",
        "ypbind.service",
        "talk.socket",
    ];

    const TIME_SYNC_UNITS: &[&str] = &[
        "chronyd.service",
        "chrony.service",
        "systemd-timesyncd.service",
        "ntpd.service",
        "ntp.service",
        "ntpsec.service",
        "openntpd.service",
    ];

    /// System files whose permissions matter: (fact name, path).
    const PERMISSION_FILES: &[(&str, &str)] = &[
        ("passwd", "/etc/passwd"),
        ("shadow", "/etc/shadow"),
        ("group", "/etc/group"),
        ("gshadow", "/etc/gshadow"),
    ];

    /// Where world-writable files would let anyone change what root runs.
    const WRITABLE_SCAN_DIRS: &[&str] = &[
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ];

    async fn systemctl(args: &[&str]) -> Option<String> {
        run_command_allow_failure("systemctl", args)
            .await
            .ok()
            .map(|o| o.stdout.trim().to_string())
    }

    pub async fn collect(elevation: &ElevationState) -> PostureFactsReport {
        let mut facts = Facts::new();
        let mut notes = Facts::new();

        // SSH: the effective config, drop-ins merged. Reads host keys, so
        // it needs root.
        if command_exists("sshd").await || std::path::Path::new("/usr/sbin/sshd").exists() {
            facts.insert("sshd.present".into(), "yes".into());
            match elevation.run_allow_failure("sshd", &["-T"]).await {
                Ok(o) if o.exit_code == Some(0) => parse_sshd_t(&o.stdout, &mut facts),
                Ok(o) => {
                    notes.insert(
                        "sshd".into(),
                        format!("`sshd -T` failed (needs root): {}", o.stderr.trim()),
                    );
                }
                Err(e) => {
                    notes.insert("sshd".into(), e);
                }
            }
        } else {
            facts.insert("sshd.present".into(), "no".into());
        }

        for key in SYSCTLS {
            let path = format!("/proc/sys/{}", key.replace('.', "/"));
            if let Ok(value) = tokio::fs::read_to_string(&path).await {
                facts.insert(format!("sysctl.{key}"), value.trim().to_string());
            }
        }

        if let Ok(text) = tokio::fs::read_to_string("/etc/login.defs").await {
            parse_login_defs(&text, &mut facts);
        }

        // Password quality and lockout, from PAM and their config files.
        let mut pam = String::new();
        if let Ok(mut dir) = tokio::fs::read_dir("/etc/pam.d").await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Ok(text) = tokio::fs::read_to_string(entry.path()).await {
                    pam.push_str(&text);
                    pam.push('\n');
                }
            }
        }
        let pwquality_in_pam = pam.contains("pam_pwquality") || pam.contains("pam_cracklib");
        facts.insert(
            "pam.pwquality".into(),
            if pwquality_in_pam { "yes" } else { "no" }.into(),
        );
        let mut pwquality = tokio::fs::read_to_string("/etc/security/pwquality.conf")
            .await
            .unwrap_or_default();
        if let Ok(mut dir) = tokio::fs::read_dir("/etc/security/pwquality.conf.d").await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Ok(text) = tokio::fs::read_to_string(entry.path()).await {
                    pwquality.push_str(&text);
                    pwquality.push('\n');
                }
            }
        }
        if let Some(minlen) = pam_arg(&pam, "pam_pwquality", "minlen")
            .or_else(|| pam_arg(&pam, "pam_cracklib", "minlen"))
            .or_else(|| conf_value(&pwquality, "minlen"))
        {
            facts.insert("pwquality.minlen".into(), minlen);
        }
        let lockout = pam.contains("pam_faillock") || pam.contains("pam_tally2");
        facts.insert(
            "pam.lockout".into(),
            if lockout { "yes" } else { "no" }.into(),
        );
        let faillock = tokio::fs::read_to_string("/etc/security/faillock.conf")
            .await
            .unwrap_or_default();
        if let Some(deny) = pam_arg(&pam, "pam_faillock", "deny")
            .or_else(|| pam_arg(&pam, "pam_tally2", "deny"))
            .or_else(|| conf_value(&faillock, "deny"))
        {
            facts.insert("pam.lockout_deny".into(), deny);
        }

        // Accounts.
        if let Ok(passwd) = tokio::fs::read_to_string("/etc/passwd").await {
            facts.insert("accounts.uid0_extra".into(), extra_uid0(&passwd).join(","));
        }
        match elevation.run_allow_failure("cat", &["/etc/shadow"]).await {
            Ok(o) if o.exit_code == Some(0) => {
                facts.insert(
                    "accounts.empty_password".into(),
                    empty_password_accounts(&o.stdout).join(","),
                );
            }
            _ => {
                notes.insert(
                    "accounts.empty_password".into(),
                    "/etc/shadow isn't readable (needs root)".into(),
                );
            }
        }

        // File permissions: mode and owner, from metadata.
        for (name, path) in PERMISSION_FILES {
            if let Ok(meta) = tokio::fs::metadata(path).await {
                facts.insert(
                    format!("perm.{name}.mode"),
                    format!("{:o}", meta.mode() & 0o7777),
                );
                facts.insert(format!("perm.{name}.uid"), meta.uid().to_string());
            }
        }
        let mut find_args: Vec<&str> = WRITABLE_SCAN_DIRS
            .iter()
            .copied()
            .filter(|d| std::path::Path::new(d).exists())
            .collect();
        find_args.extend(["-xdev", "-type", "f", "-perm", "-0002"]);
        match elevation.run_allow_failure("find", &find_args).await {
            Ok(o) => {
                let files: Vec<&str> = o.stdout.lines().filter(|l| !l.is_empty()).collect();
                facts.insert("files.world_writable.count".into(), files.len().to_string());
                facts.insert(
                    "files.world_writable.sample".into(),
                    files.iter().take(5).copied().collect::<Vec<_>>().join(","),
                );
            }
            Err(e) => {
                notes.insert("files.world_writable".into(), e);
            }
        }

        collect_firewall(elevation, &mut facts, &mut notes).await;

        // Mandatory access control and automatic updates: the same
        // detection as Cadavault's own buttons.
        if let CommandOutcome::Ok(o) = crate::cadavault::mac_status(elevation).await {
            for line in o.stdout.lines() {
                if let Some(v) = line.strip_prefix("MAC system:") {
                    facts.insert("mac.system".into(), v.trim().to_lowercase());
                }
                if let Some(v) = line.strip_prefix("MAC enforcing:") {
                    facts.insert("mac.enforcing".into(), v.trim().to_lowercase());
                }
            }
        }
        match crate::cadavault::automatic_updates_status(elevation).await {
            CommandOutcome::Ok(o) => {
                for line in o.stdout.lines() {
                    if let Some(v) = line.strip_prefix("Automatic updates:") {
                        facts.insert("updates.automatic".into(), v.trim().to_lowercase());
                    }
                    if let Some(v) = line.strip_prefix("Package manager:") {
                        facts.insert("updates.package_manager".into(), v.trim().to_string());
                    }
                }
            }
            CommandOutcome::Err(e) => {
                notes.insert("updates".into(), e);
            }
        }

        if let Ok(mounts) = tokio::fs::read_to_string("/proc/mounts").await {
            for (name, target) in [("tmp", "/tmp"), ("dev_shm", "/dev/shm")] {
                match mount_options(&mounts, target) {
                    Some(options) => {
                        facts.insert(format!("mount.{name}.separate"), "yes".into());
                        facts.insert(format!("mount.{name}.options"), options);
                    }
                    None => {
                        facts.insert(format!("mount.{name}.separate"), "no".into());
                    }
                }
            }
        }

        let systemd = crate::init_system::detect().await == crate::init_system::InitSystem::Systemd;
        if systemd {
            facts.insert("init.systemd".into(), "yes".into());
            let mut enabled = Vec::new();
            for unit in LEGACY_UNITS {
                if systemctl(&["is-enabled", unit]).await.as_deref() == Some("enabled") {
                    enabled.push(*unit);
                }
            }
            facts.insert("services.legacy_enabled".into(), enabled.join(","));

            let auditd = systemctl(&["is-active", "auditd"]).await;
            facts.insert(
                "auditd.active".into(),
                if auditd.as_deref() == Some("active") {
                    "yes"
                } else {
                    "no"
                }
                .into(),
            );
            if auditd.as_deref() == Some("active") {
                match elevation.run_allow_failure("auditctl", &["-l"]).await {
                    Ok(o) if o.exit_code == Some(0) => {
                        let rules = o
                            .stdout
                            .lines()
                            .filter(|l| !l.trim().is_empty() && !l.contains("No rules"))
                            .count();
                        facts.insert("auditd.rules".into(), rules.to_string());
                    }
                    _ => {
                        notes.insert("auditd.rules".into(), "`auditctl -l` needs root".into());
                    }
                }
            }

            let mut time_sync = None;
            for unit in TIME_SYNC_UNITS {
                if systemctl(&["is-active", unit]).await.as_deref() == Some("active") {
                    time_sync = Some(*unit);
                    break;
                }
            }
            facts.insert(
                "time.sync".into(),
                time_sync
                    .unwrap_or("none")
                    .trim_end_matches(".service")
                    .into(),
            );
        } else {
            facts.insert("init.systemd".into(), "no".into());
        }

        PostureFactsReport {
            platform: "linux".into(),
            facts,
            notes,
        }
    }

    /// `firewall.tool`, `firewall.active` and `firewall.default_input`,
    /// from the first of ufw, firewalld, nftables and iptables that's in use.
    async fn collect_firewall(elevation: &ElevationState, facts: &mut Facts, notes: &mut Facts) {
        let mut set = |tool: &str, active: bool, default: Option<String>| {
            facts.insert("firewall.tool".into(), tool.into());
            facts.insert(
                "firewall.active".into(),
                if active { "yes" } else { "no" }.into(),
            );
            if let Some(default) = default {
                facts.insert("firewall.default_input".into(), default);
            }
        };
        if command_exists("ufw").await
            && let Ok(o) = elevation
                .run_allow_failure("ufw", &["status", "verbose"])
                .await
            && o.exit_code == Some(0)
        {
            let (active, default) = parse_ufw(&o.stdout);
            if active {
                set("ufw", true, default);
                return;
            }
        }
        if command_exists("firewall-cmd").await
            && systemctl(&["is-active", "firewalld"]).await.as_deref() == Some("active")
        {
            // firewalld rejects whatever its zones don't allow.
            set("firewalld", true, Some("reject".into()));
            return;
        }
        if command_exists("nft").await
            && let Ok(o) = elevation
                .run_allow_failure("nft", &["list", "ruleset"])
                .await
            && o.exit_code == Some(0)
            && let Some(policy) = nft_input_policy(&o.stdout)
        {
            set("nftables", true, Some(policy));
            return;
        }
        if command_exists("iptables").await {
            match elevation
                .run_allow_failure("iptables", &["-S", "INPUT"])
                .await
            {
                Ok(o) if o.exit_code == Some(0) => {
                    let policy = iptables_input_policy(&o.stdout);
                    let active = iptables_has_rules(&o.stdout)
                        || policy.as_deref().is_some_and(|p| p != "accept");
                    set("iptables", active, policy);
                    return;
                }
                _ => {
                    notes.insert("firewall".into(), "reading the firewall needs root".into());
                    return;
                }
            }
        }
        set("none", false, None);
    }
}

// ---------------------------------------------------------------- windows --

/// Gathers the Windows facts as `{"facts":{...},"notes":{...}}`. Each
/// section is guarded on its own, so one missing component (no Defender, no
/// BitLocker on a Server without the feature) only leaves its facts out.
/// Registry values that aren't set are reported as `absent`, which the
/// checks read as the Windows default.
#[cfg_attr(not(windows), allow(dead_code))]
pub const WINDOWS_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$f = [ordered]@{}
$n = [ordered]@{}
function Add-Fact([string]$Key, $Value) { if ($null -ne $Value) { $f[$Key] = [string]$Value } }
function Add-Reg([string]$Key, [string]$Path, [string]$Name) {
  $v = $null
  try { $v = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $v = $null }
  if ($null -eq $v) { $f[$Key] = 'absent' } else { $f[$Key] = [string]$v }
}

try {
  $tmp = Join-Path $env:TEMP ('aa-secedit-' + [guid]::NewGuid().ToString() + '.inf')
  $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS /quiet
  if (-not (Test-Path -LiteralPath $tmp)) { throw 'secedit /export wrote no file' }
  foreach ($line in Get-Content -LiteralPath $tmp) {
    if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.*)$') { $f['secedit.' + $Matches[1]] = $Matches[2].Trim() }
  }
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
} catch { $n['secedit'] = $_.Exception.Message }

try {
  $tmp = Join-Path $env:TEMP ('aa-auditpol-' + [guid]::NewGuid().ToString() + '.csv')
  $null = & auditpol.exe /backup "/file:$tmp"
  foreach ($row in Import-Csv -LiteralPath $tmp) {
    $guid = [string]$row.'Subcategory GUID'
    if ($guid) { $f['audit.' + $guid.Trim('{', '}').ToUpperInvariant()] = [string]$row.'Setting Value' }
  }
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
} catch { $n['audit'] = $_.Exception.Message }

try {
  $smb = Get-SmbServerConfiguration
  Add-Fact 'smb.server.smb1' $smb.EnableSMB1Protocol
  Add-Fact 'smb.server.signing_required' $smb.RequireSecuritySignature
} catch { $n['smb'] = $_.Exception.Message }
Add-Reg 'smb.client.signing_required' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
Add-Reg 'smb.client.smb1_start' 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'

try {
  foreach ($p in Get-NetFirewallProfile) {
    Add-Fact ('fw.' + $p.Name + '.enabled') $p.Enabled
    Add-Fact ('fw.' + $p.Name + '.inbound') $p.DefaultInboundAction
  }
} catch { $n['firewall'] = $_.Exception.Message }

try {
  $mp = Get-MpComputerStatus
  Add-Fact 'defender.realtime' $mp.RealTimeProtectionEnabled
  Add-Fact 'defender.signature_age_days' $mp.AntivirusSignatureAge
  Add-Fact 'defender.tamper' $mp.IsTamperProtected
  Add-Fact 'defender.service' $mp.AMServiceEnabled
} catch { $n['defender'] = 'Microsoft Defender status unavailable (another antivirus, or Defender removed): ' + $_.Exception.Message }

try {
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
  Add-Fact 'bitlocker.system' $bl.ProtectionStatus
} catch { $n['bitlocker'] = 'BitLocker status unavailable (feature not installed?): ' + $_.Exception.Message }

Add-Reg 'uac.EnableLUA' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
Add-Reg 'lsa.RunAsPPL' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
Add-Reg 'lsa.LmCompatibilityLevel' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
Add-Reg 'lsa.NoLMHash' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'
Add-Reg 'lsa.RestrictAnonymous' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous'
Add-Reg 'wdigest.UseLogonCredential' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
Add-Reg 'rdp.deny.policy' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections'
Add-Reg 'rdp.deny' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
Add-Reg 'rdp.nla.policy' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
Add-Reg 'rdp.nla' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
Add-Reg 'llmnr.EnableMulticast' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
Add-Reg 'autorun.NoDriveTypeAutoRun' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
Add-Reg 'ps.ScriptBlockLogging' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
Add-Reg 'audit.cmdline' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'

try {
  $opts = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { [string]$_.TcpipNetbiosOptions })
  $f['netbios.options'] = ($opts -join ',')
} catch { $n['netbios'] = $_.Exception.Message }

try { Add-Fact 'wu.start_type' (Get-Service -Name wuauserv).StartType } catch { $n['wu'] = $_.Exception.Message }
try {
  $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
  if ($hf) {
    $f['wu.last_hotfix_days'] = [string][int]((Get-Date) - $hf.InstalledOn).TotalDays
    $f['wu.last_hotfix'] = [string]$hf.HotFixID
  }
} catch { $n['wu.hotfix'] = $_.Exception.Message }

try { $f['eventlog.security.max_kb'] = [string][int64]((Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1KB) } catch { $n['eventlog'] = $_.Exception.Message }

[pscustomobject]@{ facts = $f; notes = $n } | ConvertTo-Json -Depth 3 -Compress
"#;

/// The Windows script's output, as a report.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_report(json: &str) -> Result<PostureFactsReport, String> {
    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(default)]
        facts: Option<Facts>,
        #[serde(default)]
        notes: Option<Facts>,
    }
    let raw: Raw = serde_json::from_str(json.trim())
        .map_err(|e| format!("couldn't read the posture facts from PowerShell: {e}"))?;
    Ok(PostureFactsReport {
        platform: "windows".into(),
        facts: raw.facts.unwrap_or_default(),
        notes: raw.notes.unwrap_or_default(),
    })
}

pub async fn posture_facts(elevation: &ElevationState) -> CommandOutcome {
    #[cfg(unix)]
    {
        ok(&linux::collect(elevation).await)
    }
    #[cfg(windows)]
    {
        let _ = elevation;
        match crate::process::run_powershell(WINDOWS_SCRIPT).await {
            Ok(output) => match windows_report(&output.stdout) {
                Ok(report) => ok(&report),
                Err(e) => CommandOutcome::Err(e),
            },
            Err(e) => CommandOutcome::Err(e),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = elevation;
        crate::process::platform_unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_t_and_login_defs() {
        let mut facts = Facts::new();
        parse_sshd_t(
            "port 22\npermitrootlogin without-password\nciphers chacha20-poly1305@openssh.com,aes256-ctr\nMaxAuthTries 6\n",
            &mut facts,
        );
        assert_eq!(facts["sshd.permitrootlogin"], "without-password");
        assert_eq!(facts["sshd.maxauthtries"], "6");
        assert_eq!(
            facts["sshd.ciphers"],
            "chacha20-poly1305@openssh.com,aes256-ctr"
        );
        parse_login_defs(
            "# PASS_MAX_DAYS 1\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS 0\nUMASK\t\t022\nENCRYPT_METHOD YESCRYPT\nMAIL_DIR /var/mail\n",
            &mut facts,
        );
        assert_eq!(facts["logindefs.PASS_MAX_DAYS"], "99999");
        assert_eq!(facts["logindefs.UMASK"], "022");
        assert_eq!(facts["logindefs.ENCRYPT_METHOD"], "YESCRYPT");
        assert!(!facts.contains_key("logindefs.MAIL_DIR"));
    }

    #[test]
    fn pam_and_conf_values() {
        let pam = "password requisite pam_pwquality.so retry=3 minlen=12\n\
                   # password requisite pam_pwquality.so minlen=99\n\
                   auth required pam_faillock.so preauth deny=5 unlock_time=900\n";
        assert_eq!(
            pam_arg(pam, "pam_pwquality", "minlen").as_deref(),
            Some("12")
        );
        assert_eq!(pam_arg(pam, "pam_faillock", "deny").as_deref(), Some("5"));
        assert_eq!(pam_arg(pam, "pam_cracklib", "minlen"), None);
        let conf = "# minlen = 8\nminlen = 14\n dcredit=-1\nminlen=15\n";
        assert_eq!(conf_value(conf, "minlen").as_deref(), Some("15"));
        assert_eq!(conf_value(conf, "deny"), None);
    }

    #[test]
    fn accounts() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        assert_eq!(extra_uid0(passwd), ["toor"]);
        let shadow = "root:$y$j9T$abc:19000:0:99999:7:::\nguest::19000:0:99999:7:::\nbin:*:19000::::::\nlocked:!:19000::::::\n";
        assert_eq!(empty_password_accounts(shadow), ["guest"]);
    }

    #[test]
    fn firewalls() {
        let ufw = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n";
        assert_eq!(parse_ufw(ufw), (true, Some("deny".into())));
        assert_eq!(parse_ufw("Status: inactive\n"), (false, None));

        let nft = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n}\n";
        assert_eq!(nft_input_policy(nft).as_deref(), Some("drop"));
        let open = "table ip nat {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t}\n}\n";
        assert_eq!(nft_input_policy(open), None);

        let ipt = "-P INPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n";
        assert_eq!(iptables_input_policy(ipt).as_deref(), Some("accept"));
        assert!(iptables_has_rules(ipt));
        assert!(!iptables_has_rules("-P INPUT ACCEPT\n"));
    }

    #[test]
    fn mounts() {
        let mounts = "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n\
                      tmpfs /tmp tmpfs rw,nosuid,nodev,size=8G 0 0\n\
                      tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n";
        assert_eq!(
            mount_options(mounts, "/tmp").as_deref(),
            Some("rw,nosuid,nodev,size=8G")
        );
        assert_eq!(mount_options(mounts, "/var/tmp"), None);
    }

    #[test]
    fn windows_output() {
        let report = windows_report(
            r#"{"facts":{"secedit.MinimumPasswordLength":"0","fw.Domain.enabled":"True"},"notes":{"bitlocker":"BitLocker status unavailable"}}"#,
        )
        .unwrap();
        assert_eq!(report.platform, "windows");
        assert_eq!(report.facts["secedit.MinimumPasswordLength"], "0");
        assert!(report.notes.contains_key("bitlocker"));
        assert!(
            windows_report(r#"{"facts":{},"notes":{}}"#)
                .unwrap()
                .facts
                .is_empty()
        );
        assert!(windows_report("garbage").is_err());
    }

    /// Through the real PowerShell parser. Needs `pwsh`: skipped without it
    /// locally, required in CI.
    #[test]
    fn the_windows_script_parses_as_powershell() {
        if std::process::Command::new("pwsh")
            .arg("-Version")
            .output()
            .is_err()
        {
            assert!(
                std::env::var_os("CI").is_none(),
                "pwsh is required for this test in CI"
            );
            return;
        }
        let path = std::env::temp_dir().join(format!("posture-{}.ps1", std::process::id()));
        std::fs::write(&path, WINDOWS_SCRIPT).unwrap();
        let out = std::process::Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:SCRIPT, [ref]$t, [ref]$e); foreach ($x in $e) { $x.Message }; if ($e.Count) { exit 1 }"])
            .env("SCRIPT", &path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
