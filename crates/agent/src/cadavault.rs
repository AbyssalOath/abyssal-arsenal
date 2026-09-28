//! Cadavault: host-side security hardening and posture auditing -- sshd
//! configuration auditing and a Cadavault-owned sshd hardening drop-in, the
//! kernel/sysctl security baseline, and read-only audits of account policy,
//! mandatory access control, and automatic updates. Every config change here
//! touches only `/etc/ssh/sshd_config.d/50-cadavault.conf`, never the host's
//! own `sshd_config` in place, and every write validates the whole merged
//! config with `sshd -t` before reloading the service, rolling back to the
//! previous drop-in if validation or the reload fails -- the same managed-
//! file idiom `sepulchre.rs` uses, so a bad change can never be left
//! half-applied and lock the operator out of the host. The audit operations
//! are read-only: remediation for what they find happens in the arsenal that
//! owns it (Parish for accounts, Grimoire for MAC/config, Apothecary for
//! updates), reached through the contextual workflow suggestions.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput, SshHardeningSetting};

use crate::apothecary;
use crate::elevation::ElevationState;
use crate::process::command_exists;

const DROPIN_FILE: &str = "/etc/ssh/sshd_config.d/50-cadavault.conf";
const MANAGED_HEADER: &str = "# Managed by Abyssal Arsenal (Cadavault) -- do not edit manually\n";
/// Distros disagree on whether the SSH daemon's unit is `sshd` or `ssh`;
/// reload the first one that exists (same approach as `sepulchre.rs`).
const RELOAD_CANDIDATES: &[&str] = &["sshd", "ssh"];

/// The sshd directives the audit reports on, matched case-insensitively
/// against `sshd -T` output (sshd lowercases its keys there).
const AUDITED_KEYS: &[&str] = &[
    "permitrootlogin",
    "passwordauthentication",
    "permitemptypasswords",
    "x11forwarding",
    "maxauthtries",
];

pub async fn sshd_config_audit(elevation: &ElevationState) -> CommandOutcome {
    // `sshd -T` dumps the *effective* config with every drop-in merged in,
    // but it reads the host keys, so it needs root -- run it through
    // elevation rather than assuming the agent already has it.
    let output = match elevation.run_allow_failure("sshd", &["-T"]).await {
        Ok(o) => o,
        Err(e) => return CommandOutcome::Err(e),
    };
    if output.exit_code != Some(0) {
        let detail = if output.stderr.trim().is_empty() {
            output.stdout.trim()
        } else {
            output.stderr.trim()
        };
        return CommandOutcome::Err(format!(
            "could not read the effective sshd configuration (`sshd -T`): {detail}"
        ));
    }

    let mut lines = Vec::new();
    for key in AUDITED_KEYS {
        match find_directive(&output.stdout, key) {
            Some(value) => lines.push(format!("{key} {value}")),
            None => lines.push(format!("{key} (unset -- sshd default applies)")),
        }
    }

    CommandOutcome::Ok(OperationOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// Reports the host's current effective value for each parameter in the
/// security-sysctl baseline, one `key\tvalue` line per key (`value` is
/// `unavailable` when the kernel doesn't expose that key, e.g. IPv6 disabled).
/// Read-only; the control plane scores the values and applies fixes through
/// the shared `SetPersistentSysctl` operation.
pub async fn sysctl_security_posture(elevation: &ElevationState) -> CommandOutcome {
    let mut lines = Vec::new();
    for entry in abyssal_agent_protocol::SECURITY_SYSCTLS {
        let current = match elevation
            .run_allow_failure("sysctl", &["-n", entry.key])
            .await
        {
            Ok(o) if o.exit_code == Some(0) => {
                // Normalize whitespace: some keys print tab-separated fields;
                // the baseline keys are all scalars, so collapse to a single
                // space and let the control plane compare the whole string.
                o.stdout.split_whitespace().collect::<Vec<_>>().join(" ")
            }
            Ok(_) => "unavailable".to_string(),
            Err(e) => return CommandOutcome::Err(e),
        };
        lines.push(format!("{}\t{current}", entry.key));
    }
    CommandOutcome::Ok(OperationOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// Read-only audit of account and access policy: UID-0 accounts other than
/// root, accounts with an empty password field, sudoers rules granting
/// `NOPASSWD`, and the password-aging defaults from `/etc/login.defs`. The
/// summary count lines use fixed labels the control plane parses; a check
/// whose source file needs root and isn't readable is reported as `unknown`
/// rather than a misleading `0`.
pub async fn account_policy_audit(elevation: &ElevationState) -> CommandOutcome {
    // /etc/passwd is world-readable.
    let passwd = match elevation.run_allow_failure("cat", &["/etc/passwd"]).await {
        Ok(o) if o.exit_code == Some(0) => o.stdout,
        Ok(o) => {
            return CommandOutcome::Err(format!("could not read /etc/passwd: {}", o.stderr.trim()));
        }
        Err(e) => return CommandOutcome::Err(e),
    };
    let extra_uid0: Vec<String> = passwd
        .lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            let _pw = f.next()?;
            let uid = f.next()?;
            (uid == "0" && name != "root").then(|| name.to_string())
        })
        .collect();

    // /etc/shadow is root-only: unreadable when the agent isn't elevated, so
    // report the empty-password check as unknown rather than a false zero.
    let (empty_pw, shadow_readable): (Vec<String>, bool) =
        match elevation.run_allow_failure("cat", &["/etc/shadow"]).await {
            Ok(o) if o.exit_code == Some(0) => (
                o.stdout
                    .lines()
                    .filter_map(|line| {
                        let mut f = line.split(':');
                        let name = f.next()?;
                        let hash = f.next()?;
                        // An empty hash field means the account can log in with
                        // no password. `!`/`*` mean locked, not empty.
                        hash.is_empty().then(|| name.to_string())
                    })
                    .collect(),
                true,
            ),
            _ => (Vec::new(), false),
        };

    // sudoers is root-only. grep exit 0 = matches, 1 = readable-but-none,
    // anything else (e.g. 2) = couldn't read -> unknown.
    let (nopasswd_lines, sudoers_readable): (Vec<String>, bool) = match elevation
        .run_allow_failure(
            "grep",
            &["-rEh", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d"],
        )
        .await
    {
        Ok(o) if o.exit_code == Some(0) => (
            o.stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect(),
            true,
        ),
        Ok(o) if o.exit_code == Some(1) => (Vec::new(), true),
        _ => (Vec::new(), false),
    };

    // login.defs is world-readable.
    let login_defs = match elevation
        .run_allow_failure("cat", &["/etc/login.defs"])
        .await
    {
        Ok(o) if o.exit_code == Some(0) => o.stdout,
        _ => String::new(),
    };
    let defs_value = |key: &str| -> String {
        login_defs
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(key) && l[key.len()..].starts_with(char::is_whitespace))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("(unset)")
            .to_string()
    };

    let unknown = "unknown -- needs elevation to read this host's file";
    let mut out = String::new();
    out.push_str(&format!(
        "Extra UID-0 accounts (besides root): {}\n",
        extra_uid0.len()
    ));
    out.push_str(&format!(
        "Empty-password accounts: {}\n",
        if shadow_readable {
            empty_pw.len().to_string()
        } else {
            unknown.to_string()
        }
    ));
    out.push_str(&format!(
        "Sudoers NOPASSWD entries: {}\n",
        if sudoers_readable {
            nopasswd_lines.len().to_string()
        } else {
            unknown.to_string()
        }
    ));
    out.push_str("\nPassword aging defaults (login.defs):\n");
    out.push_str(&format!(
        "  PASS_MAX_DAYS: {}\n",
        defs_value("PASS_MAX_DAYS")
    ));
    out.push_str(&format!(
        "  PASS_MIN_DAYS: {}\n",
        defs_value("PASS_MIN_DAYS")
    ));
    out.push_str(&format!(
        "  PASS_WARN_AGE: {}\n",
        defs_value("PASS_WARN_AGE")
    ));

    if !extra_uid0.is_empty() {
        out.push_str(&format!("\nUID-0 accounts: {}\n", extra_uid0.join(", ")));
    }
    if !empty_pw.is_empty() {
        out.push_str(&format!(
            "Empty-password accounts: {}\n",
            empty_pw.join(", ")
        ));
    }
    if !nopasswd_lines.is_empty() {
        out.push_str("\nNOPASSWD rules:\n");
        for line in &nopasswd_lines {
            out.push_str(&format!("  {line}\n"));
        }
    }

    CommandOutcome::Ok(OperationOutput {
        stdout: out.trim_end().to_string(),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// Read-only status of the host's mandatory access control system, detecting
/// SELinux (`getenforce`/`sestatus`) or AppArmor (`aa-status`) rather than
/// assuming either -- the same detect-don't-assume approach the firewall uses.
/// Emits fixed `MAC system:`/`MAC enforcing:` lines the control plane parses.
pub async fn mac_status(elevation: &ElevationState) -> CommandOutcome {
    if command_exists("getenforce").await {
        let mode = match elevation.run_allow_failure("getenforce", &[]).await {
            Ok(o) => o.stdout.trim().to_string(),
            Err(e) => return CommandOutcome::Err(e),
        };
        let enforcing = mode.eq_ignore_ascii_case("Enforcing");
        let mut out = format!(
            "MAC system: SELinux\nMAC enforcing: {}\ngetenforce: {mode}\n",
            if enforcing { "yes" } else { "no" }
        );
        if command_exists("sestatus").await
            && let Ok(o) = elevation.run_allow_failure("sestatus", &[]).await
        {
            out.push_str(&format!("\n{}", o.stdout.trim_end()));
        }
        return CommandOutcome::Ok(OperationOutput {
            stdout: out.trim_end().to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    let apparmor_cmd = if command_exists("aa-status").await {
        Some("aa-status")
    } else if command_exists("apparmor_status").await {
        Some("apparmor_status")
    } else {
        None
    };
    if let Some(cmd) = apparmor_cmd {
        let text = match elevation.run_allow_failure(cmd, &[]).await {
            Ok(o) => o.stdout,
            Err(e) => return CommandOutcome::Err(e),
        };
        // aa-status prints e.g. "12 profiles are in enforce mode."
        let enforce_count = text
            .lines()
            .find(|l| l.contains("profiles are in enforce mode"))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
        let enforcing = enforce_count > 0;
        let out = format!(
            "MAC system: AppArmor\nMAC enforcing: {}\n\n{}",
            if enforcing { "yes" } else { "no" },
            text.trim_end()
        );
        return CommandOutcome::Ok(OperationOutput {
            stdout: out,
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    CommandOutcome::Ok(OperationOutput {
        stdout: "MAC system: none\nMAC enforcing: no\n\nNo SELinux (getenforce) or AppArmor (aa-status) tooling detected on this host.".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// Read-only status of automatic security updates, detecting the package
/// manager first and then checking that family's unattended-update mechanism.
/// Emits an `Automatic updates: enabled|disabled|unknown` line the control
/// plane parses; `unknown` covers families with no single standard mechanism.
pub async fn automatic_updates_status(elevation: &ElevationState) -> CommandOutcome {
    let backend = match apothecary::detect().await {
        Some(b) => b,
        None => {
            return CommandOutcome::Err(
                "no known package manager found on this host (checked apt/dnf/yum/pacman/zypper)"
                    .to_string(),
            );
        }
    };

    let (state, detail) = match backend {
        apothecary::Backend::Apt => {
            // Debian/Ubuntu drive unattended-upgrades from apt's periodic
            // config; the enabled marker is Unattended-Upgrade "1".
            let cfg = elevation
                .run_allow_failure("cat", &["/etc/apt/apt.conf.d/20auto-upgrades"])
                .await;
            match cfg {
                Ok(o) if o.exit_code == Some(0) => {
                    let on = o.stdout.contains("Unattended-Upgrade \"1\"");
                    (
                        if on { "enabled" } else { "disabled" },
                        "checked /etc/apt/apt.conf.d/20auto-upgrades".to_string(),
                    )
                }
                _ => (
                    "disabled",
                    "no /etc/apt/apt.conf.d/20auto-upgrades (unattended-upgrades not configured)"
                        .to_string(),
                ),
            }
        }
        apothecary::Backend::Dnf | apothecary::Backend::Yum => {
            let timer = elevation
                .run_allow_failure("systemctl", &["is-enabled", "dnf-automatic.timer"])
                .await;
            match timer {
                Ok(o) => {
                    let on = o.stdout.trim() == "enabled";
                    (
                        if on { "enabled" } else { "disabled" },
                        format!("dnf-automatic.timer is-enabled: {}", o.stdout.trim()),
                    )
                }
                Err(e) => (
                    "unknown",
                    format!("could not query dnf-automatic.timer: {e}"),
                ),
            }
        }
        apothecary::Backend::Zypper => {
            let timer = elevation
                .run_allow_failure("systemctl", &["is-enabled", "zypper-automatic.timer"])
                .await;
            match timer {
                Ok(o) if o.stdout.trim() == "enabled" => {
                    ("enabled", "zypper-automatic.timer is enabled".to_string())
                }
                _ => (
                    "unknown",
                    "no standard unattended-update timer detected for zypper".to_string(),
                ),
            }
        }
        apothecary::Backend::Pacman => (
            "unknown",
            "Arch/pacman has no standard unattended-upgrade mechanism".to_string(),
        ),
    };

    CommandOutcome::Ok(OperationOutput {
        stdout: format!(
            "Package manager: {}\nAutomatic updates: {state}\n({detail})",
            backend.label()
        ),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// Finds a directive's value in `sshd -T` output, matching the key
/// case-insensitively. Returns the rest of the line as the value.
fn find_directive(dump: &str, key: &str) -> Option<String> {
    dump.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let k = parts.next()?;
        if k.eq_ignore_ascii_case(key) {
            let value = parts.collect::<Vec<_>>().join(" ");
            Some(if value.is_empty() {
                "(empty)".to_string()
            } else {
                value
            })
        } else {
            None
        }
    })
}

async fn read_dropin(elevation: &ElevationState) -> Result<String, String> {
    match elevation.run_allow_failure("cat", &[DROPIN_FILE]).await {
        Ok(o) if o.exit_code == Some(0) => Ok(o.stdout),
        // No managed drop-in yet: treated as an empty starting point, same
        // as `sepulchre.rs`'s first write to a not-yet-existing file.
        Ok(_) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

async fn write_dropin(
    content: &str,
    elevation: &ElevationState,
) -> Result<OperationOutput, String> {
    elevation
        .run_with_stdin("tee", &[DROPIN_FILE], content)
        .await
}

async fn reload_sshd(elevation: &ElevationState) -> Result<OperationOutput, String> {
    let mut last_error = String::new();
    for service in RELOAD_CANDIDATES {
        match elevation.run("systemctl", &["reload", service]).await {
            Ok(output) => return Ok(output),
            Err(e) => last_error = e,
        }
    }
    Err(format!(
        "none of the candidate services ({}) could be reloaded: {last_error}",
        RELOAD_CANDIDATES.join(", ")
    ))
}

/// Parses the managed drop-in into its directive lines (`Key value`),
/// dropping the header and any blank/comment lines, preserving order so an
/// upsert leaves the rest of the file untouched.
fn parse_directives(content: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            out.push((k.to_string(), v.trim().to_string()));
        }
    }
    out
}

fn render_dropin(directives: &[(String, String)]) -> String {
    let mut s = String::from(MANAGED_HEADER);
    for (k, v) in directives {
        s.push_str(k);
        s.push(' ');
        s.push_str(v);
        s.push('\n');
    }
    s
}

/// Computes the new drop-in content after applying `setting`, upserting its
/// directive (case-insensitively, since sshd keys are case-insensitive).
/// Pure and unit-tested; the I/O lives in `harden_sshd`.
fn apply_setting(previous: &str, setting: SshHardeningSetting) -> String {
    let (key, value) = setting.directive();
    let mut directives = parse_directives(previous);
    match directives
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
    {
        Some(existing) => existing.1 = value.to_string(),
        None => directives.push((key.to_string(), value.to_string())),
    }
    render_dropin(&directives)
}

pub async fn harden_sshd(
    setting: SshHardeningSetting,
    elevation: &ElevationState,
) -> CommandOutcome {
    let previous = match read_dropin(elevation).await {
        Ok(c) => c,
        Err(e) => return CommandOutcome::Err(e),
    };
    let content = apply_setting(&previous, setting);
    apply_dropin(&content, &previous, elevation).await
}

pub async fn clear_ssh_hardening(elevation: &ElevationState) -> CommandOutcome {
    let previous = match read_dropin(elevation).await {
        Ok(c) => c,
        Err(e) => return CommandOutcome::Err(e),
    };
    apply_dropin(MANAGED_HEADER, &previous, elevation).await
}

/// Writes `content` to the managed drop-in, validates the whole sshd config
/// with `sshd -t`, reloads the service, and restores `previous` if either
/// step fails -- a validation or reload failure never leaves a broken or
/// lock-you-out config applied.
async fn apply_dropin(content: &str, previous: &str, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = write_dropin(content, elevation).await {
        return CommandOutcome::Err(e);
    }

    match elevation.run_allow_failure("sshd", &["-t"]).await {
        Ok(o) if o.exit_code == Some(0) => match reload_sshd(elevation).await {
            Ok(reload) => CommandOutcome::Ok(OperationOutput {
                stdout: format!("Applied and reloaded sshd.\n{}", reload.stdout.trim_end()),
                ..reload
            }),
            Err(e) => {
                let _ = write_dropin(previous, elevation).await;
                let _ = reload_sshd(elevation).await;
                CommandOutcome::Err(format!(
                    "reload failed after applying the new sshd config; restored the previous version: {e}"
                ))
            }
        },
        Ok(o) => {
            let _ = write_dropin(previous, elevation).await;
            CommandOutcome::Err(format!(
                "sshd configuration validation failed; restored the previous version.\n{}\n{}",
                o.stdout.trim(),
                o.stderr.trim()
            ))
        }
        Err(e) => {
            let _ = write_dropin(previous, elevation).await;
            CommandOutcome::Err(format!(
                "could not run `sshd -t` to validate the new config; restored the previous version: {e}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_finds_directive_case_insensitively() {
        let dump = "permitrootlogin without-password\npasswordauthentication yes\n";
        assert_eq!(
            find_directive(dump, "permitrootlogin").as_deref(),
            Some("without-password")
        );
        assert_eq!(
            find_directive(dump, "PasswordAuthentication").as_deref(),
            Some("yes")
        );
        assert_eq!(find_directive(dump, "x11forwarding"), None);
    }

    #[test]
    fn apply_setting_appends_to_empty_dropin() {
        let out = apply_setting("", SshHardeningSetting::DisablePasswordAuth);
        assert!(out.starts_with(MANAGED_HEADER));
        assert!(out.contains("PasswordAuthentication no\n"));
    }

    #[test]
    fn apply_setting_upserts_existing_directive_without_duplicating() {
        let previous = format!("{MANAGED_HEADER}PermitRootLogin yes\nX11Forwarding no\n");
        let out = apply_setting(&previous, SshHardeningSetting::DisableRootLogin);
        // The stale `yes` is replaced, not appended alongside a new `no`.
        assert!(out.contains("PermitRootLogin no\n"));
        assert!(!out.contains("PermitRootLogin yes\n"));
        assert_eq!(out.matches("PermitRootLogin").count(), 1);
        // Unrelated managed directives survive.
        assert!(out.contains("X11Forwarding no\n"));
    }

    #[test]
    fn apply_setting_matches_key_case_insensitively() {
        let previous = format!("{MANAGED_HEADER}permitrootlogin yes\n");
        let out = apply_setting(&previous, SshHardeningSetting::DisableRootLogin);
        assert_eq!(
            out.to_lowercase().matches("permitrootlogin").count(),
            1,
            "a differently-cased existing key must be upserted, not duplicated"
        );
    }
}
