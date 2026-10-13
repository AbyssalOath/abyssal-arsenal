//! The Windows checks. Facts come from `crates/agent/src/posture.rs`'s
//! `WINDOWS_SCRIPT`: `secedit.*` from `secedit /export`, `audit.<GUID>` from
//! `auditpol /backup` (subcategory GUIDs, so it doesn't depend on the
//! display language), and registry values, where `absent` means "not set,
//! so the Windows default applies".

use crate::{Check, Facts, Outcome, Platform, failed, int_where, not_applicable, one_of, passed};

// Audit subcategory GUIDs (stable across languages and versions).
const CREDENTIAL_VALIDATION: &str = "0CCE923F-69AE-11D9-BED3-505054503030";
const LOGON: &str = "0CCE9215-69AE-11D9-BED3-505054503030";
const SPECIAL_LOGON: &str = "0CCE921B-69AE-11D9-BED3-505054503030";
const ACCOUNT_LOCKOUT: &str = "0CCE9217-69AE-11D9-BED3-505054503030";
const USER_ACCOUNT_MANAGEMENT: &str = "0CCE9235-69AE-11D9-BED3-505054503030";
const SECURITY_GROUP_MANAGEMENT: &str = "0CCE9237-69AE-11D9-BED3-505054503030";
const PROCESS_CREATION: &str = "0CCE922B-69AE-11D9-BED3-505054503030";
const AUDIT_POLICY_CHANGE: &str = "0CCE922F-69AE-11D9-BED3-505054503030";

const SUCCESS: i64 = 1;
const FAILURE: i64 = 2;

fn audit_setting_name(value: i64) -> &'static str {
    match value {
        0 => "No Auditing",
        1 => "Success",
        2 => "Failure",
        3 => "Success and Failure",
        _ => "unknown",
    }
}

/// An audit subcategory that must include all of `need` (success and/or
/// failure bits).
fn audit(f: &Facts, guid: &str, label: &str, need: i64) -> Outcome {
    let key = format!("audit.{guid}");
    let Some(value) = f.int(&key) else {
        return match f.get(&key) {
            None => f.missing(&key),
            Some(v) => failed(format!("{label}: unreadable setting {v}")),
        };
    };
    let evidence = format!("{label}: {}", audit_setting_name(value));
    if value & need == need {
        passed(evidence)
    } else {
        failed(format!(
            "{evidence} (want {})",
            audit_setting_name(need | (value & 3))
        ))
    }
}

/// A registry value: `Some(value)`, or `None` when it isn't set.
fn reg<'a>(f: &Facts<'a>, key: &str) -> Result<Option<&'a str>, Outcome> {
    match f.get(key) {
        None => Err(f.missing(key)),
        Some("absent") => Ok(None),
        Some(v) => Ok(Some(v)),
    }
}

/// A registry value that must equal `want`; `default_ok` says whether the
/// Windows default (value not set) already meets it.
fn reg_is(f: &Facts, key: &str, label: &str, want: &[&str], default_ok: bool) -> Outcome {
    match reg(f, key) {
        Err(o) => o,
        Ok(None) if default_ok => passed(format!("{label}: not set (the Windows default is safe)")),
        Ok(None) => failed(format!("{label}: not set (the Windows default isn't)")),
        Ok(Some(v)) if want.iter().any(|w| w.eq_ignore_ascii_case(v)) => {
            passed(format!("{label} = {v}"))
        }
        Ok(Some(v)) => failed(format!("{label} = {v}")),
    }
}

/// A `secedit` policy value.
fn policy(f: &Facts, name: &str, ok: fn(i64) -> bool, want: &str) -> Outcome {
    int_where(f, &format!("secedit.{name}"), name, ok, want)
}

/// Lockout checks don't apply while lockout is off.
fn with_lockout(f: &Facts, rule: impl FnOnce(&Facts) -> Outcome) -> Outcome {
    match f.int("secedit.LockoutBadCount") {
        None => f.missing("secedit.LockoutBadCount"),
        Some(0) => not_applicable("Account lockout is off (see AA-WIN-LCK-001)."),
        Some(_) => rule(f),
    }
}

/// A firewall profile is on (`NotConfigured` falls back to on).
fn profile_on(f: &Facts, profile: &str) -> Outcome {
    let key = format!("fw.{profile}.enabled");
    match f.get(&key) {
        None => f.missing(&key),
        Some(v) if v.eq_ignore_ascii_case("True") || v.eq_ignore_ascii_case("NotConfigured") => {
            passed(format!("{profile} profile: on"))
        }
        Some(v) => failed(format!("{profile} profile: Enabled = {v}")),
    }
}

/// Defender checks don't apply without Defender.
fn with_defender(f: &Facts, rule: impl FnOnce(&Facts) -> Outcome) -> Outcome {
    if f.get("defender.realtime").is_none() {
        return f.missing("defender.realtime");
    }
    rule(f)
}

pub(crate) const CHECKS: &[Check] = &[
    // ------------------------------------------------------ Passwords --
    Check {
        id: "AA-WIN-PWD-001",
        platform: Platform::Windows,
        category: "Passwords",
        title: "Passwords must be at least 14 characters",
        rationale: "Length is the single biggest factor in how long a password takes to guess.",
        remediation: "Set Minimum password length to 14 or more.",
        command: Some(
            "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password length\nnet accounts /minpwlen:14",
        ),
        fix: None,
        mitre: &["T1110"],
        rule: |f| policy(f, "MinimumPasswordLength", |n| n >= 14, "14 or more"),
    },
    Check {
        id: "AA-WIN-PWD-002",
        platform: Platform::Windows,
        category: "Passwords",
        title: "Password complexity is required",
        rationale: "Complexity rules rule out the dictionary words and names attackers try \
                    first.",
        remediation: "Enable Password must meet complexity requirements.",
        command: Some(
            "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Password must meet complexity requirements",
        ),
        fix: None,
        mitre: &["T1110"],
        rule: |f| {
            one_of(
                f,
                "secedit.PasswordComplexity",
                "PasswordComplexity",
                &["1"],
            )
        },
    },
    Check {
        id: "AA-WIN-PWD-003",
        platform: Platform::Windows,
        category: "Passwords",
        title: "Passwords expire within 365 days",
        rationale: "A password that never expires stays useful to whoever learns it.",
        remediation: "Set Maximum password age to between 1 and 365 days.",
        command: Some("net accounts /maxpwage:365"),
        fix: None,
        mitre: &["T1110"],
        rule: |f| {
            policy(
                f,
                "MaximumPasswordAge",
                |n| (1..=365).contains(&n),
                "1 to 365 days",
            )
        },
    },
    Check {
        id: "AA-WIN-PWD-004",
        platform: Platform::Windows,
        category: "Passwords",
        title: "Passwords can't be changed again the same day",
        rationale: "A minimum age stops users cycling through the history straight back to \
                    their old password.",
        remediation: "Set Minimum password age to 1 day or more.",
        command: Some("net accounts /minpwage:1"),
        fix: None,
        mitre: &[],
        rule: |f| policy(f, "MinimumPasswordAge", |n| n >= 1, "1 or more"),
    },
    Check {
        id: "AA-WIN-PWD-005",
        platform: Platform::Windows,
        category: "Passwords",
        title: "The last 24 passwords can't be reused",
        rationale: "Without a history, users just set the same password again when it \
                    expires.",
        remediation: "Set Enforce password history to 24.",
        command: Some("net accounts /uniquepw:24"),
        fix: None,
        mitre: &[],
        rule: |f| policy(f, "PasswordHistorySize", |n| n >= 24, "24 or more"),
    },
    Check {
        id: "AA-WIN-PWD-006",
        platform: Platform::Windows,
        category: "Passwords",
        title: "Passwords aren't stored with reversible encryption",
        rationale: "Reversible encryption is effectively plain text to anyone who gets the \
                    account database.",
        remediation: "Disable Store passwords using reversible encryption.",
        command: Some(
            "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Store passwords using reversible encryption: Disabled",
        ),
        fix: None,
        mitre: &["T1003"],
        rule: |f| one_of(f, "secedit.ClearTextPassword", "ClearTextPassword", &["0"]),
    },
    // -------------------------------------------------------- Lockout --
    Check {
        id: "AA-WIN-LCK-001",
        platform: Platform::Windows,
        category: "Lockout",
        title: "Accounts lock after at most 10 failed logins",
        rationale: "Without lockout, passwords can be guessed online for as long as an \
                    attacker likes.",
        remediation: "Set Account lockout threshold to between 1 and 10 (5 is common).",
        command: Some("net accounts /lockoutthreshold:5"),
        fix: None,
        mitre: &["T1110.001"],
        rule: |f| {
            policy(
                f,
                "LockoutBadCount",
                |n| (1..=10).contains(&n),
                "1 to 10 (0 means never)",
            )
        },
    },
    Check {
        id: "AA-WIN-LCK-002",
        platform: Platform::Windows,
        category: "Lockout",
        title: "Locked accounts stay locked for 15 minutes or more",
        rationale: "A short lockout just slows guessing down a little.",
        remediation: "Set Account lockout duration to 15 minutes or more.",
        command: Some("net accounts /lockoutduration:15"),
        fix: None,
        mitre: &["T1110.001"],
        rule: |f| {
            with_lockout(f, |f| {
                policy(f, "LockoutDuration", |n| n >= 15 || n == -1, "15 or more")
            })
        },
    },
    Check {
        id: "AA-WIN-LCK-003",
        platform: Platform::Windows,
        category: "Lockout",
        title: "The failed-login counter resets after 15 minutes or more",
        rationale: "A quick reset lets an attacker pace guesses just under the threshold.",
        remediation: "Set Reset account lockout counter after to 15 minutes or more.",
        command: Some("net accounts /lockoutwindow:15"),
        fix: None,
        mitre: &["T1110.001"],
        rule: |f| {
            with_lockout(f, |f| {
                policy(f, "ResetLockoutCount", |n| n >= 15, "15 or more")
            })
        },
    },
    // ------------------------------------------------------- Accounts --
    Check {
        id: "AA-WIN-ACC-001",
        platform: Platform::Windows,
        category: "Accounts",
        title: "The Guest account is disabled",
        rationale: "Guest is a well-known account that needs no password.",
        remediation: "Disable the Guest account.",
        command: Some("Disable-LocalUser -Name Guest"),
        fix: None,
        mitre: &["T1078.001"],
        rule: |f| {
            one_of(
                f,
                "secedit.EnableGuestAccount",
                "EnableGuestAccount",
                &["0"],
            )
        },
    },
    Check {
        id: "AA-WIN-ACC-002",
        platform: Platform::Windows,
        category: "Accounts",
        title: "Anonymous users can't translate names and SIDs",
        rationale: "Anonymous SID/name translation lets an unauthenticated caller list \
                    accounts, including a renamed Administrator.",
        remediation: "Disable Network access: Allow anonymous SID/Name translation.",
        command: Some(
            "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network access: Allow anonymous SID/Name translation: Disabled",
        ),
        fix: None,
        mitre: &["T1087"],
        rule: |f| {
            one_of(
                f,
                "secedit.LSAAnonymousNameLookup",
                "LSAAnonymousNameLookup",
                &["0"],
            )
        },
    },
    Check {
        id: "AA-WIN-ACC-003",
        platform: Platform::Windows,
        category: "Accounts",
        title: "Only Administrators can debug programs",
        rationale: "SeDebugPrivilege lets a process read any other process's memory, which is \
                    how credentials are dumped from LSASS.",
        remediation: "Grant Debug programs to Administrators only.",
        command: Some(
            "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Debug programs",
        ),
        fix: None,
        mitre: &["T1003.001"],
        rule: |f| {
            if f.get("secedit.MinimumPasswordLength").is_none() {
                return f.missing("secedit.SeDebugPrivilege");
            }
            match f.get("secedit.SeDebugPrivilege") {
                None => passed("No account holds SeDebugPrivilege."),
                Some(v) => {
                    let holders: Vec<&str> = v.split(',').map(str::trim).collect();
                    if holders.iter().all(|h| *h == "*S-1-5-32-544") {
                        passed("Held by Administrators only.")
                    } else {
                        failed(format!("Held by: {}", holders.join(", ")))
                    }
                }
            }
        },
    },
    // ----------------------------------------------------------- Audit --
    Check {
        id: "AA-WIN-AUD-001",
        platform: Platform::Windows,
        category: "Audit",
        title: "Credential validation is audited (success and failure)",
        rationale: "Records every attempt to check an account's credentials, the first sign \
                    of password spraying.",
        remediation: "Audit Credential Validation: Success and Failure.",
        command: Some(
            "auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable",
        ),
        fix: None,
        mitre: &["T1562.002", "T1110"],
        rule: |f| {
            audit(
                f,
                CREDENTIAL_VALIDATION,
                "Credential Validation",
                SUCCESS | FAILURE,
            )
        },
    },
    Check {
        id: "AA-WIN-AUD-002",
        platform: Platform::Windows,
        category: "Audit",
        title: "Logons are audited (success and failure)",
        rationale: "Logon events (4624, 4625) are the backbone of any investigation.",
        remediation: "Audit Logon: Success and Failure.",
        command: Some(
            "auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable",
        ),
        fix: None,
        mitre: &["T1562.002"],
        rule: |f| audit(f, LOGON, "Logon", SUCCESS | FAILURE),
    },
    Check {
        id: "AA-WIN-AUD-003",
        platform: Platform::Windows,
        category: "Audit",
        title: "Special logons are audited",
        rationale: "Records logons with administrator-equivalent privileges (event 4672).",
        remediation: "Audit Special Logon: Success.",
        command: Some(
            "auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030} /success:enable",
        ),
        fix: None,
        mitre: &["T1562.002"],
        rule: |f| audit(f, SPECIAL_LOGON, "Special Logon", SUCCESS),
    },
    Check {
        id: "AA-WIN-AUD-004",
        platform: Platform::Windows,
        category: "Audit",
        title: "Account lockouts are audited",
        rationale: "Lockouts (event 4625 with lockout status) show guessing in progress.",
        remediation: "Audit Account Lockout: Failure.",
        command: Some(
            "auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /failure:enable",
        ),
        fix: None,
        mitre: &["T1562.002", "T1110"],
        rule: |f| audit(f, ACCOUNT_LOCKOUT, "Account Lockout", FAILURE),
    },
    Check {
        id: "AA-WIN-AUD-005",
        platform: Platform::Windows,
        category: "Audit",
        title: "User account changes are audited (success and failure)",
        rationale: "Records accounts being created, enabled, reset or changed, a common \
                    persistence step.",
        remediation: "Audit User Account Management: Success and Failure.",
        command: Some(
            "auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable",
        ),
        fix: None,
        mitre: &["T1562.002", "T1136"],
        rule: |f| {
            audit(
                f,
                USER_ACCOUNT_MANAGEMENT,
                "User Account Management",
                SUCCESS | FAILURE,
            )
        },
    },
    Check {
        id: "AA-WIN-AUD-006",
        platform: Platform::Windows,
        category: "Audit",
        title: "Security group changes are audited",
        rationale: "Records accounts being added to groups such as Administrators.",
        remediation: "Audit Security Group Management: Success.",
        command: Some(
            "auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030} /success:enable",
        ),
        fix: None,
        mitre: &["T1562.002", "T1098"],
        rule: |f| {
            audit(
                f,
                SECURITY_GROUP_MANAGEMENT,
                "Security Group Management",
                SUCCESS,
            )
        },
    },
    Check {
        id: "AA-WIN-AUD-007",
        platform: Platform::Windows,
        category: "Audit",
        title: "Process creation is audited",
        rationale: "Event 4688 for every new process is how malware execution is traced.",
        remediation: "Audit Process Creation: Success.",
        command: Some(
            "auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable",
        ),
        fix: None,
        mitre: &["T1562.002"],
        rule: |f| audit(f, PROCESS_CREATION, "Process Creation", SUCCESS),
    },
    Check {
        id: "AA-WIN-AUD-008",
        platform: Platform::Windows,
        category: "Audit",
        title: "Audit policy changes are audited",
        rationale: "An attacker turning auditing off should itself leave a record.",
        remediation: "Audit Audit Policy Change: Success.",
        command: Some(
            "auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable",
        ),
        fix: None,
        mitre: &["T1562.002"],
        rule: |f| audit(f, AUDIT_POLICY_CHANGE, "Audit Policy Change", SUCCESS),
    },
    Check {
        id: "AA-WIN-AUD-009",
        platform: Platform::Windows,
        category: "Audit",
        title: "Process creation events include the command line",
        rationale: "Without the command line, event 4688 shows that powershell.exe ran but \
                    not what it ran.",
        remediation: "Enable Include command line in process creation events.",
        command: Some(
            "Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events: Enabled",
        ),
        fix: None,
        mitre: &["T1059"],
        rule: |f| {
            reg_is(
                f,
                "audit.cmdline",
                "ProcessCreationIncludeCmdLine_Enabled",
                &["1"],
                false,
            )
        },
    },
    Check {
        id: "AA-WIN-AUD-010",
        platform: Platform::Windows,
        category: "Audit",
        title: "The Security log holds at least 192 MB",
        rationale: "The default 20 MB Security log can roll over in hours on a busy server, \
                    losing the events an investigation needs.",
        remediation: "Set the Security log's maximum size to 196,608 KB or more.",
        command: Some("wevtutil sl Security /ms:201326592"),
        fix: None,
        mitre: &["T1070.001"],
        rule: |f| {
            int_where(
                f,
                "eventlog.security.max_kb",
                "Security log maximum (KB)",
                |n| n >= 196_608,
                "196608 or more",
            )
        },
    },
    Check {
        id: "AA-WIN-AUD-011",
        platform: Platform::Windows,
        category: "Audit",
        title: "PowerShell script block logging is on",
        rationale: "Records the PowerShell code that actually runs, including deobfuscated \
                    scripts, in event 4104.",
        remediation: "Enable Turn on PowerShell Script Block Logging.",
        command: Some(
            "Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging: Enabled",
        ),
        fix: None,
        mitre: &["T1059.001"],
        rule: |f| {
            reg_is(
                f,
                "ps.ScriptBlockLogging",
                "EnableScriptBlockLogging",
                &["1"],
                false,
            )
        },
    },
    // ------------------------------------------------------------- SMB --
    Check {
        id: "AA-WIN-SMB-001",
        platform: Platform::Windows,
        category: "SMB",
        title: "The SMBv1 server is off",
        rationale: "SMBv1 is what EternalBlue (WannaCry, NotPetya) exploited, and nothing \
                    current needs it.",
        remediation: "Disable SMBv1 on the server.",
        command: Some("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"),
        fix: None,
        mitre: &["T1210"],
        rule: |f| one_of(f, "smb.server.smb1", "EnableSMB1Protocol", &["False"]),
    },
    Check {
        id: "AA-WIN-SMB-002",
        platform: Platform::Windows,
        category: "SMB",
        title: "The SMBv1 client is off",
        rationale: "The SMBv1 client driver carries the same protocol weaknesses as the \
                    server.",
        remediation: "Remove the SMB 1.0/CIFS Client feature.",
        command: Some(
            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart",
        ),
        fix: None,
        mitre: &["T1210"],
        rule: |f| match reg(f, "smb.client.smb1_start") {
            Err(o) => o,
            Ok(None) => passed("The SMBv1 client driver (mrxsmb10) isn't installed."),
            Ok(Some("4")) => passed("The SMBv1 client driver is disabled (Start = 4)."),
            Ok(Some(v)) => failed(format!("The SMBv1 client driver is enabled (Start = {v}).")),
        },
    },
    Check {
        id: "AA-WIN-SMB-003",
        platform: Platform::Windows,
        category: "SMB",
        title: "The SMB server requires signing",
        rationale: "Unsigned SMB can be relayed: an attacker passes a captured authentication \
                    on to another server.",
        remediation: "Enable Microsoft network server: Digitally sign communications (always).",
        command: Some("Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"),
        fix: None,
        mitre: &["T1557"],
        rule: |f| {
            one_of(
                f,
                "smb.server.signing_required",
                "RequireSecuritySignature",
                &["True"],
            )
        },
    },
    Check {
        id: "AA-WIN-SMB-004",
        platform: Platform::Windows,
        category: "SMB",
        title: "The SMB client requires signing",
        rationale: "Client-side signing stops this machine's own connections being relayed or \
                    tampered with.",
        remediation: "Enable Microsoft network client: Digitally sign communications (always).",
        command: Some("Set-SmbClientConfiguration -RequireSecuritySignature $true -Force"),
        fix: None,
        mitre: &["T1557"],
        rule: |f| {
            reg_is(
                f,
                "smb.client.signing_required",
                "Client RequireSecuritySignature",
                &["1"],
                false,
            )
        },
    },
    // -------------------------------------------------------- Firewall --
    Check {
        id: "AA-WIN-FW-001",
        platform: Platform::Windows,
        category: "Firewall",
        title: "The firewall's Domain profile is on",
        rationale: "With a profile off, every listening service is reachable on networks of \
                    that type.",
        remediation: "Turn the Domain profile on.",
        command: Some("Set-NetFirewallProfile -Profile Domain -Enabled True"),
        fix: None,
        mitre: &["T1562.004"],
        rule: |f| profile_on(f, "Domain"),
    },
    Check {
        id: "AA-WIN-FW-002",
        platform: Platform::Windows,
        category: "Firewall",
        title: "The firewall's Private profile is on",
        rationale: "With a profile off, every listening service is reachable on networks of \
                    that type.",
        remediation: "Turn the Private profile on.",
        command: Some("Set-NetFirewallProfile -Profile Private -Enabled True"),
        fix: None,
        mitre: &["T1562.004"],
        rule: |f| profile_on(f, "Private"),
    },
    Check {
        id: "AA-WIN-FW-003",
        platform: Platform::Windows,
        category: "Firewall",
        title: "The firewall's Public profile is on",
        rationale: "The Public profile covers untrusted networks such as hotel and café \
                    Wi-Fi.",
        remediation: "Turn the Public profile on.",
        command: Some("Set-NetFirewallProfile -Profile Public -Enabled True"),
        fix: None,
        mitre: &["T1562.004"],
        rule: |f| profile_on(f, "Public"),
    },
    Check {
        id: "AA-WIN-FW-004",
        platform: Platform::Windows,
        category: "Firewall",
        title: "Inbound connections are blocked by default",
        rationale: "Default-block means a new service is unreachable until a rule allows it.",
        remediation: "Set every profile's default inbound action to Block.",
        command: Some("Set-NetFirewallProfile -All -DefaultInboundAction Block"),
        fix: None,
        mitre: &["T1562.004"],
        rule: |f| {
            let mut open = Vec::new();
            for profile in ["Domain", "Private", "Public"] {
                let key = format!("fw.{profile}.inbound");
                match f.get(&key) {
                    None => return f.missing(&key),
                    Some(v)
                        if v.eq_ignore_ascii_case("Block")
                            || v.eq_ignore_ascii_case("NotConfigured") => {}
                    Some(v) => open.push(format!("{profile}: {v}")),
                }
            }
            if open.is_empty() {
                passed("Every profile blocks inbound by default.")
            } else {
                failed(format!("Default inbound action: {}", open.join(", ")))
            }
        },
    },
    // -------------------------------------------------------- Defender --
    Check {
        id: "AA-WIN-DEF-001",
        platform: Platform::Windows,
        category: "Antivirus",
        title: "Defender real-time protection is on",
        rationale: "Without real-time protection, malware is only found by a later scan, if \
                    at all.",
        remediation: "Turn real-time protection on (and find out what turned it off).",
        command: Some("Set-MpPreference -DisableRealtimeMonitoring $false"),
        fix: None,
        mitre: &["T1562.001"],
        rule: |f| {
            with_defender(f, |f| {
                one_of(
                    f,
                    "defender.realtime",
                    "RealTimeProtectionEnabled",
                    &["True"],
                )
            })
        },
    },
    Check {
        id: "AA-WIN-DEF-002",
        platform: Platform::Windows,
        category: "Antivirus",
        title: "Defender signatures are no more than 3 days old",
        rationale: "Old signatures miss whatever was published since.",
        remediation: "Update the signatures, and check the machine can reach Windows Update or \
                      your WSUS server.",
        command: Some("Update-MpSignature"),
        fix: None,
        mitre: &["T1562.001"],
        rule: |f| {
            with_defender(f, |f| match f.int("defender.signature_age_days") {
                None => f.missing("defender.signature_age_days"),
                Some(65535) => failed("Signatures have never been updated."),
                Some(n) if n <= 3 => passed(format!("Signatures are {n} day(s) old.")),
                Some(n) => failed(format!("Signatures are {n} days old.")),
            })
        },
    },
    Check {
        id: "AA-WIN-DEF-003",
        platform: Platform::Windows,
        category: "Antivirus",
        title: "Defender tamper protection is on",
        rationale: "Tamper protection stops malware (or an attacker with admin rights) simply \
                    switching Defender off.",
        remediation: "Turn tamper protection on in Windows Security, or centrally through \
                      Intune or Defender for Endpoint.",
        command: Some(
            "Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On",
        ),
        fix: None,
        mitre: &["T1562.001"],
        rule: |f| {
            with_defender(f, |f| {
                one_of(f, "defender.tamper", "IsTamperProtected", &["True"])
            })
        },
    },
    // ------------------------------------------------------ Encryption --
    Check {
        id: "AA-WIN-ENC-001",
        platform: Platform::Windows,
        category: "Encryption",
        title: "BitLocker protects the system drive",
        rationale: "An unencrypted disk gives anyone who removes it every file and every \
                    cached credential.",
        remediation: "Turn on BitLocker for the system drive, and store its recovery key \
                      somewhere safe (Active Directory or Entra ID).",
        command: Some("Enable-BitLocker -MountPoint $env:SystemDrive -TpmProtector -UsedSpaceOnly"),
        fix: None,
        mitre: &[],
        rule: |f| one_of(f, "bitlocker.system", "System drive protection", &["On"]),
    },
    // ---------------------------------------------------------- System --
    Check {
        id: "AA-WIN-SYS-001",
        platform: Platform::Windows,
        category: "System",
        title: "User Account Control is on",
        rationale: "With UAC off, every administrator process runs with full rights, \
                    including anything a malicious document starts.",
        remediation: "Enable User Account Control: Run all administrators in Admin Approval \
                      Mode, then restart.",
        command: Some(
            "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
        ),
        fix: None,
        mitre: &["T1548.002"],
        rule: |f| reg_is(f, "uac.EnableLUA", "EnableLUA", &["1"], true),
    },
    Check {
        id: "AA-WIN-SYS-002",
        platform: Platform::Windows,
        category: "System",
        title: "AutoPlay is off for all drives",
        rationale: "AutoPlay runs content from inserted media, the classic USB infection route.",
        remediation: "Enable Turn off AutoPlay for All drives.",
        command: Some(
            "Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies > Turn off AutoPlay: Enabled, All drives",
        ),
        fix: None,
        mitre: &["T1091"],
        rule: |f| {
            reg_is(
                f,
                "autorun.NoDriveTypeAutoRun",
                "NoDriveTypeAutoRun",
                &["255"],
                false,
            )
        },
    },
    // ----------------------------------------------------- Credentials --
    Check {
        id: "AA-WIN-CRD-001",
        platform: Platform::Windows,
        category: "Credentials",
        title: "LSA protection is on",
        rationale: "Running LSASS as a protected process blocks the usual tools for dumping \
                    credentials from memory.",
        remediation: "Set RunAsPPL to 1 and restart. Test first: some security software \
                      loads into LSASS.",
        command: Some(
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1 -Type DWord",
        ),
        fix: None,
        mitre: &["T1003.001"],
        rule: |f| reg_is(f, "lsa.RunAsPPL", "RunAsPPL", &["1", "2"], false),
    },
    Check {
        id: "AA-WIN-CRD-002",
        platform: Platform::Windows,
        category: "Credentials",
        title: "WDigest doesn't keep passwords in memory",
        rationale: "With WDigest caching on, plain-text passwords of logged-on users sit in \
                    LSASS memory.",
        remediation: "Set UseLogonCredential to 0 (or delete it).",
        command: Some(
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0 -Type DWord",
        ),
        fix: None,
        mitre: &["T1003.001"],
        rule: |f| {
            reg_is(
                f,
                "wdigest.UseLogonCredential",
                "UseLogonCredential",
                &["0"],
                true,
            )
        },
    },
    Check {
        id: "AA-WIN-CRD-003",
        platform: Platform::Windows,
        category: "Credentials",
        title: "Only NTLMv2 is accepted (LM and NTLM refused)",
        rationale: "LM and NTLMv1 responses can be cracked quickly once captured.",
        remediation: "Set Network security: LAN Manager authentication level to Send NTLMv2 \
                      response only. Refuse LM & NTLM (5). Check for old devices first.",
        command: Some(
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord",
        ),
        fix: None,
        mitre: &["T1557"],
        rule: |f| {
            reg_is(
                f,
                "lsa.LmCompatibilityLevel",
                "LmCompatibilityLevel",
                &["5"],
                false,
            )
        },
    },
    Check {
        id: "AA-WIN-CRD-004",
        platform: Platform::Windows,
        category: "Credentials",
        title: "LM hashes aren't stored",
        rationale: "LM hashes crack in seconds.",
        remediation: "Set NoLMHash to 1 (the default since Windows Vista).",
        command: Some(
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash -Value 1 -Type DWord",
        ),
        fix: None,
        mitre: &["T1003.002"],
        rule: |f| reg_is(f, "lsa.NoLMHash", "NoLMHash", &["1"], true),
    },
    // --------------------------------------------------------- Network --
    Check {
        id: "AA-WIN-NET-001",
        platform: Platform::Windows,
        category: "Network",
        title: "Anonymous users can't list accounts and shares",
        rationale: "Anonymous enumeration hands an attacker the account and share names to \
                    target.",
        remediation: "Enable Network access: Do not allow anonymous enumeration of SAM \
                      accounts and shares (RestrictAnonymous = 1).",
        command: Some(
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymous -Value 1 -Type DWord",
        ),
        fix: None,
        mitre: &["T1087", "T1135"],
        rule: |f| {
            reg_is(
                f,
                "lsa.RestrictAnonymous",
                "RestrictAnonymous",
                &["1", "2"],
                false,
            )
        },
    },
    Check {
        id: "AA-WIN-NET-002",
        platform: Platform::Windows,
        category: "Network",
        title: "LLMNR is off",
        rationale: "Any machine on the network can answer an LLMNR query and collect the \
                    asker's NTLM hash (Responder).",
        remediation: "Enable Turn off multicast name resolution.",
        command: Some(
            "Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution: Enabled",
        ),
        fix: None,
        mitre: &["T1557.001"],
        rule: |f| reg_is(f, "llmnr.EnableMulticast", "EnableMulticast", &["0"], false),
    },
    Check {
        id: "AA-WIN-NET-003",
        platform: Platform::Windows,
        category: "Network",
        title: "NetBIOS over TCP/IP is off",
        rationale: "NetBIOS name queries can be answered by any machine on the segment, the \
                    same poisoning risk as LLMNR.",
        remediation: "Disable NetBIOS over TCP/IP on each adapter (or through DHCP option \
                      001). Check nothing still needs it first.",
        command: Some(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}",
        ),
        fix: None,
        mitre: &["T1557.001"],
        rule: |f| match f.get("netbios.options") {
            None => f.missing("netbios.options"),
            Some("") => not_applicable("No network adapter with IP enabled."),
            Some(v) => {
                let on = v.split(',').filter(|o| o.trim() != "2").count();
                if on == 0 {
                    passed("Disabled on every adapter.")
                } else {
                    failed(format!(
                        "Not disabled on {on} adapter(s) (TcpipNetbiosOptions: {v}; 2 means off)."
                    ))
                }
            }
        },
    },
    Check {
        id: "AA-WIN-RDP-001",
        platform: Platform::Windows,
        category: "Network",
        title: "Remote Desktop requires Network Level Authentication",
        rationale: "NLA authenticates before a session is created, so the logon screen (and \
                    its pre-authentication bugs, such as BlueKeep) isn't exposed.",
        remediation: "Enable Require user authentication for remote connections by using \
                      Network Level Authentication.",
        command: Some(
            "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
        ),
        fix: None,
        mitre: &["T1021.001"],
        rule: |f| {
            let deny = match (reg(f, "rdp.deny.policy"), reg(f, "rdp.deny")) {
                (Err(o), _) | (_, Err(o)) => return o,
                (Ok(Some(p)), _) => Some(p),
                (Ok(None), Ok(local)) => local,
            };
            if deny == Some("1") {
                return not_applicable("Remote Desktop is off.");
            }
            let nla = match (reg(f, "rdp.nla.policy"), reg(f, "rdp.nla")) {
                (Err(o), _) | (_, Err(o)) => return o,
                (Ok(Some(p)), _) => Some(p),
                (Ok(None), Ok(local)) => local,
            };
            match nla {
                None => passed("UserAuthentication: not set (Windows requires NLA by default)"),
                Some("1") => passed("UserAuthentication = 1"),
                Some(v) => failed(format!("UserAuthentication = {v}")),
            }
        },
    },
    // ---------------------------------------------------------- Updates --
    Check {
        id: "AA-WIN-UPD-001",
        platform: Platform::Windows,
        category: "Updates",
        title: "The Windows Update service isn't disabled",
        rationale: "With the service disabled, the machine gets no security updates at all.",
        remediation: "Set the Windows Update service (wuauserv) back to Manual.",
        command: Some("Set-Service -Name wuauserv -StartupType Manual"),
        fix: None,
        mitre: &[],
        rule: |f| match f.get("wu.start_type") {
            None => f.missing("wu.start_type"),
            Some(v) if v.eq_ignore_ascii_case("Disabled") => failed("wuauserv is Disabled."),
            Some(v) => passed(format!("wuauserv start type: {v}")),
        },
    },
    Check {
        id: "AA-WIN-UPD-002",
        platform: Platform::Windows,
        category: "Updates",
        title: "An update was installed in the last 45 days",
        rationale: "Microsoft ships security fixes monthly. A machine past 45 days has missed \
                    at least one round.",
        remediation: "Install pending updates, and check the machine's update source (Windows \
                      Update, WSUS or Intune) is reachable.",
        command: Some("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5"),
        fix: None,
        mitre: &[],
        rule: |f| match f.int("wu.last_hotfix_days") {
            None => f.missing("wu.last_hotfix_days"),
            Some(n) => {
                let id = f.get("wu.last_hotfix").unwrap_or("the latest update");
                if n <= 45 {
                    passed(format!("{id} installed {n} day(s) ago."))
                } else {
                    failed(format!("{id} installed {n} days ago."))
                }
            }
        },
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use abyssal_agent_protocol::PostureFactsReport;

    use super::*;
    use crate::{Status, evaluate};

    /// Facts shaped like a stock Windows Server 2022 member server: a
    /// `secedit /export` and `auditpol /backup` of the defaults, and the
    /// registry as installed.
    fn server2022() -> BTreeMap<String, String> {
        let mut m: BTreeMap<String, String> = [
            ("secedit.MinimumPasswordLength", "0"),
            ("secedit.PasswordComplexity", "1"),
            ("secedit.MaximumPasswordAge", "42"),
            ("secedit.MinimumPasswordAge", "0"),
            ("secedit.PasswordHistorySize", "0"),
            ("secedit.LockoutBadCount", "0"),
            ("secedit.ClearTextPassword", "0"),
            ("secedit.EnableGuestAccount", "0"),
            ("secedit.LSAAnonymousNameLookup", "0"),
            ("secedit.SeDebugPrivilege", "*S-1-5-32-544"),
            ("smb.server.smb1", "False"),
            ("smb.server.signing_required", "False"),
            ("smb.client.signing_required", "0"),
            ("smb.client.smb1_start", "absent"),
            ("fw.Domain.enabled", "True"),
            ("fw.Private.enabled", "True"),
            ("fw.Public.enabled", "True"),
            ("fw.Domain.inbound", "NotConfigured"),
            ("fw.Private.inbound", "NotConfigured"),
            ("fw.Public.inbound", "NotConfigured"),
            ("defender.realtime", "True"),
            ("defender.signature_age_days", "1"),
            ("defender.tamper", "False"),
            ("defender.service", "True"),
            ("uac.EnableLUA", "1"),
            ("lsa.RunAsPPL", "absent"),
            ("lsa.LmCompatibilityLevel", "absent"),
            ("lsa.NoLMHash", "1"),
            ("lsa.RestrictAnonymous", "0"),
            ("wdigest.UseLogonCredential", "absent"),
            ("rdp.deny.policy", "absent"),
            ("rdp.deny", "1"),
            ("rdp.nla.policy", "absent"),
            ("rdp.nla", "1"),
            ("llmnr.EnableMulticast", "absent"),
            ("autorun.NoDriveTypeAutoRun", "absent"),
            ("ps.ScriptBlockLogging", "absent"),
            ("audit.cmdline", "absent"),
            ("netbios.options", "0"),
            ("wu.start_type", "Manual"),
            ("wu.last_hotfix_days", "12"),
            ("wu.last_hotfix", "KB5044281"),
            ("eventlog.security.max_kb", "20480"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        // Windows Server's default audit policy.
        for (guid, value) in [
            (CREDENTIAL_VALIDATION, "1"),
            (LOGON, "3"),
            (SPECIAL_LOGON, "1"),
            (ACCOUNT_LOCKOUT, "1"),
            (USER_ACCOUNT_MANAGEMENT, "1"),
            (SECURITY_GROUP_MANAGEMENT, "1"),
            (PROCESS_CREATION, "0"),
            (AUDIT_POLICY_CHANGE, "1"),
        ] {
            m.insert(format!("audit.{guid}"), value.to_string());
        }
        m
    }

    fn results(
        facts: BTreeMap<String, String>,
        notes: BTreeMap<String, String>,
    ) -> Vec<(String, Status, String)> {
        let report = PostureFactsReport {
            platform: "windows".into(),
            facts,
            notes,
        };
        evaluate(&report)
            .unwrap()
            .into_iter()
            .map(|r| (r.check.id.to_string(), r.outcome.status, r.outcome.evidence))
            .collect()
    }

    fn status_of(facts: BTreeMap<String, String>, id: &str) -> (Status, String) {
        results(facts, BTreeMap::new())
            .into_iter()
            .find(|(i, _, _)| i == id)
            .map(|(_, s, e)| (s, e))
            .unwrap()
    }

    fn with(mut facts: BTreeMap<String, String>, k: &str, v: &str) -> BTreeMap<String, String> {
        facts.insert(k.into(), v.into());
        facts
    }

    #[test]
    fn a_stock_server_2022() {
        let all = results(server2022(), BTreeMap::new());
        let failed: Vec<&str> = all
            .iter()
            .filter(|(_, s, _)| *s == Status::Failed)
            .map(|(id, _, _)| id.as_str())
            .collect();
        assert_eq!(
            failed,
            [
                "AA-WIN-PWD-001",
                "AA-WIN-PWD-004",
                "AA-WIN-PWD-005",
                "AA-WIN-LCK-001",
                "AA-WIN-AUD-001",
                "AA-WIN-AUD-004",
                "AA-WIN-AUD-005",
                "AA-WIN-AUD-007",
                "AA-WIN-AUD-009",
                "AA-WIN-AUD-010",
                "AA-WIN-AUD-011",
                "AA-WIN-SMB-003",
                "AA-WIN-SMB-004",
                "AA-WIN-DEF-003",
                "AA-WIN-SYS-002",
                "AA-WIN-CRD-001",
                "AA-WIN-CRD-003",
                "AA-WIN-NET-001",
                "AA-WIN-NET-002",
                "AA-WIN-NET-003",
            ]
        );
        let na: Vec<&str> = all
            .iter()
            .filter(|(_, s, _)| *s == Status::NotApplicable)
            .map(|(id, _, _)| id.as_str())
            .collect();
        // Lockout off, RDP off, and no BitLocker facts at all.
        assert_eq!(
            na,
            [
                "AA-WIN-LCK-002",
                "AA-WIN-LCK-003",
                "AA-WIN-ENC-001",
                "AA-WIN-RDP-001"
            ]
        );
    }

    #[test]
    fn audit_rules_read_the_bits() {
        let (s, e) = status_of(server2022(), "AA-WIN-AUD-001");
        assert_eq!(s, Status::Failed);
        assert_eq!(
            e,
            "Credential Validation: Success (want Success and Failure)"
        );
        let fixed = with(server2022(), &format!("audit.{CREDENTIAL_VALIDATION}"), "3");
        assert_eq!(status_of(fixed, "AA-WIN-AUD-001").0, Status::Passed);
        let lockout = with(server2022(), &format!("audit.{ACCOUNT_LOCKOUT}"), "2");
        assert_eq!(status_of(lockout, "AA-WIN-AUD-004").0, Status::Passed);
    }

    #[test]
    fn registry_defaults() {
        // Not set but safe by default.
        assert_eq!(status_of(server2022(), "AA-WIN-CRD-002").0, Status::Passed);
        // Not set and unsafe by default.
        let (s, e) = status_of(server2022(), "AA-WIN-NET-002");
        assert_eq!(s, Status::Failed);
        assert!(e.contains("not set"));
        assert_eq!(
            status_of(
                with(server2022(), "llmnr.EnableMulticast", "0"),
                "AA-WIN-NET-002"
            )
            .0,
            Status::Passed
        );
        assert_eq!(
            status_of(
                with(server2022(), "wdigest.UseLogonCredential", "1"),
                "AA-WIN-CRD-002"
            )
            .0,
            Status::Failed
        );
    }

    #[test]
    fn rdp_and_lockout_applicability() {
        let rdp_on = with(server2022(), "rdp.deny", "0");
        assert_eq!(
            status_of(rdp_on.clone(), "AA-WIN-RDP-001").0,
            Status::Passed
        );
        assert_eq!(
            status_of(with(rdp_on.clone(), "rdp.nla", "0"), "AA-WIN-RDP-001").0,
            Status::Failed
        );
        // A policy value wins over the local one.
        let policy = with(with(rdp_on, "rdp.nla", "1"), "rdp.nla.policy", "0");
        assert_eq!(status_of(policy, "AA-WIN-RDP-001").0, Status::Failed);
        let lockout = with(
            with(server2022(), "secedit.LockoutBadCount", "5"),
            "secedit.LockoutDuration",
            "10",
        );
        assert_eq!(
            status_of(lockout.clone(), "AA-WIN-LCK-002").0,
            Status::Failed
        );
        assert_eq!(
            status_of(
                with(lockout, "secedit.LockoutDuration", "-1"),
                "AA-WIN-LCK-002"
            )
            .0,
            Status::Passed
        );
    }

    #[test]
    fn defender_and_updates() {
        let mut no_defender = server2022();
        no_defender.retain(|k, _| !k.starts_with("defender."));
        let notes = BTreeMap::from([(
            "defender".to_string(),
            "Microsoft Defender status unavailable (another antivirus)".to_string(),
        )]);
        let all = results(no_defender, notes);
        let (_, s, e) = all
            .iter()
            .find(|(id, _, _)| id == "AA-WIN-DEF-001")
            .unwrap();
        assert_eq!(*s, Status::NotApplicable);
        assert!(e.contains("another antivirus"), "{e}");
        assert_eq!(
            status_of(
                with(server2022(), "defender.signature_age_days", "65535"),
                "AA-WIN-DEF-002"
            )
            .1,
            "Signatures have never been updated."
        );
        assert_eq!(
            status_of(
                with(server2022(), "wu.last_hotfix_days", "90"),
                "AA-WIN-UPD-002"
            )
            .0,
            Status::Failed
        );
        assert_eq!(
            status_of(
                with(server2022(), "wu.start_type", "Disabled"),
                "AA-WIN-UPD-001"
            )
            .0,
            Status::Failed
        );
    }

    #[test]
    fn debug_privilege_and_firewall() {
        let wide = with(
            server2022(),
            "secedit.SeDebugPrivilege",
            "*S-1-5-32-544,*S-1-5-21-1-2-3-1001",
        );
        let (s, e) = status_of(wide, "AA-WIN-ACC-003");
        assert_eq!(s, Status::Failed);
        assert!(e.contains("1001"));
        let mut nobody = server2022();
        nobody.remove("secedit.SeDebugPrivilege");
        assert_eq!(status_of(nobody, "AA-WIN-ACC-003").0, Status::Passed);
        let open = with(server2022(), "fw.Public.inbound", "Allow");
        let (s, e) = status_of(open, "AA-WIN-FW-004");
        assert_eq!(s, Status::Failed);
        assert!(e.contains("Public: Allow"));
        assert_eq!(
            status_of(
                with(server2022(), "fw.Public.enabled", "False"),
                "AA-WIN-FW-003"
            )
            .0,
            Status::Failed
        );
    }
}
