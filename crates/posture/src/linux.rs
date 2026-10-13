//! The Linux checks. Facts come from `crates/agent/src/posture.rs`.

use crate::{
    Check, Facts, Fix, Outcome, Platform, failed, int_where, list_empty, list_excludes,
    not_applicable, one_of, passed,
};

/// SSH checks don't apply without an SSH server.
fn ssh(f: &Facts, rule: impl FnOnce(&Facts) -> Outcome) -> Outcome {
    match f.get("sshd.present") {
        None => f.missing("sshd.present"),
        Some("yes") => rule(f),
        Some(_) => not_applicable("No SSH server installed."),
    }
}

/// A kernel parameter that must equal `want`.
fn sysctl_is(f: &Facts, key: &str, want: &[&str]) -> Outcome {
    let fact = format!("sysctl.{key}");
    one_of(f, &fact, key, want)
}

/// A per-interface kernel parameter, by its `all` and `default` values (the
/// kernel combines `all` with each interface's own value, and new
/// interfaces start from `default`). `None` when `all` wasn't reported.
fn sysctl_pair(f: &Facts, name: &str) -> Option<(i64, Option<i64>, String)> {
    let all_key = name.replace("{}", "all");
    let default_key = name.replace("{}", "default");
    let all = f.int(&format!("sysctl.{all_key}"))?;
    let default = f.int(&format!("sysctl.{default_key}"));
    let evidence = match default {
        Some(d) => format!("{all_key} = {all}, {default_key} = {d}"),
        None => format!("{all_key} = {all}"),
    };
    Some((all, default, evidence))
}

/// A kernel parameter that must be at least `min`.
fn sysctl_at_least(f: &Facts, key: &str, min: i64, want: &str) -> Outcome {
    let fact = format!("sysctl.{key}");
    match (f.get(&fact), f.int(&fact)) {
        (None, _) => f.missing(&fact),
        (Some(_), Some(n)) if n >= min => passed(format!("{key} = {n}")),
        (Some(v), _) => failed(format!("{key} = {v} (want {want})")),
    }
}

/// An octal mode with no bits beyond `allowed`, owned by root.
fn file_mode(f: &Facts, name: &str, path: &str, allowed: u32) -> Outcome {
    let mode_key = format!("perm.{name}.mode");
    let Some(mode) = f.get(&mode_key) else {
        return f.missing(&mode_key);
    };
    let Ok(bits) = u32::from_str_radix(mode, 8) else {
        return failed(format!("{path}: unreadable mode {mode}"));
    };
    let owner = f.get(&format!("perm.{name}.uid")).unwrap_or("?");
    let evidence = format!("{path}: mode {mode:0>4}, owner uid {owner}");
    if bits & !allowed == 0 && owner == "0" {
        passed(evidence)
    } else {
        failed(evidence)
    }
}

/// Options a mount must have.
fn mount_has(f: &Facts, name: &str, path: &str, need: &[&str]) -> Outcome {
    let separate = format!("mount.{name}.separate");
    match f.get(&separate) {
        None => return f.missing(&separate),
        Some("yes") => {}
        Some(_) => return not_applicable(format!("{path} isn't a separate mount.")),
    }
    let options = f.get(&format!("mount.{name}.options")).unwrap_or("");
    let have: Vec<&str> = options.split(',').collect();
    let lacking: Vec<&str> = need.iter().copied().filter(|o| !have.contains(o)).collect();
    if lacking.is_empty() {
        passed(format!("{path} mounted with {options}"))
    } else {
        failed(format!(
            "{path} mounted with {options}; missing {}",
            lacking.join(", ")
        ))
    }
}

/// Checks that need systemd to have been checked at all.
fn with_systemd(f: &Facts, rule: impl FnOnce(&Facts) -> Outcome) -> Outcome {
    match f.get("init.systemd") {
        None => f.missing("init.systemd"),
        Some("yes") => rule(f),
        Some(_) => not_applicable("Checked through systemd, which this host doesn't use."),
    }
}

pub(crate) const CHECKS: &[Check] = &[
    // ------------------------------------------------------------- SSH --
    Check {
        id: "AA-LNX-SSH-001",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH doesn't allow root to log in with a password",
        rationale: "Root is the one account every attacker knows exists. Logging in as root \
                    directly also leaves no record of which administrator it was.",
        remediation: "Set PermitRootLogin to no (or prohibit-password if root must log in with \
                      a key), then check the config and reload sshd. Make sure another \
                      administrator account can log in and use sudo first.",
        command: Some(
            "echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/50-hardening.conf\nsudo sshd -t && (sudo systemctl reload sshd || sudo systemctl reload ssh)",
        ),
        fix: Some(Fix::SshHardening("disable_root_login")),
        mitre: &["T1110", "T1021.004"],
        rule: |f| {
            ssh(f, |f| {
                one_of(
                    f,
                    "sshd.permitrootlogin",
                    "PermitRootLogin",
                    &[
                        "no",
                        "prohibit-password",
                        "without-password",
                        "forced-commands-only",
                    ],
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-002",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH password authentication is off",
        rationale: "With passwords allowed, anyone on the network can guess at them. Keys \
                    can't be brute-forced.",
        remediation: "Make sure every account that needs SSH has a key installed, then set \
                      PasswordAuthentication to no and reload sshd.",
        command: Some(
            "echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf\nsudo sshd -t && (sudo systemctl reload sshd || sudo systemctl reload ssh)",
        ),
        fix: Some(Fix::SshHardening("disable_password_auth")),
        mitre: &["T1110", "T1021.004"],
        rule: |f| {
            ssh(f, |f| {
                one_of(
                    f,
                    "sshd.passwordauthentication",
                    "PasswordAuthentication",
                    &["no"],
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-003",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH refuses accounts with empty passwords",
        rationale: "An account with no password would be open to anyone who can reach the \
                    SSH port.",
        remediation: "Set PermitEmptyPasswords to no and reload sshd.",
        command: Some(
            "echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf\nsudo sshd -t && (sudo systemctl reload sshd || sudo systemctl reload ssh)",
        ),
        fix: Some(Fix::SshHardening("disable_empty_passwords")),
        mitre: &["T1078"],
        rule: |f| {
            ssh(f, |f| {
                one_of(
                    f,
                    "sshd.permitemptypasswords",
                    "PermitEmptyPasswords",
                    &["no"],
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-004",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH allows at most 4 authentication attempts per connection",
        rationale: "Fewer tries per connection slows password guessing and makes it show up \
                    sooner in the logs.",
        remediation: "Set MaxAuthTries to 4 or less and reload sshd.",
        command: Some(
            "echo 'MaxAuthTries 4' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &["T1110"],
        rule: |f| {
            ssh(f, |f| {
                int_where(
                    f,
                    "sshd.maxauthtries",
                    "MaxAuthTries",
                    |n| (1..=4).contains(&n),
                    "4 or less",
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-005",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH X11 forwarding is off",
        rationale: "X11 forwarding lets a compromised server reach back into the \
                    administrator's own desktop session.",
        remediation: "Set X11Forwarding to no and reload sshd.",
        command: Some(
            "echo 'X11Forwarding no' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: Some(Fix::SshHardening("disable_x11_forwarding")),
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                one_of(f, "sshd.x11forwarding", "X11Forwarding", &["no"])
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-006",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH host-based authentication is off",
        rationale: "Host-based authentication trusts another machine's word about who a user \
                    is, so one compromised host opens this one.",
        remediation: "Set HostbasedAuthentication to no and reload sshd.",
        command: Some(
            "echo 'HostbasedAuthentication no' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &["T1021.004"],
        rule: |f| {
            ssh(f, |f| {
                one_of(
                    f,
                    "sshd.hostbasedauthentication",
                    "HostbasedAuthentication",
                    &["no"],
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-007",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH ignores .rhosts files",
        rationale: ".rhosts and .shosts files grant password-less access the way the old r* \
                    commands did.",
        remediation: "Set IgnoreRhosts to yes and reload sshd.",
        command: Some(
            "echo 'IgnoreRhosts yes' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &["T1021.004"],
        rule: |f| {
            ssh(f, |f| {
                one_of(f, "sshd.ignorerhosts", "IgnoreRhosts", &["yes"])
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-008",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH login grace time is 60 seconds or less",
        rationale: "Unauthenticated connections held open for long tie up sshd and make \
                    connection-exhaustion attacks easier.",
        remediation: "Set LoginGraceTime to 60 and reload sshd.",
        command: Some(
            "echo 'LoginGraceTime 60' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                int_where(
                    f,
                    "sshd.logingracetime",
                    "LoginGraceTime",
                    |n| (1..=60).contains(&n),
                    "1 to 60",
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-009",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH closes idle sessions",
        rationale: "An unattended logged-in session is open to anyone at the keyboard, and \
                    dead connections otherwise linger.",
        remediation: "Set ClientAliveInterval (seconds, up to 900) and ClientAliveCountMax \
                      (at least 1) and reload sshd.",
        command: Some(
            "printf 'ClientAliveInterval 300\\nClientAliveCountMax 3\\n' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                let (Some(interval), Some(count)) = (
                    f.int("sshd.clientaliveinterval"),
                    f.int("sshd.clientalivecountmax"),
                ) else {
                    return f.missing("sshd.clientaliveinterval");
                };
                let evidence =
                    format!("ClientAliveInterval = {interval}, ClientAliveCountMax = {count}");
                if (1..=900).contains(&interval) && count >= 1 {
                    passed(evidence)
                } else {
                    failed(evidence)
                }
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-010",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH doesn't let users set environment variables",
        rationale: "PermitUserEnvironment lets a user's ~/.ssh/environment change things like \
                    LD_PRELOAD for the processes sshd starts.",
        remediation: "Set PermitUserEnvironment to no and reload sshd.",
        command: Some(
            "echo 'PermitUserEnvironment no' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                one_of(
                    f,
                    "sshd.permituserenvironment",
                    "PermitUserEnvironment",
                    &["no"],
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-011",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH logs at INFO or VERBOSE",
        rationale: "Lower log levels drop the login records an investigation needs.",
        remediation: "Set LogLevel to INFO (or VERBOSE to record key fingerprints) and reload \
                      sshd.",
        command: Some(
            "echo 'LogLevel VERBOSE' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &["T1562"],
        rule: |f| {
            ssh(f, |f| {
                one_of(f, "sshd.loglevel", "LogLevel", &["INFO", "VERBOSE"])
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-012",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH allows at most 10 sessions per connection",
        rationale: "Limits how much one connection can multiplex, which caps the damage from \
                    one hijacked connection.",
        remediation: "Set MaxSessions to 10 or less and reload sshd.",
        command: Some(
            "echo 'MaxSessions 10' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                int_where(
                    f,
                    "sshd.maxsessions",
                    "MaxSessions",
                    |n| (1..=10).contains(&n),
                    "10 or less",
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-013",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH offers no weak ciphers",
        rationale: "CBC-mode, RC4 (arcfour), 3DES and Blowfish ciphers have known weaknesses \
                    that let traffic be decrypted or tampered with.",
        remediation: "List only modern ciphers in Ciphers and reload sshd.",
        command: Some(
            "echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                list_excludes(
                    f,
                    "sshd.ciphers",
                    "ciphers",
                    &[
                        "3des-cbc",
                        "aes128-cbc",
                        "aes192-cbc",
                        "aes256-cbc",
                        "arcfour",
                        "arcfour128",
                        "arcfour256",
                        "blowfish-cbc",
                        "cast128-cbc",
                        "rijndael-cbc@lysator.liu.se",
                    ],
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-014",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH offers no weak MACs",
        rationale: "MD5-based and 96-bit or 64-bit truncated MACs are too weak to protect \
                    the session's integrity.",
        remediation: "List only SHA-2 MACs in MACs and reload sshd.",
        command: Some(
            "echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                list_excludes(
                    f,
                    "sshd.macs",
                    "MACs",
                    &[
                        "hmac-md5",
                        "hmac-md5-96",
                        "hmac-md5-etm@openssh.com",
                        "hmac-md5-96-etm@openssh.com",
                        "hmac-sha1-96",
                        "hmac-sha1-96-etm@openssh.com",
                        "umac-64@openssh.com",
                        "umac-64-etm@openssh.com",
                        "hmac-ripemd160",
                    ],
                )
            })
        },
    },
    Check {
        id: "AA-LNX-SSH-015",
        platform: Platform::Linux,
        category: "SSH",
        title: "SSH offers no weak key exchange",
        rationale: "SHA-1 Diffie-Hellman key exchange (group1, group14-sha1, group-exchange-\
                    sha1) is considered broken for new connections.",
        remediation: "List only modern algorithms in KexAlgorithms and reload sshd.",
        command: Some(
            "echo 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256' | sudo tee -a /etc/ssh/sshd_config.d/50-hardening.conf",
        ),
        fix: None,
        mitre: &[],
        rule: |f| {
            ssh(f, |f| {
                list_excludes(
                    f,
                    "sshd.kexalgorithms",
                    "key exchange algorithms",
                    &[
                        "diffie-hellman-group1-sha1",
                        "diffie-hellman-group14-sha1",
                        "diffie-hellman-group-exchange-sha1",
                    ],
                )
            })
        },
    },
    // ---------------------------------------------------------- Kernel --
    Check {
        id: "AA-LNX-KRN-001",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Address space layout randomization is full",
        rationale: "Randomizing where code and data load makes memory-corruption exploits \
                    much harder to write reliably.",
        remediation: "Set kernel.randomize_va_space to 2.",
        command: Some(
            "echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        rule: |f| sysctl_is(f, "kernel.randomize_va_space", &["2"]),
    },
    Check {
        id: "AA-LNX-KRN-002",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Reverse-path filtering is on",
        rationale: "Drops packets whose source address couldn't have arrived on the interface \
                    they came in on, a common spoofing technique.",
        remediation: "Set net.ipv4.conf.all.rp_filter (or .default, which new interfaces \
                      start from) to 1 (strict) or 2 (loose, for hosts with asymmetric \
                      routing).",
        command: Some(
            "echo 'net.ipv4.conf.all.rp_filter = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        // The kernel uses the higher of `all` and the interface's own value,
        // so either being on protects (new interfaces start from `default`).
        rule: |f| match sysctl_pair(f, "net.ipv4.conf.{}.rp_filter") {
            None => f.missing("sysctl.net.ipv4.conf.all.rp_filter"),
            Some((all, default, evidence)) => {
                if (1..=2).contains(&all) || default.is_some_and(|d| (1..=2).contains(&d)) {
                    passed(evidence)
                } else {
                    failed(evidence)
                }
            }
        },
    },
    Check {
        id: "AA-LNX-KRN-003",
        platform: Platform::Linux,
        category: "Kernel",
        title: "ICMP redirects are ignored",
        rationale: "An attacker on the local network can send ICMP redirects to route this \
                    host's traffic through their machine.",
        remediation: "Set net.ipv4.conf.all.accept_redirects and \
                      net.ipv4.conf.default.accept_redirects to 0.",
        command: Some(
            "printf 'net.ipv4.conf.all.accept_redirects = 0\\nnet.ipv4.conf.default.accept_redirects = 0\\n' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &["T1557"],
        // A host that doesn't forward accepts redirects if `all` OR the
        // interface allows them; a forwarding one only if both do.
        rule: |f| match sysctl_pair(f, "net.ipv4.conf.{}.accept_redirects") {
            None => f.missing("sysctl.net.ipv4.conf.all.accept_redirects"),
            Some((all, default, evidence)) => {
                let forwarding = f.get("sysctl.net.ipv4.ip_forward") == Some("1");
                let off = if forwarding {
                    all == 0 || default == Some(0)
                } else {
                    all == 0 && default.is_none_or(|d| d == 0)
                };
                if off {
                    passed(evidence)
                } else {
                    failed(evidence)
                }
            }
        },
    },
    Check {
        id: "AA-LNX-KRN-004",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Secure ICMP redirects are ignored",
        rationale: "\"Secure\" redirects only come from listed gateways, but a compromised \
                    gateway can still use them to reroute traffic.",
        remediation: "Set net.ipv4.conf.all.secure_redirects to 0.",
        command: Some(
            "echo 'net.ipv4.conf.all.secure_redirects = 0' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: None,
        mitre: &["T1557"],
        rule: |f| sysctl_is(f, "net.ipv4.conf.all.secure_redirects", &["0"]),
    },
    Check {
        id: "AA-LNX-KRN-005",
        platform: Platform::Linux,
        category: "Kernel",
        title: "This host doesn't send ICMP redirects",
        rationale: "Only routers should tell other hosts to change routes. A host that does \
                    can be used to misdirect its neighbours.",
        remediation: "Set net.ipv4.conf.all.send_redirects to 0. (Not checked on hosts that \
                      forward packets, such as routers and container hosts.)",
        command: Some(
            "echo 'net.ipv4.conf.all.send_redirects = 0' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        rule: |f| {
            if f.get("sysctl.net.ipv4.ip_forward") == Some("1") {
                return not_applicable(
                    "This host forwards packets (net.ipv4.ip_forward = 1): a router or \
                     container host.",
                );
            }
            sysctl_is(f, "net.ipv4.conf.all.send_redirects", &["0"])
        },
    },
    Check {
        id: "AA-LNX-KRN-006",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Source-routed packets are refused",
        rationale: "Source routing lets the sender choose the path, which can get packets \
                    past filtering.",
        remediation: "Set net.ipv4.conf.all.accept_source_route to 0.",
        command: Some(
            "echo 'net.ipv4.conf.all.accept_source_route = 0' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        rule: |f| sysctl_is(f, "net.ipv4.conf.all.accept_source_route", &["0"]),
    },
    Check {
        id: "AA-LNX-KRN-007",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Martian packets are logged",
        rationale: "Packets with impossible source addresses are a sign of spoofing or \
                    misconfiguration, worth having in the log.",
        remediation: "Set net.ipv4.conf.all.log_martians to 1.",
        command: Some(
            "echo 'net.ipv4.conf.all.log_martians = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        // Logged if `all` OR the interface says so.
        rule: |f| match sysctl_pair(f, "net.ipv4.conf.{}.log_martians") {
            None => f.missing("sysctl.net.ipv4.conf.all.log_martians"),
            Some((all, default, evidence)) => {
                if all == 1 || default == Some(1) {
                    passed(evidence)
                } else {
                    failed(evidence)
                }
            }
        },
    },
    Check {
        id: "AA-LNX-KRN-008",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Broadcast pings are ignored",
        rationale: "Answering broadcast ICMP makes this host an amplifier in smurf-style \
                    floods.",
        remediation: "Set net.ipv4.icmp_echo_ignore_broadcasts to 1.",
        command: Some(
            "echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        rule: |f| sysctl_is(f, "net.ipv4.icmp_echo_ignore_broadcasts", &["1"]),
    },
    Check {
        id: "AA-LNX-KRN-009",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Bogus ICMP error responses are ignored",
        rationale: "Keeps malformed ICMP error replies from filling the log.",
        remediation: "Set net.ipv4.icmp_ignore_bogus_error_responses to 1.",
        command: Some(
            "echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: None,
        mitre: &[],
        rule: |f| sysctl_is(f, "net.ipv4.icmp_ignore_bogus_error_responses", &["1"]),
    },
    Check {
        id: "AA-LNX-KRN-010",
        platform: Platform::Linux,
        category: "Kernel",
        title: "TCP SYN cookies are on",
        rationale: "SYN cookies keep the host answering legitimate connections during a SYN \
                    flood.",
        remediation: "Set net.ipv4.tcp_syncookies to 1.",
        command: Some(
            "echo 'net.ipv4.tcp_syncookies = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &["T1499"],
        rule: |f| sysctl_is(f, "net.ipv4.tcp_syncookies", &["1"]),
    },
    Check {
        id: "AA-LNX-KRN-011",
        platform: Platform::Linux,
        category: "Kernel",
        title: "IPv6 redirects are ignored",
        rationale: "The IPv6 equivalent of ICMP redirects, with the same rerouting risk.",
        remediation: "Set net.ipv6.conf.all.accept_redirects and \
                      net.ipv6.conf.default.accept_redirects to 0.",
        command: Some(
            "printf 'net.ipv6.conf.all.accept_redirects = 0\\nnet.ipv6.conf.default.accept_redirects = 0\\n' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &["T1557"],
        rule: |f| {
            if f.get("sysctl.net.ipv6.conf.all.accept_redirects").is_none()
                && f.get("sysctl.kernel.randomize_va_space").is_some()
            {
                return not_applicable("IPv6 is disabled on this host.");
            }
            // IPv6 keeps the setting per interface (writing `all` sets
            // them all), so both `all` and `default` must be off.
            match sysctl_pair(f, "net.ipv6.conf.{}.accept_redirects") {
                None => f.missing("sysctl.net.ipv6.conf.all.accept_redirects"),
                Some((all, default, evidence)) => {
                    if all == 0 && default.is_none_or(|d| d == 0) {
                        passed(evidence)
                    } else {
                        failed(evidence)
                    }
                }
            }
        },
    },
    Check {
        id: "AA-LNX-KRN-012",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Only root can read the kernel log",
        rationale: "The kernel log can reveal memory addresses that help an exploit get past \
                    address randomization.",
        remediation: "Set kernel.dmesg_restrict to 1.",
        command: Some(
            "echo 'kernel.dmesg_restrict = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        rule: |f| sysctl_is(f, "kernel.dmesg_restrict", &["1"]),
    },
    Check {
        id: "AA-LNX-KRN-013",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Kernel pointers are hidden",
        rationale: "Kernel addresses in /proc help an attacker defeat kernel address \
                    randomization.",
        remediation: "Set kernel.kptr_restrict to 1 or 2.",
        command: Some(
            "echo 'kernel.kptr_restrict = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: Some(Fix::SysctlBaseline),
        mitre: &[],
        rule: |f| sysctl_at_least(f, "kernel.kptr_restrict", 1, "1 or more"),
    },
    Check {
        id: "AA-LNX-KRN-014",
        platform: Platform::Linux,
        category: "Kernel",
        title: "ptrace is limited to parent processes",
        rationale: "Unrestricted ptrace lets any process read the memory of others run by \
                    the same user, including credentials in a shell or browser.",
        remediation: "Set kernel.yama.ptrace_scope to 1 (or higher).",
        command: Some(
            "echo 'kernel.yama.ptrace_scope = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: None,
        mitre: &["T1055.008"],
        rule: |f| {
            if f.get("sysctl.kernel.yama.ptrace_scope").is_none()
                && f.get("sysctl.kernel.randomize_va_space").is_some()
            {
                return not_applicable("The Yama security module isn't loaded on this kernel.");
            }
            sysctl_at_least(f, "kernel.yama.ptrace_scope", 1, "1 or more")
        },
    },
    Check {
        id: "AA-LNX-KRN-015",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Hard links are protected",
        rationale: "Stops users creating hard links to files they don't own, a classic way to \
                    trick a privileged program.",
        remediation: "Set fs.protected_hardlinks to 1.",
        command: Some(
            "echo 'fs.protected_hardlinks = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: None,
        mitre: &[],
        rule: |f| sysctl_is(f, "fs.protected_hardlinks", &["1"]),
    },
    Check {
        id: "AA-LNX-KRN-016",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Symbolic links are protected",
        rationale: "Stops symlink races in world-writable sticky directories like /tmp.",
        remediation: "Set fs.protected_symlinks to 1.",
        command: Some(
            "echo 'fs.protected_symlinks = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: None,
        mitre: &[],
        rule: |f| sysctl_is(f, "fs.protected_symlinks", &["1"]),
    },
    Check {
        id: "AA-LNX-KRN-017",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Setuid programs don't dump core",
        rationale: "A core dump from a setuid program can contain secrets it read as root, \
                    such as password hashes.",
        remediation: "Set fs.suid_dumpable to 0.",
        command: Some(
            "echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: None,
        mitre: &[],
        rule: |f| sysctl_is(f, "fs.suid_dumpable", &["0"]),
    },
    Check {
        id: "AA-LNX-KRN-018",
        platform: Platform::Linux,
        category: "Kernel",
        title: "Unprivileged users can't load BPF programs",
        rationale: "Unprivileged BPF has been the way in for several kernel privilege-\
                    escalation exploits.",
        remediation: "Set kernel.unprivileged_bpf_disabled to 1.",
        command: Some(
            "echo 'kernel.unprivileged_bpf_disabled = 1' | sudo tee -a /etc/sysctl.d/60-hardening.conf && sudo sysctl --system",
        ),
        fix: None,
        mitre: &["T1068"],
        rule: |f| {
            if f.get("sysctl.kernel.unprivileged_bpf_disabled").is_none()
                && f.get("sysctl.kernel.randomize_va_space").is_some()
            {
                return not_applicable("This kernel has no unprivileged BPF setting.");
            }
            sysctl_at_least(f, "kernel.unprivileged_bpf_disabled", 1, "1 or 2")
        },
    },
    // -------------------------------------------------------- Firewall --
    Check {
        id: "AA-LNX-FW-001",
        platform: Platform::Linux,
        category: "Firewall",
        title: "A host firewall is active",
        rationale: "Without a firewall, every service listening on the host is reachable \
                    from the network, including ones started by mistake.",
        remediation: "Enable the host's firewall (ufw, firewalld or nftables). Allow SSH \
                      before enabling it, or you'll lock yourself out.",
        command: Some(
            "sudo ufw allow OpenSSH && sudo ufw enable\n# or: sudo systemctl enable --now firewalld",
        ),
        fix: Some(Fix::FirewallEnable),
        mitre: &["T1562.004"],
        rule: |f| match (f.get("firewall.tool"), f.get("firewall.active")) {
            (None, _) | (_, None) => f.missing("firewall.active"),
            (Some(tool), Some("yes")) => passed(format!("{tool} is active.")),
            (Some("none"), Some(_)) => {
                failed("No firewall (ufw, firewalld, nftables or iptables) is configured.")
            }
            (Some(tool), Some(_)) => failed(format!("{tool} is installed but not active.")),
        },
    },
    Check {
        id: "AA-LNX-FW-002",
        platform: Platform::Linux,
        category: "Firewall",
        title: "The firewall drops inbound traffic by default",
        rationale: "Default-deny means a new service is unreachable until it's deliberately \
                    allowed, rather than exposed until someone notices.",
        remediation: "Set the incoming default to deny (ufw default deny incoming) or the \
                      input chain's policy to drop, after allowing what must stay reachable.",
        command: Some("sudo ufw default deny incoming"),
        fix: None,
        mitre: &["T1562.004"],
        rule: |f| {
            if f.get("firewall.active") != Some("yes") {
                return match f.get("firewall.active") {
                    None => f.missing("firewall.active"),
                    Some(_) => not_applicable("The firewall isn't active (see AA-LNX-FW-001)."),
                };
            }
            let tool = f.get("firewall.tool").unwrap_or("firewall");
            one_of(
                f,
                "firewall.default_input",
                &format!("{tool} default inbound"),
                &["deny", "drop", "reject"],
            )
        },
    },
    // ------------------------------------------------------- Accounts --
    Check {
        id: "AA-LNX-AUTH-001",
        platform: Platform::Linux,
        category: "Accounts",
        title: "Passwords expire within 365 days",
        rationale: "A password that never expires stays useful to whoever learns it, for as \
                    long as the account exists.",
        remediation: "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs. Existing accounts \
                      keep their own setting: change them with chage --maxdays.",
        command: Some("sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs"),
        fix: None,
        mitre: &["T1110"],
        rule: |f| {
            int_where(
                f,
                "logindefs.PASS_MAX_DAYS",
                "PASS_MAX_DAYS",
                |n| (1..=365).contains(&n),
                "1 to 365",
            )
        },
    },
    Check {
        id: "AA-LNX-AUTH-002",
        platform: Platform::Linux,
        category: "Accounts",
        title: "Passwords can't be changed again the same day",
        rationale: "A minimum age stops users cycling straight back to their old password.",
        remediation: "Set PASS_MIN_DAYS to 1 or more in /etc/login.defs.",
        command: Some("sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs"),
        fix: None,
        mitre: &[],
        rule: |f| {
            int_where(
                f,
                "logindefs.PASS_MIN_DAYS",
                "PASS_MIN_DAYS",
                |n| n >= 1,
                "1 or more",
            )
        },
    },
    Check {
        id: "AA-LNX-AUTH-003",
        platform: Platform::Linux,
        category: "Accounts",
        title: "Users are warned 7 days before a password expires",
        rationale: "Without warning, expiring passwords lock people out and push them toward \
                    weak last-minute choices.",
        remediation: "Set PASS_WARN_AGE to 7 or more in /etc/login.defs.",
        command: Some("sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs"),
        fix: None,
        mitre: &[],
        rule: |f| {
            int_where(
                f,
                "logindefs.PASS_WARN_AGE",
                "PASS_WARN_AGE",
                |n| n >= 7,
                "7 or more",
            )
        },
    },
    Check {
        id: "AA-LNX-AUTH-004",
        platform: Platform::Linux,
        category: "Accounts",
        title: "Passwords are hashed with SHA-512 or yescrypt",
        rationale: "Older hashes (MD5, DES) crack quickly if /etc/shadow is ever copied.",
        remediation: "Set ENCRYPT_METHOD to YESCRYPT (or SHA512) in /etc/login.defs. Hashes \
                      change as users next set their passwords.",
        command: Some("sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs"),
        fix: None,
        mitre: &["T1110.002"],
        rule: |f| {
            one_of(
                f,
                "logindefs.ENCRYPT_METHOD",
                "ENCRYPT_METHOD",
                &["SHA512", "YESCRYPT"],
            )
        },
    },
    Check {
        id: "AA-LNX-AUTH-005",
        platform: Platform::Linux,
        category: "Accounts",
        title: "Passwords must be at least 14 characters",
        rationale: "Length is the single biggest factor in how long a password takes to guess.",
        remediation: "Enable pam_pwquality and set minlen = 14 in \
                      /etc/security/pwquality.conf.",
        command: Some(
            "echo 'minlen = 14' | sudo tee /etc/security/pwquality.conf.d/50-length.conf",
        ),
        fix: None,
        mitre: &["T1110"],
        rule: |f| match f.get("pam.pwquality") {
            None => f.missing("pam.pwquality"),
            Some("yes") => match f.int("pwquality.minlen") {
                Some(n) if n >= 14 => passed(format!("pam_pwquality minlen = {n}")),
                Some(n) => failed(format!("pam_pwquality minlen = {n} (want 14 or more)")),
                None => failed("pam_pwquality is on but minlen isn't set (its default is 8)."),
            },
            Some(_) => failed("No password-quality module (pam_pwquality or pam_cracklib) in PAM."),
        },
    },
    Check {
        id: "AA-LNX-AUTH-006",
        platform: Platform::Linux,
        category: "Accounts",
        title: "Accounts lock after repeated failed logins",
        rationale: "Locking after a handful of failures stops online password guessing.",
        remediation: "Enable pam_faillock (authselect enable-feature with-faillock on \
                      RHEL-family hosts) with deny = 5 or less in \
                      /etc/security/faillock.conf.",
        command: Some(
            "sudo authselect enable-feature with-faillock\necho 'deny = 5' | sudo tee -a /etc/security/faillock.conf",
        ),
        fix: None,
        mitre: &["T1110.001"],
        rule: |f| match f.get("pam.lockout") {
            None => f.missing("pam.lockout"),
            Some("yes") => match f.int("pam.lockout_deny") {
                Some(n) if (1..=5).contains(&n) => passed(format!("Lockout after {n} failures.")),
                Some(n) => failed(format!("Lockout after {n} failures (want 5 or fewer).")),
                None => passed("pam_faillock is on with its default (3 failures)."),
            },
            Some(_) => failed("No account lockout module (pam_faillock or pam_tally2) in PAM."),
        },
    },
    Check {
        id: "AA-LNX-AUTH-007",
        platform: Platform::Linux,
        category: "Accounts",
        title: "Only root has UID 0",
        rationale: "Any other UID 0 account is a second root, often a backdoor.",
        remediation: "Find out why the account exists. Remove it or give it its own UID with \
                      usermod -u.",
        command: Some("awk -F: '$3 == 0' /etc/passwd"),
        fix: None,
        mitre: &["T1078.003", "T1136.001"],
        rule: |f| list_empty(f, "accounts.uid0_extra", "other UID 0 accounts"),
    },
    Check {
        id: "AA-LNX-AUTH-008",
        platform: Platform::Linux,
        category: "Accounts",
        title: "No account has an empty password",
        rationale: "An empty password means anyone can log in as that account wherever \
                    passwords are accepted.",
        remediation: "Lock the account (passwd -l) or set a password.",
        command: Some("sudo passwd -l <account>"),
        fix: None,
        mitre: &["T1078"],
        rule: |f| {
            list_empty(
                f,
                "accounts.empty_password",
                "accounts with empty passwords",
            )
        },
    },
    Check {
        id: "AA-LNX-AUTH-009",
        platform: Platform::Linux,
        category: "Accounts",
        title: "New files aren't readable by everyone",
        rationale: "With the common umask 022, every file a user creates is world-readable \
                    unless they think about it.",
        remediation: "Set UMASK to 027 (or 077) in /etc/login.defs.",
        command: Some("sudo sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs"),
        fix: None,
        mitre: &[],
        rule: |f| match f.get("logindefs.UMASK") {
            None => f.missing("logindefs.UMASK"),
            Some(v) => match u32::from_str_radix(v.trim(), 8) {
                Ok(bits) if bits & 0o027 == 0o027 => passed(format!("UMASK = {v}")),
                _ => failed(format!("UMASK = {v} (want 027 or stricter)")),
            },
        },
    },
    // ---------------------------------------------------------- Files --
    Check {
        id: "AA-LNX-FILE-001",
        platform: Platform::Linux,
        category: "Files",
        title: "/etc/passwd is 644 or stricter, owned by root",
        rationale: "A writable /etc/passwd lets anyone add an account or give themselves \
                    UID 0.",
        remediation: "Reset the owner and mode.",
        command: Some("sudo chown root:root /etc/passwd && sudo chmod 644 /etc/passwd"),
        fix: None,
        mitre: &["T1222.002"],
        rule: |f| file_mode(f, "passwd", "/etc/passwd", 0o644),
    },
    Check {
        id: "AA-LNX-FILE-002",
        platform: Platform::Linux,
        category: "Files",
        title: "/etc/shadow is 640 or stricter, owned by root",
        rationale: "/etc/shadow holds every password hash. Anyone who can read it can try to \
                    crack them offline.",
        remediation: "Reset the owner and mode (the group is shadow on Debian-family hosts).",
        command: Some("sudo chown root /etc/shadow && sudo chmod 640 /etc/shadow"),
        fix: None,
        mitre: &["T1003.008"],
        rule: |f| file_mode(f, "shadow", "/etc/shadow", 0o640),
    },
    Check {
        id: "AA-LNX-FILE-003",
        platform: Platform::Linux,
        category: "Files",
        title: "/etc/group is 644 or stricter, owned by root",
        rationale: "A writable /etc/group lets anyone add themselves to sudo or wheel.",
        remediation: "Reset the owner and mode.",
        command: Some("sudo chown root:root /etc/group && sudo chmod 644 /etc/group"),
        fix: None,
        mitre: &["T1222.002"],
        rule: |f| file_mode(f, "group", "/etc/group", 0o644),
    },
    Check {
        id: "AA-LNX-FILE-004",
        platform: Platform::Linux,
        category: "Files",
        title: "/etc/gshadow is 640 or stricter, owned by root",
        rationale: "/etc/gshadow holds group passwords and administrators.",
        remediation: "Reset the owner and mode.",
        command: Some("sudo chown root /etc/gshadow && sudo chmod 640 /etc/gshadow"),
        fix: None,
        mitre: &["T1222.002"],
        rule: |f| file_mode(f, "gshadow", "/etc/gshadow", 0o640),
    },
    Check {
        id: "AA-LNX-FILE-005",
        platform: Platform::Linux,
        category: "Files",
        title: "No world-writable files in system directories",
        rationale: "A world-writable file in /etc or a bin directory lets any user change what \
                    root runs or reads.",
        remediation: "Remove the write bit for others from each file listed (chmod o-w), \
                      after checking what put it there.",
        command: Some(
            "sudo find /etc /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -type f -perm -0002",
        ),
        fix: None,
        mitre: &["T1222.002"],
        rule: |f| match f.int("files.world_writable.count") {
            None => f.missing("files.world_writable.count"),
            Some(0) => passed("None found in /etc, /usr/bin, /usr/sbin or /usr/local."),
            Some(n) => failed(format!(
                "{n} found, including {}",
                f.get("files.world_writable.sample")
                    .unwrap_or("")
                    .replace(',', ", ")
            )),
        },
    },
    // ---------------------------------------------------- Protection --
    Check {
        id: "AA-LNX-MAC-001",
        platform: Platform::Linux,
        category: "Protection",
        title: "SELinux or AppArmor is enforcing",
        rationale: "Mandatory access control confines services, so a compromised one can't \
                    reach beyond what its policy allows.",
        remediation: "Put SELinux in enforcing mode (setenforce 1, and SELINUX=enforcing in \
                      /etc/selinux/config), or enable AppArmor with its profiles enforcing.",
        command: Some(
            "sudo setenforce 1   # SELinux\nsudo aa-enforce /etc/apparmor.d/*   # AppArmor",
        ),
        fix: None,
        mitre: &[],
        rule: |f| match (f.get("mac.system"), f.get("mac.enforcing")) {
            (None, _) | (_, None) => f.missing("mac.system"),
            (Some("none"), _) => failed("Neither SELinux nor AppArmor is installed."),
            (Some(system), Some("yes")) => passed(format!("{system} is enforcing.")),
            (Some(system), Some(_)) => failed(format!("{system} is present but not enforcing.")),
        },
    },
    Check {
        id: "AA-LNX-UPD-001",
        platform: Platform::Linux,
        category: "Protection",
        title: "Security updates install automatically",
        rationale: "Most compromises use vulnerabilities that already have a fix. Automatic \
                    updates close that window without anyone having to remember.",
        remediation: "Debian/Ubuntu: install and enable unattended-upgrades. RHEL/Fedora: \
                      install dnf-automatic and enable its timer.",
        command: Some(
            "sudo dpkg-reconfigure -plow unattended-upgrades   # Debian/Ubuntu\nsudo systemctl enable --now dnf-automatic-install.timer   # RHEL/Fedora",
        ),
        fix: None,
        mitre: &[],
        rule: |f| match f.get("updates.automatic") {
            None => f.missing("updates.automatic"),
            Some("enabled") => passed(format!(
                "Automatic updates are on ({}).",
                f.get("updates.package_manager")
                    .unwrap_or("package manager")
            )),
            Some("disabled") => failed(format!(
                "Automatic updates are off ({}).",
                f.get("updates.package_manager")
                    .unwrap_or("package manager")
            )),
            Some(_) => not_applicable(
                "This package manager has no standard automatic-update mechanism to check.",
            ),
        },
    },
    Check {
        id: "AA-LNX-MNT-001",
        platform: Platform::Linux,
        category: "Mounts",
        title: "/tmp is a separate mount",
        rationale: "A separate /tmp can be mounted nosuid and nodev, and filling it can't fill \
                    the root filesystem.",
        remediation: "Mount /tmp as tmpfs (systemctl enable tmp.mount) or give it its own \
                      partition in /etc/fstab.",
        command: Some("sudo systemctl enable --now tmp.mount"),
        fix: None,
        mitre: &[],
        rule: |f| match f.get("mount.tmp.separate") {
            None => f.missing("mount.tmp.separate"),
            Some("yes") => passed(format!(
                "/tmp is mounted separately ({}).",
                f.get("mount.tmp.options").unwrap_or("")
            )),
            Some(_) => failed("/tmp is part of the root filesystem."),
        },
    },
    Check {
        id: "AA-LNX-MNT-002",
        platform: Platform::Linux,
        category: "Mounts",
        title: "/tmp is mounted nosuid and nodev",
        rationale: "Anyone can write to /tmp, so it shouldn't honour setuid bits or device \
                    files.",
        remediation: "Add nosuid,nodev to /tmp's options in /etc/fstab (or tmp.mount) and \
                      remount.",
        command: Some("sudo mount -o remount,nosuid,nodev /tmp"),
        fix: None,
        mitre: &[],
        rule: |f| mount_has(f, "tmp", "/tmp", &["nosuid", "nodev"]),
    },
    Check {
        id: "AA-LNX-MNT-003",
        platform: Platform::Linux,
        category: "Mounts",
        title: "/dev/shm is mounted nosuid, nodev and noexec",
        rationale: "Shared memory is world-writable, a common place to drop and run attack \
                    tools from.",
        remediation: "Add nosuid,nodev,noexec to /dev/shm in /etc/fstab and remount.",
        command: Some("sudo mount -o remount,nosuid,nodev,noexec /dev/shm"),
        fix: None,
        mitre: &[],
        rule: |f| mount_has(f, "dev_shm", "/dev/shm", &["nosuid", "nodev", "noexec"]),
    },
    Check {
        id: "AA-LNX-SVC-001",
        platform: Platform::Linux,
        category: "Services",
        title: "No legacy cleartext services are enabled",
        rationale: "telnet, rsh, rlogin, rexec, TFTP, FTP, NIS and talk send credentials or \
                    data unencrypted.",
        remediation: "Disable each service listed and use SSH/SFTP instead.",
        command: Some("sudo systemctl disable --now <unit>"),
        fix: None,
        mitre: &["T1040"],
        rule: |f| {
            with_systemd(f, |f| {
                list_empty(f, "services.legacy_enabled", "legacy services enabled")
            })
        },
    },
    Check {
        id: "AA-LNX-AUD-001",
        platform: Platform::Linux,
        category: "Logging",
        title: "auditd is running",
        rationale: "The audit daemon records security events (logins, privilege use, file \
                    changes) that ordinary logs don't.",
        remediation: "Install auditd and enable it.",
        command: Some("sudo systemctl enable --now auditd"),
        fix: None,
        mitre: &["T1562.012"],
        rule: |f| {
            with_systemd(f, |f| {
                one_of(f, "auditd.active", "auditd running", &["yes"])
            })
        },
    },
    Check {
        id: "AA-LNX-AUD-002",
        platform: Platform::Linux,
        category: "Logging",
        title: "Audit rules are loaded",
        rationale: "auditd with no rules records almost nothing.",
        remediation: "Add rules under /etc/audit/rules.d/ (your distribution's sample rules, or \
                      a published baseline), then load them with augenrules --load.",
        command: Some("sudo augenrules --load && sudo auditctl -l"),
        fix: None,
        mitre: &["T1562.012"],
        rule: |f| {
            with_systemd(f, |f| {
                if f.get("auditd.active") != Some("yes") {
                    return match f.get("auditd.active") {
                        None => f.missing("auditd.active"),
                        Some(_) => not_applicable("auditd isn't running (see AA-LNX-AUD-001)."),
                    };
                }
                int_where(
                    f,
                    "auditd.rules",
                    "audit rules loaded",
                    |n| n > 0,
                    "at least one",
                )
            })
        },
    },
    Check {
        id: "AA-LNX-TIME-001",
        platform: Platform::Linux,
        category: "Logging",
        title: "The clock is kept in sync",
        rationale: "Accurate time is what lets logs from different hosts be lined up during an \
                    investigation, and Kerberos and TLS depend on it.",
        remediation: "Enable chrony or systemd-timesyncd.",
        command: Some("sudo systemctl enable --now chronyd   # or systemd-timesyncd"),
        fix: None,
        mitre: &[],
        rule: |f| {
            with_systemd(f, |f| match f.get("time.sync") {
                None => f.missing("time.sync"),
                Some("none") => failed("No time synchronization service is running."),
                Some(service) => passed(format!("{service} is running.")),
            })
        },
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use abyssal_agent_protocol::PostureFactsReport;

    use crate::{Status, evaluate};

    /// Facts as a stock Ubuntu 24.04 server reports them, with root.
    fn ubuntu() -> BTreeMap<String, String> {
        [
            ("sshd.present", "yes"),
            ("sshd.permitrootlogin", "without-password"),
            ("sshd.passwordauthentication", "yes"),
            ("sshd.permitemptypasswords", "no"),
            ("sshd.maxauthtries", "6"),
            ("sshd.x11forwarding", "yes"),
            ("sshd.hostbasedauthentication", "no"),
            ("sshd.ignorerhosts", "yes"),
            ("sshd.logingracetime", "120"),
            ("sshd.clientaliveinterval", "0"),
            ("sshd.clientalivecountmax", "3"),
            ("sshd.permituserenvironment", "no"),
            ("sshd.loglevel", "INFO"),
            ("sshd.maxsessions", "10"),
            ("sshd.ciphers", "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"),
            ("sshd.macs", "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"),
            ("sshd.kexalgorithms", "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256"),
            ("sysctl.kernel.randomize_va_space", "2"),
            ("sysctl.net.ipv4.conf.all.rp_filter", "2"),
            ("sysctl.net.ipv4.conf.all.accept_redirects", "0"),
            ("sysctl.net.ipv4.conf.default.accept_redirects", "1"),
            ("sysctl.net.ipv4.conf.all.secure_redirects", "1"),
            ("sysctl.net.ipv4.conf.all.send_redirects", "1"),
            ("sysctl.net.ipv4.ip_forward", "0"),
            ("sysctl.net.ipv4.conf.all.accept_source_route", "0"),
            ("sysctl.net.ipv4.conf.all.log_martians", "0"),
            ("sysctl.net.ipv4.icmp_echo_ignore_broadcasts", "1"),
            ("sysctl.net.ipv4.icmp_ignore_bogus_error_responses", "1"),
            ("sysctl.net.ipv4.tcp_syncookies", "1"),
            ("sysctl.net.ipv6.conf.all.accept_redirects", "1"),
            ("sysctl.kernel.dmesg_restrict", "1"),
            ("sysctl.kernel.kptr_restrict", "1"),
            ("sysctl.kernel.yama.ptrace_scope", "1"),
            ("sysctl.fs.protected_hardlinks", "1"),
            ("sysctl.fs.protected_symlinks", "1"),
            ("sysctl.fs.suid_dumpable", "2"),
            ("sysctl.kernel.unprivileged_bpf_disabled", "2"),
            ("firewall.tool", "ufw"),
            ("firewall.active", "yes"),
            ("firewall.default_input", "deny"),
            ("logindefs.PASS_MAX_DAYS", "99999"),
            ("logindefs.PASS_MIN_DAYS", "0"),
            ("logindefs.PASS_WARN_AGE", "7"),
            ("logindefs.ENCRYPT_METHOD", "YESCRYPT"),
            ("logindefs.UMASK", "022"),
            ("pam.pwquality", "no"),
            ("pam.lockout", "no"),
            ("accounts.uid0_extra", ""),
            ("accounts.empty_password", ""),
            ("perm.passwd.mode", "644"),
            ("perm.passwd.uid", "0"),
            ("perm.shadow.mode", "640"),
            ("perm.shadow.uid", "0"),
            ("perm.group.mode", "644"),
            ("perm.group.uid", "0"),
            ("perm.gshadow.mode", "640"),
            ("perm.gshadow.uid", "0"),
            ("files.world_writable.count", "0"),
            ("files.world_writable.sample", ""),
            ("mac.system", "apparmor"),
            ("mac.enforcing", "yes"),
            ("updates.automatic", "enabled"),
            ("updates.package_manager", "apt"),
            ("mount.tmp.separate", "no"),
            ("mount.dev_shm.separate", "yes"),
            ("mount.dev_shm.options", "rw,nosuid,nodev,inode64"),
            ("init.systemd", "yes"),
            ("services.legacy_enabled", ""),
            ("auditd.active", "no"),
            ("time.sync", "systemd-timesyncd"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn status_of(facts: BTreeMap<String, String>, id: &str) -> (Status, String) {
        let report = PostureFactsReport {
            platform: "linux".into(),
            facts,
            notes: BTreeMap::new(),
        };
        let results = evaluate(&report).unwrap();
        let r = results.iter().find(|r| r.check.id == id).unwrap();
        (r.outcome.status, r.outcome.evidence.clone())
    }

    fn with(mut facts: BTreeMap<String, String>, k: &str, v: &str) -> BTreeMap<String, String> {
        facts.insert(k.into(), v.into());
        facts
    }

    #[test]
    fn a_stock_ubuntu_server() {
        let report = PostureFactsReport {
            platform: "linux".into(),
            facts: ubuntu(),
            notes: BTreeMap::new(),
        };
        let results = evaluate(&report).unwrap();
        let failed: Vec<&str> = results
            .iter()
            .filter(|r| r.outcome.status == Status::Failed)
            .map(|r| r.check.id)
            .collect();
        assert_eq!(
            failed,
            [
                "AA-LNX-SSH-002",
                "AA-LNX-SSH-004",
                "AA-LNX-SSH-005",
                "AA-LNX-SSH-008",
                "AA-LNX-SSH-009",
                "AA-LNX-SSH-014",
                "AA-LNX-KRN-003",
                "AA-LNX-KRN-004",
                "AA-LNX-KRN-005",
                "AA-LNX-KRN-007",
                "AA-LNX-KRN-011",
                "AA-LNX-KRN-017",
                "AA-LNX-AUTH-001",
                "AA-LNX-AUTH-002",
                "AA-LNX-AUTH-005",
                "AA-LNX-AUTH-006",
                "AA-LNX-AUTH-009",
                "AA-LNX-MNT-001",
                "AA-LNX-MNT-003",
                "AA-LNX-AUD-001",
            ]
        );
        // Not applicable: /tmp options (no separate /tmp), audit rules
        // (auditd off).
        let na: Vec<&str> = results
            .iter()
            .filter(|r| r.outcome.status == Status::NotApplicable)
            .map(|r| r.check.id)
            .collect();
        assert_eq!(na, ["AA-LNX-MNT-002", "AA-LNX-AUD-002"]);
    }

    #[test]
    fn ssh_rules() {
        let (s, e) = status_of(ubuntu(), "AA-LNX-SSH-001");
        assert_eq!(s, Status::Passed, "{e}");
        let (s, _) = status_of(
            with(ubuntu(), "sshd.permitrootlogin", "yes"),
            "AA-LNX-SSH-001",
        );
        assert_eq!(s, Status::Failed);
        let (s, e) = status_of(with(ubuntu(), "sshd.present", "no"), "AA-LNX-SSH-001");
        assert_eq!(s, Status::NotApplicable);
        assert!(e.contains("No SSH server"));
        let (_, e) = status_of(ubuntu(), "AA-LNX-SSH-014");
        assert!(
            e.contains("umac-64-etm@openssh.com") && e.contains("umac-64@openssh.com"),
            "{e}"
        );
        let (s, _) = status_of(ubuntu(), "AA-LNX-SSH-015");
        assert_eq!(s, Status::Passed);
        let weak = with(
            ubuntu(),
            "sshd.kexalgorithms",
            "curve25519-sha256,diffie-hellman-group1-sha1",
        );
        assert_eq!(status_of(weak, "AA-LNX-SSH-015").0, Status::Failed);
        let idle = with(ubuntu(), "sshd.clientaliveinterval", "300");
        assert_eq!(status_of(idle, "AA-LNX-SSH-009").0, Status::Passed);
    }

    #[test]
    fn kernel_rules() {
        let router = with(ubuntu(), "sysctl.net.ipv4.ip_forward", "1");
        assert_eq!(status_of(router, "AA-LNX-KRN-005").0, Status::NotApplicable);
        let mut no_ipv6 = ubuntu();
        no_ipv6.remove("sysctl.net.ipv6.conf.all.accept_redirects");
        let (s, e) = status_of(no_ipv6, "AA-LNX-KRN-011");
        assert_eq!(s, Status::NotApplicable);
        assert!(e.contains("IPv6"));
        let fixed = with(
            ubuntu(),
            "sysctl.net.ipv4.conf.default.accept_redirects",
            "0",
        );
        assert_eq!(status_of(fixed, "AA-LNX-KRN-003").0, Status::Passed);
        // A forwarding host needs only `all` off (the kernel ANDs them).
        let forwarding = with(ubuntu(), "sysctl.net.ipv4.ip_forward", "1");
        assert_eq!(status_of(forwarding, "AA-LNX-KRN-003").0, Status::Passed);
        // Fedora: `all` is 0, but `default` (and so every interface) is 2.
        let fedora = with(
            with(ubuntu(), "sysctl.net.ipv4.conf.all.rp_filter", "0"),
            "sysctl.net.ipv4.conf.default.rp_filter",
            "2",
        );
        let (s, e) = status_of(fedora, "AA-LNX-KRN-002");
        assert_eq!(s, Status::Passed);
        assert_eq!(
            e,
            "net.ipv4.conf.all.rp_filter = 0, net.ipv4.conf.default.rp_filter = 2"
        );
        let off = with(ubuntu(), "sysctl.net.ipv4.conf.all.rp_filter", "0");
        assert_eq!(status_of(off, "AA-LNX-KRN-002").0, Status::Failed);
        let martians = with(ubuntu(), "sysctl.net.ipv4.conf.default.log_martians", "1");
        assert_eq!(status_of(martians, "AA-LNX-KRN-007").0, Status::Passed);
        assert_eq!(status_of(ubuntu(), "AA-LNX-KRN-018").0, Status::Passed);
    }

    #[test]
    fn account_and_file_rules() {
        let pw = with(
            with(ubuntu(), "pam.pwquality", "yes"),
            "pwquality.minlen",
            "14",
        );
        assert_eq!(status_of(pw, "AA-LNX-AUTH-005").0, Status::Passed);
        let (s, e) = status_of(with(ubuntu(), "pam.pwquality", "yes"), "AA-LNX-AUTH-005");
        assert_eq!(s, Status::Failed);
        assert!(e.contains("default is 8"));
        let lock = with(ubuntu(), "pam.lockout", "yes");
        assert_eq!(status_of(lock.clone(), "AA-LNX-AUTH-006").0, Status::Passed);
        assert_eq!(
            status_of(with(lock, "pam.lockout_deny", "10"), "AA-LNX-AUTH-006").0,
            Status::Failed
        );
        let (s, e) = status_of(
            with(ubuntu(), "accounts.uid0_extra", "toor"),
            "AA-LNX-AUTH-007",
        );
        assert_eq!(s, Status::Failed);
        assert!(e.contains("toor"));
        assert_eq!(
            status_of(with(ubuntu(), "logindefs.UMASK", "077"), "AA-LNX-AUTH-009").0,
            Status::Passed
        );
        let (s, e) = status_of(with(ubuntu(), "perm.shadow.mode", "644"), "AA-LNX-FILE-002");
        assert_eq!(s, Status::Failed);
        assert!(e.contains("0644"));
        assert_eq!(
            status_of(with(ubuntu(), "perm.shadow.mode", "0"), "AA-LNX-FILE-002").0,
            Status::Passed
        );
        assert_eq!(
            status_of(with(ubuntu(), "perm.passwd.uid", "1000"), "AA-LNX-FILE-001").0,
            Status::Failed
        );
    }

    #[test]
    fn firewall_and_service_rules() {
        let off = with(ubuntu(), "firewall.active", "no");
        assert_eq!(status_of(off.clone(), "AA-LNX-FW-001").0, Status::Failed);
        assert_eq!(status_of(off, "AA-LNX-FW-002").0, Status::NotApplicable);
        let open = with(ubuntu(), "firewall.default_input", "accept");
        assert_eq!(status_of(open, "AA-LNX-FW-002").0, Status::Failed);
        let none = with(
            with(ubuntu(), "firewall.tool", "none"),
            "firewall.active",
            "no",
        );
        assert!(status_of(none, "AA-LNX-FW-001").1.contains("No firewall"));
        let telnet = with(ubuntu(), "services.legacy_enabled", "telnet.socket");
        assert_eq!(status_of(telnet, "AA-LNX-SVC-001").0, Status::Failed);
        let no_systemd = with(ubuntu(), "init.systemd", "no");
        assert_eq!(
            status_of(no_systemd, "AA-LNX-SVC-001").0,
            Status::NotApplicable
        );
        let audit = with(with(ubuntu(), "auditd.active", "yes"), "auditd.rules", "0");
        assert_eq!(status_of(audit, "AA-LNX-AUD-002").0, Status::Failed);
        let mut tmp = with(ubuntu(), "mount.tmp.separate", "yes");
        tmp.insert("mount.tmp.options".into(), "rw,nosuid,nodev,size=8G".into());
        assert_eq!(status_of(tmp, "AA-LNX-MNT-002").0, Status::Passed);
    }
}
