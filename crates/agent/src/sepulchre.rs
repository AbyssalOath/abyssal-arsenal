//! Sepulchre: host-side SFTP/SMB share provisioning and mounts. Every
//! config write here touches only a Sepulchre-owned drop-in/include
//! file, never the host's own `sshd_config`/`smb.conf` in place -- the
//! same managed-file idiom `grimoire.rs` already uses for sysctl/cron,
//! extended with a validate-before-reload step and a restore-previous-
//! and-reload-again rollback if validation or reload fails. A bad
//! render can never be left half-applied.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput, SepulchreConfigTarget};

use crate::apothecary;
use crate::elevation::ElevationState;
use crate::process::present;

const SSHD_DROPIN_FILE: &str = "/etc/ssh/sshd_config.d/50-sepulchre.conf";
const SSHD_MAIN_CONFIG: &str = "/etc/ssh/sshd_config";
const SAMBA_INCLUDE_FILE: &str = "/etc/samba/sepulchre.conf";
const SAMBA_MAIN_CONFIG: &str = "/etc/samba/smb.conf";
const AUTHORIZED_KEYS_DIR: &str = "/etc/ssh/sepulchre/authorized_keys";
const MANAGED_HEADER: &str = "# Managed by Abyssal Arsenal (Sepulchre) -- do not edit manually\n";

pub async fn detect_package_backend(_elevation: &ElevationState) -> CommandOutcome {
    match apothecary::detect().await {
        Some(backend) => CommandOutcome::Ok(OperationOutput {
            stdout: backend.label().to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        None => CommandOutcome::Err("no known package manager found on this host".to_string()),
    }
}

struct TargetInfo {
    path: &'static str,
    main_config: &'static str,
    include_needle: &'static str,
    validate: (&'static str, &'static [&'static str]),
    reload_service_candidates: &'static [&'static str],
}

fn target_info(target: SepulchreConfigTarget) -> TargetInfo {
    match target {
        SepulchreConfigTarget::SshdDropIn => TargetInfo {
            path: SSHD_DROPIN_FILE,
            main_config: SSHD_MAIN_CONFIG,
            include_needle: "Include /etc/ssh/sshd_config.d",
            validate: ("sshd", &["-t"]),
            reload_service_candidates: &["sshd", "ssh"],
        },
        SepulchreConfigTarget::SambaInclude => TargetInfo {
            path: SAMBA_INCLUDE_FILE,
            main_config: SAMBA_MAIN_CONFIG,
            include_needle: "include = /etc/samba/sepulchre.conf",
            validate: ("testparm", &["-s"]),
            reload_service_candidates: &["smbd", "samba"],
        },
    }
}

async fn read_managed_file(path: &str, elevation: &ElevationState) -> Result<String, String> {
    match elevation.run_allow_failure("cat", &[path]).await {
        Ok(output) if output.exit_code == Some(0) => Ok(output.stdout),
        Ok(_) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

async fn write_managed_file(
    path: &str,
    content: &str,
    elevation: &ElevationState,
) -> Result<OperationOutput, String> {
    elevation.run_with_stdin("tee", &[path], content).await
}

/// Tries each candidate systemd unit name in turn (distros disagree on
/// whether the SSH daemon's unit is called `sshd` or `ssh`) and reloads
/// the first one that exists -- errors only if none of them do.
async fn reload_service(
    candidates: &[&str],
    elevation: &ElevationState,
) -> Result<OperationOutput, String> {
    let mut last_error = String::new();
    for service in candidates {
        match elevation.run("systemctl", &["reload", service]).await {
            Ok(output) => return Ok(output),
            Err(e) => last_error = e,
        }
    }
    Err(format!(
        "none of the candidate services ({}) could be reloaded: {last_error}",
        candidates.join(", ")
    ))
}

pub async fn render_sepulchre_config(
    target: SepulchreConfigTarget,
    content: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    let info = target_info(target);
    let previous = match read_managed_file(info.path, elevation).await {
        Ok(c) => c,
        Err(e) => return CommandOutcome::Err(e),
    };

    if let Err(e) = write_managed_file(info.path, &content, elevation).await {
        return CommandOutcome::Err(e);
    }

    let (validate_cmd, validate_args) = info.validate;
    match elevation
        .run_allow_failure(validate_cmd, validate_args)
        .await
    {
        Ok(output) if output.exit_code == Some(0) => {
            match reload_service(info.reload_service_candidates, elevation).await {
                Ok(reload_output) => CommandOutcome::Ok(OperationOutput {
                    stdout: format!("Applied and reloaded.\n{}", reload_output.stdout),
                    ..reload_output
                }),
                Err(e) => {
                    let _ = write_managed_file(info.path, &previous, elevation).await;
                    let _ = reload_service(info.reload_service_candidates, elevation).await;
                    CommandOutcome::Err(format!(
                        "reload failed after applying the new config; restored the previous version: {e}"
                    ))
                }
            }
        }
        Ok(output) => {
            let _ = write_managed_file(info.path, &previous, elevation).await;
            CommandOutcome::Err(format!(
                "configuration validation failed; restored the previous version.\n{}\n{}",
                output.stdout, output.stderr
            ))
        }
        Err(e) => {
            let _ = write_managed_file(info.path, &previous, elevation).await;
            CommandOutcome::Err(format!(
                "could not run the validation command; restored the previous version: {e}"
            ))
        }
    }
}

pub async fn clear_sepulchre_config(
    target: SepulchreConfigTarget,
    elevation: &ElevationState,
) -> CommandOutcome {
    let header = match target {
        SepulchreConfigTarget::SshdDropIn => MANAGED_HEADER.to_string(),
        SepulchreConfigTarget::SambaInclude => format!("{MANAGED_HEADER}[global]\n"),
    };
    render_sepulchre_config(target, header, elevation).await
}

pub async fn check_config_include_directive(
    target: SepulchreConfigTarget,
    elevation: &ElevationState,
) -> CommandOutcome {
    let info = target_info(target);
    match read_managed_file(info.main_config, elevation).await {
        Ok(content) => {
            let present = content
                .lines()
                .any(|line| line.trim_start().starts_with(info.include_needle));
            CommandOutcome::Ok(OperationOutput {
                stdout: if present {
                    "present".to_string()
                } else {
                    "missing".to_string()
                },
                stderr: String::new(),
                exit_code: Some(0),
            })
        }
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn create_sftp_chroot_account(
    username: String,
    chroot_dir: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = elevation
        .run(
            "useradd",
            &[
                "--system",
                "--home-dir",
                &chroot_dir,
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                &username,
            ],
        )
        .await
    {
        return CommandOutcome::Err(e);
    }
    // The chroot directory itself must be root-owned and not group/world
    // writable (OpenSSH refuses ChrootDirectory otherwise); a writable
    // subdirectory inside it is where the account's own files actually
    // go.
    let upload_dir = format!("{}/upload", chroot_dir.trim_end_matches('/'));
    for step in [
        elevation.run("mkdir", &["-p", &upload_dir]).await,
        elevation.run("chown", &["root:root", &chroot_dir]).await,
        elevation.run("chmod", &["755", &chroot_dir]).await,
        elevation
            .run("chown", &[&format!("{username}:{username}"), &upload_dir])
            .await,
        elevation.run("chmod", &["700", &upload_dir]).await,
    ] {
        if let Err(e) = step {
            return CommandOutcome::Err(e);
        }
    }
    CommandOutcome::Ok(OperationOutput {
        stdout: format!("Created SFTP chroot account {username} at {chroot_dir}"),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

pub async fn remove_sftp_chroot_account(
    username: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    let key_file = format!("{AUTHORIZED_KEYS_DIR}/{username}");
    let _ = elevation.run_allow_failure("rm", &["-f", &key_file]).await;
    // `userdel -r`'s exit code 12 ("can't remove home directory" and the
    // same code shadow-utils uses for a missing mail spool it expected to
    // clean up) fires even when the account itself was removed
    // successfully -- caught live against a chroot account created with
    // `--no-create-home` in a minimal container with no `/var/mail` set
    // up at all. Since this feature already deliberately leaves a
    // chroot's data on disk regardless (never delete data unless
    // separately, explicitly requested -- see docs/sepulchre.md), a
    // leftover home directory here is the intended outcome, not a
    // failure to surface as one.
    match elevation
        .run_allow_failure("userdel", &["-r", &username])
        .await
    {
        Ok(output) if output.exit_code == Some(0) || output.exit_code == Some(12) => {
            CommandOutcome::Ok(output)
        }
        Ok(output) => CommandOutcome::Err(format!(
            "userdel exited with {:?}: {}{}",
            output.exit_code, output.stdout, output.stderr
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn install_sepulchre_authorized_key(
    username: String,
    public_key: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = elevation.run("mkdir", &["-p", AUTHORIZED_KEYS_DIR]).await {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = elevation.run("chmod", &["755", AUTHORIZED_KEYS_DIR]).await {
        return CommandOutcome::Err(e);
    }
    let key_file = format!("{AUTHORIZED_KEYS_DIR}/{username}");
    // Idempotent: read whatever's there already (a missing file is an
    // empty starting point, same as `grimoire.rs`'s managed files), skip
    // if this exact key is already present, otherwise append.
    let existing = read_managed_file(&key_file, elevation)
        .await
        .unwrap_or_default();
    let trimmed_key = public_key.trim();
    if existing.lines().any(|line| line.trim() == trimmed_key) {
        return CommandOutcome::Ok(OperationOutput {
            stdout: format!("Key already installed for {username}"),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(trimmed_key);
    updated.push('\n');
    if let Err(e) = write_managed_file(&key_file, &updated, elevation).await {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = elevation.run("chmod", &["644", &key_file]).await {
        return CommandOutcome::Err(e);
    }
    CommandOutcome::Ok(OperationOutput {
        stdout: format!("Installed an authorized key for {username}"),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

pub async fn create_samba_service_user(
    username: String,
    password: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    let account_exists = elevation
        .run_allow_failure("id", &[&username])
        .await
        .map(|o| o.exit_code == Some(0))
        .unwrap_or(false);
    if !account_exists
        && let Err(e) = elevation
            .run(
                "useradd",
                &["--system", "--shell", "/usr/sbin/nologin", &username],
            )
            .await
    {
        return CommandOutcome::Err(e);
    }
    // `smbpasswd -s -a` reads the new password from stdin twice
    // (confirmation) -- never as an argument, never logged.
    let stdin_data = format!("{password}\n{password}\n");
    match elevation
        .run_with_stdin("smbpasswd", &["-s", "-a", &username], &stdin_data)
        .await
    {
        Ok(_) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Created Samba service user {username}"),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_samba_service_user(
    username: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    let _ = elevation
        .run_allow_failure("smbpasswd", &["-x", &username])
        .await;
    match elevation.run("userdel", &[&username]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn render_mount_unit(
    unit_name: String,
    mount_point: String,
    content: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = elevation.run("mkdir", &["-p", &mount_point]).await {
        return CommandOutcome::Err(e);
    }
    let unit_path = format!("/etc/systemd/system/{unit_name}");
    if let Err(e) = write_managed_file(&unit_path, &content, elevation).await {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = elevation.run("systemctl", &["daemon-reload"]).await {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("systemctl", &["enable", "--now", &unit_name])
        .await
    {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Mounted {mount_point} via {unit_name}\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_mount_unit(
    unit_name: String,
    mount_point: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    let _ = elevation
        .run_allow_failure("systemctl", &["disable", "--now", &unit_name])
        .await;
    let _ = elevation.run_allow_failure("umount", &[&mount_point]).await;
    let unit_path = format!("/etc/systemd/system/{unit_name}");
    if let Err(e) = elevation.run("rm", &["-f", &unit_path]).await {
        return CommandOutcome::Err(e);
    }
    match elevation.run("systemctl", &["daemon-reload"]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Removed mount {mount_point}\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Creates a root-owned `0755` directory at `path`, tolerating "already
/// exists" -- used to prepare where a Samba share stanza will point
/// before the share is announced.
pub async fn create_share_directory(
    path: String,
    owner: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = elevation.run("mkdir", &["-p", &path]).await {
        return CommandOutcome::Err(e);
    }
    // Owned by the Samba service account, not root: `smbd` enforces real
    // filesystem permissions underneath its own `valid users` ACL, so a
    // root-owned directory would make every write fail with
    // `NT_STATUS_ACCESS_DENIED` no matter what the share stanza allows.
    let owner_group = format!("{owner}:{owner}");
    for step in [
        elevation.run("chown", &[owner_group.as_str(), &path]).await,
        elevation.run("chmod", &["750", &path]).await,
    ] {
        if let Err(e) = step {
            return CommandOutcome::Err(e);
        }
    }
    CommandOutcome::Ok(OperationOutput {
        stdout: format!("Created share directory {path}"),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

const MOUNT_CREDENTIALS_DIR: &str = "/etc/sepulchre/mounts";

/// Writes a CIFS mount's `credentials=` file. `path` must already have
/// been validated by the control plane to be under
/// [`MOUNT_CREDENTIALS_DIR`] -- re-checked here too, since this is the
/// one place a bad path would otherwise write an arbitrary file as root.
pub async fn write_mount_credentials(
    path: String,
    contents: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !path.starts_with(&format!("{MOUNT_CREDENTIALS_DIR}/")) {
        return CommandOutcome::Err(format!(
            "refusing to write outside {MOUNT_CREDENTIALS_DIR}: {path}"
        ));
    }
    if let Err(e) = elevation.run("mkdir", &["-p", MOUNT_CREDENTIALS_DIR]).await {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = elevation
        .run("chmod", &["700", MOUNT_CREDENTIALS_DIR])
        .await
    {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = write_managed_file(&path, &contents, elevation).await {
        return CommandOutcome::Err(e);
    }
    match elevation.run("chmod", &["600", &path]).await {
        Ok(_) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Wrote mount credentials file {path}"),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn check_mount_status(mount_point: String, elevation: &ElevationState) -> CommandOutcome {
    match elevation.run_allow_failure("cat", &["/proc/mounts"]).await {
        Ok(output) => {
            let mounted = output
                .stdout
                .lines()
                .any(|line| line.split_whitespace().nth(1) == Some(mount_point.as_str()));
            CommandOutcome::Ok(present(
                OperationOutput {
                    stdout: if mounted {
                        "mounted".to_string()
                    } else {
                        "not_mounted".to_string()
                    },
                    stderr: String::new(),
                    exit_code: Some(0),
                },
                "not_mounted",
            ))
        }
        Err(e) => CommandOutcome::Err(e),
    }
}
