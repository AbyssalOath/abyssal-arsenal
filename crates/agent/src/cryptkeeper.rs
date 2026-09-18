//! Secrets, credentials, certificates, keys, and sensitive configuration
//! ("Cryptkeeper"). Distinct from Parish (Linux account/group
//! administration): Parish manages *who* exists, Cryptkeeper manages
//! *what proves who they are* -- SSH keys, TLS certificates, and the
//! files holding other secrets.
//!
//! Two safety principles run through every operation here:
//! - Never show raw key material where a fingerprint says the same
//!   thing more safely (`ssh-keygen -lf` throughout, never `cat` on a
//!   private or public key).
//! - Never crawl the filesystem for "anything that looks like a
//!   secret" -- `ViewSensitiveFile` only ever reads a path the admin
//!   names explicitly, and `ScanSensitiveFilePermissions` only reports
//!   *permissions*, never contents, on files it finds.

use std::os::unix::fs::PermissionsExt;

use abyssal_agent_protocol::{
    is_valid_account_name, is_valid_gecos_comment, CommandOutcome, OperationOutput,
};

use crate::elevation::ElevationState;
use crate::process::present;

const HOST_KEY_DIR: &str = "/etc/ssh";

/// Directories to walk for `ScanSensitiveFilePermissions` -- `find`
/// itself recurses, so listing real top-level directories here (rather
/// than a shell glob like `/home/*/.ssh`, which would never expand
/// without a shell this codebase deliberately never uses) covers every
/// user's home directory in one pass.
const SENSITIVE_SCAN_DIRS: &[&str] = &["/root/.ssh", "/home", "/etc/ssh", "/etc/ssl/private"];

/// Common locations a TLS certificate might live, across distros and
/// Let's Encrypt's own layout.
const CERT_DIRS: &[&str] = &[
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/letsencrypt/live",
];

async fn resolve_home_dir(username: &str, elevation: &ElevationState) -> Result<String, String> {
    let output = elevation.run("getent", &["passwd", username]).await?;
    output
        .stdout
        .trim()
        .split(':')
        .nth(5)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("could not resolve a home directory for {username}"))
}

// ---------------------------------------------------------------------
// SSH keys
// ---------------------------------------------------------------------

pub async fn list_ssh_host_keys(elevation: &ElevationState) -> CommandOutcome {
    let mut entries = match tokio::fs::read_dir(HOST_KEY_DIR).await {
        Ok(entries) => entries,
        Err(e) => return CommandOutcome::Err(format!("failed to read {HOST_KEY_DIR}: {e}")),
    };

    let mut pubkeys = Vec::new();
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("ssh_host_") && name.ends_with("_key.pub") {
                    pubkeys.push(format!("{HOST_KEY_DIR}/{name}"));
                }
            }
            Ok(None) => break,
            Err(e) => return CommandOutcome::Err(format!("failed to read {HOST_KEY_DIR}: {e}")),
        }
    }
    pubkeys.sort();

    if pubkeys.is_empty() {
        return CommandOutcome::Ok(OperationOutput {
            stdout: format!("No SSH host keys found in {HOST_KEY_DIR}."),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    let mut out = String::new();
    for pubkey_path in &pubkeys {
        let fingerprint = match elevation.run("ssh-keygen", &["-lf", pubkey_path]).await {
            Ok(o) => o.stdout.trim().to_string(),
            Err(e) => format!("(failed to read fingerprint: {e})"),
        };
        let private_path = pubkey_path.trim_end_matches(".pub");
        let permission_note = match tokio::fs::metadata(private_path).await {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    format!(" -- INSECURE PERMISSIONS ({mode:o}, should be 600)")
                } else {
                    String::new()
                }
            }
            Err(_) => " -- private key file not found".to_string(),
        };
        out.push_str(&format!("{fingerprint}{permission_note}\n"));
    }

    CommandOutcome::Ok(OperationOutput {
        stdout: out,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

pub async fn list_ssh_authorized_keys(
    username: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !is_valid_account_name(&username) {
        return CommandOutcome::Err(format!("refusing invalid username: {username}"));
    }
    let home = match resolve_home_dir(&username, elevation).await {
        Ok(h) => h,
        Err(e) => return CommandOutcome::Err(e),
    };
    let path = format!("{home}/.ssh/authorized_keys");

    match elevation
        .run_allow_failure("ssh-keygen", &["-lf", &path])
        .await
    {
        Ok(output) if output.exit_code == Some(0) => {
            CommandOutcome::Ok(present(output, "No authorized keys."))
        }
        Ok(_) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("No authorized_keys file for {username} (or it's empty)."),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn validate_ssh_key_type(key_type: &str) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_ssh_key_type(key_type) {
        return Err(format!("refusing unsupported SSH key type: {key_type}"));
    }
    Ok(())
}

pub async fn generate_ssh_keypair(
    key_type: String,
    comment: String,
    path: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_ssh_key_type(&key_type) {
        return CommandOutcome::Err(e);
    }
    if !is_valid_gecos_comment(&comment) {
        return CommandOutcome::Err(format!("refusing invalid comment: {comment}"));
    }
    if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
        return CommandOutcome::Err(format!("refusing invalid path: {path}"));
    }
    if tokio::fs::metadata(&path).await.is_ok() {
        return CommandOutcome::Err(format!("refusing to overwrite existing file at {path}"));
    }

    if let Some(parent) = std::path::Path::new(&path).parent() {
        if let Some(parent) = parent.to_str().filter(|p| !p.is_empty()) {
            let _ = elevation.run("mkdir", &["-p", parent]).await;
        }
    }

    match elevation
        .run(
            "ssh-keygen",
            &["-t", &key_type, "-f", &path, "-N", "", "-C", &comment],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Generated {key_type} keypair at {path}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_authorized_key(
    username: String,
    fingerprint: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !is_valid_account_name(&username) {
        return CommandOutcome::Err(format!("refusing invalid username: {username}"));
    }
    if !abyssal_agent_protocol::is_valid_ssh_fingerprint(&fingerprint) {
        return CommandOutcome::Err(format!("refusing invalid fingerprint: {fingerprint}"));
    }
    let home = match resolve_home_dir(&username, elevation).await {
        Ok(h) => h,
        Err(e) => return CommandOutcome::Err(e),
    };
    let path = format!("{home}/.ssh/authorized_keys");

    let current = match elevation.run_allow_failure("cat", &[path.as_str()]).await {
        Ok(o) if o.exit_code == Some(0) => o.stdout,
        Ok(_) => return CommandOutcome::Err(format!("no authorized_keys file for {username}")),
        Err(e) => return CommandOutcome::Err(e),
    };

    let mut kept = Vec::new();
    let mut removed = false;
    for line in current.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            kept.push(line.to_string());
            continue;
        }
        let stdin = format!("{trimmed}\n");
        match elevation
            .run_with_stdin("ssh-keygen", &["-lf", "-"], &stdin)
            .await
        {
            Ok(fp_output) if fp_output.stdout.contains(&fingerprint) => removed = true,
            _ => kept.push(line.to_string()),
        }
    }

    if !removed {
        return CommandOutcome::Err(format!(
            "no authorized_keys entry matching fingerprint {fingerprint} for {username}"
        ));
    }

    let new_content = if kept.is_empty() {
        String::new()
    } else {
        format!("{}\n", kept.join("\n"))
    };

    match elevation
        .run_with_stdin("tee", &[path.as_str()], &new_content)
        .await
    {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Removed the matching authorized_keys entry for {username}.\n{}",
                output.stdout
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn delete_ssh_keypair(path: String, elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
        return CommandOutcome::Err(format!("refusing invalid path: {path}"));
    }
    let pub_path = format!("{path}.pub");
    match elevation.run("rm", &["-f", &path, &pub_path]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Deleted keypair at {path} (and its .pub counterpart, if present).\n{}",
                output.stdout
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

// ---------------------------------------------------------------------
// TLS certificates
// ---------------------------------------------------------------------

pub async fn list_tls_certificates(elevation: &ElevationState) -> CommandOutcome {
    let mut find_args: Vec<&str> = CERT_DIRS.to_vec();
    find_args.extend([
        "-maxdepth",
        "3",
        "-type",
        "f",
        "(",
        "-iname",
        "*.pem",
        "-o",
        "-iname",
        "*.crt",
        "-o",
        "-iname",
        "*.cer",
        ")",
    ]);

    let output = match elevation.run_allow_failure("find", &find_args).await {
        Ok(o) => o,
        Err(e) => return CommandOutcome::Err(e),
    };
    let paths: Vec<&str> = output.stdout.lines().filter(|l| !l.is_empty()).collect();
    if paths.is_empty() {
        return CommandOutcome::Ok(present(
            output,
            "No certificates found in common locations.",
        ));
    }

    let mut out = String::new();
    for path in paths {
        match elevation
            .run_allow_failure(
                "openssl",
                &["x509", "-noout", "-subject", "-enddate", "-in", path],
            )
            .await
        {
            Ok(cert_output) if cert_output.exit_code == Some(0) => {
                out.push_str(&format!("{path}\n{}\n\n", cert_output.stdout.trim()));
            }
            _ => {
                out.push_str(&format!(
                    "{path}\n  (not a readable X.509 certificate, or permission denied)\n\n"
                ));
            }
        }
    }

    CommandOutcome::Ok(OperationOutput {
        stdout: out,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

pub async fn certificate_detail(path: String, elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
        return CommandOutcome::Err(format!("refusing invalid path: {path}"));
    }
    match elevation
        .run("openssl", &["x509", "-noout", "-text", "-in", &path])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(format!("failed to read certificate at {path}: {e}")),
    }
}

// ---------------------------------------------------------------------
// Sensitive files
// ---------------------------------------------------------------------

pub async fn scan_sensitive_file_permissions(elevation: &ElevationState) -> CommandOutcome {
    let mut find_args: Vec<&str> = SENSITIVE_SCAN_DIRS.to_vec();
    find_args.extend([
        "-maxdepth",
        "4",
        "-type",
        "f",
        "(",
        "-name",
        "id_*",
        "-o",
        "-name",
        "*_key",
        "-o",
        "-name",
        "authorized_keys",
        "-o",
        "-iname",
        "*.pem",
        "-o",
        "-iname",
        "*.key",
        ")",
        "!",
        "-name",
        "*.pub",
        "-perm",
        "/go+rw",
        "-printf",
        "%m\t%U:%G\t%p\n",
    ]);

    match elevation.run_allow_failure("find", &find_args).await {
        Ok(output) => CommandOutcome::Ok(present(
            output,
            "No insecure permissions found on sensitive files in common locations.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn view_sensitive_file(path: String, elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
        return CommandOutcome::Err(format!("refusing invalid path: {path}"));
    }
    match elevation.run("cat", &[&path]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(format!("failed to read {path}: {e}")),
    }
}

pub async fn fix_file_permissions(
    path: String,
    mode: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
        return CommandOutcome::Err(format!("refusing invalid path: {path}"));
    }
    if !abyssal_agent_protocol::is_valid_tightened_permission_mode(&mode) {
        return CommandOutcome::Err(format!(
            "refusing mode {mode} (only 600, 400, 640, 700 are allowed)"
        ));
    }
    match elevation.run("chmod", &[&mode, &path]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Set permissions on {path} to {mode}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}
