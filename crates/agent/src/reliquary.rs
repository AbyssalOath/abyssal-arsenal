//! Backup creation, verification, and restoration ("Reliquary"). Backups
//! are plain `tar.gz` archives under a fixed directory on the managed
//! host -- deliberately not built on any particular filesystem's own
//! snapshot feature (LVM, Btrfs, and ZFS all vary too much in setup and
//! semantics to genericize safely the way firewall/init-system detection
//! does), since `tar` works identically on every Linux host this agent
//! targets. Each archive's filename encodes the operator-chosen name and
//! its creation time as a Unix timestamp, so repeated backups of the same
//! source never collide.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::present;

const BACKUP_DIR: &str = "/var/backups/abyssal-arsenal";

pub async fn list_backups(elevation: &ElevationState) -> CommandOutcome {
    if tokio::fs::metadata(BACKUP_DIR).await.is_err() {
        return CommandOutcome::Ok(OperationOutput {
            stdout: format!("No backups yet -- {BACKUP_DIR} doesn't exist on this host."),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }
    match elevation
        .run_allow_failure(
            "find",
            &[
                BACKUP_DIR,
                "-maxdepth",
                "1",
                "-type",
                "f",
                "-name",
                "*.tar.gz",
                "-printf",
                "%f\t%s bytes\t%TY-%Tm-%Td %TH:%TM\n",
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(output, "No backups found.")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn create_backup(
    source_path: String,
    name: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    // Defense in depth: the control plane already validates these before
    // dispatching, but this agent is the actual execution boundary and
    // never trusts a wire value on that basis alone.
    if !abyssal_agent_protocol::is_valid_absolute_path(&source_path) {
        return CommandOutcome::Err(format!("refusing invalid source path: {source_path}"));
    }
    if !abyssal_agent_protocol::is_valid_backup_name(&name) {
        return CommandOutcome::Err(format!("refusing invalid backup name: {name}"));
    }

    let path = Path::new(&source_path);
    let (parent, base) = match (
        path.parent().and_then(|p| p.to_str()),
        path.file_name().and_then(|f| f.to_str()),
    ) {
        (Some(parent), Some(base)) => (parent, base),
        _ => {
            return CommandOutcome::Err(format!(
                "can't determine a parent directory and name for {source_path}"
            ))
        }
    };
    let parent = if parent.is_empty() { "/" } else { parent };

    if let Err(e) = elevation.run("mkdir", &["-p", BACKUP_DIR]).await {
        return CommandOutcome::Err(format!("failed to create {BACKUP_DIR}: {e}"));
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let archive_name = format!("{name}-{timestamp}.tar.gz");
    let archive_path = format!("{BACKUP_DIR}/{archive_name}");

    match elevation
        .run("tar", &["-czf", &archive_path, "-C", parent, base])
        .await
    {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Created {archive_name} from {source_path}.\n{}",
                output.stdout
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn verify_backup(filename: String, elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_backup_filename(&filename) {
        return CommandOutcome::Err(format!("refusing invalid backup filename: {filename}"));
    }
    let archive_path = format!("{BACKUP_DIR}/{filename}");
    match elevation.run("tar", &["-tzf", &archive_path]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "{filename} is a valid archive. Contents:\n{}",
                output.stdout
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(format!(
            "verification failed -- archive may be corrupt or unreadable: {e}"
        )),
    }
}

pub async fn restore_backup(
    filename: String,
    target_path: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_backup_filename(&filename) {
        return CommandOutcome::Err(format!("refusing invalid backup filename: {filename}"));
    }
    if !abyssal_agent_protocol::is_valid_absolute_path(&target_path) {
        return CommandOutcome::Err(format!("refusing invalid target path: {target_path}"));
    }
    let archive_path = format!("{BACKUP_DIR}/{filename}");

    if let Err(e) = elevation.run("mkdir", &["-p", &target_path]).await {
        return CommandOutcome::Err(format!("failed to create {target_path}: {e}"));
    }

    match elevation
        .run("tar", &["-xzf", &archive_path, "-C", &target_path])
        .await
    {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Restored {filename} to {target_path}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}
