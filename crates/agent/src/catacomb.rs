//! Filesystem inspection, maintenance, traversal, and repair utilities
//! ("Catacomb"): directory-size traversal, large-file search,
//! read-only/repair filesystem checks, and TRIM. Operates on the
//! filesystem layer itself -- distinct from Necropsy (block/hardware
//! inventory), Resurrection (mount *state*), and Ossuary's future
//! partition/LVM/RAID scope (the block/volume layer underneath).

use abyssal_agent_protocol::{CommandOutcome, is_valid_mount_target};

use crate::elevation::ElevationState;

fn validate_path(path: &str) -> Result<(), String> {
    if !is_valid_mount_target(path) {
        return Err(format!("refusing invalid path: {path}"));
    }
    Ok(())
}

/// `du`/`find` both exit non-zero the moment traversal hits *any*
/// permission-denied subdirectory -- inevitable when scanning a broad
/// path like `/` or `/home` on a real host (root-owned
/// `systemd-private-*` directories, other users' home directories, ...).
/// That's a normal partial result, not a failure: confirmed as a real
/// bug in this exact shape in Defleshing's `ClearTmpFiles` earlier this
/// session, so both traversal ops here go through `run_allow_failure`
/// from the start rather than repeating it.
pub async fn directory_usage_breakdown(path: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&path) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run_allow_failure("du", &["-h", "--max-depth=1", path.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(crate::process::present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn find_large_files(
    path: String,
    min_size_mb: u32,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&path) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_size_mb(min_size_mb) {
        return CommandOutcome::Err(format!("refusing invalid size threshold: {min_size_mb}MB"));
    }
    let size_arg = format!("+{min_size_mb}M");
    match elevation
        .run_allow_failure(
            "find",
            &[
                path.as_str(),
                "-xdev",
                "-type",
                "f",
                "-size",
                size_arg.as_str(),
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(crate::process::present(
            output,
            "No files at or above that size threshold.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// `fsck -n` reports problems via a non-zero exit even when it ran
/// perfectly correctly (that's the whole point -- it's telling you
/// something is wrong), so this goes through `run_allow_failure` and
/// presents the report either way, same reasoning as every other
/// state-reflecting exit code in this codebase.
pub async fn filesystem_check_dry_run(
    device: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run_allow_failure("fsck", &["-n", device.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(crate::process::present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn trim_filesystem(mountpoint: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&mountpoint) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("fstrim", &["-v", mountpoint.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// The safety gate `FilesystemRepair` depends on: `findmnt --source
/// <device>` exits 0 if `device` is currently mounted anywhere, non-zero
/// if it isn't. Fails *closed* -- if `findmnt` itself can't be run at
/// all, this reports "can't confirm it's safe" rather than "assume it's
/// fine," because the failure mode of guessing wrong here is real
/// filesystem corruption, not just a confusing error message.
async fn refuse_if_mounted(device: &str, elevation: &ElevationState) -> Result<(), String> {
    match elevation
        .run_allow_failure("findmnt", &["--source", device])
        .await
    {
        Ok(output) if output.exit_code == Some(0) => Err(format!(
            "refusing to repair {device}: it is currently mounted. Unmount it first -- \
             running fsck's repair mode on a mounted filesystem can cause severe corruption."
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "refusing to repair {device}: could not verify it is unmounted ({e})"
        )),
    }
}

/// `fsck`'s exit code is a bitmask of outcomes (0 clean, 1 errors
/// corrected, 2 corrected + reboot needed, 4 errors left uncorrected,
/// ...), not a simple success/failure signal -- a successful repair that
/// actually fixed something normally exits non-zero. Goes through
/// `run_allow_failure` for the same reason `DiskHealth`'s `smartctl` call
/// does: a plain `elevation.run` would misreport the good case (errors
/// found and corrected) as a failure.
pub async fn filesystem_repair(device: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = refuse_if_mounted(&device, elevation).await {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run_allow_failure("fsck", &["-y", device.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(crate::process::present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}
