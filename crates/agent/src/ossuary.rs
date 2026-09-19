//! Disk, partition, LVM, RAID, volume, mount, and storage management
//! ("Ossuary"). The block/volume layer beneath the filesystem --
//! distinct from Necropsy (hardware inventory), Catacomb (the filesystem
//! layer itself), and Resurrection (mount *state*).
//!
//! The high-risk operations here (partition table create/delete, RAID
//! array create/stop, LVM physical/volume-group/logical-volume create
//! and remove, and creating a filesystem) are gated a second time at the
//! control-plane level, behind an admin-configured setting that's off by
//! default (see `abyssal_core::settings::HIGH_RISK_STORAGE_OPS_ENABLED`)
//! -- the agent itself has no knowledge of that setting (it has no DB
//! access), so this module just executes whatever it's sent; the gate is
//! enforced entirely in `crates/web/src/routes/ossuary.rs` before
//! dispatch ever happens.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput, is_valid_mount_target};

use crate::elevation::ElevationState;
use crate::process::present;

fn validate_path(path: &str) -> Result<(), String> {
    if !is_valid_mount_target(path) {
        return Err(format!("refusing invalid path: {path}"));
    }
    Ok(())
}

fn validate_paths(paths: &[String]) -> Result<(), String> {
    if paths.is_empty() {
        return Err("refusing an empty device list".to_string());
    }
    for path in paths {
        validate_path(path)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------

/// `parted print` exits non-zero on a device with no recognized
/// partition table at all ("unrecognised disk label") -- a normal,
/// informational result (the device just isn't partitioned yet), not a
/// failure.
pub async fn partition_table(device: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run_allow_failure("parted", &["-s", device.as_str(), "print"])
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn lvm_summary(elevation: &ElevationState) -> CommandOutcome {
    let pvs = match elevation.run("pvs", &[]).await {
        Ok(o) => o.stdout,
        Err(e) => return CommandOutcome::Err(e),
    };
    let vgs = match elevation.run("vgs", &[]).await {
        Ok(o) => o.stdout,
        Err(e) => return CommandOutcome::Err(e),
    };
    let lvs = match elevation.run("lvs", &[]).await {
        Ok(o) => o.stdout,
        Err(e) => return CommandOutcome::Err(e),
    };
    CommandOutcome::Ok(OperationOutput {
        stdout: format!(
            "== Physical Volumes ==\n{}\n== Volume Groups ==\n{}\n== Logical Volumes ==\n{}",
            pvs.trim_end(),
            vgs.trim_end(),
            lvs.trim_end()
        ),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

pub async fn raid_status(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("cat", &["/proc/mdstat"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

// ---------------------------------------------------------------------
// Write / Destructive (conservative tier -- always available)
// ---------------------------------------------------------------------

pub async fn mount_filesystem(
    device: String,
    target: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_path(&target) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("mount", &[device.as_str(), target.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Mounted {device} at {target}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn extend_logical_volume(
    lv_path: String,
    size: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&lv_path) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_vacuum_size(&size) {
        return CommandOutcome::Err(format!("refusing invalid size: {size}"));
    }
    let size_arg = format!("+{size}");
    match elevation
        .run("lvextend", &["-L", size_arg.as_str(), lv_path.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn unmount_filesystem(target: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&target) {
        return CommandOutcome::Err(e);
    }
    match elevation.run("umount", &[target.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Unmounted {target}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

// ---------------------------------------------------------------------
// High-risk tier -- control-plane-gated (see module doc comment)
// ---------------------------------------------------------------------

pub async fn create_partition(
    device: String,
    start: String,
    end: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_partition_position(&start)
        || !abyssal_agent_protocol::is_valid_partition_position(&end)
    {
        return CommandOutcome::Err(format!("refusing invalid partition bounds: {start}..{end}"));
    }
    match elevation
        .run(
            "parted",
            &[
                "-s",
                device.as_str(),
                "mkpart",
                "primary",
                start.as_str(),
                end.as_str(),
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn delete_partition(
    device: String,
    partition_number: u32,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_partition_number(partition_number) {
        return CommandOutcome::Err(format!(
            "refusing invalid partition number: {partition_number}"
        ));
    }
    let number_str = partition_number.to_string();
    match elevation
        .run(
            "parted",
            &["-s", device.as_str(), "rm", number_str.as_str()],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// `mdadm --create` prompts "Continue creating array?" the moment any
/// listed device looks like it might already hold data -- exactly the
/// case worth double-checking, so this answers that prompt via stdin
/// (`"y\n"`) rather than suppressing the check entirely with `--run`.
pub async fn create_raid_array(
    array_name: String,
    level: String,
    devices: Vec<String>,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&array_name) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_raid_level(&level) {
        return CommandOutcome::Err(format!("refusing invalid RAID level: {level}"));
    }
    if let Err(e) = validate_paths(&devices) {
        return CommandOutcome::Err(e);
    }
    let level_arg = format!("--level={level}");
    let count_arg = format!("--raid-devices={}", devices.len());
    let mut args: Vec<&str> = vec![
        "--create",
        array_name.as_str(),
        level_arg.as_str(),
        count_arg.as_str(),
    ];
    args.extend(devices.iter().map(String::as_str));
    match elevation.run_with_stdin("mdadm", &args, "y\n").await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn stop_raid_array(array_name: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&array_name) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("mdadm", &["--stop", array_name.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn create_physical_volume(device: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("pvcreate", &["-f", "-y", device.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn create_volume_group(
    name: String,
    physical_volumes: Vec<String>,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&name) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_paths(&physical_volumes) {
        return CommandOutcome::Err(e);
    }
    let mut args: Vec<&str> = vec![name.as_str()];
    args.extend(physical_volumes.iter().map(String::as_str));
    match elevation.run("vgcreate", &args).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn create_logical_volume(
    vg_name: String,
    lv_name: String,
    size: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&vg_name) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_path(&lv_name) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_vacuum_size(&size) {
        return CommandOutcome::Err(format!("refusing invalid size: {size}"));
    }
    match elevation
        .run(
            "lvcreate",
            &[
                "-y",
                "-n",
                lv_name.as_str(),
                "-L",
                size.as_str(),
                vg_name.as_str(),
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_logical_volume(lv_path: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&lv_path) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("lvremove", &["-f", "-y", lv_path.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_volume_group(name: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&name) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("vgremove", &["-f", "-y", name.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_physical_volume(device: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run("pvremove", &["-f", "-y", device.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// The force flag differs by filesystem family: ext2/3/4 use uppercase
/// `-F`, everything else supported here uses lowercase `-f`, and
/// `mkfs.vfat` doesn't have (or need) one at all.
fn mkfs_force_flag(fstype: &str) -> Option<&'static str> {
    match fstype {
        "ext2" | "ext3" | "ext4" => Some("-F"),
        "xfs" | "btrfs" | "f2fs" => Some("-f"),
        _ => None,
    }
}

pub async fn create_filesystem(
    device: String,
    fstype: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_path(&device) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_fstype(&fstype) {
        return CommandOutcome::Err(format!("refusing unrecognized filesystem type: {fstype}"));
    }
    let program = format!("mkfs.{fstype}");
    let mut args: Vec<&str> = Vec::with_capacity(2);
    if let Some(flag) = mkfs_force_flag(&fstype) {
        args.push(flag);
    }
    args.push(device.as_str());
    match elevation.run(program.as_str(), &args).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}
