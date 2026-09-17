//! Hardware inspection and diagnostics ("Necropsy"): CPU, PCI devices,
//! block devices, memory modules, and per-disk SMART health. Read-only --
//! inspecting hardware doesn't mutate anything, so there's no write or
//! destructive tier here, the same shape as Mortiscope.

use abyssal_agent_protocol::CommandOutcome;

use crate::elevation::ElevationState;
use crate::process::present;

pub async fn cpu_info(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("lscpu", &[]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn pci_devices(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("lspci", &[]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn block_devices(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run(
            "lsblk",
            &["-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL"],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// `dmidecode` reporting no data (common in VMs/containers with no real
/// SMBIOS tables to read) is a normal, informational result, not a
/// failure -- goes through `run_allow_failure` and presents whatever came
/// back rather than treating that as an error.
pub async fn memory_hardware(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run_allow_failure("dmidecode", &["-t", "memory"])
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(
            output,
            "No SMBIOS/DMI memory data available on this host.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn validate_device(device: &str) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_absolute_path(device) {
        return Err(format!("refusing invalid device path: {device}"));
    }
    Ok(())
}

/// `smartctl`'s exit code is a bitmask of SMART findings, not a simple
/// success/failure signal -- a non-zero exit reporting a real finding
/// (a failing attribute, a pre-fail warning) is exactly the useful case
/// here, not an error, so this goes through `run_allow_failure` too.
pub async fn disk_health(device: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_device(&device) {
        return CommandOutcome::Err(e);
    }
    match elevation
        .run_allow_failure("smartctl", &["-H", "-i", device.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}
