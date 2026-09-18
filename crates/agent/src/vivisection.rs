//! Performance analysis, profiling, and system tuning ("Vivisection"):
//! sampled activity and interrupt data beyond Mortiscope's point-in-time
//! monitoring, plus a small set of runtime-only, trivially-reversible
//! tuning knobs (swappiness, per-device I/O scheduler). Deliberately
//! stops short of anything that edits a persistent config file or needs
//! a real profiler (`perf`) -- the former belongs to Grimoire's future
//! configuration-management scope, the latter needs kernel
//! `perf_event_paranoid` cooperation this tool can't assume it has.

use abyssal_agent_protocol::CommandOutcome;

use crate::elevation::ElevationState;
use crate::process::present;

const CPU0_CPUFREQ: &str = "/sys/devices/system/cpu/cpu0/cpufreq";

/// `vmstat 1 3` -- three one-second samples, not a static snapshot, so
/// this genuinely takes a few seconds to return.
pub async fn vm_statistics(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("vmstat", &["1", "3"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn interrupt_statistics(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("cat", &["/proc/interrupts"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Reading cpu0's cpufreq files fails outright on a host with no active
/// frequency scaling (common in VMs/containers reporting one fixed
/// frequency) -- a normal "not applicable here" result, not an error.
pub async fn cpu_governor_status(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run_allow_failure(
            "cat",
            &[
                &format!("{CPU0_CPUFREQ}/scaling_governor"),
                &format!("{CPU0_CPUFREQ}/scaling_cur_freq"),
                &format!("{CPU0_CPUFREQ}/scaling_min_freq"),
                &format!("{CPU0_CPUFREQ}/scaling_max_freq"),
            ],
        )
        .await
    {
        Ok(output) => {
            let stdout = if output.stdout.trim().is_empty() {
                "No active CPU frequency scaling on this host (fixed frequency or virtualized)."
                    .to_string()
            } else {
                let mut lines = output.stdout.lines();
                format!(
                    "governor:          {}\ncurrent frequency: {} kHz\nmin frequency:     {} kHz\nmax frequency:     {} kHz",
                    lines.next().unwrap_or("?"),
                    lines.next().unwrap_or("?"),
                    lines.next().unwrap_or("?"),
                    lines.next().unwrap_or("?"),
                )
            };
            CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput { stdout, ..output })
        }
        Err(e) => CommandOutcome::Err(e),
    }
}

const TUNABLE_SYSCTLS: &[&str] = &[
    "vm.swappiness",
    "vm.dirty_ratio",
    "vm.dirty_background_ratio",
];

pub async fn tuning_parameters_status(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("sysctl", TUNABLE_SYSCTLS).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn set_swappiness(value: u32, elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_swappiness(value) {
        return CommandOutcome::Err(format!("refusing invalid swappiness value: {value}"));
    }
    let arg = format!("vm.swappiness={value}");
    match elevation.run("sysctl", &["-w", arg.as_str()]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn set_io_scheduler(
    device: String,
    scheduler: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_block_device_name(&device) {
        return CommandOutcome::Err(format!("refusing invalid block device name: {device}"));
    }
    if !abyssal_agent_protocol::is_valid_io_scheduler(&scheduler) {
        return CommandOutcome::Err(format!("refusing unrecognized I/O scheduler: {scheduler}"));
    }
    let path = format!("/sys/block/{device}/queue/scheduler");
    match elevation
        .run_with_stdin("tee", &[path.as_str()], &scheduler)
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(
            output,
            &format!("Set {device}'s I/O scheduler to {scheduler}."),
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}
