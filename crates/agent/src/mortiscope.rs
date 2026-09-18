//! System health and resource monitoring ("Mortiscope"): load average, top
//! processes by CPU/memory, detailed memory breakdown, disk I/O stats, and
//! failed systemd units. Every op here is read-only observability -- pure
//! monitoring, not management (that's Cystoolbox's job, which owns the
//! only other system-level ops in this app: `SystemInfo`/`ResourceUsage`
//! summaries, plus the actual `SetHostname`/`Reboot` mutations). Nothing
//! here should ever need write/destructive framing.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::process::truncate_lines;

pub async fn load_average(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("uptime", &[]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

const PS_FIELDS: &str = "pid,ppid,user,%cpu,%mem,comm";
/// Header row + 15 processes.
const TOP_PROCESS_LINES: usize = 16;

pub async fn top_processes_by_cpu(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run("ps", &["-eo", PS_FIELDS, "--sort=-%cpu"])
        .await
    {
        Ok(output) => CommandOutcome::Ok(truncate_lines(output, TOP_PROCESS_LINES)),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn top_processes_by_memory(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run("ps", &["-eo", PS_FIELDS, "--sort=-%mem"])
        .await
    {
        Ok(output) => CommandOutcome::Ok(truncate_lines(output, TOP_PROCESS_LINES)),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn memory_detail(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("cat", &["/proc/meminfo"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn disk_io_stats(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("vmstat", &["-d"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn failed_services(elevation: &ElevationState) -> CommandOutcome {
    match init_system::detect().await {
        InitSystem::Systemd => match elevation
            .run("systemctl", &["--failed", "--no-pager"])
            .await
        {
            Ok(output) => CommandOutcome::Ok(output),
            Err(e) => CommandOutcome::Err(e),
        },
        InitSystem::Other => CommandOutcome::Ok(OperationOutput {
            stdout: "No systemd on this host -- failed-unit reporting only applies to systemd."
                .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }),
    }
}
