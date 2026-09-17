//! Historical log/audit-record management ("Obituary"): journal disk usage,
//! logrotate status, archived-log listing, per-directory log sizes, and
//! (destructive, systemd-only) vacuuming journal data by size or by age.
//! Read ops share Postmortem's `run_allow_failure`/friendly-empty-message
//! pattern; the vacuum ops are real, irreversible deletions and go through
//! the normal `elevation.run` (a genuine command failure there -- e.g. a
//! malformed size -- really is an error, not a "ran fine, found nothing"
//! case, so there's no reason to suppress it).

use abyssal_agent_protocol::CommandOutcome;

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::process::{command_exists, present};

async fn run_and_present(
    elevation: &ElevationState,
    program: &str,
    args: &[&str],
) -> CommandOutcome {
    match elevation.run_allow_failure(program, args).await {
        Ok(output) => CommandOutcome::Ok(present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn journal_disk_usage(elevation: &ElevationState) -> CommandOutcome {
    match init_system::detect().await {
        InitSystem::Systemd => run_and_present(elevation, "journalctl", &["--disk-usage"]).await,
        InitSystem::Other => run_and_present(elevation, "du", &["-sh", "/var/log"]).await,
    }
}

const LOGROTATE_STATUS_PATHS: &[&str] = &[
    "/var/lib/logrotate/status",
    "/var/lib/logrotate/logrotate.status",
    "/var/lib/logrotate.status",
    "/var/log/logrotate/status",
];

pub async fn log_rotation_status(elevation: &ElevationState) -> CommandOutcome {
    for path in LOGROTATE_STATUS_PATHS {
        if tokio::fs::metadata(path).await.is_ok() {
            return run_and_present(elevation, "cat", &[path]).await;
        }
    }
    CommandOutcome::Err(format!(
        "No logrotate status file found (checked {}).",
        LOGROTATE_STATUS_PATHS.join(", ")
    ))
}

pub async fn archived_log_listing(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run_allow_failure(
            "find",
            &[
                "/var/log", "-type", "f", "(", "-name", "*.gz", "-o", "-name", "*.[0-9]", "-o",
                "-name", "*.old", ")",
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(
            output,
            "No rotated/archived log files found under /var/log.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn log_directory_sizes(elevation: &ElevationState) -> CommandOutcome {
    run_and_present(elevation, "du", &["-h", "--max-depth=1", "/var/log"]).await
}

pub async fn vacuum_journal_by_size(size: String, elevation: &ElevationState) -> CommandOutcome {
    // Defense in depth: the control plane already validates this before
    // dispatching, but this agent is the actual execution boundary and never
    // trusts a wire value on that basis alone.
    if !abyssal_agent_protocol::is_valid_vacuum_size(&size) {
        return CommandOutcome::Err(format!("refusing invalid vacuum size: {size}"));
    }
    if !command_exists("journalctl").await {
        return CommandOutcome::Err(
            "No systemd journal on this host -- vacuuming by size only applies to journald."
                .to_string(),
        );
    }
    let arg = format!("--vacuum-size={size}");
    match elevation.run("journalctl", &[&arg]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn vacuum_journal_by_time(
    duration: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_vacuum_duration(&duration) {
        return CommandOutcome::Err(format!("refusing invalid vacuum duration: {duration}"));
    }
    if !command_exists("journalctl").await {
        return CommandOutcome::Err(
            "No systemd journal on this host -- vacuuming by age only applies to journald."
                .to_string(),
        );
    }
    let arg = format!("--vacuum-time={duration}");
    match elevation.run("journalctl", &[&arg]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}
