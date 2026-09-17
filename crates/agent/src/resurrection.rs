//! Disaster recovery and restoration of failed systems ("Resurrection"):
//! triage and recovery actions for a host that's currently in a degraded
//! or failed state. Distinct from Postmortem (after-the-fact forensics of
//! what already happened) and Incarnation (routine day-to-day service
//! lifecycle) -- this is what you reach for when a host won't come back
//! cleanly on its own.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::process::present;

const NO_SYSTEMD: &str = "No systemd on this host -- this check only applies to systemd.";

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

/// `journalctl`'s exit status for a boot index that doesn't exist (e.g.
/// `-1` on a host that's only booted once) reflects "no such boot," not a
/// command failure -- goes through `run_allow_failure` and presents
/// whatever came back rather than treating that as an error.
pub async fn previous_boot_errors(elevation: &ElevationState) -> CommandOutcome {
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    run_and_present(
        elevation,
        "journalctl",
        &["-b", "-1", "-p", "err", "--no-pager"],
    )
    .await
}

/// `systemctl is-system-running`'s exit code reflects overall state
/// (0 = running, non-zero for degraded/maintenance/starting/...), not
/// command success -- same reasoning as Incarnation's `ServiceStatus`.
pub async fn system_running_state(elevation: &ElevationState) -> CommandOutcome {
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    run_and_present(elevation, "systemctl", &["is-system-running"]).await
}

/// `findmnt` exits non-zero when nothing matches the `--options ro`
/// filter, which here means "nothing is read-only" -- a normal, good
/// result, not a failure.
pub async fn read_only_filesystems(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run_allow_failure(
            "findmnt",
            &[
                "--raw",
                "--noheadings",
                "--options",
                "ro",
                "--output",
                "TARGET,SOURCE,FSTYPE,OPTIONS",
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(
            output,
            "No filesystems are currently mounted read-only.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn reload_systemd_daemon(elevation: &ElevationState) -> CommandOutcome {
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    match elevation.run("systemctl", &["daemon-reload"]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("systemd unit files reloaded.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn reset_failed_units(elevation: &ElevationState) -> CommandOutcome {
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    match elevation.run("systemctl", &["reset-failed"]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Failed-unit state cleared.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remount_read_write(target: String, elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_mount_target(&target) {
        return CommandOutcome::Err(format!("refusing invalid mount target: {target}"));
    }
    match elevation
        .run("mount", &["-o", "remount,rw", target.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Remounted {target} read-write.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}
