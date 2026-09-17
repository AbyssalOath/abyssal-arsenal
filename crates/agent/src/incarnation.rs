//! Application and service deployment and provisioning ("Incarnation"):
//! systemd service lifecycle management -- list, inspect, and control the
//! services that make up whatever's actually deployed on a host. Doesn't
//! assume any particular application stack (npm, pip, Docker, ...) --
//! systemd units are the one deployment mechanism universal enough across
//! the hosts this app targets to manage generically, the same reasoning
//! that kept firewall/init-system handling detect-first instead of
//! assuming one. Non-systemd hosts get a clear "not applicable" message
//! rather than a raw command-not-found error.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::process::present;

const NO_SYSTEMD: &str = "No systemd on this host -- service management only applies to systemd.";

/// `systemctl status` (and, more subtly, `journalctl`'s exit status in some
/// configurations) uses a non-zero exit to reflect unit *state*, not
/// command failure -- a stopped unit is a perfectly normal result, not an
/// error. Every read op here goes through `run_allow_failure` and presents
/// whatever came back rather than treating that as a hard failure.
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

fn validate_unit(unit: &str) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_unit_name(unit) {
        return Err(format!("refusing invalid unit name: {unit}"));
    }
    Ok(())
}

pub async fn list_services(elevation: &ElevationState) -> CommandOutcome {
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    run_and_present(
        elevation,
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
        ],
    )
    .await
}

pub async fn service_status(unit: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_unit(&unit) {
        return CommandOutcome::Err(e);
    }
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    run_and_present(
        elevation,
        "systemctl",
        &["status", unit.as_str(), "--no-pager"],
    )
    .await
}

pub async fn service_logs(unit: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_unit(&unit) {
        return CommandOutcome::Err(e);
    }
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    run_and_present(
        elevation,
        "journalctl",
        &["-u", unit.as_str(), "-n", "50", "--no-pager"],
    )
    .await
}

/// Shared by the five lifecycle mutations below -- a genuine command
/// failure here (unit not found, permission denied) really is an error,
/// unlike the read ops above, so this goes through plain `elevation.run`
/// rather than `run_allow_failure`.
async fn run_lifecycle_action(
    unit: &str,
    verb_past_tense: &str,
    systemctl_args: &[&str],
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_unit(unit) {
        return CommandOutcome::Err(e);
    }
    if init_system::detect().await != InitSystem::Systemd {
        return CommandOutcome::Err(NO_SYSTEMD.to_string());
    }
    match elevation.run("systemctl", systemctl_args).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("{verb_past_tense} {unit}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn start_service(unit: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(&unit, "Started", &["start", unit.as_str()], elevation).await
}

pub async fn stop_service(unit: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(&unit, "Stopped", &["stop", unit.as_str()], elevation).await
}

pub async fn restart_service(unit: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(&unit, "Restarted", &["restart", unit.as_str()], elevation).await
}

pub async fn enable_service(unit: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(&unit, "Enabled", &["enable", unit.as_str()], elevation).await
}

pub async fn disable_service(unit: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(&unit, "Disabled", &["disable", unit.as_str()], elevation).await
}
