//! Container and container-runtime administration ("Necropolis"): list,
//! inspect, and control containers and images. Works with whichever of
//! Docker or Podman is present on the host -- their CLI syntax is
//! identical for every operation used here, so one code path covers both,
//! unlike firewall/init-system detection where the backends genuinely
//! differ.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::{command_exists, present};

const NO_RUNTIME: &str = "No container runtime (Docker or Podman) detected on this host.";

async fn detect_binary() -> Option<&'static str> {
    if command_exists("docker").await {
        Some("docker")
    } else if command_exists("podman").await {
        Some("podman")
    } else {
        None
    }
}

fn validate_container(container: &str) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_container_ref(container) {
        return Err(format!("refusing invalid container reference: {container}"));
    }
    Ok(())
}

async fn run(elevation: &ElevationState, args: &[&str]) -> CommandOutcome {
    let Some(bin) = detect_binary().await else {
        return CommandOutcome::Err(NO_RUNTIME.to_string());
    };
    match elevation.run(bin, args).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn list_containers(elevation: &ElevationState) -> CommandOutcome {
    run(
        elevation,
        &[
            "ps",
            "-a",
            "--format",
            "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
        ],
    )
    .await
}

/// `docker logs`/`podman logs` write the container's log stream to their
/// own stderr, not stdout (confirmed empirically -- this isn't a failure
/// case, just where the CLI puts real, successful output), so this can't
/// use the shared `run` helper, which only surfaces stdout on success.
pub async fn container_logs(container: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_container(&container) {
        return CommandOutcome::Err(e);
    }
    let Some(bin) = detect_binary().await else {
        return CommandOutcome::Err(NO_RUNTIME.to_string());
    };
    match elevation
        .run(bin, &["logs", "--tail", "100", container.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(output, "(no log output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn container_inspect(container: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_container(&container) {
        return CommandOutcome::Err(e);
    }
    run(elevation, &["inspect", container.as_str()]).await
}

pub async fn list_images(elevation: &ElevationState) -> CommandOutcome {
    run(elevation, &["images"]).await
}

pub async fn runtime_info(elevation: &ElevationState) -> CommandOutcome {
    run(elevation, &["info"]).await
}

/// Shared by the four lifecycle mutations below -- a genuine command
/// failure here (container not found, permission denied) really is an
/// error, so this goes through plain `elevation.run` rather than
/// `run_allow_failure`, same reasoning as Incarnation's service lifecycle.
async fn run_lifecycle_action(
    container: &str,
    verb_past_tense: &str,
    runtime_args: &[&str],
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_container(container) {
        return CommandOutcome::Err(e);
    }
    let Some(bin) = detect_binary().await else {
        return CommandOutcome::Err(NO_RUNTIME.to_string());
    };
    match elevation.run(bin, runtime_args).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("{verb_past_tense} {container}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn start_container(container: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(
        &container,
        "Started",
        &["start", container.as_str()],
        elevation,
    )
    .await
}

pub async fn stop_container(container: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(
        &container,
        "Stopped",
        &["stop", container.as_str()],
        elevation,
    )
    .await
}

pub async fn restart_container(container: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(
        &container,
        "Restarted",
        &["restart", container.as_str()],
        elevation,
    )
    .await
}

/// Deliberately no `-f` -- a currently-running container is refused by
/// the runtime rather than force-killed and removed in one step, keeping
/// "stop" and "remove" as two distinct, individually confirmed actions.
pub async fn remove_container(container: String, elevation: &ElevationState) -> CommandOutcome {
    run_lifecycle_action(
        &container,
        "Removed",
        &["rm", container.as_str()],
        elevation,
    )
    .await
}
