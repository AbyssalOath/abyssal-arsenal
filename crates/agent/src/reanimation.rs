//! Process and service management ("Reanimation"): the process half of
//! that description -- listing, inspecting, renicing, and signaling
//! individual processes. The service half is already Incarnation's job
//! (systemd unit lifecycle), so nothing here duplicates that.

use abyssal_agent_protocol::CommandOutcome;

use crate::elevation::ElevationState;
use crate::process::truncate_lines;

/// Header row + 40 processes -- deliberately more generous than
/// Mortiscope's top-15 truncation, since this is meant to be the "show me
/// everything" view, not a top-N ranking.
const PROCESS_LIST_LINES: usize = 41;

pub async fn list_processes(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("ps", &["-ef", "--forest"]).await {
        Ok(output) => CommandOutcome::Ok(truncate_lines(output, PROCESS_LIST_LINES)),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn validate_pid(pid: u32) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_pid(pid) {
        return Err(format!("refusing to operate on protected pid {pid}"));
    }
    if pid == std::process::id() {
        return Err("refusing to operate on the agent's own process".to_string());
    }
    Ok(())
}

pub async fn process_detail(pid: u32, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let pid_str = pid.to_string();
    match elevation
        .run(
            "ps",
            &[
                "-p",
                pid_str.as_str(),
                "-o",
                "pid,ppid,user,stat,%cpu,%mem,etime,lstart,cmd",
                "-ww",
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn validate_priority(priority: i32) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_nice_priority(priority) {
        return Err(format!(
            "refusing invalid nice priority {priority} (must be -20 to 19)"
        ));
    }
    Ok(())
}

pub async fn renice_priority(
    pid: u32,
    priority: i32,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_priority(priority) {
        return CommandOutcome::Err(e);
    }
    let pid_str = pid.to_string();
    let priority_str = priority.to_string();
    match elevation
        .run(
            "renice",
            &["-n", priority_str.as_str(), "-p", pid_str.as_str()],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn validate_signal(signal: &str) -> Result<String, String> {
    if !abyssal_agent_protocol::is_valid_signal_name(signal) {
        return Err(format!("refusing unrecognized signal: {signal}"));
    }
    let normalized = signal.to_ascii_uppercase();
    Ok(normalized
        .strip_prefix("SIG")
        .unwrap_or(&normalized)
        .to_string())
}

pub async fn send_signal(pid: u32, signal: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let signal = match validate_signal(&signal) {
        Ok(s) => s,
        Err(e) => return CommandOutcome::Err(e),
    };
    let pid_str = pid.to_string();
    match elevation
        .run("kill", &["-s", signal.as_str(), pid_str.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
            stdout: format!("Sent SIG{signal} to pid {pid}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}
