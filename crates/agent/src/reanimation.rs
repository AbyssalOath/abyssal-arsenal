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

#[cfg(unix)]
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

/// Windows has no POSIX signal delivery at all -- `Stop-Process -Force`
/// is a forced termination, not a signal, so only the two signal names
/// that already mean "terminate this process" on Unix (`KILL`/`TERM`)
/// have any real Windows equivalent. Any other validated-but-not-
/// terminating signal (`HUP`/`USR1`/`STOP`/...) is refused with a clear
/// reason rather than silently terminating the process anyway, which
/// would be a surprising and platform-inconsistent side effect for a
/// caller that asked for something else entirely.
#[cfg(windows)]
pub async fn send_signal(pid: u32, signal: String, _elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let signal = match validate_signal(&signal) {
        Ok(s) => s,
        Err(e) => return CommandOutcome::Err(e),
    };
    if !matches!(signal.as_str(), "KILL" | "TERM") {
        return CommandOutcome::Err(format!(
            "SIG{signal} has no Windows equivalent -- only KILL/TERM (both map to a forced \
             process termination via Stop-Process) are supported on this platform"
        ));
    }
    let script = crate::process::ps_checked(&format!("Stop-Process -Id {pid} -Force"));
    match crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    )
    .await
    {
        Ok(output) => CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
            stdout: format!("Terminated pid {pid} (SIG{signal}).\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}
