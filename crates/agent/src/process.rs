use abyssal_agent_protocol::OperationOutput;
use tokio::io::AsyncWriteExt;

/// Runs a process with an explicit argument vector -- never a shell string --
/// matching the same discipline the control plane's own local execution uses
/// (`crates/execution/src/process.rs`).
///
/// A non-zero exit is treated as a failure here, not just a spawn error.
/// Without this, a command that runs but fails partway (e.g. `hostnamectl`
/// refusing for lack of privilege) would come back as `CommandOutcome::Ok`
/// with empty-looking output -- silently reporting success for something
/// that didn't happen. That matters most for the destructive/write ops in
/// this crate: a failed firewall change or reboot must never be reported as
/// one that succeeded.
pub async fn run_command(program: &str, args: &[&str]) -> Result<OperationOutput, String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    finish(program, output)
}

/// Like `run_command`, but feeds `stdin_data` to the process's stdin before
/// waiting on it -- for the handful of tools that write to a destination
/// through stdin rather than an argument (`tee` being the standard one).
/// Kept separate from `elevation.rs`'s own stdin-piping code for `sudo -S`:
/// that one carries stricter requirements (the data is a password, wiped
/// with `Zeroizing`) that a general-purpose helper like this one shouldn't
/// have to account for.
pub async fn run_command_with_stdin(
    program: &str,
    args: &[&str],
    stdin_data: &str,
) -> Result<OperationOutput, String> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run {program}: {e}"))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| format!("failed to open stdin for {program}"))?;
        stdin
            .write_all(stdin_data.as_bytes())
            .await
            .map_err(|e| format!("failed to write to {program}'s stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("failed to wait for {program}: {e}"))?;
    finish(program, output)
}

/// Like `run_command`, but never turns a non-zero exit into an `Err` --
/// returns the raw stdout/stderr/exit code regardless of status. Some tools
/// use a non-zero exit to mean "ran fine, found nothing" rather than
/// "something went wrong" (`coredumpctl list` with zero recorded dumps,
/// `find` hitting a permission-denied subdirectory while still finding
/// everything else) -- callers that know they're dealing with one of those
/// should use this instead of `run_command` and interpret the result
/// themselves, rather than have a clean "nothing found" misreported as a
/// failure.
pub async fn run_command_allow_failure(
    program: &str,
    args: &[&str],
) -> Result<OperationOutput, String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    Ok(OperationOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
    })
}

/// Substitutes a friendly message when `output.stdout` is empty, falling
/// back to `stderr` if that has something more specific to say -- for
/// tools run via `run_command_allow_failure` whose "found nothing" and
/// "failed outright" cases both come back as empty stdout, so the caller
/// needs to present *something* useful either way rather than an empty box.
/// Shared by every read-only forensic/log op across Postmortem and
/// Obituary.
pub fn present(output: OperationOutput, empty_message: &str) -> OperationOutput {
    if output.stdout.trim().is_empty() {
        let stdout = if !output.stderr.trim().is_empty() {
            output.stderr.trim().to_string()
        } else {
            empty_message.to_string()
        };
        OperationOutput { stdout, ..output }
    } else {
        output
    }
}

fn finish(program: &str, output: std::process::Output) -> Result<OperationOutput, String> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        let detail = if !stderr.trim().is_empty() {
            stderr.trim()
        } else if !stdout.trim().is_empty() {
            stdout.trim()
        } else {
            "(no output)"
        };
        let status = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return Err(format!("{program} exited with status {status}: {detail}"));
    }

    Ok(OperationOutput {
        stdout,
        stderr,
        exit_code: output.status.code(),
    })
}

/// Checks whether a program is on `PATH` without running it -- used for
/// picking which of several possible tools (firewall backends, etc.) is
/// actually available on this host.
pub async fn command_exists(program: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(program)
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}
