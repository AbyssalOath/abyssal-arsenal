use tokio::process::Command;

use crate::{ExecutionError, OperationOutput};

/// Runs a process with an explicit argument vector — never a shell string —
/// so operations built on this can't be turned into command injection by a
/// crafted parameter. Callers are responsible for validating/sanitizing any
/// argument that came from user input before it reaches here.
pub async fn run_command(program: &str, args: &[&str]) -> Result<OperationOutput, ExecutionError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| ExecutionError::Failed(format!("failed to spawn {program}: {e}")))?;

    Ok(OperationOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
    })
}
