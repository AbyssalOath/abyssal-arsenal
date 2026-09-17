use abyssal_agent_protocol::{AgentOperation, CommandOutcome, OperationOutput};

/// Executes one of the fixed, whitelisted operations. This match is
/// exhaustive over `AgentOperation` on purpose — adding a capability means
/// adding a variant to the shared protocol crate *and* a branch here; there
/// is no path from a wire message to running something outside this list.
pub async fn run(operation: AgentOperation) -> CommandOutcome {
    match operation {
        AgentOperation::Ping => CommandOutcome::Ok(OperationOutput {
            stdout: "pong".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        AgentOperation::SystemInfo => system_info().await,
    }
}

async fn system_info() -> CommandOutcome {
    let uname = tokio::process::Command::new("uname")
        .arg("-a")
        .output()
        .await;

    match uname {
        Ok(output) => {
            let mut stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Ok(uptime_raw) = tokio::fs::read_to_string("/proc/uptime").await {
                if let Some(seconds) = uptime_raw.split_whitespace().next() {
                    stdout.push_str(&format!("\nuptime_seconds: {seconds}"));
                }
            }
            CommandOutcome::Ok(OperationOutput {
                stdout,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code(),
            })
        }
        Err(e) => CommandOutcome::Err(format!("failed to run uname: {e}")),
    }
}
