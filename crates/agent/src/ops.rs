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
        AgentOperation::ResourceUsage => resource_usage().await,
        AgentOperation::LoggedInUsers => logged_in_users().await,
        AgentOperation::Reboot => reboot().await,
    }
}

/// Runs a process with an explicit argument vector -- never a shell string --
/// matching the same discipline the control plane's own local execution uses
/// (`crates/execution/src/process.rs`).
async fn run_command(program: &str, args: &[&str]) -> Result<OperationOutput, String> {
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

async fn system_info() -> CommandOutcome {
    match run_command("uname", &["-a"]).await {
        Ok(mut output) => {
            output.stdout = output.stdout.trim().to_string();
            if let Ok(uptime_raw) = tokio::fs::read_to_string("/proc/uptime").await {
                if let Some(seconds) = uptime_raw.split_whitespace().next() {
                    output
                        .stdout
                        .push_str(&format!("\nuptime_seconds: {seconds}"));
                }
            }
            CommandOutcome::Ok(output)
        }
        Err(e) => CommandOutcome::Err(e),
    }
}

async fn resource_usage() -> CommandOutcome {
    let memory = match run_command("free", &["-h"]).await {
        Ok(output) => output.stdout,
        Err(e) => return CommandOutcome::Err(e),
    };
    let disk = match run_command("df", &["-h"]).await {
        Ok(output) => output.stdout,
        Err(e) => return CommandOutcome::Err(e),
    };

    CommandOutcome::Ok(OperationOutput {
        stdout: format!(
            "== Memory ==\n{}\n== Disk ==\n{}",
            memory.trim_end(),
            disk.trim_end()
        ),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

async fn logged_in_users() -> CommandOutcome {
    match run_command("who", &[]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

async fn reboot() -> CommandOutcome {
    match run_command("systemctl", &["reboot"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}
