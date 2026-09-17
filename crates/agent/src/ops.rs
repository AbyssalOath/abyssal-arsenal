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
        AgentOperation::SetHostname { hostname } => set_hostname(hostname).await,
        AgentOperation::Reboot => reboot().await,
    }
}

/// Runs a process with an explicit argument vector -- never a shell string --
/// matching the same discipline the control plane's own local execution uses
/// (`crates/execution/src/process.rs`).
///
/// A non-zero exit is treated as a failure here, not just a spawn error.
/// Without this, a command that runs but fails partway (e.g. `hostnamectl`
/// refusing for lack of privilege) would come back as `CommandOutcome::Ok`
/// with empty-looking output -- silently reporting success for something
/// that didn't happen. That's especially dangerous for `Reboot`: a failed
/// reboot must never be reported as one that succeeded.
async fn run_command(program: &str, args: &[&str]) -> Result<OperationOutput, String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("failed to run {program}: {e}"))?;

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

async fn set_hostname(hostname: String) -> CommandOutcome {
    // Defense in depth: the control plane already validates this before
    // dispatching, but this agent is the actual execution boundary and never
    // trusts a wire value on that basis alone.
    if !abyssal_agent_protocol::is_valid_hostname(&hostname) {
        return CommandOutcome::Err(format!("refusing to set invalid hostname: {hostname}"));
    }

    match run_command("hostnamectl", &["set-hostname", &hostname]).await {
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
