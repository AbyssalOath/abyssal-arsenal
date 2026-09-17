use abyssal_agent_protocol::{AgentOperation, CommandOutcome, OperationOutput};
use zeroize::Zeroizing;

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::{firewall, network, obituary, postmortem, process::run_command};

/// Executes one of the fixed, whitelisted operations. This match is
/// exhaustive over `AgentOperation` on purpose — adding a capability means
/// adding a variant to the shared protocol crate *and* a branch here; there
/// is no path from a wire message to running something outside this list.
pub async fn run(operation: AgentOperation, elevation: &ElevationState) -> CommandOutcome {
    match operation {
        AgentOperation::Ping => CommandOutcome::Ok(OperationOutput {
            stdout: "pong".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        AgentOperation::SystemInfo => system_info().await,
        AgentOperation::ResourceUsage => resource_usage().await,
        AgentOperation::LoggedInUsers => logged_in_users().await,
        AgentOperation::SetHostname { hostname } => set_hostname(hostname, elevation).await,
        AgentOperation::Reboot => reboot(elevation).await,
        AgentOperation::ListeningPorts => listening_ports().await,
        AgentOperation::RecentAuthLog => recent_auth_log().await,
        AgentOperation::FirewallStatus => firewall::status(elevation).await,
        AgentOperation::FirewallAllowPort { port, protocol } => {
            firewall::allow_port(port, &protocol, elevation).await
        }
        AgentOperation::FirewallEnable => firewall::enable(elevation).await,
        AgentOperation::Elevate {
            password,
            idle_timeout_secs,
        } => elevate(password, idle_timeout_secs, elevation).await,
        AgentOperation::Deescalate => deescalate(elevation).await,
        AgentOperation::ElevationStatus => elevation_status(elevation).await,
        AgentOperation::NetworkInterfaces => network::interfaces().await,
        AgentOperation::NetworkRoutes => network::routes().await,
        AgentOperation::DnsConfig => network::dns_config().await,
        AgentOperation::ActiveConnections => network::active_connections().await,
        AgentOperation::ConnectivityCheck { target } => network::connectivity_check(target).await,
        AgentOperation::InterfaceSetState { interface, up } => {
            network::interface_set_state(interface, up, elevation).await
        }
        AgentOperation::NetworkScan { target, ports } => {
            network::network_scan(target, ports, elevation).await
        }
        AgentOperation::BootHistory => postmortem::boot_history().await,
        AgentOperation::KernelRingBuffer => postmortem::kernel_ring_buffer(elevation).await,
        AgentOperation::SystemJournalErrors => postmortem::system_journal_errors(elevation).await,
        AgentOperation::FailedLoginAttempts => postmortem::failed_login_attempts(elevation).await,
        AgentOperation::OomKillEvents => postmortem::oom_kill_events(elevation).await,
        AgentOperation::CoreDumps => postmortem::core_dumps(elevation).await,
        AgentOperation::RecentlyModifiedFiles { hours } => {
            postmortem::recently_modified_files(hours, elevation).await
        }
        AgentOperation::JournalDiskUsage => obituary::journal_disk_usage(elevation).await,
        AgentOperation::LogRotationStatus => obituary::log_rotation_status(elevation).await,
        AgentOperation::ArchivedLogListing => obituary::archived_log_listing(elevation).await,
        AgentOperation::LogDirectorySizes => obituary::log_directory_sizes(elevation).await,
        AgentOperation::VacuumJournalBySize { size } => {
            obituary::vacuum_journal_by_size(size, elevation).await
        }
        AgentOperation::VacuumJournalByTime { duration } => {
            obituary::vacuum_journal_by_time(duration, elevation).await
        }
    }
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

async fn set_hostname(hostname: String, elevation: &ElevationState) -> CommandOutcome {
    // Defense in depth: the control plane already validates this before
    // dispatching, but this agent is the actual execution boundary and never
    // trusts a wire value on that basis alone.
    if !abyssal_agent_protocol::is_valid_hostname(&hostname) {
        return CommandOutcome::Err(format!("refusing to set invalid hostname: {hostname}"));
    }

    match init_system::detect().await {
        InitSystem::Systemd => {
            match elevation
                .run("hostnamectl", &["set-hostname", &hostname])
                .await
            {
                Ok(output) => CommandOutcome::Ok(output),
                Err(e) => CommandOutcome::Err(e),
            }
        }
        // No systemd machinery to hand this to -- set the live hostname
        // directly and persist it the traditional way `/etc/hostname` is
        // read by virtually every non-systemd init's boot scripts.
        InitSystem::Other => {
            if let Err(e) = elevation.run("hostname", &[&hostname]).await {
                return CommandOutcome::Err(format!("failed to set runtime hostname: {e}"));
            }
            match elevation
                .run_with_stdin("tee", &["/etc/hostname"], &format!("{hostname}\n"))
                .await
            {
                Ok(_) => CommandOutcome::Ok(OperationOutput {
                    stdout: format!(
                        "Hostname set to {hostname} (runtime) and persisted to /etc/hostname."
                    ),
                    stderr: String::new(),
                    exit_code: Some(0),
                }),
                Err(e) => CommandOutcome::Err(format!(
                    "runtime hostname was set, but persisting to /etc/hostname failed: {e}"
                )),
            }
        }
    }
}

async fn reboot(elevation: &ElevationState) -> CommandOutcome {
    let result = match init_system::detect().await {
        InitSystem::Systemd => elevation.run("systemctl", &["reboot"]).await,
        // `reboot` (util-linux) works the same regardless of which
        // non-systemd init is actually running.
        InitSystem::Other => elevation.run("reboot", &[]).await,
    };
    match result {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

async fn elevate(
    password: String,
    idle_timeout_secs: u64,
    elevation: &ElevationState,
) -> CommandOutcome {
    let password = Zeroizing::new(password);
    let idle_timeout = std::time::Duration::from_secs(idle_timeout_secs);
    match elevation.elevate(password, idle_timeout).await {
        Ok(()) => CommandOutcome::Ok(OperationOutput {
            stdout: "Elevated.".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

async fn deescalate(elevation: &ElevationState) -> CommandOutcome {
    elevation.deescalate().await;
    CommandOutcome::Ok(OperationOutput {
        stdout: "De-escalated.".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

async fn elevation_status(elevation: &ElevationState) -> CommandOutcome {
    CommandOutcome::Ok(OperationOutput {
        stdout: elevation.status_text().await,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

async fn listening_ports() -> CommandOutcome {
    match run_command("ss", &["-tulpn"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

async fn recent_auth_log() -> CommandOutcome {
    match run_command("journalctl", &["-u", "sshd", "-n", "30", "--no-pager"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}
