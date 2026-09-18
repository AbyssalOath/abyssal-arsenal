use abyssal_agent_protocol::{AgentOperation, CommandOutcome, OperationOutput};
use zeroize::Zeroizing;

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::{
    apothecary, catacomb, defleshing, firewall, incarnation, mortiscope, necropolis, necropsy,
    network, obituary, ossuary, parish, postmortem, process::run_command, reanimation, reliquary,
    resurrection, vivisection,
};

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
        AgentOperation::ListBackups => reliquary::list_backups(elevation).await,
        AgentOperation::CreateBackup { source_path, name } => {
            reliquary::create_backup(source_path, name, elevation).await
        }
        AgentOperation::VerifyBackup { filename } => {
            reliquary::verify_backup(filename, elevation).await
        }
        AgentOperation::RestoreBackup {
            filename,
            target_path,
        } => reliquary::restore_backup(filename, target_path, elevation).await,
        AgentOperation::LoadAverage => mortiscope::load_average(elevation).await,
        AgentOperation::TopProcessesByCpu => mortiscope::top_processes_by_cpu(elevation).await,
        AgentOperation::TopProcessesByMemory => {
            mortiscope::top_processes_by_memory(elevation).await
        }
        AgentOperation::MemoryDetail => mortiscope::memory_detail(elevation).await,
        AgentOperation::DiskIoStats => mortiscope::disk_io_stats(elevation).await,
        AgentOperation::FailedServices => mortiscope::failed_services(elevation).await,
        AgentOperation::ListServices => incarnation::list_services(elevation).await,
        AgentOperation::ServiceStatus { unit } => {
            incarnation::service_status(unit, elevation).await
        }
        AgentOperation::ServiceLogs { unit } => incarnation::service_logs(unit, elevation).await,
        AgentOperation::StartService { unit } => incarnation::start_service(unit, elevation).await,
        AgentOperation::StopService { unit } => incarnation::stop_service(unit, elevation).await,
        AgentOperation::RestartService { unit } => {
            incarnation::restart_service(unit, elevation).await
        }
        AgentOperation::EnableService { unit } => {
            incarnation::enable_service(unit, elevation).await
        }
        AgentOperation::DisableService { unit } => {
            incarnation::disable_service(unit, elevation).await
        }
        AgentOperation::PreviousBootErrors => resurrection::previous_boot_errors(elevation).await,
        AgentOperation::SystemRunningState => resurrection::system_running_state(elevation).await,
        AgentOperation::ReadOnlyFilesystems => resurrection::read_only_filesystems(elevation).await,
        AgentOperation::ReloadSystemdDaemon => resurrection::reload_systemd_daemon(elevation).await,
        AgentOperation::ResetFailedUnits => resurrection::reset_failed_units(elevation).await,
        AgentOperation::RemountReadWrite { target } => {
            resurrection::remount_read_write(target, elevation).await
        }
        AgentOperation::CpuInfo => necropsy::cpu_info(elevation).await,
        AgentOperation::PciDevices => necropsy::pci_devices(elevation).await,
        AgentOperation::BlockDevices => necropsy::block_devices(elevation).await,
        AgentOperation::MemoryHardware => necropsy::memory_hardware(elevation).await,
        AgentOperation::DiskHealth { device } => necropsy::disk_health(device, elevation).await,
        AgentOperation::ListContainers => necropolis::list_containers(elevation).await,
        AgentOperation::ContainerLogs { container } => {
            necropolis::container_logs(container, elevation).await
        }
        AgentOperation::ContainerInspect { container } => {
            necropolis::container_inspect(container, elevation).await
        }
        AgentOperation::ListImages => necropolis::list_images(elevation).await,
        AgentOperation::RuntimeInfo => necropolis::runtime_info(elevation).await,
        AgentOperation::StartContainer { container } => {
            necropolis::start_container(container, elevation).await
        }
        AgentOperation::StopContainer { container } => {
            necropolis::stop_container(container, elevation).await
        }
        AgentOperation::RestartContainer { container } => {
            necropolis::restart_container(container, elevation).await
        }
        AgentOperation::RemoveContainer { container } => {
            necropolis::remove_container(container, elevation).await
        }
        AgentOperation::ListProcesses => reanimation::list_processes(elevation).await,
        AgentOperation::ProcessDetail { pid } => reanimation::process_detail(pid, elevation).await,
        AgentOperation::RenicePriority { pid, priority } => {
            reanimation::renice_priority(pid, priority, elevation).await
        }
        AgentOperation::SendSignal { pid, signal } => {
            reanimation::send_signal(pid, signal, elevation).await
        }
        AgentOperation::CleanupTargetsSummary => {
            defleshing::cleanup_targets_summary(elevation).await
        }
        AgentOperation::ForceLogRotation => defleshing::force_log_rotation(elevation).await,
        AgentOperation::ClearTmpFiles { older_than_days } => {
            defleshing::clear_tmp_files(older_than_days, elevation).await
        }
        AgentOperation::ClearCoreDumps => defleshing::clear_core_dumps(elevation).await,
        AgentOperation::VmStatistics => vivisection::vm_statistics(elevation).await,
        AgentOperation::InterruptStatistics => vivisection::interrupt_statistics(elevation).await,
        AgentOperation::CpuGovernorStatus => vivisection::cpu_governor_status(elevation).await,
        AgentOperation::TuningParametersStatus => {
            vivisection::tuning_parameters_status(elevation).await
        }
        AgentOperation::SetSwappiness { value } => {
            vivisection::set_swappiness(value, elevation).await
        }
        AgentOperation::SetIoScheduler { device, scheduler } => {
            vivisection::set_io_scheduler(device, scheduler, elevation).await
        }
        AgentOperation::ListUsers => parish::list_users(elevation).await,
        AgentOperation::ListGroups => parish::list_groups(elevation).await,
        AgentOperation::UserDetail { username } => parish::user_detail(username, elevation).await,
        AgentOperation::CreateUser { username, comment } => {
            parish::create_user(username, comment, elevation).await
        }
        AgentOperation::CreateGroup { group } => parish::create_group(group, elevation).await,
        AgentOperation::AddUserToGroup { username, group } => {
            parish::add_user_to_group(username, group, elevation).await
        }
        AgentOperation::RemoveUserFromGroup { username, group } => {
            parish::remove_user_from_group(username, group, elevation).await
        }
        AgentOperation::LockUserAccount { username } => {
            parish::lock_user_account(username, elevation).await
        }
        AgentOperation::UnlockUserAccount { username } => {
            parish::unlock_user_account(username, elevation).await
        }
        AgentOperation::DeleteUser {
            username,
            remove_home,
        } => parish::delete_user(username, remove_home, elevation).await,
        AgentOperation::DeleteGroup { group } => parish::delete_group(group, elevation).await,
        AgentOperation::DirectoryUsageBreakdown { path } => {
            catacomb::directory_usage_breakdown(path, elevation).await
        }
        AgentOperation::FindLargeFiles { path, min_size_mb } => {
            catacomb::find_large_files(path, min_size_mb, elevation).await
        }
        AgentOperation::FilesystemCheckDryRun { device } => {
            catacomb::filesystem_check_dry_run(device, elevation).await
        }
        AgentOperation::TrimFilesystem { mountpoint } => {
            catacomb::trim_filesystem(mountpoint, elevation).await
        }
        AgentOperation::FilesystemRepair { device } => {
            catacomb::filesystem_repair(device, elevation).await
        }
        AgentOperation::ListInstalledPackages => {
            apothecary::list_installed_packages(elevation).await
        }
        AgentOperation::SearchPackage { query } => {
            apothecary::search_package(query, elevation).await
        }
        AgentOperation::PackageInfo { package } => {
            apothecary::package_info(package, elevation).await
        }
        AgentOperation::ListUpgradable => apothecary::list_upgradable(elevation).await,
        AgentOperation::RefreshPackageIndex => apothecary::refresh_package_index(elevation).await,
        AgentOperation::InstallPackage { package } => {
            apothecary::install_package(package, elevation).await
        }
        AgentOperation::UpgradePackage { package } => {
            apothecary::upgrade_package(package, elevation).await
        }
        AgentOperation::RemovePackage { package } => {
            apothecary::remove_package(package, elevation).await
        }
        AgentOperation::PartitionTable { device } => {
            ossuary::partition_table(device, elevation).await
        }
        AgentOperation::LvmSummary => ossuary::lvm_summary(elevation).await,
        AgentOperation::RaidStatus => ossuary::raid_status(elevation).await,
        AgentOperation::MountFilesystem { device, target } => {
            ossuary::mount_filesystem(device, target, elevation).await
        }
        AgentOperation::ExtendLogicalVolume { lv_path, size } => {
            ossuary::extend_logical_volume(lv_path, size, elevation).await
        }
        AgentOperation::UnmountFilesystem { target } => {
            ossuary::unmount_filesystem(target, elevation).await
        }
        AgentOperation::CreatePartition { device, start, end } => {
            ossuary::create_partition(device, start, end, elevation).await
        }
        AgentOperation::DeletePartition {
            device,
            partition_number,
        } => ossuary::delete_partition(device, partition_number, elevation).await,
        AgentOperation::CreateRaidArray {
            array_name,
            level,
            devices,
        } => ossuary::create_raid_array(array_name, level, devices, elevation).await,
        AgentOperation::StopRaidArray { array_name } => {
            ossuary::stop_raid_array(array_name, elevation).await
        }
        AgentOperation::CreatePhysicalVolume { device } => {
            ossuary::create_physical_volume(device, elevation).await
        }
        AgentOperation::CreateVolumeGroup {
            name,
            physical_volumes,
        } => ossuary::create_volume_group(name, physical_volumes, elevation).await,
        AgentOperation::CreateLogicalVolume {
            vg_name,
            lv_name,
            size,
        } => ossuary::create_logical_volume(vg_name, lv_name, size, elevation).await,
        AgentOperation::RemoveLogicalVolume { lv_path } => {
            ossuary::remove_logical_volume(lv_path, elevation).await
        }
        AgentOperation::RemoveVolumeGroup { name } => {
            ossuary::remove_volume_group(name, elevation).await
        }
        AgentOperation::RemovePhysicalVolume { device } => {
            ossuary::remove_physical_volume(device, elevation).await
        }
        AgentOperation::CreateFilesystem { device, fstype } => {
            ossuary::create_filesystem(device, fstype, elevation).await
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
