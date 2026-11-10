//! Which host operating systems each operation runs on.
//!
//! The control plane uses this to stop offering, and refuse to send, what a
//! host's OS can't run (`HostConnectionRegistry::dispatch`), and the agent
//! checks it too before running anything (`ops::run`), so the two can't
//! disagree. Like `min_protocol`, there's deliberately no `_` arm: a new
//! operation doesn't compile until it says where it runs.
//!
//! "Linux" here means the agent's Unix code path. An operation is `Both` only
//! when the agent has a real Windows implementation; one that would just run a
//! Linux tool on Windows (`ss`, `systemctl`, `/proc`) is `Linux`.

use crate::AgentOperation;

/// The operating systems an operation (or an arsenal) supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platforms {
    Linux,
    Windows,
    Both,
}

impl Platforms {
    /// Whether a host running `os` can use this. An unknown OS (an agent too
    /// old to report one, or macOS, which hasn't been checked) is always
    /// allowed: that's how every host was treated before this existed.
    pub fn allows(self, os: HostOs) -> bool {
        match (self, os) {
            (Platforms::Both, _) | (_, HostOs::Unknown) => true,
            (Platforms::Linux, HostOs::Linux) | (Platforms::Windows, HostOs::Windows) => true,
            (Platforms::Linux, HostOs::Windows) | (Platforms::Windows, HostOs::Linux) => false,
        }
    }

    /// "Linux", "Windows", or "Linux and Windows", for messages.
    pub const fn label(self) -> &'static str {
        match self {
            Platforms::Linux => "Linux",
            Platforms::Windows => "Windows",
            Platforms::Both => "Linux and Windows",
        }
    }
}

/// A host's operating system as far as platform support goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostOs {
    Linux,
    Windows,
    /// Not reported (an old agent), or an OS nothing has been checked on yet
    /// (macOS). Everything is allowed.
    #[default]
    Unknown,
}

impl HostOs {
    /// From `hosts.os` or the value the agent reports (`std::env::consts::OS`).
    pub fn parse(os: Option<&str>) -> Self {
        match os.map(str::trim) {
            Some(os) if os.eq_ignore_ascii_case("linux") => HostOs::Linux,
            Some(os) if os.eq_ignore_ascii_case("windows") => HostOs::Windows,
            _ => HostOs::Unknown,
        }
    }

    /// The OS this binary was built for, for the agent's own check.
    pub const fn current() -> Self {
        if cfg!(windows) {
            HostOs::Windows
        } else if cfg!(target_os = "linux") {
            HostOs::Linux
        } else {
            HostOs::Unknown
        }
    }

    /// "Linux", "Windows", or "unknown", for messages.
    pub const fn label(self) -> &'static str {
        match self {
            HostOs::Linux => "Linux",
            HostOs::Windows => "Windows",
            HostOs::Unknown => "unknown",
        }
    }
}

impl AgentOperation {
    /// The operating systems this operation runs on, as sent.
    pub fn platforms(&self) -> Platforms {
        use AgentOperation as Op;
        match self {
            // Turning the real-time event stream off works anywhere (there's
            // nothing to stop on Linux); turning it on needs Windows.
            Op::ThanatosStream { enabled: true, .. } => Platforms::Windows,
            Op::ThanatosStream { enabled: false, .. } => Platforms::Both,
            Op::DeleteQuarantinedFile { .. }
            | Op::SelfUpdate { .. }
            | Op::Ping
            | Op::SystemInfo
            | Op::ResourceUsage
            | Op::LoggedInUsers
            | Op::ListeningPorts
            | Op::RecentAuthLog
            | Op::Deescalate
            | Op::ElevationStatus
            | Op::MemoryDetail
            | Op::FailedServices
            | Op::SendSignal { .. }
            | Op::LockUserAccount { .. }
            | Op::UnlockUserAccount { .. }
            | Op::ListBlockedIps
            | Op::IsolationStatus
            | Op::ListQuarantinedFiles
            | Op::BlockRemoteIp { .. }
            | Op::UnblockRemoteIp { .. }
            | Op::QuarantineFile { .. }
            | Op::RestoreQuarantinedFile { .. }
            | Op::DeisolateHost
            | Op::IsolateHost
            | Op::ScanSecurityEvents { .. }
            | Op::CpuUtilization
            | Op::ListFailedUnits
            | Op::RecoverUnit { .. }
            | Op::DiskSpaceCritical
            | Op::UpdateTrustedCa { .. }
            | Op::UninstallAgent { .. }
            | Op::NeighborTable
            | Op::DhcpLeases
            | Op::PostureFacts => Platforms::Both,
            Op::DirectoryUsageBreakdown { .. }
            | Op::AdDnsReport { .. }
            | Op::AdHealthReport { .. }
            | Op::DirectoryDiscoverForest
            | Op::DirectoryTestDelegation { .. }
            | Op::DirectoryOuTree { .. }
            | Op::DirectorySearch { .. }
            | Op::DirectoryGetObject { .. }
            | Op::DirectoryUnlockAccount { .. }
            | Op::DirectorySetEnabled { .. }
            | Op::DirectorySetPassword { .. }
            | Op::DirectoryCreateUser(..)
            | Op::ExchangeTestConnection { .. }
            | Op::ExchangeEnableMailbox { .. }
            | Op::DirectoryCreateGroup(..)
            | Op::DirectoryDeleteGroup { .. }
            | Op::DirectoryAddGroupMember { .. }
            | Op::DirectoryRemoveGroupMember { .. }
            | Op::DirectoryMove { .. }
            | Op::DirectoryDeleteObject { .. }
            | Op::DirectoryOffboard { .. }
            | Op::DirectoryUndoOffboard(..)
            | Op::ExchangeSetMailboxOffboard { .. }
            | Op::DirectoryStaleAccounts { .. }
            | Op::DirectoryRotateServiceAccountPassword { .. } => Platforms::Windows,
            Op::DeleteSshKeypair { .. }
            | Op::SetHostname { .. }
            | Op::Reboot
            | Op::FirewallStatus
            | Op::FirewallAllowPort { .. }
            | Op::FirewallEnable
            | Op::Elevate { .. }
            | Op::NetworkInterfaces
            | Op::NetworkRoutes
            | Op::DnsConfig
            | Op::ActiveConnections
            | Op::ConnectivityCheck { .. }
            | Op::InterfaceSetState { .. }
            | Op::NetworkScan { .. }
            | Op::BootHistory
            | Op::KernelRingBuffer
            | Op::SystemJournalErrors
            | Op::FailedLoginAttempts
            | Op::OomKillEvents
            | Op::CoreDumps
            | Op::RecentlyModifiedFiles { .. }
            | Op::JournalDiskUsage
            | Op::LogRotationStatus
            | Op::ArchivedLogListing
            | Op::LogDirectorySizes
            | Op::VacuumJournalBySize { .. }
            | Op::VacuumJournalByTime { .. }
            | Op::ListBackups
            | Op::CreateBackup { .. }
            | Op::VerifyBackup { .. }
            | Op::RestoreBackup { .. }
            | Op::LoadAverage
            | Op::TopProcessesByCpu
            | Op::TopProcessesByMemory
            | Op::DiskIoStats
            | Op::ListServices
            | Op::ServiceStatus { .. }
            | Op::ServiceLogs { .. }
            | Op::StartService { .. }
            | Op::StopService { .. }
            | Op::RestartService { .. }
            | Op::EnableService { .. }
            | Op::DisableService { .. }
            | Op::PreviousBootErrors
            | Op::SystemRunningState
            | Op::ReadOnlyFilesystems
            | Op::ReloadSystemdDaemon
            | Op::ResetFailedUnits
            | Op::RemountReadWrite { .. }
            | Op::CpuInfo
            | Op::PciDevices
            | Op::BlockDevices
            | Op::MemoryHardware
            | Op::DiskHealth { .. }
            | Op::ListContainers
            | Op::ContainerLogs { .. }
            | Op::ContainerInspect { .. }
            | Op::ListImages
            | Op::RuntimeInfo
            | Op::StartContainer { .. }
            | Op::StopContainer { .. }
            | Op::RestartContainer { .. }
            | Op::RemoveContainer { .. }
            | Op::ListProcesses
            | Op::ProcessDetail { .. }
            | Op::RenicePriority { .. }
            | Op::CleanupTargetsSummary
            | Op::ForceLogRotation
            | Op::ClearTmpFiles { .. }
            | Op::ClearCoreDumps
            | Op::VmStatistics
            | Op::InterruptStatistics
            | Op::CpuGovernorStatus
            | Op::TuningParametersStatus
            | Op::SetSwappiness { .. }
            | Op::SetIoScheduler { .. }
            | Op::ListUsers
            | Op::ListGroups
            | Op::UserDetail { .. }
            | Op::CreateUser { .. }
            | Op::CreateGroup { .. }
            | Op::AddUserToGroup { .. }
            | Op::RemoveUserFromGroup { .. }
            | Op::DeleteUser { .. }
            | Op::DeleteGroup { .. }
            | Op::FindLargeFiles { .. }
            | Op::FilesystemCheckDryRun { .. }
            | Op::TrimFilesystem { .. }
            | Op::FilesystemRepair { .. }
            | Op::ListInstalledPackages
            | Op::SearchPackage { .. }
            | Op::PackageInfo { .. }
            | Op::ListUpgradable
            | Op::RefreshPackageIndex
            | Op::InstallPackage { .. }
            | Op::UpgradePackage { .. }
            | Op::RemovePackage { .. }
            | Op::PartitionTable { .. }
            | Op::LvmSummary
            | Op::RaidStatus
            | Op::MountFilesystem { .. }
            | Op::ExtendLogicalVolume { .. }
            | Op::UnmountFilesystem { .. }
            | Op::CreatePartition { .. }
            | Op::DeletePartition { .. }
            | Op::CreateRaidArray { .. }
            | Op::StopRaidArray { .. }
            | Op::CreatePhysicalVolume { .. }
            | Op::CreateVolumeGroup { .. }
            | Op::CreateLogicalVolume { .. }
            | Op::RemoveLogicalVolume { .. }
            | Op::RemoveVolumeGroup { .. }
            | Op::RemovePhysicalVolume { .. }
            | Op::CreateFilesystem { .. }
            | Op::ViewManagedSysctl
            | Op::ViewManagedCronJobs
            | Op::SetPersistentSysctl { .. }
            | Op::RemovePersistentSysctlKey { .. }
            | Op::ClearManagedSysctl
            | Op::SetCronJob { .. }
            | Op::RemoveCronJob { .. }
            | Op::ClearManagedCronJobs
            | Op::ListSshHostKeys
            | Op::ListSshAuthorizedKeys { .. }
            | Op::ListTlsCertificates
            | Op::CertificateDetail { .. }
            | Op::ScanSensitiveFilePermissions
            | Op::ViewSensitiveFile { .. }
            | Op::GenerateSshKeypair { .. }
            | Op::FixFilePermissions { .. }
            | Op::RemoveAuthorizedKey { .. }
            | Op::DetectPackageBackend
            | Op::RenderSepulchreConfig { .. }
            | Op::ClearSepulchreConfig { .. }
            | Op::CheckSepulchreConfigIncludeDirective { .. }
            | Op::CreateSftpChrootAccount { .. }
            | Op::InstallSepulchreAuthorizedKey { .. }
            | Op::RemoveSftpChrootAccount { .. }
            | Op::CreateSambaServiceUser { .. }
            | Op::RemoveSambaServiceUser { .. }
            | Op::RenderMountUnit { .. }
            | Op::RemoveMountUnit { .. }
            | Op::CheckMountStatus { .. }
            | Op::CreateSepulchreShareDirectory { .. }
            | Op::WriteSepulchreMountCredentials { .. }
            | Op::FirewallDenyPort { .. }
            | Op::FirewallRemovePort { .. }
            | Op::SshdConfigAudit
            | Op::HardenSshd { .. }
            | Op::ClearSshHardening
            | Op::SysctlSecurityPosture
            | Op::AccountPolicyAudit
            | Op::MacStatus
            | Op::AutomaticUpdatesStatus
            | Op::NetworkThroughput
            | Op::ThermalSensors
            | Op::MemoryPressure
            | Op::SignalByName { .. }
            | Op::SetIoPriority { .. }
            | Op::SetOomScoreAdj { .. }
            | Op::ProcessOpenFiles { .. }
            | Op::ProcessLimits { .. }
            | Op::ZombieReport
            | Op::SysctlManagedDrift
            | Op::ViewModuleBlacklist
            | Op::BlacklistModule { .. }
            | Op::RemoveModuleBlacklist { .. }
            | Op::ClearModuleBlacklist
            | Op::ViewJournaldConfig
            | Op::SetJournaldRetention { .. }
            | Op::ClearJournaldConfig
            | Op::FstabCheck
            | Op::ScourgeSensorStatus
            | Op::ScourgeCollectEvents { .. }
            | Op::ScourgeListRules { .. }
            | Op::ScourgePcapList
            | Op::ScourgeInstall
            | Op::ScourgeApplyConfig { .. }
            | Op::ScourgeServiceAction { .. }
            | Op::ScourgeUpdateRules
            | Op::ScourgeSetSidEnabled { .. }
            | Op::ScourgeSuppressSid { .. }
            | Op::ScourgeRuleTest { .. }
            | Op::ScourgeCaptureStart { .. }
            | Op::ScourgeCaptureStatus { .. }
            | Op::ScourgeCaptureCancel { .. }
            | Op::ScourgePcapDelete { .. }
            | Op::ScourgePcapRead { .. }
            | Op::ScourgeIpsStatus
            | Op::ScourgeSetMode { .. }
            | Op::ScourgeSetSidAction { .. } => Platforms::Linux,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_matrix() {
        use HostOs::*;
        assert!(Platforms::Both.allows(Linux) && Platforms::Both.allows(Windows));
        assert!(Platforms::Linux.allows(Linux) && !Platforms::Linux.allows(Windows));
        assert!(Platforms::Windows.allows(Windows) && !Platforms::Windows.allows(Linux));
        // Unknown OS: today's behaviour, everything allowed.
        for p in [Platforms::Linux, Platforms::Windows, Platforms::Both] {
            assert!(p.allows(Unknown));
        }
    }

    #[test]
    fn parses_host_os() {
        assert_eq!(HostOs::parse(Some("linux")), HostOs::Linux);
        assert_eq!(HostOs::parse(Some("Windows")), HostOs::Windows);
        assert_eq!(HostOs::parse(Some("macos")), HostOs::Unknown);
        assert_eq!(HostOs::parse(Some("")), HostOs::Unknown);
        assert_eq!(HostOs::parse(None), HostOs::Unknown);
    }

    /// Pins the audit's answers for a sample of each kind, so moving an
    /// operation between platforms is a deliberate change here too.
    #[test]
    fn pins_the_audit() {
        let both = [
            AgentOperation::Ping,
            AgentOperation::SystemInfo,
            AgentOperation::PostureFacts,
            AgentOperation::MemoryDetail,
            AgentOperation::FailedServices,
            AgentOperation::IsolateHost,
            AgentOperation::SendSignal {
                pid: 1,
                signal: "TERM".into(),
            },
            AgentOperation::LockUserAccount {
                username: "x".into(),
            },
            AgentOperation::ThanatosStream {
                enabled: false,
                c2_ports: vec![],
            },
        ];
        for op in &both {
            assert_eq!(op.platforms(), Platforms::Both, "{op:?}");
        }
        let linux = [
            AgentOperation::LoadAverage,
            AgentOperation::ThermalSensors,
            AgentOperation::MemoryPressure,
            AgentOperation::ListProcesses,
            AgentOperation::ListServices,
            AgentOperation::FirewallStatus,
            AgentOperation::Reboot,
            AgentOperation::ScourgeSensorStatus,
            AgentOperation::ListContainers,
            AgentOperation::Elevate {
                password: String::new(),
                idle_timeout_secs: 0,
            },
        ];
        for op in &linux {
            assert_eq!(op.platforms(), Platforms::Linux, "{op:?}");
        }
        let windows = [
            AgentOperation::AdHealthReport {
                domain: "corp.example".into(),
            },
            AgentOperation::DirectoryDiscoverForest,
            AgentOperation::ThanatosStream {
                enabled: true,
                c2_ports: vec![],
            },
        ];
        for op in &windows {
            assert_eq!(op.platforms(), Platforms::Windows, "{op:?}");
        }
    }
}
