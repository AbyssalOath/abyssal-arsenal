//! Which agent protocol version each operation needs.
//!
//! The control plane checks this before sending anything
//! (`HostConnectionRegistry::dispatch`): an agent too old for an operation
//! gets a clear "update the agent" instead of a message it can't parse (which
//! made agents before 0.2.2 drop their connection). One table instead of a
//! version check next to every feature.
//!
//! The numbers come from the git history of this crate: each operation's
//! version is the lowest `PROTOCOL_VERSION` from which every build has had it.
//! There's deliberately no `_` arm, so a new operation doesn't compile until
//! it's given the `PROTOCOL_VERSION` it ships in -- bump that constant and
//! use the new value. A field that changes what an older agent would do with
//! the operation gets its own arm above the rest.

use crate::AgentOperation;

impl AgentOperation {
    /// The lowest agent protocol version that can carry out this operation
    /// as sent.
    pub fn min_protocol(&self) -> u32 {
        use AgentOperation as Op;
        match self {
            // Older agents would ignore these fields and do something else:
            // plain-delete instead of shredding (39), download from GitHub
            // instead of the control plane (43).
            Op::DeleteQuarantinedFile {
                shred_passes: 1.., ..
            }
            | Op::DeleteSshKeypair {
                shred_passes: 1.., ..
            } => 39,
            Op::SelfUpdate {
                from_control_plane: true,
                ..
            } => 43,
            Op::Ping | Op::SystemInfo => 0,
            Op::ResourceUsage
            | Op::LoggedInUsers
            | Op::SetHostname { .. }
            | Op::Reboot
            | Op::ListeningPorts
            | Op::RecentAuthLog
            | Op::FirewallStatus
            | Op::FirewallAllowPort { .. }
            | Op::FirewallEnable
            | Op::Elevate { .. }
            | Op::Deescalate
            | Op::ElevationStatus
            | Op::NetworkInterfaces
            | Op::NetworkRoutes
            | Op::DnsConfig
            | Op::ActiveConnections
            | Op::ConnectivityCheck { .. }
            | Op::InterfaceSetState { .. }
            | Op::NetworkScan { .. } => 1,
            Op::BootHistory
            | Op::KernelRingBuffer
            | Op::SystemJournalErrors
            | Op::FailedLoginAttempts
            | Op::OomKillEvents
            | Op::CoreDumps
            | Op::RecentlyModifiedFiles { .. } => 2,
            Op::JournalDiskUsage
            | Op::LogRotationStatus
            | Op::ArchivedLogListing
            | Op::LogDirectorySizes
            | Op::VacuumJournalBySize { .. }
            | Op::VacuumJournalByTime { .. } => 3,
            Op::ListBackups
            | Op::CreateBackup { .. }
            | Op::VerifyBackup { .. }
            | Op::RestoreBackup { .. } => 4,
            Op::LoadAverage
            | Op::TopProcessesByCpu
            | Op::TopProcessesByMemory
            | Op::MemoryDetail
            | Op::DiskIoStats
            | Op::FailedServices => 5,
            Op::ListServices
            | Op::ServiceStatus { .. }
            | Op::ServiceLogs { .. }
            | Op::StartService { .. }
            | Op::StopService { .. }
            | Op::RestartService { .. }
            | Op::EnableService { .. }
            | Op::DisableService { .. } => 6,
            Op::PreviousBootErrors
            | Op::SystemRunningState
            | Op::ReadOnlyFilesystems
            | Op::ReloadSystemdDaemon
            | Op::ResetFailedUnits
            | Op::RemountReadWrite { .. } => 7,
            Op::CpuInfo
            | Op::PciDevices
            | Op::BlockDevices
            | Op::MemoryHardware
            | Op::DiskHealth { .. } => 8,
            Op::ListContainers
            | Op::ContainerLogs { .. }
            | Op::ContainerInspect { .. }
            | Op::ListImages
            | Op::RuntimeInfo
            | Op::StartContainer { .. }
            | Op::StopContainer { .. }
            | Op::RestartContainer { .. }
            | Op::RemoveContainer { .. } => 9,
            Op::ListProcesses
            | Op::ProcessDetail { .. }
            | Op::RenicePriority { .. }
            | Op::SendSignal { .. } => 10,
            Op::CleanupTargetsSummary
            | Op::ForceLogRotation
            | Op::ClearTmpFiles { .. }
            | Op::ClearCoreDumps => 11,
            Op::VmStatistics
            | Op::InterruptStatistics
            | Op::CpuGovernorStatus
            | Op::TuningParametersStatus
            | Op::SetSwappiness { .. }
            | Op::SetIoScheduler { .. } => 12,
            Op::ListUsers
            | Op::ListGroups
            | Op::UserDetail { .. }
            | Op::CreateUser { .. }
            | Op::CreateGroup { .. }
            | Op::AddUserToGroup { .. }
            | Op::RemoveUserFromGroup { .. }
            | Op::LockUserAccount { .. }
            | Op::UnlockUserAccount { .. }
            | Op::DeleteUser { .. }
            | Op::DeleteGroup { .. } => 13,
            Op::DirectoryUsageBreakdown { .. }
            | Op::FindLargeFiles { .. }
            | Op::FilesystemCheckDryRun { .. }
            | Op::TrimFilesystem { .. }
            | Op::FilesystemRepair { .. } => 14,
            Op::ListInstalledPackages
            | Op::SearchPackage { .. }
            | Op::PackageInfo { .. }
            | Op::ListUpgradable
            | Op::RefreshPackageIndex
            | Op::InstallPackage { .. }
            | Op::UpgradePackage { .. }
            | Op::RemovePackage { .. } => 15,
            Op::PartitionTable { .. }
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
            | Op::CreateFilesystem { .. } => 16,
            Op::ViewManagedSysctl
            | Op::ViewManagedCronJobs
            | Op::SetPersistentSysctl { .. }
            | Op::RemovePersistentSysctlKey { .. }
            | Op::ClearManagedSysctl
            | Op::SetCronJob { .. }
            | Op::RemoveCronJob { .. }
            | Op::ClearManagedCronJobs => 17,
            Op::ListBlockedIps
            | Op::IsolationStatus
            | Op::ListQuarantinedFiles
            | Op::BlockRemoteIp { .. }
            | Op::UnblockRemoteIp { .. }
            | Op::QuarantineFile { .. }
            | Op::RestoreQuarantinedFile { .. }
            | Op::DeleteQuarantinedFile { .. }
            | Op::DeisolateHost
            | Op::IsolateHost => 18,
            Op::ListSshHostKeys
            | Op::ListSshAuthorizedKeys { .. }
            | Op::ListTlsCertificates
            | Op::CertificateDetail { .. }
            | Op::ScanSensitiveFilePermissions
            | Op::ViewSensitiveFile { .. }
            | Op::GenerateSshKeypair { .. }
            | Op::FixFilePermissions { .. }
            | Op::RemoveAuthorizedKey { .. }
            | Op::DeleteSshKeypair { .. } => 19,
            Op::ScanSecurityEvents { .. } => 20,
            Op::DetectPackageBackend
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
            | Op::WriteSepulchreMountCredentials { .. } => 22,
            Op::SelfUpdate { .. } => 24,
            Op::FirewallDenyPort { .. }
            | Op::FirewallRemovePort { .. }
            | Op::SshdConfigAudit
            | Op::HardenSshd { .. }
            | Op::ClearSshHardening
            | Op::SysctlSecurityPosture
            | Op::AccountPolicyAudit
            | Op::MacStatus
            | Op::AutomaticUpdatesStatus => 25,
            Op::CpuUtilization
            | Op::NetworkThroughput
            | Op::ThermalSensors
            | Op::MemoryPressure => 26,
            Op::SignalByName { .. }
            | Op::SetIoPriority { .. }
            | Op::SetOomScoreAdj { .. }
            | Op::ProcessOpenFiles { .. }
            | Op::ProcessLimits { .. }
            | Op::ZombieReport => 29,
            Op::SysctlManagedDrift
            | Op::ViewModuleBlacklist
            | Op::BlacklistModule { .. }
            | Op::RemoveModuleBlacklist { .. }
            | Op::ClearModuleBlacklist
            | Op::ViewJournaldConfig
            | Op::SetJournaldRetention { .. }
            | Op::ClearJournaldConfig => 31,
            Op::ListFailedUnits
            | Op::RecoverUnit { .. }
            | Op::DiskSpaceCritical
            | Op::FstabCheck => 33,
            Op::AdDnsReport { .. } | Op::AdHealthReport { .. } => 35,
            Op::UpdateTrustedCa { .. } => 36,
            Op::ScourgeSensorStatus
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
            | Op::ScourgePcapDelete { .. } => 40,
            Op::ScourgeIpsStatus | Op::ScourgeSetMode { .. } | Op::ScourgeSetSidAction { .. } => 41,
            Op::UninstallAgent { .. } | Op::NeighborTable => 42,
            Op::ThanatosStream { .. } => 44,
            Op::DhcpLeases => 45,
        }
    }
}

/// Each release's protocol version, oldest first. Add a row per release.
const RELEASES: &[(u32, &str)] = &[
    (33, "0.1.6"),
    (34, "0.1.8"),
    (38, "0.2.0"),
    (42, "0.2.2"),
    (45, "0.2.3"),
];

/// The first release whose agent speaks at least `protocol`, for messages
/// ("needs agent 0.2.2 or later"). `None` past the newest known release.
pub fn agent_release_for_protocol(protocol: u32) -> Option<&'static str> {
    RELEASES
        .iter()
        .find(|(p, _)| *p >= protocol)
        .map(|(_, release)| *release)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PROTOCOL_VERSION;

    #[test]
    fn versions_match_when_operations_arrived() {
        assert!(AgentOperation::Ping.min_protocol() <= 1);
        assert_eq!(
            AgentOperation::UpdateTrustedCa {
                bundle_pem: String::new()
            }
            .min_protocol(),
            36
        );
        assert_eq!(AgentOperation::ScourgeSensorStatus.min_protocol(), 40);
        assert_eq!(
            AgentOperation::ScourgeSetMode { ips: false }.min_protocol(),
            41
        );
        assert_eq!(AgentOperation::NeighborTable.min_protocol(), 42);
        assert_eq!(
            AgentOperation::UninstallAgent { purge: true }.min_protocol(),
            42
        );
        assert_eq!(
            AgentOperation::ThanatosStream {
                enabled: true,
                c2_ports: vec![]
            }
            .min_protocol(),
            44
        );
    }

    #[test]
    fn fields_that_change_meaning_raise_the_version() {
        let delete = |shred_passes| AgentOperation::DeleteQuarantinedFile {
            filename: "x".into(),
            shred_passes,
        };
        assert!(
            delete(0).min_protocol() < 39,
            "a plain delete works on any agent"
        );
        assert_eq!(delete(3).min_protocol(), 39);
        let update = |from_control_plane| AgentOperation::SelfUpdate {
            version: "1.0.0".into(),
            from_control_plane,
            sha256: None,
        };
        assert_eq!(update(false).min_protocol(), 24);
        assert_eq!(update(true).min_protocol(), 43);
    }

    #[test]
    fn nothing_needs_more_than_this_build_speaks() {
        // The newest entries, which a forgotten bump would push past it.
        for op in [
            AgentOperation::NeighborTable,
            AgentOperation::SelfUpdate {
                version: "1.0.0".into(),
                from_control_plane: true,
                sha256: None,
            },
        ] {
            assert!(op.min_protocol() <= PROTOCOL_VERSION, "{op:?}");
        }
    }

    #[test]
    fn releases_for_protocols() {
        assert_eq!(agent_release_for_protocol(36), Some("0.2.0"));
        assert_eq!(agent_release_for_protocol(40), Some("0.2.2"));
        assert_eq!(agent_release_for_protocol(42), Some("0.2.2"));
        assert_eq!(agent_release_for_protocol(43), Some("0.2.3"));
        assert_eq!(agent_release_for_protocol(1), Some("0.1.6"));
        assert_eq!(agent_release_for_protocol(999), None);
        assert!(
            agent_release_for_protocol(PROTOCOL_VERSION).is_some(),
            "add this release to RELEASES"
        );
    }
}
