//! Wire format shared between the control plane and `abyssal-agent`. This
//! crate is pure data — no I/O — so both sides link the exact same
//! definitions instead of hand-keeping two copies in sync.
//!
//! `AgentOperation` is the actual security boundary for remote execution: an
//! agent will only ever run one of these fixed, named operations, never an
//! arbitrary command string sent over the wire. Adding a capability means
//! adding a variant here (and implementing it in the agent) — the protocol
//! itself can't be used to smuggle in anything else.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped whenever a change here could break an older agent build's ability
/// to deserialize a message from the control plane -- most commonly, adding
/// a new `AgentOperation` variant (an agent that predates it has no match
/// arm for it and fails to deserialize the whole `ServerMessage`, which
/// disconnects it). The agent reports this over an HTTP header on every
/// connection (`X-Agent-Protocol-Version`, see `crates/agent/src/transport.rs`);
/// the control plane compares it against its own copy of this constant and
/// surfaces a mismatch in the UI rather than letting a stale agent silently
/// disconnect/reconnect in a loop the moment it's sent an operation it
/// doesn't recognize. This is a coarse, conservative signal, not a real
/// compatibility check -- an old agent might still handle every operation
/// actually sent to it, but there's no cheap way to know that in advance,
/// so any change here just calls the whole build "out of date."
pub const PROTOCOL_VERSION: u32 = 9;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOperation {
    /// Pure connectivity/liveness check — no work performed.
    Ping,
    /// Hostname, kernel version, and uptime, read locally on the agent's host.
    SystemInfo,
    /// Memory and disk usage, read locally on the agent's host.
    ResourceUsage,
    /// Currently logged-in users/sessions on the agent's host.
    LoggedInUsers,
    /// Sets the agent's host's persistent hostname. Write -- a real mutation,
    /// but not destructive/irreversible, so it doesn't require the explicit
    /// confirmation a `Destructive` operation does.
    SetHostname { hostname: String },
    /// Immediately reboots the agent's host. Destructive -- the control
    /// plane requires explicit confirmation before ever dispatching this.
    Reboot,
    /// Listening TCP/UDP sockets on the agent's host (`ss -tulpn`).
    ListeningPorts,
    /// The last ~30 sshd journal entries (login attempts, failures).
    RecentAuthLog,
    /// Current firewall status, from whichever of firewalld/ufw/nftables/
    /// iptables the agent detects on its host.
    FirewallStatus,
    /// Allows a port through the detected firewall backend. Write -- a real
    /// mutation, but additive/non-destructive, so no confirmation required.
    FirewallAllowPort { port: u16, protocol: String },
    /// Enables the detected firewall backend (firewalld/ufw only -- raw
    /// nftables/iptables have no single well-defined "enable"). Destructive:
    /// can cut off remote access if the current management port isn't
    /// already allowed, so the control plane requires explicit confirmation.
    FirewallEnable,
    /// Validates a sudo password via `sudo -S -v` and starts/refreshes a
    /// time-boxed elevation window on the agent ("Apotheosis"). Write --
    /// the password prompt itself is the meaningful confirmation step, so
    /// this doesn't additionally require the `Destructive` confirmation
    /// gate. `idle_timeout_secs` is the control plane's admin-configured
    /// window (Settings); the agent has no DB access of its own, so it has
    /// to be told the value on every elevation rather than reading it
    /// locally.
    Elevate {
        password: String,
        idle_timeout_secs: u64,
    },
    /// Clears the elevation window early and drops sudo's own cache too.
    Deescalate,
    /// Human-readable elevation status (elevated or not, remaining time).
    ElevationStatus,
    /// Network interfaces and their addresses (`ip addr show`).
    NetworkInterfaces,
    /// The routing table (`ip route show`).
    NetworkRoutes,
    /// DNS resolver configuration, from whichever of systemd-resolved or
    /// plain `/etc/resolv.conf` the agent detects on its host.
    DnsConfig,
    /// All active TCP/UDP sockets, not just listening ones -- complements
    /// Cadavault's `ListeningPorts` (attack-surface focus) with a
    /// diagnostics-focused view of what's actually connected right now.
    ActiveConnections,
    /// Ping + DNS lookup against a target the operator supplies. Read --
    /// sends network traffic, but only ICMP echo/DNS query, not the kind
    /// of thing that needs a confirmation gate.
    ConnectivityCheck { target: String },
    /// Brings a network interface up or down (`ip link set <iface> up|down`).
    /// The control plane treats `up: true` as Write (additive, safe) and
    /// `up: false` as Destructive (can cut off remote access to the host if
    /// it's the interface currently in use) -- same command either way, the
    /// risk categorization lives on the control-plane side of the dispatch,
    /// same as every other op here.
    InterfaceSetState { interface: String, up: bool },
    /// Active network scan ("Necrolink" -- network visibility) via nmap, if
    /// present on the host. Destructive: sends real traffic to a
    /// third-party target and can trip IDS/IPS elsewhere on the network, so
    /// the control plane requires explicit confirmation and gates this
    /// behind its own dedicated `network.scan` permission (Super Admin
    /// only by default), independent of the general `network.manage`
    /// permission the rest of this arsenal's write operations use.
    /// `ports` is an optional nmap `-p` spec (e.g. `"22,80,443"` or
    /// `"1-1024"`); omitted means nmap's own default port set. Uses a TCP
    /// connect scan (`-sT`), which doesn't need root -- unlike a SYN scan,
    /// so this isn't entangled with Apotheosis elevation.
    NetworkScan {
        target: String,
        ports: Option<String>,
    },
    /// Reboot/shutdown history (`last -x`) -- forensic starting point for
    /// "did this host crash or was it intentional."
    BootHistory,
    /// Recent error/warning-level kernel ring buffer messages (`dmesg`) --
    /// crash traces, hardware errors, driver failures.
    KernelRingBuffer,
    /// Recent warning-or-worse system log entries since the current boot.
    SystemJournalErrors,
    /// Failed login/authentication attempts (ssh, sudo, su, PAM in general)
    /// found in the recent system log window -- a standard first check when
    /// a host is suspected of compromise. Distinct from Cadavault's
    /// `RecentAuthLog` (a raw recent-activity tail): this one searches
    /// specifically for failures, not everything.
    FailedLoginAttempts,
    /// Out-of-memory killer events from the kernel ring buffer -- explains
    /// processes that died with no other obvious cause.
    OomKillEvents,
    /// Recorded crash/core dumps (`coredumpctl`, or on-disk artifacts under
    /// `/var/crash` / `/var/lib/systemd/coredump` where that's unavailable).
    CoreDumps,
    /// Files under common system binary/config directories modified within
    /// the last `hours` -- a classic tamper/backdoor indicator after a
    /// suspected compromise. Read-only (stats file metadata, reads no file
    /// contents); `hours` is validated (1-720, i.e. up to 30 days) both here
    /// and again on the agent, which is the actual execution boundary.
    RecentlyModifiedFiles { hours: u32 },
    /// Disk space consumed by the systemd journal (`journalctl --disk-usage`).
    JournalDiskUsage,
    /// `logrotate`'s own status file -- when each configured log was last
    /// rotated.
    LogRotationStatus,
    /// Already-rotated/compressed log files under `/var/log`
    /// (`*.gz`, `*.N`, `*.old`) -- what historical log data actually exists
    /// on this host and how far back it goes.
    ArchivedLogListing,
    /// Per-subdirectory disk usage under `/var/log` -- which logs are
    /// actually consuming space.
    LogDirectorySizes,
    /// Deletes journal data down to (at most) `size`
    /// (`journalctl --vacuum-size=<size>`, e.g. `"500M"`, `"1G"`).
    /// Destructive and irreversible -- this permanently discards historical
    /// log data, which is exactly what a later investigation might need.
    /// systemd-only; the control plane requires explicit confirmation and
    /// gates this behind the dedicated `audit.manage` permission (Super
    /// Admin only by default), not the general `audit.view` the rest of
    /// this arsenal's read operations use.
    VacuumJournalBySize { size: String },
    /// Deletes journal entries older than `duration`
    /// (`journalctl --vacuum-time=<duration>`, e.g. `"7d"`, `"2weeks"`).
    /// Same destructive/irreversible characteristics and permission gate as
    /// `VacuumJournalBySize`.
    VacuumJournalByTime { duration: String },
    /// Backups already present under this host's fixed backup directory
    /// (`/var/backups/abyssal-arsenal`) -- name, size, and creation time.
    ListBackups,
    /// Archives `source_path` into a timestamped `<name>-<unix-time>.tar.gz`
    /// under the fixed backup directory. Write -- a real mutation (creates
    /// a file), but purely additive, so it doesn't require the explicit
    /// confirmation a `Destructive` operation does.
    CreateBackup { source_path: String, name: String },
    /// Tests a backup archive's integrity (`tar -tzf`) and lists its
    /// contents, without extracting anything.
    VerifyBackup { filename: String },
    /// Extracts `filename` from the fixed backup directory into
    /// `target_path`, overwriting anything already there. Destructive --
    /// this can silently clobber current data with an old backup, so the
    /// control plane requires explicit confirmation before ever dispatching
    /// this.
    RestoreBackup {
        filename: String,
        target_path: String,
    },
    /// Load averages and uptime (`uptime`).
    LoadAverage,
    /// The 15 processes currently consuming the most CPU
    /// (`ps -eo ... --sort=-%cpu`).
    TopProcessesByCpu,
    /// The 15 processes currently consuming the most memory
    /// (`ps -eo ... --sort=-%mem`).
    TopProcessesByMemory,
    /// Full `/proc/meminfo` -- buffers, cache, swap, dirty pages, and more
    /// detail than the summary `ResourceUsage` (Cystoolbox) gives.
    MemoryDetail,
    /// Per-device disk I/O statistics (`vmstat -d`).
    DiskIoStats,
    /// Currently-failed systemd units (`systemctl --failed`) -- a direct
    /// "is anything broken right now" health signal. systemd-only.
    FailedServices,
    /// Every systemd service unit and its current state
    /// (`systemctl list-units --type=service --all`).
    ListServices,
    /// Detailed status for one unit (`systemctl status`) -- active/inactive,
    /// recent log lines, and process info. systemd's own exit code for this
    /// reflects the unit's state (0 active, non-zero otherwise), not
    /// whether the command itself succeeded, so a "stopped" unit is a
    /// perfectly normal result here, not an error.
    ServiceStatus { unit: String },
    /// The last 50 journal lines for one unit (`journalctl -u`).
    ServiceLogs { unit: String },
    /// Starts a stopped unit. Write -- a real mutation, but not
    /// irreversible (stopping it again undoes it), so it doesn't require
    /// the explicit confirmation a `Destructive` operation does.
    StartService { unit: String },
    /// Stops a running unit. Destructive: whatever the unit was providing
    /// becomes unavailable immediately, so the control plane requires
    /// explicit confirmation before ever dispatching this.
    StopService { unit: String },
    /// Restarts a unit. Destructive for the same reason as `StopService`
    /// -- a brief outage is guaranteed, and if the unit is what's carrying
    /// the connection used to manage this host (e.g. `sshd`), restarting
    /// it can cut that connection.
    RestartService { unit: String },
    /// Enables a unit to start automatically at boot, without touching
    /// whether it's running right now. Write -- additive, not disruptive.
    EnableService { unit: String },
    /// Disables a unit from starting automatically at boot, without
    /// touching whether it's running right now. Write, not Destructive --
    /// the currently-running instance (if any) is unaffected.
    DisableService { unit: String },
    /// Warning-or-worse journal entries from the *previous* boot
    /// (`journalctl -b -1 -p err`) -- the direct "why did it go down last
    /// time" query, the natural first read after an unexpected restart.
    /// Distinct from Postmortem's `SystemJournalErrors`, which covers the
    /// *current* boot. systemd-only: there's no reliable way to delimit
    /// "the previous boot" in plain rotated syslog files.
    PreviousBootErrors,
    /// One-word overall systemd health (`running`, `degraded`,
    /// `maintenance`, ...) via `systemctl is-system-running` -- the
    /// fastest possible top-level "is anything wrong" check, one level
    /// coarser than `FailedServices` (which lists *which* units failed).
    /// systemd-only. Its exit code reflects system state, not command
    /// success, so a "degraded" result is a normal outcome here, not an
    /// error.
    SystemRunningState,
    /// Filesystems currently mounted read-only (`findmnt --options ro`) --
    /// the classic signature of a disk that hit I/O errors and was forced
    /// read-only by the kernel, often the actual root cause behind a host
    /// that looks "failed" in every other respect.
    ReadOnlyFilesystems,
    /// Reloads systemd's unit file cache (`systemctl daemon-reload`) --
    /// the standard first step after fixing a broken unit file on disk.
    /// Write -- reloading is idempotent and never disruptive on its own.
    ReloadSystemdDaemon,
    /// Clears systemd's failed-unit bookkeeping (`systemctl reset-failed`)
    /// once whatever broke has actually been fixed -- doesn't touch any
    /// unit's running state. Write, not Destructive.
    ResetFailedUnits,
    /// Remounts an already-mounted filesystem read-write
    /// (`mount -o remount,rw <target>`) -- restores write access after a
    /// filesystem was forced read-only, most commonly the root filesystem
    /// itself. Destructive: forcing writes to resume on a filesystem the
    /// kernel chose to protect can worsen underlying corruption if the
    /// I/O error that caused the read-only remount is still present, so
    /// the control plane requires explicit confirmation before ever
    /// dispatching this.
    RemountReadWrite { target: String },
    /// CPU model, core/thread counts, and clock speeds (`lscpu`).
    CpuInfo,
    /// PCI-attached hardware (GPUs, NICs, storage/RAID controllers, ...)
    /// (`lspci`).
    PciDevices,
    /// Block devices and their partitions -- size, type, filesystem, and
    /// mount point (`lsblk`).
    BlockDevices,
    /// Installed memory modules -- slots, capacity, speed, manufacturer
    /// (`dmidecode -t memory`). Often sparse or entirely unavailable
    /// inside VMs and containers (no real SMBIOS data to report), which
    /// is a normal result here, not a failure.
    MemoryHardware,
    /// SMART health and identification for one block device
    /// (`smartctl -H -i <device>`), e.g. `/dev/sda`. `smartctl`'s exit
    /// code is a bitmask of SMART findings (failing attributes, pre-fail
    /// warnings, ...), not a simple success/failure signal, so a non-zero
    /// exit reporting a real finding is exactly the useful case here, not
    /// an error.
    DiskHealth { device: String },
    /// Every container, running or stopped (`docker ps -a` /
    /// `podman ps -a` -- whichever runtime is present; their CLI syntax
    /// is identical for every op in this arsenal).
    ListContainers,
    /// The last 100 log lines for one container (`... logs --tail 100`).
    ContainerLogs { container: String },
    /// Full inspection detail for one container -- config, mounts,
    /// network settings, restart policy (`... inspect`).
    ContainerInspect { container: String },
    /// Every image present on the host (`... images`).
    ListImages,
    /// Runtime-level status: storage driver, container/image counts,
    /// version (`... info`).
    RuntimeInfo,
    /// Starts a stopped container. Write -- a real mutation, but not
    /// irreversible (stopping it again undoes it), so it doesn't require
    /// the explicit confirmation a `Destructive` operation does.
    StartContainer { container: String },
    /// Stops a running container. Destructive: whatever the container was
    /// providing becomes unavailable immediately, so the control plane
    /// requires explicit confirmation before ever dispatching this.
    StopContainer { container: String },
    /// Restarts a container. Destructive for the same reason as
    /// `StopContainer` -- a brief outage is guaranteed.
    RestartContainer { container: String },
    /// Deletes a container entirely (`... rm`, without `-f`, so a
    /// currently-running container is refused rather than force-killed).
    /// Destructive and irreversible -- the container's own writable layer
    /// and state are gone, though named volumes survive -- so the control
    /// plane requires explicit confirmation before ever dispatching this.
    RemoveContainer { container: String },
}

/// Hand-written rather than derived so a value carrying a real sudo password
/// (`Elevate`) can never have that password land in a log line just because
/// something somewhere formatted an operation with `{:?}` -- this is a
/// backstop, not the primary control (the primary control is that nothing
/// logs an `AgentOperation` at all), but it means that stays true even if a
/// future change accidentally would have.
impl fmt::Debug for AgentOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentOperation::Ping => write!(f, "Ping"),
            AgentOperation::SystemInfo => write!(f, "SystemInfo"),
            AgentOperation::ResourceUsage => write!(f, "ResourceUsage"),
            AgentOperation::LoggedInUsers => write!(f, "LoggedInUsers"),
            AgentOperation::SetHostname { hostname } => f
                .debug_struct("SetHostname")
                .field("hostname", hostname)
                .finish(),
            AgentOperation::Reboot => write!(f, "Reboot"),
            AgentOperation::ListeningPorts => write!(f, "ListeningPorts"),
            AgentOperation::RecentAuthLog => write!(f, "RecentAuthLog"),
            AgentOperation::FirewallStatus => write!(f, "FirewallStatus"),
            AgentOperation::FirewallAllowPort { port, protocol } => f
                .debug_struct("FirewallAllowPort")
                .field("port", port)
                .field("protocol", protocol)
                .finish(),
            AgentOperation::FirewallEnable => write!(f, "FirewallEnable"),
            AgentOperation::Elevate {
                idle_timeout_secs, ..
            } => f
                .debug_struct("Elevate")
                .field("password", &"[REDACTED]")
                .field("idle_timeout_secs", idle_timeout_secs)
                .finish(),
            AgentOperation::Deescalate => write!(f, "Deescalate"),
            AgentOperation::ElevationStatus => write!(f, "ElevationStatus"),
            AgentOperation::NetworkInterfaces => write!(f, "NetworkInterfaces"),
            AgentOperation::NetworkRoutes => write!(f, "NetworkRoutes"),
            AgentOperation::DnsConfig => write!(f, "DnsConfig"),
            AgentOperation::ActiveConnections => write!(f, "ActiveConnections"),
            AgentOperation::ConnectivityCheck { target } => f
                .debug_struct("ConnectivityCheck")
                .field("target", target)
                .finish(),
            AgentOperation::InterfaceSetState { interface, up } => f
                .debug_struct("InterfaceSetState")
                .field("interface", interface)
                .field("up", up)
                .finish(),
            AgentOperation::NetworkScan { target, ports } => f
                .debug_struct("NetworkScan")
                .field("target", target)
                .field("ports", ports)
                .finish(),
            AgentOperation::BootHistory => write!(f, "BootHistory"),
            AgentOperation::KernelRingBuffer => write!(f, "KernelRingBuffer"),
            AgentOperation::SystemJournalErrors => write!(f, "SystemJournalErrors"),
            AgentOperation::FailedLoginAttempts => write!(f, "FailedLoginAttempts"),
            AgentOperation::OomKillEvents => write!(f, "OomKillEvents"),
            AgentOperation::CoreDumps => write!(f, "CoreDumps"),
            AgentOperation::RecentlyModifiedFiles { hours } => f
                .debug_struct("RecentlyModifiedFiles")
                .field("hours", hours)
                .finish(),
            AgentOperation::JournalDiskUsage => write!(f, "JournalDiskUsage"),
            AgentOperation::LogRotationStatus => write!(f, "LogRotationStatus"),
            AgentOperation::ArchivedLogListing => write!(f, "ArchivedLogListing"),
            AgentOperation::LogDirectorySizes => write!(f, "LogDirectorySizes"),
            AgentOperation::VacuumJournalBySize { size } => f
                .debug_struct("VacuumJournalBySize")
                .field("size", size)
                .finish(),
            AgentOperation::VacuumJournalByTime { duration } => f
                .debug_struct("VacuumJournalByTime")
                .field("duration", duration)
                .finish(),
            AgentOperation::ListBackups => write!(f, "ListBackups"),
            AgentOperation::CreateBackup { source_path, name } => f
                .debug_struct("CreateBackup")
                .field("source_path", source_path)
                .field("name", name)
                .finish(),
            AgentOperation::VerifyBackup { filename } => f
                .debug_struct("VerifyBackup")
                .field("filename", filename)
                .finish(),
            AgentOperation::RestoreBackup {
                filename,
                target_path,
            } => f
                .debug_struct("RestoreBackup")
                .field("filename", filename)
                .field("target_path", target_path)
                .finish(),
            AgentOperation::LoadAverage => write!(f, "LoadAverage"),
            AgentOperation::TopProcessesByCpu => write!(f, "TopProcessesByCpu"),
            AgentOperation::TopProcessesByMemory => write!(f, "TopProcessesByMemory"),
            AgentOperation::MemoryDetail => write!(f, "MemoryDetail"),
            AgentOperation::DiskIoStats => write!(f, "DiskIoStats"),
            AgentOperation::FailedServices => write!(f, "FailedServices"),
            AgentOperation::ListServices => write!(f, "ListServices"),
            AgentOperation::ServiceStatus { unit } => {
                f.debug_struct("ServiceStatus").field("unit", unit).finish()
            }
            AgentOperation::ServiceLogs { unit } => {
                f.debug_struct("ServiceLogs").field("unit", unit).finish()
            }
            AgentOperation::StartService { unit } => {
                f.debug_struct("StartService").field("unit", unit).finish()
            }
            AgentOperation::StopService { unit } => {
                f.debug_struct("StopService").field("unit", unit).finish()
            }
            AgentOperation::RestartService { unit } => f
                .debug_struct("RestartService")
                .field("unit", unit)
                .finish(),
            AgentOperation::EnableService { unit } => {
                f.debug_struct("EnableService").field("unit", unit).finish()
            }
            AgentOperation::DisableService { unit } => f
                .debug_struct("DisableService")
                .field("unit", unit)
                .finish(),
            AgentOperation::PreviousBootErrors => write!(f, "PreviousBootErrors"),
            AgentOperation::SystemRunningState => write!(f, "SystemRunningState"),
            AgentOperation::ReadOnlyFilesystems => write!(f, "ReadOnlyFilesystems"),
            AgentOperation::ReloadSystemdDaemon => write!(f, "ReloadSystemdDaemon"),
            AgentOperation::ResetFailedUnits => write!(f, "ResetFailedUnits"),
            AgentOperation::RemountReadWrite { target } => f
                .debug_struct("RemountReadWrite")
                .field("target", target)
                .finish(),
            AgentOperation::CpuInfo => write!(f, "CpuInfo"),
            AgentOperation::PciDevices => write!(f, "PciDevices"),
            AgentOperation::BlockDevices => write!(f, "BlockDevices"),
            AgentOperation::MemoryHardware => write!(f, "MemoryHardware"),
            AgentOperation::DiskHealth { device } => f
                .debug_struct("DiskHealth")
                .field("device", device)
                .finish(),
            AgentOperation::ListContainers => write!(f, "ListContainers"),
            AgentOperation::ContainerLogs { container } => f
                .debug_struct("ContainerLogs")
                .field("container", container)
                .finish(),
            AgentOperation::ContainerInspect { container } => f
                .debug_struct("ContainerInspect")
                .field("container", container)
                .finish(),
            AgentOperation::ListImages => write!(f, "ListImages"),
            AgentOperation::RuntimeInfo => write!(f, "RuntimeInfo"),
            AgentOperation::StartContainer { container } => f
                .debug_struct("StartContainer")
                .field("container", container)
                .finish(),
            AgentOperation::StopContainer { container } => f
                .debug_struct("StopContainer")
                .field("container", container)
                .finish(),
            AgentOperation::RestartContainer { container } => f
                .debug_struct("RestartContainer")
                .field("container", container)
                .finish(),
            AgentOperation::RemoveContainer { container } => f
                .debug_struct("RemoveContainer")
                .field("container", container)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandOutcome {
    Ok(OperationOutput),
    Err(String),
}

/// Sent from the control plane down an established agent connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    Command {
        request_id: Uuid,
        operation: AgentOperation,
    },
    Ping,
}

/// Sent from the agent back up to the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    Response {
        request_id: Uuid,
        outcome: CommandOutcome,
    },
    Pong,
}

/// Shared by both the control plane (for a useful validation error before
/// ever dispatching) and the agent (the actual execution boundary, which
/// never trusts a wire value just because the control plane already checked
/// it) -- RFC 1123 hostname/label rules.
pub fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Shared the same way `is_valid_hostname` is: both the control plane (for a
/// clean validation error) and the agent (the real execution boundary) check
/// this independently before a `FirewallAllowPort` dispatch is honored.
pub fn is_valid_port_protocol(port: u16, protocol: &str) -> bool {
    port != 0 && (protocol == "tcp" || protocol == "udp")
}

/// A target for `ConnectivityCheck` or `NetworkScan`: an IPv4 address, an
/// IPv4 CIDR range (e.g. `192.168.1.0/24`), or a hostname. Explicitly
/// rejects anything starting with `-` even though the character classes
/// below already couldn't produce one -- belt and suspenders against the
/// value ever being misread as a flag by whatever it's eventually passed
/// to as an argv entry (`ping`, `nmap`, ...).
pub fn is_valid_network_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 253 || target.starts_with('-') {
        return false;
    }

    if let Some((addr, prefix)) = target.split_once('/') {
        return addr.parse::<std::net::Ipv4Addr>().is_ok()
            && prefix.parse::<u8>().is_ok_and(|p| p <= 32);
    }

    target.parse::<std::net::Ipv4Addr>().is_ok() || is_valid_hostname(target)
}

/// A Linux network interface name: up to `IFNAMSIZ - 1` (15) characters,
/// no spaces or path separators.
pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// An nmap `-p` port spec: digits, commas, and hyphens only (e.g.
/// `"22,80,443"` or `"1-1024"`). The restricted character set is itself
/// the argument-injection defense: no letters or spaces means this value
/// can never spell out a different flag, even though a literal `-` is
/// allowed for ranges.
pub fn is_valid_port_spec(spec: &str) -> bool {
    !spec.is_empty()
        && spec.len() <= 256
        && spec
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ',' | '-'))
}

/// The lookback window for `RecentlyModifiedFiles`, in hours. Bounded to
/// 1-720 (30 days) -- long enough to cover any plausible incident window,
/// short enough that the underlying `find` stays fast on a normal host.
pub fn is_valid_lookback_hours(hours: u32) -> bool {
    (1..=720).contains(&hours)
}

/// Shared shape for the two `journalctl --vacuum-*` value formats: a
/// leading digit followed by letters/digits only (e.g. `"500M"`, `"7d"`,
/// `"2weeks"`). The restricted character set is the argument-injection
/// defense -- no spaces, hyphens, or symbols means this can never spell out
/// a different flag, even though the exact unit suffixes journalctl
/// recognizes vary between the size and time forms.
fn is_digit_led_alphanumeric(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.chars().next().is_some_and(|c| c.is_ascii_digit())
        && value.chars().all(|c| c.is_ascii_alphanumeric())
}

/// A `journalctl --vacuum-size=<size>` value (e.g. `"500M"`, `"1G"`).
pub fn is_valid_vacuum_size(value: &str) -> bool {
    is_digit_led_alphanumeric(value, 16)
}

/// A `journalctl --vacuum-time=<duration>` value (e.g. `"7d"`, `"2weeks"`).
pub fn is_valid_vacuum_duration(value: &str) -> bool {
    is_digit_led_alphanumeric(value, 32)
}

/// A backup archive's logical name, as the operator chooses it when
/// creating a backup (the agent appends `-<unix-time>.tar.gz` itself to
/// build the actual filename). Letters, digits, hyphens, and underscores
/// only -- both the argument-injection defense and the path-traversal
/// defense, since no `.` or `/` means this can never escape the fixed
/// backup directory or spell out a different flag.
pub fn is_valid_backup_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// A backup archive's exact on-disk filename (as shown by `ListBackups`),
/// used to build the full path for verify/restore. Must end in `.tar.gz`
/// and contain no path separators or `..` -- same defense as
/// `is_valid_backup_name`, extended to allow the `-<unix-time>.tar.gz`
/// suffix this agent appends when creating one.
pub fn is_valid_backup_filename(filename: &str) -> bool {
    filename.ends_with(".tar.gz")
        && filename.len() <= 120
        && !filename.contains('/')
        && !filename.contains("..")
        && filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// An absolute filesystem path for a backup source or restore target --
/// must start with `/`, must not be root itself (backing up or restoring
/// onto the entire filesystem at once isn't a sane single operation for
/// this tool), and must contain no control characters. Deliberately
/// permissive on which printable characters are allowed -- real paths can
/// contain spaces and most punctuation, and argument-injection safety here
/// comes from never passing this through a shell, not from a restricted
/// character set. A leading `/` also means this can never be mistaken for
/// a flag by whichever tool receives it as an argument.
pub fn is_valid_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && path != "/"
        && path.len() <= 4096
        && path.chars().all(|c| !c.is_control())
}

/// A systemd unit name (e.g. `"sshd.service"`, `"nginx"`,
/// `"getty@tty1.service"`). Letters, digits, and the punctuation systemd
/// itself allows in unit names (`-_.:@`) only, and never starting with
/// `-` -- the argument-injection defense, same reasoning as every other
/// validator here: this can never spell out a different flag.
pub fn is_valid_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@'))
}

/// An absolute filesystem path to remount (`RemountReadWrite`), e.g. `"/"`
/// or `"/var"`. Unlike `is_valid_absolute_path`, root is explicitly
/// allowed here -- remounting `/` itself read-write is the single most
/// common disaster-recovery scenario this operation exists for (a root
/// filesystem forced read-only by I/O errors), so excluding it the way
/// backup source/target paths do would rule out the main case.
pub fn is_valid_mount_target(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 4096 && path.chars().all(|c| !c.is_control())
}

/// A container name or ID (Docker/Podman), e.g. `"web-1"` or a hex
/// container ID. Letters, digits, and the punctuation container names
/// allow (`-_.`) only, and never starting with `-` -- the
/// argument-injection defense, same reasoning as every other validator
/// here: this can never spell out a different flag.
pub fn is_valid_container_ref(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reasonable_hostnames() {
        assert!(is_valid_hostname("web-01"));
        assert!(is_valid_hostname("db1"));
        assert!(is_valid_hostname("host.example.com"));
    }

    #[test]
    fn rejects_malformed_hostnames() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-leading-hyphen"));
        assert!(!is_valid_hostname("trailing-hyphen-"));
        assert!(!is_valid_hostname("has a space"));
        assert!(!is_valid_hostname("has_underscore"));
        assert!(!is_valid_hostname("semi;colon"));
        assert!(!is_valid_hostname(&"a".repeat(254)));
    }

    #[test]
    fn validates_port_and_protocol() {
        assert!(is_valid_port_protocol(22, "tcp"));
        assert!(is_valid_port_protocol(53, "udp"));
        assert!(!is_valid_port_protocol(0, "tcp"));
        assert!(!is_valid_port_protocol(22, "icmp"));
        assert!(!is_valid_port_protocol(22, "TCP"));
    }

    #[test]
    fn accepts_reasonable_network_targets() {
        assert!(is_valid_network_target("192.168.1.1"));
        assert!(is_valid_network_target("192.168.1.0/24"));
        assert!(is_valid_network_target("host.example.com"));
        assert!(is_valid_network_target("web-01"));
    }

    #[test]
    fn rejects_malformed_network_targets() {
        assert!(!is_valid_network_target(""));
        assert!(!is_valid_network_target("-oN /etc/passwd"));
        assert!(!is_valid_network_target("192.168.1.0/33"));
        assert!(!is_valid_network_target("192.168.1.0/"));
        assert!(!is_valid_network_target("not a hostname"));
        assert!(!is_valid_network_target("2001:db8::1"));
    }

    #[test]
    fn accepts_reasonable_interface_names() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("wlan0"));
        assert!(is_valid_interface_name("enp0s3"));
        assert!(is_valid_interface_name("br-abc123"));
    }

    #[test]
    fn rejects_malformed_interface_names() {
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name("-eth0"));
        assert!(!is_valid_interface_name("eth0; rm -rf /"));
        assert!(!is_valid_interface_name(&"a".repeat(16)));
    }

    #[test]
    fn accepts_reasonable_port_specs() {
        assert!(is_valid_port_spec("22"));
        assert!(is_valid_port_spec("22,80,443"));
        assert!(is_valid_port_spec("1-1024"));
    }

    #[test]
    fn rejects_malformed_port_specs() {
        assert!(!is_valid_port_spec(""));
        assert!(!is_valid_port_spec("22,80,--script=vuln"));
        assert!(!is_valid_port_spec("22 80"));
        assert!(!is_valid_port_spec(&"1".repeat(257)));
    }

    #[test]
    fn accepts_reasonable_lookback_windows() {
        assert!(is_valid_lookback_hours(1));
        assert!(is_valid_lookback_hours(24));
        assert!(is_valid_lookback_hours(720));
    }

    #[test]
    fn rejects_out_of_range_lookback_windows() {
        assert!(!is_valid_lookback_hours(0));
        assert!(!is_valid_lookback_hours(721));
        assert!(!is_valid_lookback_hours(u32::MAX));
    }

    #[test]
    fn accepts_reasonable_vacuum_sizes() {
        assert!(is_valid_vacuum_size("500M"));
        assert!(is_valid_vacuum_size("1G"));
        assert!(is_valid_vacuum_size("2048"));
    }

    #[test]
    fn rejects_malformed_vacuum_sizes() {
        assert!(!is_valid_vacuum_size(""));
        assert!(!is_valid_vacuum_size("-1G"));
        assert!(!is_valid_vacuum_size("G500"));
        assert!(!is_valid_vacuum_size("500 M"));
        assert!(!is_valid_vacuum_size("500M; rm -rf /"));
        assert!(!is_valid_vacuum_size(&"1".repeat(17)));
    }

    #[test]
    fn accepts_reasonable_vacuum_durations() {
        assert!(is_valid_vacuum_duration("7d"));
        assert!(is_valid_vacuum_duration("2weeks"));
        assert!(is_valid_vacuum_duration("1month"));
    }

    #[test]
    fn rejects_malformed_vacuum_durations() {
        assert!(!is_valid_vacuum_duration(""));
        assert!(!is_valid_vacuum_duration("-7d"));
        assert!(!is_valid_vacuum_duration("d7"));
        assert!(!is_valid_vacuum_duration("7 days"));
        assert!(!is_valid_vacuum_duration("7d; rm -rf /"));
    }

    #[test]
    fn accepts_reasonable_backup_names() {
        assert!(is_valid_backup_name("mydata"));
        assert!(is_valid_backup_name("my-data_2"));
    }

    #[test]
    fn rejects_malformed_backup_names() {
        assert!(!is_valid_backup_name(""));
        assert!(!is_valid_backup_name("../etc"));
        assert!(!is_valid_backup_name("my/data"));
        assert!(!is_valid_backup_name("my data"));
        assert!(!is_valid_backup_name(&"a".repeat(101)));
    }

    #[test]
    fn accepts_reasonable_backup_filenames() {
        assert!(is_valid_backup_filename("mydata-1758138245.tar.gz"));
        assert!(is_valid_backup_filename("my-data_2-1.tar.gz"));
    }

    #[test]
    fn rejects_malformed_backup_filenames() {
        assert!(!is_valid_backup_filename(""));
        assert!(!is_valid_backup_filename("mydata.tar.gz/../../etc/passwd"));
        assert!(!is_valid_backup_filename("../../etc/passwd.tar.gz"));
        assert!(!is_valid_backup_filename("mydata.tar"));
        assert!(!is_valid_backup_filename("mydata; rm -rf /.tar.gz"));
    }

    #[test]
    fn accepts_reasonable_absolute_paths() {
        assert!(is_valid_absolute_path("/etc"));
        assert!(is_valid_absolute_path("/home/user/my project"));
        assert!(is_valid_absolute_path("/var/backups/restore-target"));
    }

    #[test]
    fn rejects_malformed_absolute_paths() {
        assert!(!is_valid_absolute_path(""));
        assert!(!is_valid_absolute_path("relative/path"));
        assert!(!is_valid_absolute_path("/"));
        assert!(!is_valid_absolute_path("/etc\nmalicious"));
        assert!(!is_valid_absolute_path(&format!("/{}", "a".repeat(4096))));
    }

    #[test]
    fn accepts_reasonable_unit_names() {
        assert!(is_valid_unit_name("sshd.service"));
        assert!(is_valid_unit_name("nginx"));
        assert!(is_valid_unit_name("getty@tty1.service"));
        assert!(is_valid_unit_name("docker.socket"));
    }

    #[test]
    fn rejects_malformed_unit_names() {
        assert!(!is_valid_unit_name(""));
        assert!(!is_valid_unit_name("-sshd"));
        assert!(!is_valid_unit_name("sshd; rm -rf /"));
        assert!(!is_valid_unit_name("sshd service"));
        assert!(!is_valid_unit_name(&"a".repeat(257)));
    }

    #[test]
    fn accepts_reasonable_mount_targets() {
        assert!(is_valid_mount_target("/"));
        assert!(is_valid_mount_target("/var"));
        assert!(is_valid_mount_target("/mnt/data disk"));
    }

    #[test]
    fn rejects_malformed_mount_targets() {
        assert!(!is_valid_mount_target(""));
        assert!(!is_valid_mount_target("relative/path"));
        assert!(!is_valid_mount_target("/etc\nmalicious"));
        assert!(!is_valid_mount_target(&format!("/{}", "a".repeat(4096))));
    }

    #[test]
    fn accepts_reasonable_container_refs() {
        assert!(is_valid_container_ref("web-1"));
        assert!(is_valid_container_ref("my_app.service"));
        assert!(is_valid_container_ref("a1b2c3d4e5f6"));
    }

    #[test]
    fn rejects_malformed_container_refs() {
        assert!(!is_valid_container_ref(""));
        assert!(!is_valid_container_ref("-web"));
        assert!(!is_valid_container_ref("web; rm -rf /"));
        assert!(!is_valid_container_ref("web 1"));
        assert!(!is_valid_container_ref(&"a".repeat(256)));
    }
}
