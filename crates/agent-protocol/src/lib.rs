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
pub const PROTOCOL_VERSION: u32 = 23;

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
    SetHostname {
        hostname: String,
    },
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
    FirewallAllowPort {
        port: u16,
        protocol: String,
    },
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
    ConnectivityCheck {
        target: String,
    },
    /// Brings a network interface up or down (`ip link set <iface> up|down`).
    /// The control plane treats `up: true` as Write (additive, safe) and
    /// `up: false` as Destructive (can cut off remote access to the host if
    /// it's the interface currently in use) -- same command either way, the
    /// risk categorization lives on the control-plane side of the dispatch,
    /// same as every other op here.
    InterfaceSetState {
        interface: String,
        up: bool,
    },
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
    RecentlyModifiedFiles {
        hours: u32,
    },
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
    VacuumJournalBySize {
        size: String,
    },
    /// Deletes journal entries older than `duration`
    /// (`journalctl --vacuum-time=<duration>`, e.g. `"7d"`, `"2weeks"`).
    /// Same destructive/irreversible characteristics and permission gate as
    /// `VacuumJournalBySize`.
    VacuumJournalByTime {
        duration: String,
    },
    /// Backups already present under this host's fixed backup directory
    /// (`/var/backups/abyssal-arsenal`) -- name, size, and creation time.
    ListBackups,
    /// Archives `source_path` into a timestamped `<name>-<unix-time>.tar.gz`
    /// under the fixed backup directory. Write -- a real mutation (creates
    /// a file), but purely additive, so it doesn't require the explicit
    /// confirmation a `Destructive` operation does.
    CreateBackup {
        source_path: String,
        name: String,
    },
    /// Tests a backup archive's integrity (`tar -tzf`) and lists its
    /// contents, without extracting anything.
    VerifyBackup {
        filename: String,
    },
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
    ServiceStatus {
        unit: String,
    },
    /// The last 50 journal lines for one unit (`journalctl -u`).
    ServiceLogs {
        unit: String,
    },
    /// Starts a stopped unit. Write -- a real mutation, but not
    /// irreversible (stopping it again undoes it), so it doesn't require
    /// the explicit confirmation a `Destructive` operation does.
    StartService {
        unit: String,
    },
    /// Stops a running unit. Destructive: whatever the unit was providing
    /// becomes unavailable immediately, so the control plane requires
    /// explicit confirmation before ever dispatching this.
    StopService {
        unit: String,
    },
    /// Restarts a unit. Destructive for the same reason as `StopService`
    /// -- a brief outage is guaranteed, and if the unit is what's carrying
    /// the connection used to manage this host (e.g. `sshd`), restarting
    /// it can cut that connection.
    RestartService {
        unit: String,
    },
    /// Enables a unit to start automatically at boot, without touching
    /// whether it's running right now. Write -- additive, not disruptive.
    EnableService {
        unit: String,
    },
    /// Disables a unit from starting automatically at boot, without
    /// touching whether it's running right now. Write, not Destructive --
    /// the currently-running instance (if any) is unaffected.
    DisableService {
        unit: String,
    },
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
    RemountReadWrite {
        target: String,
    },
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
    DiskHealth {
        device: String,
    },
    /// Every container, running or stopped (`docker ps -a` /
    /// `podman ps -a` -- whichever runtime is present; their CLI syntax
    /// is identical for every op in this arsenal).
    ListContainers,
    /// The last 100 log lines for one container (`... logs --tail 100`).
    ContainerLogs {
        container: String,
    },
    /// Full inspection detail for one container -- config, mounts,
    /// network settings, restart policy (`... inspect`).
    ContainerInspect {
        container: String,
    },
    /// Every image present on the host (`... images`).
    ListImages,
    /// Runtime-level status: storage driver, container/image counts,
    /// version (`... info`).
    RuntimeInfo,
    /// Starts a stopped container. Write -- a real mutation, but not
    /// irreversible (stopping it again undoes it), so it doesn't require
    /// the explicit confirmation a `Destructive` operation does.
    StartContainer {
        container: String,
    },
    /// Stops a running container. Destructive: whatever the container was
    /// providing becomes unavailable immediately, so the control plane
    /// requires explicit confirmation before ever dispatching this.
    StopContainer {
        container: String,
    },
    /// Restarts a container. Destructive for the same reason as
    /// `StopContainer` -- a brief outage is guaranteed.
    RestartContainer {
        container: String,
    },
    /// Deletes a container entirely (`... rm`, without `-f`, so a
    /// currently-running container is refused rather than force-killed).
    /// Destructive and irreversible -- the container's own writable layer
    /// and state are gone, though named volumes survive -- so the control
    /// plane requires explicit confirmation before ever dispatching this.
    RemoveContainer {
        container: String,
    },
    /// Every process on the host, as a PID-ordered tree
    /// (`ps -ef --forest`) -- the complete picture, unlike Mortiscope's
    /// `TopProcessesByCpu`/`TopProcessesByMemory` (top 15 by resource
    /// usage only).
    ListProcesses,
    /// Full detail for one process -- user, state, resource usage,
    /// start time, and complete (untruncated) command line
    /// (`ps -p <pid> -o ... -ww`).
    ProcessDetail {
        pid: u32,
    },
    /// Adjusts a running process's scheduling priority
    /// (`renice -n <priority> -p <pid>`, range -20 to 19). Write -- a
    /// real mutation, but reversible (renice again) and not disruptive on
    /// its own, so it doesn't require the explicit confirmation a
    /// `Destructive` operation does.
    RenicePriority {
        pid: u32,
        priority: i32,
    },
    /// Sends a signal to a process (`kill -s <SIGNAL> <pid>`). Destructive
    /// regardless of which signal: any signal sent to a process is an
    /// intentional interruption of whatever it's doing, so the control
    /// plane requires explicit confirmation before ever dispatching this
    /// -- there's no "softer" signal choice that bypasses that gate.
    SendSignal {
        pid: u32,
        signal: String,
    },
    /// Disk usage of the standard cleanup-relevant locations -- `/tmp`,
    /// `/var/tmp`, and the systemd core dump directory (`du -sh`) --
    /// visibility into what's actually consuming space before deciding
    /// to clean any of it. Paths that don't exist on this host (e.g. no
    /// systemd-coredump) are skipped, not treated as a failure.
    CleanupTargetsSummary,
    /// Forces `logrotate` to run immediately against its configured
    /// rules (`logrotate -f /etc/logrotate.conf`), rather than waiting
    /// for its own cron/timer schedule. Write, not Destructive: this
    /// triggers logrotate's own configured rotation/retention behavior,
    /// it doesn't itself choose what gets deleted.
    ForceLogRotation,
    /// Deletes files under the fixed `/tmp` and `/var/tmp` locations
    /// whose data hasn't been modified in more than `older_than_days`
    /// days (`find /tmp /var/tmp -type f -mtime +N -delete`). Fixed,
    /// hardcoded paths only -- never an admin-supplied directory, since
    /// accepting an arbitrary path here would turn this into a general
    /// recursive-delete primitive. Destructive and irreversible: deleted
    /// files are gone, so the control plane requires explicit
    /// confirmation before ever dispatching this.
    ClearTmpFiles {
        older_than_days: u32,
    },
    /// Deletes every file under the systemd core dump directory
    /// (`/var/lib/systemd/coredump`), unconditionally -- distinct from
    /// `coredumpctl vacuum`'s own size/age-based retention policy, which
    /// may not free anything at all if nothing currently exceeds it.
    /// Destructive and irreversible: a later investigation may need a
    /// dump this removes (the same reasoning Obituary's journal vacuum
    /// documents), so the control plane requires explicit confirmation.
    ClearCoreDumps,
    /// Sampled system activity -- procs, memory, swap, I/O, system, and
    /// CPU columns across a few one-second samples (`vmstat 1 3`).
    /// Distinct from Mortiscope's `DiskIoStats` (`vmstat -d`, a static
    /// one-shot per-device counter dump): this is the classic
    /// over-time activity sample used to catch momentary CPU/memory
    /// pressure or context-switch storms.
    VmStatistics,
    /// Per-CPU interrupt counts by IRQ and device (`cat /proc/interrupts`)
    /// -- an IRQ storm on one core is a common, otherwise-invisible cause
    /// of a host that "feels slow."
    InterruptStatistics,
    /// The active CPU frequency-scaling governor and current/min/max
    /// clock speed, read from cpu0's cpufreq sysfs files as a
    /// representative sample (the governor is normally uniform across
    /// cores). Not available on hosts with no active cpufreq scaling
    /// (common in VMs/containers reporting a fixed frequency) -- that's
    /// a normal result here, not an error.
    CpuGovernorStatus,
    /// Current values of the `vm.*` sysctls this arsenal can tune
    /// (`sysctl vm.swappiness vm.dirty_ratio vm.dirty_background_ratio`)
    /// -- read-side visibility into the same knobs `SetSwappiness` turns.
    TuningParametersStatus,
    /// Sets `vm.swappiness` at runtime (`sysctl -w vm.swappiness=<value>`,
    /// 0-200). Write, not Destructive: a runtime-only sysctl change that
    /// doesn't persist across reboot and is trivially undone by setting
    /// it back.
    SetSwappiness {
        value: u32,
    },
    /// Sets a block device's I/O scheduler by writing the scheduler name
    /// to its sysfs queue file (`tee /sys/block/<device>/queue/scheduler`,
    /// fed via stdin since there's no shell here to do the `>` redirection
    /// this file conventionally takes). Write, not Destructive: purely a
    /// runtime queuing-policy change, reversible by writing a different
    /// name back.
    SetIoScheduler {
        device: String,
        scheduler: String,
    },
    /// Every local/NSS-resolved account (`getent passwd`).
    ListUsers,
    /// Every local/NSS-resolved group and its members (`getent group`).
    ListGroups,
    /// UID, primary GID, and every supplementary group for one account
    /// (`id <username>`).
    UserDetail {
        username: String,
    },
    /// Creates a new local account with a home directory
    /// (`useradd -m -c <comment> <username>`). The account has no
    /// password set (locked, per `useradd`'s own default) until someone
    /// assigns one directly on the host. Write -- additive, undone by
    /// `DeleteUser`.
    CreateUser {
        username: String,
        comment: String,
    },
    /// Creates a new local group (`groupadd <group>`). Write, additive.
    CreateGroup {
        group: String,
    },
    /// Adds an account to a supplementary group
    /// (`usermod -aG <group> <username>`). Write -- additive, reversible
    /// via `RemoveUserFromGroup`.
    AddUserToGroup {
        username: String,
        group: String,
    },
    /// Removes an account from a supplementary group
    /// (`gpasswd -d <username> <group>`). Write, not Destructive: the
    /// account and group both still exist, only the membership changes,
    /// and it's trivially reversed by adding them back.
    RemoveUserFromGroup {
        username: String,
        group: String,
    },
    /// Locks an account, disabling password login without deleting
    /// anything (`usermod -L <username>`). Write, not Destructive:
    /// reversible via `UnlockUserAccount`. Refuses `"root"` -- locking
    /// the one universally-critical account is never the intended
    /// target.
    LockUserAccount {
        username: String,
    },
    /// Reverses `LockUserAccount` (`usermod -U <username>`). Write.
    UnlockUserAccount {
        username: String,
    },
    /// Deletes a local account (`userdel [-r] <username>`), optionally
    /// removing its home directory too. Destructive and irreversible --
    /// the control plane requires explicit confirmation before ever
    /// dispatching this. Refuses `"root"`.
    DeleteUser {
        username: String,
        remove_home: bool,
    },
    /// Deletes a local group (`groupdel <group>`). Destructive and
    /// irreversible for the same reason as `DeleteUser`. Refuses
    /// `"root"`.
    DeleteGroup {
        group: String,
    },
    /// Immediate-subdirectory disk usage under `path`
    /// (`du -h --max-depth=1 <path>`) -- the classic "what's eating this
    /// directory" traversal, one level deep.
    DirectoryUsageBreakdown {
        path: String,
    },
    /// Files at or under `path` larger than `min_size_mb` megabytes
    /// (`find <path> -xdev -type f -size +<N>M`). `-xdev` keeps the
    /// search from wandering into other mounted filesystems under
    /// `path`, so scanning `/` doesn't also walk every remote mount.
    FindLargeFiles {
        path: String,
        min_size_mb: u32,
    },
    /// Read-only filesystem consistency check (`fsck -n <device>`) --
    /// reports problems without fixing anything, so unlike
    /// `FilesystemRepair` this is safe to run even on a mounted
    /// filesystem.
    FilesystemCheckDryRun {
        device: String,
    },
    /// Discards unused blocks on a mounted filesystem so the underlying
    /// SSD/storage can reclaim them (`fstrim -v <mountpoint>`) --
    /// routine, low-risk maintenance (the same operation most distros
    /// already run on a timer). Write, not Destructive: it never removes
    /// anything a filesystem still considers live.
    TrimFilesystem {
        mountpoint: String,
    },
    /// Runs `fsck`'s actual repair mode (`fsck -y <device>`, auto-answer
    /// yes to every fix). Destructive and genuinely dangerous if
    /// misused: the agent refuses outright if `device` is currently
    /// mounted (verified via `findmnt` immediately before dispatch,
    /// failing closed if that check itself can't be completed) --
    /// repairing a mounted filesystem's on-disk structures while it's
    /// live is a well-known way to cause the exact corruption this
    /// operation exists to fix. The control plane requires explicit
    /// confirmation before ever dispatching this regardless.
    FilesystemRepair {
        device: String,
    },
    /// Every installed package, from whichever of apt/dnf/yum/pacman/
    /// zypper the agent detects on its host (same "detect the tool
    /// present, don't assume one" approach as the firewall backends).
    ListInstalledPackages,
    /// Searches the package manager's repo metadata for `query`.
    SearchPackage {
        query: String,
    },
    /// Detailed info (version, description, dependencies, ...) for one
    /// package, whether installed or just available in a repo.
    PackageInfo {
        package: String,
    },
    /// Packages with an available upgrade. Some backends (`dnf`/`yum`
    /// `check-update`) use a non-zero exit specifically to mean "updates
    /// are available," not "the check failed" -- handled as a normal
    /// result, not an error.
    ListUpgradable,
    /// Refreshes the package manager's local repo metadata cache
    /// (`apt-get update` / `dnf makecache` / ...). Write -- doesn't
    /// install, remove, or change any package, just the cache used to
    /// decide what's available.
    RefreshPackageIndex,
    /// Installs a package (pulling in dependencies as the backend
    /// decides). Write -- additive, undone by `RemovePackage`.
    InstallPackage {
        package: String,
    },
    /// Upgrades one specific package to the latest version the refreshed
    /// index knows about, without touching any other package. Write, not
    /// Destructive: updates code in place, doesn't delete data, and can
    /// be undone by installing an older version directly if needed.
    UpgradePackage {
        package: String,
    },
    /// Removes an installed package (without purging its configuration
    /// files, where the backend distinguishes the two). Destructive:
    /// removing a package can break whatever depended on it, and
    /// reinstalling doesn't necessarily restore prior state exactly, so
    /// the control plane requires explicit confirmation before ever
    /// dispatching this.
    RemovePackage {
        package: String,
    },
    /// A disk's partition table (`parted <device> print`) -- MBR/GPT,
    /// partition list, sizes, types.
    PartitionTable {
        device: String,
    },
    /// LVM physical volumes, volume groups, and logical volumes
    /// (`pvs`/`vgs`/`lvs`), combined into one report.
    LvmSummary,
    /// Current software RAID array status (`cat /proc/mdstat`) -- which
    /// arrays exist, their state, and rebuild/resync progress if any.
    RaidStatus,
    /// Mounts an existing filesystem (`mount <device> <target>`). Write,
    /// not Destructive: doesn't create or destroy anything, and is
    /// reversible via `UnmountFilesystem`.
    MountFilesystem {
        device: String,
        target: String,
    },
    /// Grows an LVM logical volume by `size` (e.g. `"10G"`)
    /// (`lvextend -L +<size> <lv_path>`). Write, not Destructive: only
    /// adds space (fails cleanly if the volume group doesn't have enough
    /// free), never removes anything. Grows the block device only -- the
    /// filesystem on top still needs its own resize (`resize2fs`,
    /// `xfs_growfs`, ...), which this tool deliberately doesn't attempt,
    /// since picking the wrong filesystem-specific tool automatically is
    /// itself a real risk.
    ExtendLogicalVolume {
        lv_path: String,
        size: String,
    },
    /// Unmounts a filesystem (`umount <target>`). Destructive: whatever
    /// was using that mount loses access immediately, the same reasoning
    /// `StopService`/`StopContainer` document -- the data itself is
    /// untouched, but the control plane requires explicit confirmation
    /// before ever dispatching this regardless.
    UnmountFilesystem {
        target: String,
    },
    /// Creates a new partition (`parted -s <device> mkpart primary
    /// <start> <end>`, e.g. start `"0%"` end `"50%"`). Destructive and
    /// irreversible, and gated behind the admin-configured "high-risk
    /// storage operations" setting on top of the normal confirmation --
    /// a wrong `device` here can corrupt or destroy an entire disk's
    /// existing layout.
    CreatePartition {
        device: String,
        start: String,
        end: String,
    },
    /// Deletes a partition (`parted -s <device> rm <partition_number>`).
    /// Destructive, irreversible, and high-risk-gated for the same
    /// reason as `CreatePartition`.
    DeletePartition {
        device: String,
        partition_number: u32,
    },
    /// Creates a new software RAID array (`mdadm --create <array_name>
    /// --level=<level> --raid-devices=<N> <devices...>`), consuming every
    /// device listed. Destructive, irreversible, and high-risk-gated --
    /// listing the wrong device destroys its existing contents the
    /// moment the array is created.
    CreateRaidArray {
        array_name: String,
        level: String,
        devices: Vec<String>,
    },
    /// Stops (deactivates) a RAID array (`mdadm --stop <array_name>`)
    /// without touching the data on its member devices -- reassembling
    /// it later is possible, but not automatic, so this is still
    /// Destructive and high-risk-gated rather than assumed safe.
    StopRaidArray {
        array_name: String,
    },
    /// Initializes a device as an LVM physical volume (`pvcreate
    /// <device>`), wiping any existing filesystem signature on it.
    /// Destructive, irreversible, and high-risk-gated.
    CreatePhysicalVolume {
        device: String,
    },
    /// Creates an LVM volume group from one or more physical volumes
    /// (`vgcreate <name> <physical_volumes...>`). Destructive
    /// (consumes the listed PVs into the new VG) and high-risk-gated.
    CreateVolumeGroup {
        name: String,
        physical_volumes: Vec<String>,
    },
    /// Creates a new logical volume within an existing volume group
    /// (`lvcreate -n <lv_name> -L <size> <vg_name>`). Destructive and
    /// high-risk-gated along with the rest of LVM's create/remove
    /// surface, even though its own blast radius (new space carved from
    /// already-free VG capacity) is narrower than `CreatePhysicalVolume`
    /// or `CreateVolumeGroup`.
    CreateLogicalVolume {
        vg_name: String,
        lv_name: String,
        size: String,
    },
    /// Removes a logical volume and its data (`lvremove -f <lv_path>`).
    /// Destructive, irreversible, and high-risk-gated.
    RemoveLogicalVolume {
        lv_path: String,
    },
    /// Removes a volume group (`vgremove -f <name>`) -- refused by `vgremove`
    /// itself if it still contains logical volumes. Destructive,
    /// irreversible, and high-risk-gated.
    RemoveVolumeGroup {
        name: String,
    },
    /// Removes a device's LVM physical volume metadata (`pvremove -f
    /// <device>`). Destructive, irreversible, and high-risk-gated.
    RemovePhysicalVolume {
        device: String,
    },
    /// Creates a filesystem on a device (`mkfs.<fstype> -F <device>`),
    /// destroying whatever was there before. The single most dangerous
    /// operation this platform can dispatch -- unlike `FilesystemRepair`
    /// (Catacomb), which can at worst do nothing useful, a wrong
    /// `device` here instantly and unconditionally destroys everything
    /// on it with no partial-safety case at all. Destructive,
    /// irreversible, and high-risk-gated.
    CreateFilesystem {
        device: String,
        fstype: String,
    },
    /// Configuration management ("Grimoire"), deliberately narrow:
    /// everything here reads or writes exactly one of two files this
    /// tool exclusively owns -- `/etc/sysctl.d/99-abyssal-arsenal.conf`
    /// (persistent sysctl overrides) and `/etc/cron.d/abyssal-arsenal`
    /// (scheduled tasks) -- never an arbitrary or pre-existing system
    /// file. Editing a shared file like `/etc/hosts` in place risks
    /// corrupting it through a string-manipulation bug; a dedicated
    /// drop-in file this tool always fully controls and always renders
    /// from scratch can't have that failure mode.
    ViewManagedSysctl,
    ViewManagedCronJobs,
    /// Idempotently sets `key = value` in the managed sysctl file
    /// (creating it if needed) and applies it immediately
    /// (`sysctl -p <file>`). Write -- a real mutation, but narrowly
    /// scoped to one key in one tool-owned file, reversible via
    /// `RemovePersistentSysctlKey`.
    SetPersistentSysctl {
        key: String,
        value: String,
    },
    /// Removes one key from the managed sysctl file (the file itself,
    /// and every other key in it, is untouched). Write, not Destructive:
    /// narrow and reversible by setting it again.
    RemovePersistentSysctlKey {
        key: String,
    },
    /// Wipes the entire managed sysctl file, reverting every persistent
    /// override this tool has set back to distro defaults at once.
    /// Destructive: broader impact than removing a single key.
    ClearManagedSysctl,
    /// Idempotently adds or updates one named scheduled task in the
    /// managed cron.d file (adding it if `job_name` doesn't exist yet,
    /// replacing it if it does). Write -- narrowly scoped to one job in
    /// one tool-owned file.
    SetCronJob {
        job_name: String,
        schedule: String,
        run_as_user: String,
        command: String,
    },
    /// Removes one named scheduled task from the managed cron.d file.
    /// Destructive: stops whatever recurring behavior that job
    /// provided, the same reasoning `StopService`/`StopContainer`
    /// document for interrupting something ongoing.
    RemoveCronJob {
        job_name: String,
    },
    /// Wipes the entire managed cron.d file, removing every scheduled
    /// task this tool has set at once. Destructive: broader impact than
    /// removing a single job.
    ClearManagedCronJobs,
    /// Active incident response ("Inquest"): containment (blocking a
    /// specific remote IP, or -- gated, see `IsolateHost` -- isolating
    /// the whole host) and remediation (quarantining a suspicious file
    /// rather than deleting it outright, preserving it for later
    /// analysis). Distinct from Postmortem (passive, read-only
    /// forensics): this arsenal actually *does* something about an
    /// incident in progress.
    ListBlockedIps,
    /// Whether full host isolation (see `IsolateHost`) is currently
    /// active on this host, and if so, how it was applied (nftables
    /// table present, or iptables policy/tagged rules present).
    IsolationStatus,
    /// Every currently quarantined file, with the original path each was
    /// moved from.
    ListQuarantinedFiles,
    /// Blocks a specific remote IP address at the firewall level (both
    /// directions), via whichever of nftables/iptables the agent
    /// detects. Write -- narrow and reversible via `UnblockRemoteIp`,
    /// and never touches the agent's own connection to the control
    /// plane (unlike `IsolateHost`, this targets one specific address,
    /// not "everything except an allow-list").
    BlockRemoteIp {
        ip: String,
    },
    /// Reverses `BlockRemoteIp`. Write, not Destructive: narrow and
    /// reversible by blocking it again.
    UnblockRemoteIp {
        ip: String,
    },
    /// Moves a file to a fixed, tool-owned quarantine directory,
    /// preserving it rather than deleting it -- the classic incident-
    /// response "get this off the host without destroying evidence"
    /// action. The quarantined filename itself encodes where the file
    /// came from, so restoring it later never depends on an
    /// admin-retyped (and therefore arbitrary, error-prone) path. Write:
    /// relocates a file, doesn't destroy it, reversible via
    /// `RestoreQuarantinedFile`.
    QuarantineFile {
        path: String,
    },
    /// Moves a quarantined file back to exactly the path it was
    /// quarantined from (decoded from the quarantine filename itself,
    /// never an admin-supplied path -- the same reasoning Grimoire's
    /// drop-in-file-only design documents: accepting an arbitrary
    /// restore *destination* would turn this into a general
    /// arbitrary-file-write primitive). Write, for the false-positive
    /// case.
    RestoreQuarantinedFile {
        quarantine_filename: String,
    },
    /// Permanently deletes a quarantined file (confirmed malicious, no
    /// longer needed as evidence). Destructive and irreversible.
    DeleteQuarantinedFile {
        filename: String,
    },
    /// Reverses `IsolateHost` -- removes whichever isolation mechanism
    /// (nftables table or iptables policy/tagged rules) is currently
    /// applied, restoring normal connectivity. Write, not Destructive,
    /// and deliberately *not* gated behind the high-risk isolation
    /// setting: undoing isolation should never have more friction than
    /// applying it did. Idempotent and safe to run even if the host
    /// isn't currently isolated.
    DeisolateHost,
    /// Blocks all network traffic on this host except the connection
    /// back to the control plane (auto-resolved from the agent's own
    /// `--control-plane-url`) and loopback -- full containment for a
    /// host actively participating in an incident (data exfiltration,
    /// lateral movement). The single most dangerous operation this
    /// platform can dispatch in a different way than Ossuary's `mkfs`:
    /// where `mkfs` can only harm the device it targets, a wrong edge
    /// case here (NAT, a DNS-based control-plane address, a multi-homed
    /// host) can sever the agent's own manageability with **no remote
    /// way to undo it** -- recovery needs physical or console access.
    /// Destructive, irreversible-without-console-access, and gated
    /// behind the admin-configured "host isolation" setting on top of
    /// the normal confirmation, exactly mirroring Ossuary's high-risk
    /// storage gate.
    IsolateHost,
    /// Secrets, credentials, certificates, keys, and sensitive
    /// configuration on the managed host ("Cryptkeeper"). Distinct from
    /// Parish (Linux account/group administration): Parish manages *who*
    /// exists, Cryptkeeper manages *what proves who they are* and *what
    /// they can prove it to* -- SSH keys, TLS certificates, and the
    /// files that hold other secrets. The control plane deliberately
    /// does see plaintext here (unlike a zero-knowledge password
    /// manager) -- it's the trusted administrator surface for hosts it
    /// already fully manages, not an untrusted party.
    ///
    /// Every discovered host SSH keypair's fingerprint (never the raw
    /// key material) plus a permission-safety note on each private key.
    ListSshHostKeys,
    /// A user's `~/.ssh/authorized_keys`, fingerprinted per entry (via
    /// `ssh-keygen -lf`, which accepts a whole authorized_keys-format
    /// file) rather than shown as raw key blobs -- enough to audit who
    /// can log in as that user without dumping key material that's
    /// awkward to eyeball anyway.
    ListSshAuthorizedKeys {
        username: String,
    },
    /// Every certificate found under this host's common certificate
    /// locations, with subject and expiry -- the fast "what's expiring
    /// soon" view. Certificates are public by nature, so this reads
    /// freely; only a private key alongside one is sensitive (see
    /// `ScanSensitiveFilePermissions`).
    ListTlsCertificates,
    /// The full parsed detail (`openssl x509 -text`) of one specific
    /// certificate file.
    CertificateDetail {
        path: String,
    },
    /// Finds private keys, `authorized_keys` files, and similar
    /// credential material under common locations (`/etc/ssh`,
    /// `/etc/ssl/private`, home directories' `.ssh`) that are readable
    /// or writable by group or other -- the single most common real-world
    /// credential-exposure mistake, and the thing this operation exists
    /// to catch.
    ScanSensitiveFilePermissions,
    /// Reads one specific file the admin names explicitly, in full,
    /// including whatever secret material it contains -- deliberately
    /// not an automatic crawler that scrapes every config file on the
    /// host for anything that looks like a credential; the admin must
    /// already know (from `ScanSensitiveFilePermissions` or otherwise)
    /// which file they mean to look at.
    ViewSensitiveFile {
        path: String,
    },
    /// Generates a new SSH keypair at an admin-chosen path with no
    /// passphrase (the common case for a new deploy/service key --
    /// nothing here supports an interactive passphrase prompt). Write:
    /// creates a new file, doesn't touch anything existing. Refuses to
    /// overwrite a path that's already in use.
    GenerateSshKeypair {
        key_type: String,
        comment: String,
        path: String,
    },
    /// Tightens a file's permission bits to one of a small fixed set of
    /// safe modes -- never an arbitrary chmod target, since this
    /// operation exists specifically to fix exposures
    /// `ScanSensitiveFilePermissions` finds, not to be a general
    /// permission-management primitive. Write: always makes a file
    /// *more* restrictive, which is safe and easily reversed by an
    /// admin who actually needed the looser mode.
    FixFilePermissions {
        path: String,
        mode: String,
    },
    /// Removes one `authorized_keys` entry matched by its exact
    /// fingerprint (never by comment, which isn't reliably unique) --
    /// revokes whatever access that key granted. Destructive: this is
    /// an access-revocation action, and the entry isn't recoverable
    /// from this operation alone once removed.
    RemoveAuthorizedKey {
        username: String,
        fingerprint: String,
    },
    /// Permanently deletes an SSH keypair (both the private key and its
    /// `.pub` counterpart, if present) at an admin-chosen path.
    /// Destructive and irreversible -- deliberately not restricted to
    /// non-system paths, since revoking a compromised key is exactly
    /// the kind of thing this needs to do even for a host key under
    /// `/etc/ssh`; the type-to-confirm step is the safeguard, not a
    /// path allow-list.
    DeleteSshKeypair {
        path: String,
    },
    /// Security telemetry collection and threat detection ("Thanatos"):
    /// tails this host's security-relevant logs (`/var/log/auth.log` or
    /// `/var/log/secure`, whichever exists, falling back to `journalctl`
    /// for `sshd`/`sudo`/`systemd-logind` on hosts with neither) and
    /// classifies each line against a fixed, ordered rule table into a
    /// severity (low/medium/high -- `critical` is reserved for the
    /// control plane's own correlation findings, never assigned by the
    /// agent) and a human label. Returns only lines that matched a rule,
    /// one per line as tab-separated `severity\tlabel\tsource\traw_line`
    /// -- the control plane persists these for its own event-correlation
    /// and alerting (see `crates/web/src/thanatos_ops.rs`), which is why
    /// this needs structured-ish output rather than the free-text
    /// `OperationOutput` every other read op returns. Read: never
    /// modifies anything on the host.
    ///
    /// `extra_fim_paths` (Phase 7b): admin-configured paths to hash
    /// alongside the agent's own small hardcoded watch-list (never a
    /// replacement for it -- an admin clearing this setting shouldn't
    /// lose default coverage). Each path is validated
    /// control-plane-side before being sent (`is_valid_absolute_path`/
    /// `is_valid_windows_absolute_path` depending on the target host's
    /// `Host.os`), but the agent re-validates too, same as every other
    /// operation here -- this crate's own doc comment's rule that the
    /// agent never trusts a wire value just because the control plane
    /// already checked it.
    ScanSecurityEvents {
        extra_fim_paths: Vec<String>,
    },

    // -------------------------------------------------------------
    // Sepulchre: host-side SFTP/SMB share provisioning and mounts.
    // "Never edit the main sshd_config/smb.conf in place" -- every
    // write here touches only a Sepulchre-owned drop-in/include file,
    // the same managed-file idiom `SetPersistentSysctl`/`SetCronJob`
    // above already use, extended with a validate-before-reload step
    // (`sshd -t` / `testparm -s`) and a rollback-on-failure restore of
    // the previous file content.
    // -------------------------------------------------------------
    /// Live-probes for `apt-get`/`dnf`/`yum`/`pacman`/`zypper` (the same
    /// detection `Backend::detect()` in `apothecary.rs` already does for
    /// package install/remove) so the control plane can pick the right
    /// package names and show "this host uses apt" before offering to
    /// install prerequisites. Read: no state is read or changed beyond
    /// checking which binaries exist on `PATH`.
    DetectPackageBackend,
    /// Renders `content` into the Sepulchre-owned drop-in/include file
    /// for `target`, validates it (`sshd -t` / `testparm -s`) *before*
    /// reloading, and restores the previous content and reloads again if
    /// validation fails -- a bad render can never be left half-applied.
    /// Write.
    RenderSepulchreConfig {
        target: SepulchreConfigTarget,
        content: String,
    },
    /// Empties (not deletes -- keeps the file present but content-only
    /// the managed header) the drop-in/include file for `target`,
    /// validates, and reloads. Destructive: removes every share/account
    /// directive Sepulchre had configured there.
    ClearSepulchreConfig {
        target: SepulchreConfigTarget,
    },
    /// Whether the host's own main config (`sshd_config`/`smb.conf`)
    /// actually includes the directory/file Sepulchre's drop-in lives
    /// in -- a prerequisite check, surfaced as a finding rather than
    /// silently assumed. Read.
    CheckSepulchreConfigIncludeDirective {
        target: SepulchreConfigTarget,
    },
    /// Creates a dedicated, restricted SFTP account: `ChrootDirectory`-
    /// ready (the chroot dir itself is created root-owned, not group/
    /// world-writable, with a writable subdirectory inside it), nologin
    /// shell, no password login. Write.
    CreateSftpChrootAccount {
        username: String,
        chroot_dir: String,
    },
    /// Installs `public_key` into a Sepulchre-owned
    /// `AuthorizedKeysFile` location (e.g.
    /// `/etc/ssh/sepulchre/authorized_keys/<username>`), never the
    /// account's own `~/.ssh/authorized_keys` -- keeps the chroot
    /// directory's required root-owned, non-writable-by-the-user
    /// permissions from ever conflicting with where its authorized keys
    /// live. Write. Public key material only, never a private key.
    InstallSepulchreAuthorizedKey {
        username: String,
        public_key: String,
    },
    /// Removes an SFTP chroot account and its home/chroot directory.
    /// Destructive: data under the chroot directory is removed with the
    /// account unless a caller has already relocated it -- Sepulchre's
    /// own web-layer confirmation flow is what actually enforces "never
    /// deletes data unless separately, explicitly requested" (see
    /// `docs/sepulchre.md`); this operation itself just does what it's
    /// asked.
    RemoveSftpChrootAccount {
        username: String,
    },
    /// Creates (or resets the password of) a Samba service account: a
    /// matching nologin system account plus an `smbpasswd`/`pdbedit`
    /// entry. `password` travels only as a field on this already-
    /// encrypted WebSocket operation -- never as an argument to the
    /// `smbpasswd`/`pdbedit` subprocess the agent runs, which receives it
    /// over stdin instead (same "never argv, never a log line" rule
    /// `Elevate`'s sudo password already follows). Write.
    CreateSambaServiceUser {
        username: String,
        password: String,
    },
    /// Removes a Samba service account (both the `smbpasswd`/`pdbedit`
    /// entry and the matching system account). Destructive.
    RemoveSambaServiceUser {
        username: String,
    },
    /// Writes and enables a systemd mount unit (SSHFS or CIFS,
    /// depending on `content`) -- credentials, if any, live in a
    /// separate root-owned `0600` file `content` references, never
    /// inline in the unit itself. Write.
    RenderMountUnit {
        unit_name: String,
        mount_point: String,
        content: String,
    },
    /// Stops, disables, and removes a previously-rendered mount unit
    /// (and unmounts `mount_point` if still mounted). Destructive: the
    /// remote data itself is untouched, only the local mount goes away.
    RemoveMountUnit {
        unit_name: String,
        mount_point: String,
    },
    /// Confirms `mount_point` is actually mounted (parses
    /// `/proc/mounts`) -- the apply-then-verify half of Sepulchre's
    /// plan/preview/apply/verify host-side flow. Read.
    CheckMountStatus {
        mount_point: String,
    },
    /// Creates a directory at `path`, owned by `owner` (the Samba service
    /// account that will actually read/write through the share) and mode
    /// `0750`, if it doesn't already exist -- used to prepare the on-disk
    /// location an SMB share stanza points at before the share is
    /// announced (unlike an SFTP chroot, a Samba share has no dedicated
    /// account-creation step that would otherwise create it). Deliberately
    /// *not* root-owned the way an SFTP `ChrootDirectory` must be --
    /// `smbd` still enforces real filesystem permissions underneath its
    /// own `valid users` ACL, so a root-owned directory would make every
    /// write fail with `NT_STATUS_ACCESS_DENIED` regardless of what the
    /// share stanza allows (caught live against a real Samba server).
    /// Write, but idempotent: safe to call again against a directory
    /// that's already there.
    CreateSepulchreShareDirectory {
        path: String,
        owner: String,
    },
    /// Writes a CIFS mount's `credentials=` file -- `path` must be under
    /// the Sepulchre-reserved `/etc/sepulchre/mounts/` directory (checked
    /// both here and again by the agent, never trusting the caller
    /// already did), created root-owned `0600`, referenced by
    /// `RenderMountUnit`'s own `Options=` rather than ever embedding
    /// credentials in the unit file itself. `contents` travels only as a
    /// field on this already-encrypted WebSocket operation. Write.
    WriteSepulchreMountCredentials {
        path: String,
        contents: String,
    },
}

/// Which Sepulchre-owned config drop-in/include an operation targets --
/// see `AgentOperation::RenderSepulchreConfig` and friends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SepulchreConfigTarget {
    SshdDropIn,
    SambaInclude,
}

impl AgentOperation {
    /// A short, human-readable past-tense description for the audit trail
    /// and the dashboard's "recent activity" feed (e.g. `"Rebooted"`,
    /// `"Created backup: nightly"`). Every mutating (Write/Destructive)
    /// variant gets a specific, hand-written phrase, since those are the
    /// ones the activity feed actually surfaces. Read-only variants fall
    /// back to a label auto-derived from the variant's own name (reusing
    /// the same name `Debug` already prints, which is why `Debug` redacts
    /// `Elevate`'s password rather than this needing its own redaction) --
    /// they're filtered out of the trimmed feed as noise, but still get a
    /// real label for the raw audit record and any future full-detail view.
    pub fn label(&self) -> String {
        match self {
            AgentOperation::SetHostname { hostname } => format!("Set hostname to {hostname}"),
            AgentOperation::Reboot => "Rebooted".to_string(),
            AgentOperation::FirewallAllowPort { port, protocol } => {
                format!("Allowed port {port}/{protocol}")
            }
            AgentOperation::FirewallEnable => "Enabled firewall".to_string(),
            AgentOperation::Elevate { .. } => "Elevated privileges".to_string(),
            AgentOperation::Deescalate => "De-escalated privileges".to_string(),
            AgentOperation::InterfaceSetState { interface, up } => {
                format!(
                    "Set interface {interface} {}",
                    if *up { "up" } else { "down" }
                )
            }
            AgentOperation::NetworkScan { target, .. } => {
                format!("Ran network scan against {target}")
            }
            AgentOperation::VacuumJournalBySize { size } => format!("Vacuumed journal to {size}"),
            AgentOperation::VacuumJournalByTime { duration } => {
                format!("Vacuumed journal older than {duration}")
            }
            AgentOperation::CreateBackup { name, .. } => format!("Created backup: {name}"),
            AgentOperation::RestoreBackup { filename, .. } => format!("Restored backup {filename}"),
            AgentOperation::StartService { unit } => format!("Started service {unit}"),
            AgentOperation::StopService { unit } => format!("Stopped service {unit}"),
            AgentOperation::RestartService { unit } => format!("Restarted service {unit}"),
            AgentOperation::EnableService { unit } => format!("Enabled service {unit}"),
            AgentOperation::DisableService { unit } => format!("Disabled service {unit}"),
            AgentOperation::ReloadSystemdDaemon => "Reloaded systemd daemon".to_string(),
            AgentOperation::ResetFailedUnits => "Reset failed systemd units".to_string(),
            AgentOperation::RemountReadWrite { target } => format!("Remounted {target} read-write"),
            AgentOperation::StartContainer { container } => {
                format!("Started container {container}")
            }
            AgentOperation::StopContainer { container } => format!("Stopped container {container}"),
            AgentOperation::RestartContainer { container } => {
                format!("Restarted container {container}")
            }
            AgentOperation::RemoveContainer { container } => {
                format!("Removed container {container}")
            }
            AgentOperation::RenicePriority { pid, priority } => {
                format!("Reniced PID {pid} to priority {priority}")
            }
            AgentOperation::SendSignal { pid, signal } => format!("Sent {signal} to PID {pid}"),
            AgentOperation::ForceLogRotation => "Forced log rotation".to_string(),
            AgentOperation::ClearTmpFiles { older_than_days } => {
                format!("Cleared temp files older than {older_than_days}d")
            }
            AgentOperation::ClearCoreDumps => "Cleared core dumps".to_string(),
            AgentOperation::SetSwappiness { value } => format!("Set swappiness to {value}"),
            AgentOperation::SetIoScheduler { device, scheduler } => {
                format!("Set I/O scheduler on {device} to {scheduler}")
            }
            AgentOperation::CreateUser { username, .. } => format!("Created user {username}"),
            AgentOperation::CreateGroup { group } => format!("Created group {group}"),
            AgentOperation::AddUserToGroup { username, group } => {
                format!("Added {username} to group {group}")
            }
            AgentOperation::RemoveUserFromGroup { username, group } => {
                format!("Removed {username} from group {group}")
            }
            AgentOperation::LockUserAccount { username } => format!("Locked user {username}"),
            AgentOperation::UnlockUserAccount { username } => format!("Unlocked user {username}"),
            AgentOperation::DeleteUser { username, .. } => format!("Deleted user {username}"),
            AgentOperation::DeleteGroup { group } => format!("Deleted group {group}"),
            AgentOperation::TrimFilesystem { mountpoint } => {
                format!("Trimmed filesystem at {mountpoint}")
            }
            AgentOperation::FilesystemRepair { device } => {
                format!("Repaired filesystem on {device}")
            }
            AgentOperation::InstallPackage { package } => format!("Installed package {package}"),
            AgentOperation::UpgradePackage { package } => format!("Upgraded package {package}"),
            AgentOperation::RemovePackage { package } => format!("Removed package {package}"),
            AgentOperation::RefreshPackageIndex => "Refreshed package index".to_string(),
            AgentOperation::MountFilesystem { device, target } => {
                format!("Mounted {device} at {target}")
            }
            AgentOperation::UnmountFilesystem { target } => format!("Unmounted {target}"),
            AgentOperation::ExtendLogicalVolume { lv_path, size } => {
                format!("Extended logical volume {lv_path} by {size}")
            }
            AgentOperation::CreatePartition { device, .. } => {
                format!("Created partition on {device}")
            }
            AgentOperation::DeletePartition {
                device,
                partition_number,
            } => format!("Deleted partition {partition_number} on {device}"),
            AgentOperation::CreateRaidArray { array_name, .. } => {
                format!("Created RAID array {array_name}")
            }
            AgentOperation::StopRaidArray { array_name } => {
                format!("Stopped RAID array {array_name}")
            }
            AgentOperation::CreatePhysicalVolume { device } => {
                format!("Created physical volume {device}")
            }
            AgentOperation::CreateVolumeGroup { name, .. } => {
                format!("Created volume group {name}")
            }
            AgentOperation::CreateLogicalVolume {
                vg_name, lv_name, ..
            } => format!("Created logical volume {lv_name} in {vg_name}"),
            AgentOperation::RemoveLogicalVolume { lv_path } => {
                format!("Removed logical volume {lv_path}")
            }
            AgentOperation::RemoveVolumeGroup { name } => format!("Removed volume group {name}"),
            AgentOperation::RemovePhysicalVolume { device } => {
                format!("Removed physical volume {device}")
            }
            AgentOperation::CreateFilesystem { device, fstype } => {
                format!("Created {fstype} filesystem on {device}")
            }
            AgentOperation::SetPersistentSysctl { key, value } => {
                format!("Set sysctl {key} = {value}")
            }
            AgentOperation::RemovePersistentSysctlKey { key } => {
                format!("Removed sysctl key {key}")
            }
            AgentOperation::ClearManagedSysctl => {
                "Cleared all managed sysctl overrides".to_string()
            }
            AgentOperation::SetCronJob { job_name, .. } => format!("Set cron job {job_name}"),
            AgentOperation::RemoveCronJob { job_name } => format!("Removed cron job {job_name}"),
            AgentOperation::ClearManagedCronJobs => "Cleared all managed cron jobs".to_string(),
            AgentOperation::BlockRemoteIp { ip } => format!("Blocked IP {ip}"),
            AgentOperation::UnblockRemoteIp { ip } => format!("Unblocked IP {ip}"),
            AgentOperation::QuarantineFile { path } => format!("Quarantined file {path}"),
            AgentOperation::RestoreQuarantinedFile {
                quarantine_filename,
            } => format!("Restored quarantined file {quarantine_filename}"),
            AgentOperation::DeleteQuarantinedFile { filename } => {
                format!("Deleted quarantined file {filename}")
            }
            AgentOperation::DeisolateHost => "Removed host isolation".to_string(),
            AgentOperation::IsolateHost => "Isolated host".to_string(),
            AgentOperation::GenerateSshKeypair { key_type, path, .. } => {
                format!("Generated {key_type} SSH keypair at {path}")
            }
            AgentOperation::FixFilePermissions { path, mode } => {
                format!("Fixed permissions on {path} ({mode})")
            }
            AgentOperation::RemoveAuthorizedKey { username, .. } => {
                format!("Removed authorized key for {username}")
            }
            AgentOperation::DeleteSshKeypair { path } => format!("Deleted SSH keypair {path}"),
            AgentOperation::RenderSepulchreConfig { target, .. } => {
                format!("Updated Sepulchre {target:?} configuration")
            }
            AgentOperation::ClearSepulchreConfig { target } => {
                format!("Cleared Sepulchre {target:?} configuration")
            }
            AgentOperation::CreateSftpChrootAccount { username, .. } => {
                format!("Created SFTP chroot account {username}")
            }
            AgentOperation::InstallSepulchreAuthorizedKey { username, .. } => {
                format!("Installed an authorized key for {username}")
            }
            AgentOperation::RemoveSftpChrootAccount { username } => {
                format!("Removed SFTP chroot account {username}")
            }
            AgentOperation::CreateSambaServiceUser { username, .. } => {
                format!("Created Samba service user {username}")
            }
            AgentOperation::RemoveSambaServiceUser { username } => {
                format!("Removed Samba service user {username}")
            }
            AgentOperation::RenderMountUnit { mount_point, .. } => {
                format!("Mounted {mount_point}")
            }
            AgentOperation::RemoveMountUnit { mount_point, .. } => {
                format!("Unmounted {mount_point}")
            }
            AgentOperation::WriteSepulchreMountCredentials { path, .. } => {
                format!("Wrote mount credentials file {path}")
            }
            AgentOperation::CreateSepulchreShareDirectory { path, .. } => {
                format!("Created share directory {path}")
            }
            other => humanize_variant_name(&variant_debug_name(other)),
        }
    }
}

/// The bare variant name from `AgentOperation`'s own redacting `Debug` impl
/// below (e.g. `"RecentlyModifiedFiles { hours: 24 }"` -> `"RecentlyModifiedFiles"`),
/// reused rather than duplicated so a fallback label can never accidentally
/// include a field `Debug` deliberately redacts.
fn variant_debug_name(op: &AgentOperation) -> String {
    let full = format!("{op:?}");
    full.split(['{', ' ']).next().unwrap_or(&full).to_string()
}

/// `"RecentlyModifiedFiles"` -> `"Recently Modified Files"`: inserts a space
/// before every uppercase letter that follows a lowercase letter or digit.
fn humanize_variant_name(name: &str) -> String {
    let mut out = String::new();
    let mut prev_lower_or_digit = false;
    for c in name.chars() {
        if c.is_uppercase() && prev_lower_or_digit {
            out.push(' ');
        }
        out.push(c);
        prev_lower_or_digit = c.is_lowercase() || c.is_ascii_digit();
    }
    out
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
            AgentOperation::ListProcesses => write!(f, "ListProcesses"),
            AgentOperation::ProcessDetail { pid } => {
                f.debug_struct("ProcessDetail").field("pid", pid).finish()
            }
            AgentOperation::RenicePriority { pid, priority } => f
                .debug_struct("RenicePriority")
                .field("pid", pid)
                .field("priority", priority)
                .finish(),
            AgentOperation::SendSignal { pid, signal } => f
                .debug_struct("SendSignal")
                .field("pid", pid)
                .field("signal", signal)
                .finish(),
            AgentOperation::CleanupTargetsSummary => write!(f, "CleanupTargetsSummary"),
            AgentOperation::ForceLogRotation => write!(f, "ForceLogRotation"),
            AgentOperation::ClearTmpFiles { older_than_days } => f
                .debug_struct("ClearTmpFiles")
                .field("older_than_days", older_than_days)
                .finish(),
            AgentOperation::ClearCoreDumps => write!(f, "ClearCoreDumps"),
            AgentOperation::VmStatistics => write!(f, "VmStatistics"),
            AgentOperation::InterruptStatistics => write!(f, "InterruptStatistics"),
            AgentOperation::CpuGovernorStatus => write!(f, "CpuGovernorStatus"),
            AgentOperation::TuningParametersStatus => write!(f, "TuningParametersStatus"),
            AgentOperation::SetSwappiness { value } => f
                .debug_struct("SetSwappiness")
                .field("value", value)
                .finish(),
            AgentOperation::SetIoScheduler { device, scheduler } => f
                .debug_struct("SetIoScheduler")
                .field("device", device)
                .field("scheduler", scheduler)
                .finish(),
            AgentOperation::ListUsers => write!(f, "ListUsers"),
            AgentOperation::ListGroups => write!(f, "ListGroups"),
            AgentOperation::UserDetail { username } => f
                .debug_struct("UserDetail")
                .field("username", username)
                .finish(),
            AgentOperation::CreateUser { username, comment } => f
                .debug_struct("CreateUser")
                .field("username", username)
                .field("comment", comment)
                .finish(),
            AgentOperation::CreateGroup { group } => {
                f.debug_struct("CreateGroup").field("group", group).finish()
            }
            AgentOperation::AddUserToGroup { username, group } => f
                .debug_struct("AddUserToGroup")
                .field("username", username)
                .field("group", group)
                .finish(),
            AgentOperation::RemoveUserFromGroup { username, group } => f
                .debug_struct("RemoveUserFromGroup")
                .field("username", username)
                .field("group", group)
                .finish(),
            AgentOperation::LockUserAccount { username } => f
                .debug_struct("LockUserAccount")
                .field("username", username)
                .finish(),
            AgentOperation::UnlockUserAccount { username } => f
                .debug_struct("UnlockUserAccount")
                .field("username", username)
                .finish(),
            AgentOperation::DeleteUser {
                username,
                remove_home,
            } => f
                .debug_struct("DeleteUser")
                .field("username", username)
                .field("remove_home", remove_home)
                .finish(),
            AgentOperation::DeleteGroup { group } => {
                f.debug_struct("DeleteGroup").field("group", group).finish()
            }
            AgentOperation::DirectoryUsageBreakdown { path } => f
                .debug_struct("DirectoryUsageBreakdown")
                .field("path", path)
                .finish(),
            AgentOperation::FindLargeFiles { path, min_size_mb } => f
                .debug_struct("FindLargeFiles")
                .field("path", path)
                .field("min_size_mb", min_size_mb)
                .finish(),
            AgentOperation::FilesystemCheckDryRun { device } => f
                .debug_struct("FilesystemCheckDryRun")
                .field("device", device)
                .finish(),
            AgentOperation::TrimFilesystem { mountpoint } => f
                .debug_struct("TrimFilesystem")
                .field("mountpoint", mountpoint)
                .finish(),
            AgentOperation::FilesystemRepair { device } => f
                .debug_struct("FilesystemRepair")
                .field("device", device)
                .finish(),
            AgentOperation::ListInstalledPackages => write!(f, "ListInstalledPackages"),
            AgentOperation::SearchPackage { query } => f
                .debug_struct("SearchPackage")
                .field("query", query)
                .finish(),
            AgentOperation::PackageInfo { package } => f
                .debug_struct("PackageInfo")
                .field("package", package)
                .finish(),
            AgentOperation::ListUpgradable => write!(f, "ListUpgradable"),
            AgentOperation::RefreshPackageIndex => write!(f, "RefreshPackageIndex"),
            AgentOperation::InstallPackage { package } => f
                .debug_struct("InstallPackage")
                .field("package", package)
                .finish(),
            AgentOperation::UpgradePackage { package } => f
                .debug_struct("UpgradePackage")
                .field("package", package)
                .finish(),
            AgentOperation::RemovePackage { package } => f
                .debug_struct("RemovePackage")
                .field("package", package)
                .finish(),
            AgentOperation::PartitionTable { device } => f
                .debug_struct("PartitionTable")
                .field("device", device)
                .finish(),
            AgentOperation::LvmSummary => write!(f, "LvmSummary"),
            AgentOperation::RaidStatus => write!(f, "RaidStatus"),
            AgentOperation::MountFilesystem { device, target } => f
                .debug_struct("MountFilesystem")
                .field("device", device)
                .field("target", target)
                .finish(),
            AgentOperation::ExtendLogicalVolume { lv_path, size } => f
                .debug_struct("ExtendLogicalVolume")
                .field("lv_path", lv_path)
                .field("size", size)
                .finish(),
            AgentOperation::UnmountFilesystem { target } => f
                .debug_struct("UnmountFilesystem")
                .field("target", target)
                .finish(),
            AgentOperation::CreatePartition { device, start, end } => f
                .debug_struct("CreatePartition")
                .field("device", device)
                .field("start", start)
                .field("end", end)
                .finish(),
            AgentOperation::DeletePartition {
                device,
                partition_number,
            } => f
                .debug_struct("DeletePartition")
                .field("device", device)
                .field("partition_number", partition_number)
                .finish(),
            AgentOperation::CreateRaidArray {
                array_name,
                level,
                devices,
            } => f
                .debug_struct("CreateRaidArray")
                .field("array_name", array_name)
                .field("level", level)
                .field("devices", devices)
                .finish(),
            AgentOperation::StopRaidArray { array_name } => f
                .debug_struct("StopRaidArray")
                .field("array_name", array_name)
                .finish(),
            AgentOperation::CreatePhysicalVolume { device } => f
                .debug_struct("CreatePhysicalVolume")
                .field("device", device)
                .finish(),
            AgentOperation::CreateVolumeGroup {
                name,
                physical_volumes,
            } => f
                .debug_struct("CreateVolumeGroup")
                .field("name", name)
                .field("physical_volumes", physical_volumes)
                .finish(),
            AgentOperation::CreateLogicalVolume {
                vg_name,
                lv_name,
                size,
            } => f
                .debug_struct("CreateLogicalVolume")
                .field("vg_name", vg_name)
                .field("lv_name", lv_name)
                .field("size", size)
                .finish(),
            AgentOperation::RemoveLogicalVolume { lv_path } => f
                .debug_struct("RemoveLogicalVolume")
                .field("lv_path", lv_path)
                .finish(),
            AgentOperation::RemoveVolumeGroup { name } => f
                .debug_struct("RemoveVolumeGroup")
                .field("name", name)
                .finish(),
            AgentOperation::RemovePhysicalVolume { device } => f
                .debug_struct("RemovePhysicalVolume")
                .field("device", device)
                .finish(),
            AgentOperation::CreateFilesystem { device, fstype } => f
                .debug_struct("CreateFilesystem")
                .field("device", device)
                .field("fstype", fstype)
                .finish(),
            AgentOperation::ViewManagedSysctl => write!(f, "ViewManagedSysctl"),
            AgentOperation::ViewManagedCronJobs => write!(f, "ViewManagedCronJobs"),
            AgentOperation::SetPersistentSysctl { key, value } => f
                .debug_struct("SetPersistentSysctl")
                .field("key", key)
                .field("value", value)
                .finish(),
            AgentOperation::RemovePersistentSysctlKey { key } => f
                .debug_struct("RemovePersistentSysctlKey")
                .field("key", key)
                .finish(),
            AgentOperation::ClearManagedSysctl => write!(f, "ClearManagedSysctl"),
            AgentOperation::SetCronJob {
                job_name,
                schedule,
                run_as_user,
                command,
            } => f
                .debug_struct("SetCronJob")
                .field("job_name", job_name)
                .field("schedule", schedule)
                .field("run_as_user", run_as_user)
                .field("command", command)
                .finish(),
            AgentOperation::RemoveCronJob { job_name } => f
                .debug_struct("RemoveCronJob")
                .field("job_name", job_name)
                .finish(),
            AgentOperation::ClearManagedCronJobs => write!(f, "ClearManagedCronJobs"),
            AgentOperation::ListBlockedIps => write!(f, "ListBlockedIps"),
            AgentOperation::IsolationStatus => write!(f, "IsolationStatus"),
            AgentOperation::ListQuarantinedFiles => write!(f, "ListQuarantinedFiles"),
            AgentOperation::BlockRemoteIp { ip } => {
                f.debug_struct("BlockRemoteIp").field("ip", ip).finish()
            }
            AgentOperation::UnblockRemoteIp { ip } => {
                f.debug_struct("UnblockRemoteIp").field("ip", ip).finish()
            }
            AgentOperation::QuarantineFile { path } => f
                .debug_struct("QuarantineFile")
                .field("path", path)
                .finish(),
            AgentOperation::RestoreQuarantinedFile {
                quarantine_filename,
            } => f
                .debug_struct("RestoreQuarantinedFile")
                .field("quarantine_filename", quarantine_filename)
                .finish(),
            AgentOperation::DeleteQuarantinedFile { filename } => f
                .debug_struct("DeleteQuarantinedFile")
                .field("filename", filename)
                .finish(),
            AgentOperation::DeisolateHost => write!(f, "DeisolateHost"),
            AgentOperation::IsolateHost => write!(f, "IsolateHost"),
            AgentOperation::ListSshHostKeys => write!(f, "ListSshHostKeys"),
            AgentOperation::ListSshAuthorizedKeys { username } => f
                .debug_struct("ListSshAuthorizedKeys")
                .field("username", username)
                .finish(),
            AgentOperation::ListTlsCertificates => write!(f, "ListTlsCertificates"),
            AgentOperation::CertificateDetail { path } => f
                .debug_struct("CertificateDetail")
                .field("path", path)
                .finish(),
            AgentOperation::ScanSensitiveFilePermissions => {
                write!(f, "ScanSensitiveFilePermissions")
            }
            AgentOperation::ViewSensitiveFile { path } => f
                .debug_struct("ViewSensitiveFile")
                .field("path", path)
                .finish(),
            AgentOperation::GenerateSshKeypair {
                key_type,
                comment,
                path,
            } => f
                .debug_struct("GenerateSshKeypair")
                .field("key_type", key_type)
                .field("comment", comment)
                .field("path", path)
                .finish(),
            AgentOperation::FixFilePermissions { path, mode } => f
                .debug_struct("FixFilePermissions")
                .field("path", path)
                .field("mode", mode)
                .finish(),
            AgentOperation::RemoveAuthorizedKey {
                username,
                fingerprint,
            } => f
                .debug_struct("RemoveAuthorizedKey")
                .field("username", username)
                .field("fingerprint", fingerprint)
                .finish(),
            AgentOperation::DeleteSshKeypair { path } => f
                .debug_struct("DeleteSshKeypair")
                .field("path", path)
                .finish(),
            AgentOperation::ScanSecurityEvents { .. } => write!(f, "ScanSecurityEvents"),
            AgentOperation::DetectPackageBackend => write!(f, "DetectPackageBackend"),
            AgentOperation::RenderSepulchreConfig { target, content } => f
                .debug_struct("RenderSepulchreConfig")
                .field("target", target)
                .field("content_len", &content.len())
                .finish(),
            AgentOperation::ClearSepulchreConfig { target } => f
                .debug_struct("ClearSepulchreConfig")
                .field("target", target)
                .finish(),
            AgentOperation::CheckSepulchreConfigIncludeDirective { target } => f
                .debug_struct("CheckSepulchreConfigIncludeDirective")
                .field("target", target)
                .finish(),
            AgentOperation::CreateSftpChrootAccount {
                username,
                chroot_dir,
            } => f
                .debug_struct("CreateSftpChrootAccount")
                .field("username", username)
                .field("chroot_dir", chroot_dir)
                .finish(),
            AgentOperation::InstallSepulchreAuthorizedKey {
                username,
                public_key,
            } => f
                .debug_struct("InstallSepulchreAuthorizedKey")
                .field("username", username)
                .field("public_key", public_key)
                .finish(),
            AgentOperation::RemoveSftpChrootAccount { username } => f
                .debug_struct("RemoveSftpChrootAccount")
                .field("username", username)
                .finish(),
            AgentOperation::CreateSambaServiceUser { username, .. } => f
                .debug_struct("CreateSambaServiceUser")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            AgentOperation::RemoveSambaServiceUser { username } => f
                .debug_struct("RemoveSambaServiceUser")
                .field("username", username)
                .finish(),
            AgentOperation::RenderMountUnit {
                unit_name,
                mount_point,
                content,
            } => f
                .debug_struct("RenderMountUnit")
                .field("unit_name", unit_name)
                .field("mount_point", mount_point)
                .field("content_len", &content.len())
                .finish(),
            AgentOperation::RemoveMountUnit {
                unit_name,
                mount_point,
            } => f
                .debug_struct("RemoveMountUnit")
                .field("unit_name", unit_name)
                .field("mount_point", mount_point)
                .finish(),
            AgentOperation::CheckMountStatus { mount_point } => f
                .debug_struct("CheckMountStatus")
                .field("mount_point", mount_point)
                .finish(),
            AgentOperation::WriteSepulchreMountCredentials { path, .. } => f
                .debug_struct("WriteSepulchreMountCredentials")
                .field("path", path)
                .field("contents", &"[REDACTED]")
                .finish(),
            AgentOperation::CreateSepulchreShareDirectory { path, owner } => f
                .debug_struct("CreateSepulchreShareDirectory")
                .field("path", path)
                .field("owner", owner)
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

/// A Windows absolute filesystem path (e.g. `C:\Users\foo\bad.exe`) for
/// `QuarantineFile` on a Windows-managed host -- `is_valid_absolute_path`
/// above hard-requires a leading `/` and would reject every Windows path
/// outright, so this is a sibling, not a replacement: every other caller
/// of `is_valid_absolute_path` stays Unix-only and untouched. Requires a
/// drive letter (`X:\`), no `..` traversal segment, and no control
/// characters -- deliberately permissive on which printable characters
/// are otherwise allowed, same reasoning as the Unix validator's own doc
/// comment (argument-injection safety here comes from never passing this
/// through a shell, not from a restricted character set).
pub fn is_valid_windows_absolute_path(path: &str) -> bool {
    let mut chars = path.chars();
    let Some(drive) = chars.next() else {
        return false;
    };
    if !drive.is_ascii_alphabetic() || chars.next() != Some(':') || chars.next() != Some('\\') {
        return false;
    }
    path.len() <= 4096
        && !path.split(['\\', '/']).any(|segment| segment == "..")
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

/// A process ID safe to renice or signal. Excludes 0 (not a real PID) and
/// 1 (init/PID 1 -- signaling or renicing it is either a no-op guarded by
/// the kernel or catastrophic, never something this tool should attempt).
/// The agent additionally refuses its own PID at the point it knows it
/// (protocol-level validation alone can't know that).
pub fn is_valid_pid(pid: u32) -> bool {
    pid > 1
}

/// A `nice` priority value, standard Linux range -20 (highest priority)
/// to 19 (lowest).
pub fn is_valid_nice_priority(priority: i32) -> bool {
    (-20..=19).contains(&priority)
}

/// A `find -mtime +N` day threshold for `ClearTmpFiles`. Bounded well
/// below `u32`'s range -- there's no legitimate reason to ask for
/// anything close to that, and an absurd value is more likely a mistake
/// than intent.
pub fn is_valid_cleanup_days(days: u32) -> bool {
    (1..=3650).contains(&days)
}

/// A `vm.swappiness` value. The kernel documents 0-200 as the valid
/// range (100 used to be treated as the practical ceiling, but modern
/// kernels accept up to 200).
pub fn is_valid_swappiness(value: u32) -> bool {
    value <= 200
}

/// A block device's short name under `/sys/block/`, e.g. `"sda"`,
/// `"nvme0n1"`, `"dm-0"`. Letters, digits, and `-` only, and never
/// starting with `-` -- this also doubles as the traversal defense for
/// `SetIoScheduler`, since excluding `/` and `.` means the resulting
/// `/sys/block/<device>/queue/scheduler` path can never point outside
/// that fixed directory.
pub fn is_valid_block_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// An I/O scheduler name for `SetIoScheduler`, checked against a fixed
/// allow-list of schedulers the Linux block layer actually ships --
/// same reasoning as `is_valid_signal_name`: a typo fails clearly here
/// instead of producing a confusing kernel error.
pub fn is_valid_io_scheduler(name: &str) -> bool {
    const ALLOWED: &[&str] = &["mq-deadline", "kyber", "bfq", "none", "deadline", "noop"];
    ALLOWED.contains(&name)
}

/// A Linux username or group name (Parish uses the same rule for both --
/// the POSIX syntax is identical). Must start with a lowercase letter or
/// underscore, then only lowercase letters, digits, underscore, or
/// hyphen, capped at 32 characters -- the conventional Linux
/// `NAME_REGEX`/`useradd` limits, and (as with every validator here) a
/// leading character that could never be mistaken for a flag.
pub fn is_valid_account_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 32 {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

/// Windows analog of `is_valid_account_name` above -- deliberately a
/// separate, more permissive validator rather than reusing the Unix one
/// as-is: real Windows local account names are conventionally mixed-
/// case (`Administrator`, `svc-Backup`, ...), so a lowercase-only check
/// would reject entirely ordinary Windows usernames, not just malformed
/// input. Capped at 20 characters -- the real `sAMAccountName` limit --
/// and kept to a conservative alphanumeric-plus-`-_.` character set
/// rather than the full (much wider) range Windows itself actually
/// allows, same "restrictive charset, not shell-escaping" reasoning as
/// every other name validator in this file.
pub fn is_valid_windows_account_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 20 {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// The one Linux account/group name this tool refuses to lock, delete, or
/// otherwise touch destructively, regardless of what the caller asks for.
/// There's no portable way to know every distro's other "don't touch
/// this" names (wheel, sudo, and similar vary), but `root` is universal.
pub fn is_protected_account_name(name: &str) -> bool {
    name == "root"
}

/// Windows analog of `is_protected_account_name` above -- the small set
/// of built-in local accounts present on essentially every install that
/// this tool refuses to lock/disable regardless of what the caller asks
/// for. Case-insensitive: Windows account names aren't case-sensitive.
pub fn is_protected_windows_account_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "administrator" | "guest" | "defaultaccount" | "wdagutilityaccount"
    )
}

/// A GECOS/comment field for `useradd -c`. Permissive on content (real
/// comments contain spaces and punctuation), but a leading `-` could be
/// mistaken for a flag by `useradd` itself, and control characters have
/// no business in a comment field.
pub fn is_valid_gecos_comment(comment: &str) -> bool {
    !comment.starts_with('-') && comment.len() <= 200 && comment.chars().all(|c| !c.is_control())
}

/// A minimum file size in megabytes for `FindLargeFiles`. Bounded well
/// below what `find -size` could actually express, just to keep the
/// value sane (0 would match everything, which isn't "large files").
pub fn is_valid_size_mb(mb: u32) -> bool {
    (1..=1_000_000).contains(&mb)
}

/// A package name/spec across the package-manager backends Apothecary
/// supports -- permissive enough for real names (rpm epochs like
/// `pkg-1:2.3-4`, pacman's `repo/pkgname` syntax) while still refusing a
/// leading `-` (the argument-injection defense every validator here
/// shares) and control characters.
pub fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && !name.starts_with('-')
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | ':' | '@' | '/')
        })
}

/// A package search query. Permissive on content (real search terms
/// contain spaces), but a leading `-` could be mistaken for a flag, and
/// control characters have no business in a search string.
pub fn is_valid_search_query(query: &str) -> bool {
    !query.is_empty()
        && query.len() <= 200
        && !query.starts_with('-')
        && query.chars().all(|c| !c.is_control())
}

/// A `parted` start/end position (e.g. `"0%"`, `"100%"`, `"1MiB"`,
/// `"500.5GiB"`). Permissive on unit spelling (parted accepts several),
/// but digits/`.`/`%`/letters only, and never a leading `-` -- the
/// argument-injection defense every validator here shares.
pub fn is_valid_partition_position(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && !value.starts_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '%'))
}

/// A partition number for `parted rm`/`mkpart` -- 1-128 covers every
/// real partition table this tool will ever meet (GPT alone caps out at
/// 128 by convention).
pub fn is_valid_partition_number(number: u32) -> bool {
    (1..=128).contains(&number)
}

/// An `mdadm --level` value, checked against the RAID levels mdadm
/// actually implements.
pub fn is_valid_raid_level(level: &str) -> bool {
    const ALLOWED: &[&str] = &["linear", "0", "1", "4", "5", "6", "10"];
    ALLOWED.contains(&level)
}

/// A filesystem type for `mkfs.<fstype>`, checked against a fixed
/// allow-list of filesystems this platform actually knows how to expect
/// -- an unrecognized type fails clearly here rather than trying to run
/// a `mkfs.<anything>` that may not even exist.
pub fn is_valid_fstype(fstype: &str) -> bool {
    const ALLOWED: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "f2fs"];
    ALLOWED.contains(&fstype)
}

/// A sysctl key (e.g. `"vm.swappiness"`, `"net/ipv4/ip_forward"` -- both
/// `.` and `/` separators are valid sysctl syntax). Letters, digits,
/// `.`, `/`, `_`, `-` only, never a leading `-`.
pub fn is_valid_sysctl_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 200
        && !key.starts_with('-')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '-'))
}

/// A sysctl value. Permissive (values are numbers, strings, or even
/// space-separated lists depending on the key), but no control
/// characters -- this becomes one line of a config file, so a newline
/// here would let the value smuggle in a second, unintended line.
pub fn is_valid_sysctl_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 200 && value.chars().all(|c| !c.is_control())
}

/// A cron schedule -- either a `@nickname` (`@reboot`, `@daily`, ...) or
/// a permissive character set covering real 5-field cron expressions
/// (digits, `*`, `/`, `,`, `-`, and the month/weekday name abbreviations
/// some cron implementations accept). Not a full grammar check --
/// consistent with every other validator here, the goal is rejecting
/// injection and garbage input, not verifying the schedule is
/// semantically sensible.
pub fn is_valid_cron_schedule(schedule: &str) -> bool {
    if schedule.is_empty() || schedule.len() > 100 {
        return false;
    }
    if let Some(rest) = schedule.strip_prefix('@') {
        const NICKNAMES: &[&str] = &[
            "reboot", "yearly", "annually", "monthly", "weekly", "daily", "hourly",
        ];
        return NICKNAMES.contains(&rest);
    }
    schedule
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '*' | '/' | ',' | '-' | ' '))
}

/// The command field of a managed cron job. Deliberately permissive --
/// cron invokes this through a shell on purpose, so shell metacharacters
/// (pipes, semicolons, quotes) are normal and expected here, not an
/// injection risk the way they would be in an argument passed directly
/// to a non-shell subprocess. The one real risk is a newline smuggling
/// in an extra, unintended cron.d line, so control characters are the
/// only thing this actually excludes.
pub fn is_valid_cron_command(command: &str) -> bool {
    !command.is_empty() && command.len() <= 500 && command.chars().all(|c| !c.is_control())
}

/// A signal name for `kill -s <NAME>`, checked against a fixed allow-list
/// rather than passed through unvalidated -- not for argument-injection
/// safety (this never touches a shell), but so a typo or bogus value
/// fails clearly here instead of producing a confusing error from `kill`
/// itself. Case-insensitive; the `SIG` prefix is optional either way.
pub fn is_valid_signal_name(signal: &str) -> bool {
    const ALLOWED: &[&str] = &[
        "TERM", "KILL", "HUP", "INT", "QUIT", "USR1", "USR2", "STOP", "CONT",
    ];
    let normalized = signal.to_ascii_uppercase();
    let normalized = normalized.strip_prefix("SIG").unwrap_or(&normalized);
    ALLOWED.contains(&normalized)
}

/// A remote IP address for Inquest's blocklist/isolation operations.
/// Delegates entirely to `std::net::IpAddr`'s own parser (accepts both
/// IPv4 and IPv6) rather than a hand-rolled character check, since the
/// only property that matters here is "this is a real, unambiguous IP
/// address" -- exactly what the standard parser already guarantees.
pub fn is_valid_ip_address(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// A quarantine filename as produced by `QuarantineFile` and consumed by
/// `RestoreQuarantinedFile`/`DeleteQuarantinedFile` --
/// `<unix_ts>__<percent-encoded original path>`. Never accepts either
/// path separator (`/` on Unix, `\` on Windows -- this validator is
/// shared by both platforms' quarantine implementations) or a `..`
/// segment: this filename is joined directly onto the quarantine
/// directory, so allowing any of them would turn a quarantine restore/
/// delete into an arbitrary-file read/write primitive. A well-formed
/// filename should never contain a raw `\` anyway -- `percent_encode`
/// always escapes it -- but this doesn't rely on that being true by
/// construction alone.
pub fn is_valid_quarantine_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename.len() <= 4096
        && !filename.contains('/')
        && !filename.contains('\\')
        && !filename.contains("..")
        && filename.chars().all(|c| !c.is_control())
}

/// An SSH key algorithm for `GenerateSshKeypair`, checked against a fixed
/// allow-list of algorithms `ssh-keygen -t` actually supports and that
/// are still reasonable to generate today -- deliberately excludes `dsa`
/// (deprecated, disabled by default in modern OpenSSH).
pub fn is_valid_ssh_key_type(key_type: &str) -> bool {
    matches!(key_type, "rsa" | "ed25519" | "ecdsa")
}

/// An SSH key fingerprint as `ssh-keygen -lf` prints it, e.g.
/// `"SHA256:abcd...=="` or the legacy colon-separated MD5 hex form --
/// used to match one `RemoveAuthorizedKey` line unambiguously (a key's
/// comment isn't reliably unique, so matching on that would risk
/// removing the wrong entry).
pub fn is_valid_ssh_fingerprint(fingerprint: &str) -> bool {
    !fingerprint.is_empty()
        && fingerprint.len() <= 100
        && fingerprint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '+' | '/' | '='))
}

/// A target permission mode for `FixFilePermissions` -- a fixed set of
/// safe, *more restrictive* modes only, never an arbitrary chmod target.
/// This operation exists to fix the exact exposures
/// `ScanSensitiveFilePermissions` finds (group/other readable or
/// writable secrets), not to be a general permission-management
/// primitive, so nothing here can ever loosen a file's permissions.
pub fn is_valid_tightened_permission_mode(mode: &str) -> bool {
    matches!(mode, "600" | "400" | "640" | "700")
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
    fn accepts_reasonable_windows_absolute_paths() {
        assert!(is_valid_windows_absolute_path(r"C:\Users\foo\bad.exe"));
        assert!(is_valid_windows_absolute_path(
            r"D:\Program Files\app\file.dll"
        ));
        assert!(is_valid_windows_absolute_path(r"c:\lowercase\drive"));
    }

    #[test]
    fn rejects_malformed_windows_absolute_paths() {
        assert!(!is_valid_windows_absolute_path(""));
        assert!(!is_valid_windows_absolute_path(r"\no\drive\letter"));
        assert!(!is_valid_windows_absolute_path("relative\\path"));
        assert!(!is_valid_windows_absolute_path(
            r"C:\Users\..\..\Windows\System32"
        ));
        assert!(!is_valid_windows_absolute_path("C:\\evil\nmalicious"));
        assert!(!is_valid_windows_absolute_path(r"C/Users\missing-colon"));
        assert!(!is_valid_windows_absolute_path(&format!(
            r"C:\{}",
            "a".repeat(4096)
        )));
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

    #[test]
    fn accepts_reasonable_pids() {
        assert!(is_valid_pid(2));
        assert!(is_valid_pid(123456));
    }

    #[test]
    fn rejects_protected_pids() {
        assert!(!is_valid_pid(0));
        assert!(!is_valid_pid(1));
    }

    #[test]
    fn accepts_reasonable_nice_priorities() {
        assert!(is_valid_nice_priority(-20));
        assert!(is_valid_nice_priority(0));
        assert!(is_valid_nice_priority(19));
    }

    #[test]
    fn rejects_out_of_range_nice_priorities() {
        assert!(!is_valid_nice_priority(-21));
        assert!(!is_valid_nice_priority(20));
    }

    #[test]
    fn accepts_allowed_signal_names() {
        assert!(is_valid_signal_name("TERM"));
        assert!(is_valid_signal_name("sigkill"));
        assert!(is_valid_signal_name("Hup"));
    }

    #[test]
    fn rejects_disallowed_signal_names() {
        assert!(!is_valid_signal_name(""));
        assert!(!is_valid_signal_name("SEGV"));
        assert!(!is_valid_signal_name("9; rm -rf /"));
    }

    #[test]
    fn accepts_valid_ip_addresses() {
        assert!(is_valid_ip_address("203.0.113.42"));
        assert!(is_valid_ip_address("::1"));
        assert!(is_valid_ip_address("2001:db8::1"));
    }

    #[test]
    fn rejects_invalid_ip_addresses() {
        assert!(!is_valid_ip_address(""));
        assert!(!is_valid_ip_address("not-an-ip"));
        assert!(!is_valid_ip_address("203.0.113.42; rm -rf /"));
        assert!(!is_valid_ip_address("999.999.999.999"));
    }

    #[test]
    fn accepts_reasonable_quarantine_filenames() {
        assert!(is_valid_quarantine_filename("1737072000__%2Fetc%2Fevil.sh"));
        assert!(is_valid_quarantine_filename("1737072000__plainfile"));
    }

    #[test]
    fn rejects_unsafe_quarantine_filenames() {
        assert!(!is_valid_quarantine_filename(""));
        assert!(!is_valid_quarantine_filename("../../etc/passwd"));
        assert!(!is_valid_quarantine_filename("some/path"));
        assert!(!is_valid_quarantine_filename("has\ncontrol"));
        assert!(!is_valid_quarantine_filename(
            "1737072000__C%3A..\\..\\Windows\\System32"
        ));
    }

    #[test]
    fn accepts_supported_ssh_key_types() {
        assert!(is_valid_ssh_key_type("rsa"));
        assert!(is_valid_ssh_key_type("ed25519"));
        assert!(is_valid_ssh_key_type("ecdsa"));
    }

    #[test]
    fn rejects_unsupported_ssh_key_types() {
        assert!(!is_valid_ssh_key_type(""));
        assert!(!is_valid_ssh_key_type("dsa"));
        assert!(!is_valid_ssh_key_type("rsa; rm -rf /"));
    }

    #[test]
    fn accepts_reasonable_ssh_fingerprints() {
        assert!(is_valid_ssh_fingerprint("SHA256:abcd1234EFGH5678+/=="));
        assert!(is_valid_ssh_fingerprint(
            "MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
        ));
    }

    #[test]
    fn rejects_unsafe_ssh_fingerprints() {
        assert!(!is_valid_ssh_fingerprint(""));
        assert!(!is_valid_ssh_fingerprint("SHA256:abcd; rm -rf /"));
        assert!(!is_valid_ssh_fingerprint(&"a".repeat(101)));
    }

    #[test]
    fn accepts_tightened_permission_modes() {
        assert!(is_valid_tightened_permission_mode("600"));
        assert!(is_valid_tightened_permission_mode("400"));
        assert!(is_valid_tightened_permission_mode("640"));
        assert!(is_valid_tightened_permission_mode("700"));
    }

    #[test]
    fn rejects_loosening_or_invalid_permission_modes() {
        assert!(!is_valid_tightened_permission_mode(""));
        assert!(!is_valid_tightened_permission_mode("777"));
        assert!(!is_valid_tightened_permission_mode("644"));
        assert!(!is_valid_tightened_permission_mode("0600"));
    }

    #[test]
    fn accepts_reasonable_cleanup_days() {
        assert!(is_valid_cleanup_days(1));
        assert!(is_valid_cleanup_days(30));
        assert!(is_valid_cleanup_days(3650));
    }

    #[test]
    fn rejects_out_of_range_cleanup_days() {
        assert!(!is_valid_cleanup_days(0));
        assert!(!is_valid_cleanup_days(3651));
    }

    #[test]
    fn accepts_reasonable_swappiness() {
        assert!(is_valid_swappiness(0));
        assert!(is_valid_swappiness(60));
        assert!(is_valid_swappiness(200));
    }

    #[test]
    fn rejects_out_of_range_swappiness() {
        assert!(!is_valid_swappiness(201));
    }

    #[test]
    fn accepts_reasonable_block_device_names() {
        assert!(is_valid_block_device_name("sda"));
        assert!(is_valid_block_device_name("nvme0n1"));
        assert!(is_valid_block_device_name("dm-0"));
    }

    #[test]
    fn rejects_malformed_block_device_names() {
        assert!(!is_valid_block_device_name(""));
        assert!(!is_valid_block_device_name("-sda"));
        assert!(!is_valid_block_device_name("sda/../../etc"));
        assert!(!is_valid_block_device_name(&"a".repeat(33)));
    }

    #[test]
    fn accepts_allowed_io_schedulers() {
        assert!(is_valid_io_scheduler("mq-deadline"));
        assert!(is_valid_io_scheduler("bfq"));
        assert!(is_valid_io_scheduler("none"));
    }

    #[test]
    fn rejects_disallowed_io_schedulers() {
        assert!(!is_valid_io_scheduler(""));
        assert!(!is_valid_io_scheduler("totally-made-up"));
    }

    #[test]
    fn accepts_reasonable_account_names() {
        assert!(is_valid_account_name("deploy"));
        assert!(is_valid_account_name("web-svc"));
        assert!(is_valid_account_name("_daemon"));
        assert!(is_valid_account_name("user123"));
    }

    #[test]
    fn rejects_malformed_account_names() {
        assert!(!is_valid_account_name(""));
        assert!(!is_valid_account_name("-flag"));
        assert!(!is_valid_account_name("Deploy"));
        assert!(!is_valid_account_name("9start"));
        assert!(!is_valid_account_name("has space"));
        assert!(!is_valid_account_name(&"a".repeat(33)));
    }

    #[test]
    fn accepts_reasonable_windows_account_names() {
        assert!(is_valid_windows_account_name("Administrator"));
        assert!(is_valid_windows_account_name("svc-Backup"));
        assert!(is_valid_windows_account_name("_service"));
        assert!(is_valid_windows_account_name("user.name"));
    }

    #[test]
    fn rejects_malformed_windows_account_names() {
        assert!(!is_valid_windows_account_name(""));
        assert!(!is_valid_windows_account_name("-flag"));
        assert!(!is_valid_windows_account_name("9start"));
        assert!(!is_valid_windows_account_name("has space"));
        assert!(!is_valid_windows_account_name(&"a".repeat(21)));
    }

    #[test]
    fn protects_root_account_name() {
        assert!(is_protected_account_name("root"));
        assert!(!is_protected_account_name("deploy"));
    }

    #[test]
    fn protects_builtin_windows_account_names_case_insensitively() {
        assert!(is_protected_windows_account_name("Administrator"));
        assert!(is_protected_windows_account_name("GUEST"));
        assert!(is_protected_windows_account_name("defaultaccount"));
        assert!(!is_protected_windows_account_name("deploy-svc"));
    }

    #[test]
    fn accepts_reasonable_gecos_comments() {
        assert!(is_valid_gecos_comment(""));
        assert!(is_valid_gecos_comment("Deploy Bot, Ops Team"));
    }

    #[test]
    fn rejects_malformed_gecos_comments() {
        assert!(!is_valid_gecos_comment("-x"));
        assert!(!is_valid_gecos_comment("bad\ncomment"));
        assert!(!is_valid_gecos_comment(&"a".repeat(201)));
    }

    #[test]
    fn accepts_reasonable_size_mb() {
        assert!(is_valid_size_mb(1));
        assert!(is_valid_size_mb(100));
        assert!(is_valid_size_mb(1_000_000));
    }

    #[test]
    fn rejects_out_of_range_size_mb() {
        assert!(!is_valid_size_mb(0));
        assert!(!is_valid_size_mb(1_000_001));
    }

    #[test]
    fn accepts_reasonable_package_names() {
        assert!(is_valid_package_name("nginx"));
        assert!(is_valid_package_name("nginx-1:2.3-4"));
        assert!(is_valid_package_name("extra/nginx"));
        assert!(is_valid_package_name("lib_foo++"));
    }

    #[test]
    fn rejects_malformed_package_names() {
        assert!(!is_valid_package_name(""));
        assert!(!is_valid_package_name("-y"));
        assert!(!is_valid_package_name("nginx; rm -rf /"));
        assert!(!is_valid_package_name(&"a".repeat(201)));
    }

    #[test]
    fn accepts_reasonable_search_queries() {
        assert!(is_valid_search_query("web server"));
        assert!(is_valid_search_query("nginx"));
    }

    #[test]
    fn rejects_malformed_search_queries() {
        assert!(!is_valid_search_query(""));
        assert!(!is_valid_search_query("-y"));
        assert!(!is_valid_search_query("bad\ncontrol"));
        assert!(!is_valid_search_query(&"a".repeat(201)));
    }

    #[test]
    fn accepts_reasonable_partition_positions() {
        assert!(is_valid_partition_position("0%"));
        assert!(is_valid_partition_position("100%"));
        assert!(is_valid_partition_position("1MiB"));
        assert!(is_valid_partition_position("500.5GiB"));
    }

    #[test]
    fn rejects_malformed_partition_positions() {
        assert!(!is_valid_partition_position(""));
        assert!(!is_valid_partition_position("-1"));
        assert!(!is_valid_partition_position("50%; rm -rf /"));
    }

    #[test]
    fn accepts_reasonable_partition_numbers() {
        assert!(is_valid_partition_number(1));
        assert!(is_valid_partition_number(128));
    }

    #[test]
    fn rejects_out_of_range_partition_numbers() {
        assert!(!is_valid_partition_number(0));
        assert!(!is_valid_partition_number(129));
    }

    #[test]
    fn accepts_allowed_raid_levels() {
        assert!(is_valid_raid_level("0"));
        assert!(is_valid_raid_level("5"));
        assert!(is_valid_raid_level("10"));
        assert!(is_valid_raid_level("linear"));
    }

    #[test]
    fn rejects_disallowed_raid_levels() {
        assert!(!is_valid_raid_level(""));
        assert!(!is_valid_raid_level("2"));
        assert!(!is_valid_raid_level("9"));
    }

    #[test]
    fn accepts_allowed_fstypes() {
        assert!(is_valid_fstype("ext4"));
        assert!(is_valid_fstype("xfs"));
        assert!(is_valid_fstype("btrfs"));
    }

    #[test]
    fn rejects_disallowed_fstypes() {
        assert!(!is_valid_fstype(""));
        assert!(!is_valid_fstype("ntfs"));
        assert!(!is_valid_fstype("ext4; rm -rf /"));
    }

    #[test]
    fn accepts_reasonable_sysctl_keys() {
        assert!(is_valid_sysctl_key("vm.swappiness"));
        assert!(is_valid_sysctl_key("net/ipv4/ip_forward"));
    }

    #[test]
    fn rejects_malformed_sysctl_keys() {
        assert!(!is_valid_sysctl_key(""));
        assert!(!is_valid_sysctl_key("-x"));
        assert!(!is_valid_sysctl_key("vm.swappiness; rm -rf /"));
    }

    #[test]
    fn accepts_reasonable_sysctl_values() {
        assert!(is_valid_sysctl_value("60"));
        assert!(is_valid_sysctl_value("1 2 3"));
    }

    #[test]
    fn rejects_malformed_sysctl_values() {
        assert!(!is_valid_sysctl_value(""));
        assert!(!is_valid_sysctl_value("bad\nvalue"));
    }

    #[test]
    fn accepts_reasonable_cron_schedules() {
        assert!(is_valid_cron_schedule("@daily"));
        assert!(is_valid_cron_schedule("* * * * *"));
        assert!(is_valid_cron_schedule("0 3 * * MON"));
    }

    #[test]
    fn rejects_malformed_cron_schedules() {
        assert!(!is_valid_cron_schedule(""));
        assert!(!is_valid_cron_schedule("@bogus"));
        assert!(!is_valid_cron_schedule("* * * * *; rm -rf /"));
    }

    #[test]
    fn accepts_reasonable_cron_commands() {
        assert!(is_valid_cron_command("/usr/bin/backup.sh --full"));
        assert!(is_valid_cron_command(
            "echo hi | mail -s report admin@example.com"
        ));
    }

    #[test]
    fn rejects_malformed_cron_commands() {
        assert!(!is_valid_cron_command(""));
        assert!(!is_valid_cron_command("echo hi\nrm -rf /"));
    }
}
