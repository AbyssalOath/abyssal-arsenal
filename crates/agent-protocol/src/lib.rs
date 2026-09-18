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
pub const PROTOCOL_VERSION: u32 = 16;

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
    /// Every process on the host, as a PID-ordered tree
    /// (`ps -ef --forest`) -- the complete picture, unlike Mortiscope's
    /// `TopProcessesByCpu`/`TopProcessesByMemory` (top 15 by resource
    /// usage only).
    ListProcesses,
    /// Full detail for one process -- user, state, resource usage,
    /// start time, and complete (untruncated) command line
    /// (`ps -p <pid> -o ... -ww`).
    ProcessDetail { pid: u32 },
    /// Adjusts a running process's scheduling priority
    /// (`renice -n <priority> -p <pid>`, range -20 to 19). Write -- a
    /// real mutation, but reversible (renice again) and not disruptive on
    /// its own, so it doesn't require the explicit confirmation a
    /// `Destructive` operation does.
    RenicePriority { pid: u32, priority: i32 },
    /// Sends a signal to a process (`kill -s <SIGNAL> <pid>`). Destructive
    /// regardless of which signal: any signal sent to a process is an
    /// intentional interruption of whatever it's doing, so the control
    /// plane requires explicit confirmation before ever dispatching this
    /// -- there's no "softer" signal choice that bypasses that gate.
    SendSignal { pid: u32, signal: String },
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
    ClearTmpFiles { older_than_days: u32 },
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
    SetSwappiness { value: u32 },
    /// Sets a block device's I/O scheduler by writing the scheduler name
    /// to its sysfs queue file (`tee /sys/block/<device>/queue/scheduler`,
    /// fed via stdin since there's no shell here to do the `>` redirection
    /// this file conventionally takes). Write, not Destructive: purely a
    /// runtime queuing-policy change, reversible by writing a different
    /// name back.
    SetIoScheduler { device: String, scheduler: String },
    /// Every local/NSS-resolved account (`getent passwd`).
    ListUsers,
    /// Every local/NSS-resolved group and its members (`getent group`).
    ListGroups,
    /// UID, primary GID, and every supplementary group for one account
    /// (`id <username>`).
    UserDetail { username: String },
    /// Creates a new local account with a home directory
    /// (`useradd -m -c <comment> <username>`). The account has no
    /// password set (locked, per `useradd`'s own default) until someone
    /// assigns one directly on the host. Write -- additive, undone by
    /// `DeleteUser`.
    CreateUser { username: String, comment: String },
    /// Creates a new local group (`groupadd <group>`). Write, additive.
    CreateGroup { group: String },
    /// Adds an account to a supplementary group
    /// (`usermod -aG <group> <username>`). Write -- additive, reversible
    /// via `RemoveUserFromGroup`.
    AddUserToGroup { username: String, group: String },
    /// Removes an account from a supplementary group
    /// (`gpasswd -d <username> <group>`). Write, not Destructive: the
    /// account and group both still exist, only the membership changes,
    /// and it's trivially reversed by adding them back.
    RemoveUserFromGroup { username: String, group: String },
    /// Locks an account, disabling password login without deleting
    /// anything (`usermod -L <username>`). Write, not Destructive:
    /// reversible via `UnlockUserAccount`. Refuses `"root"` -- locking
    /// the one universally-critical account is never the intended
    /// target.
    LockUserAccount { username: String },
    /// Reverses `LockUserAccount` (`usermod -U <username>`). Write.
    UnlockUserAccount { username: String },
    /// Deletes a local account (`userdel [-r] <username>`), optionally
    /// removing its home directory too. Destructive and irreversible --
    /// the control plane requires explicit confirmation before ever
    /// dispatching this. Refuses `"root"`.
    DeleteUser { username: String, remove_home: bool },
    /// Deletes a local group (`groupdel <group>`). Destructive and
    /// irreversible for the same reason as `DeleteUser`. Refuses
    /// `"root"`.
    DeleteGroup { group: String },
    /// Immediate-subdirectory disk usage under `path`
    /// (`du -h --max-depth=1 <path>`) -- the classic "what's eating this
    /// directory" traversal, one level deep.
    DirectoryUsageBreakdown { path: String },
    /// Files at or under `path` larger than `min_size_mb` megabytes
    /// (`find <path> -xdev -type f -size +<N>M`). `-xdev` keeps the
    /// search from wandering into other mounted filesystems under
    /// `path`, so scanning `/` doesn't also walk every remote mount.
    FindLargeFiles { path: String, min_size_mb: u32 },
    /// Read-only filesystem consistency check (`fsck -n <device>`) --
    /// reports problems without fixing anything, so unlike
    /// `FilesystemRepair` this is safe to run even on a mounted
    /// filesystem.
    FilesystemCheckDryRun { device: String },
    /// Discards unused blocks on a mounted filesystem so the underlying
    /// SSD/storage can reclaim them (`fstrim -v <mountpoint>`) --
    /// routine, low-risk maintenance (the same operation most distros
    /// already run on a timer). Write, not Destructive: it never removes
    /// anything a filesystem still considers live.
    TrimFilesystem { mountpoint: String },
    /// Runs `fsck`'s actual repair mode (`fsck -y <device>`, auto-answer
    /// yes to every fix). Destructive and genuinely dangerous if
    /// misused: the agent refuses outright if `device` is currently
    /// mounted (verified via `findmnt` immediately before dispatch,
    /// failing closed if that check itself can't be completed) --
    /// repairing a mounted filesystem's on-disk structures while it's
    /// live is a well-known way to cause the exact corruption this
    /// operation exists to fix. The control plane requires explicit
    /// confirmation before ever dispatching this regardless.
    FilesystemRepair { device: String },
    /// Every installed package, from whichever of apt/dnf/yum/pacman/
    /// zypper the agent detects on its host (same "detect the tool
    /// present, don't assume one" approach as the firewall backends).
    ListInstalledPackages,
    /// Searches the package manager's repo metadata for `query`.
    SearchPackage { query: String },
    /// Detailed info (version, description, dependencies, ...) for one
    /// package, whether installed or just available in a repo.
    PackageInfo { package: String },
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
    InstallPackage { package: String },
    /// Upgrades one specific package to the latest version the refreshed
    /// index knows about, without touching any other package. Write, not
    /// Destructive: updates code in place, doesn't delete data, and can
    /// be undone by installing an older version directly if needed.
    UpgradePackage { package: String },
    /// Removes an installed package (without purging its configuration
    /// files, where the backend distinguishes the two). Destructive:
    /// removing a package can break whatever depended on it, and
    /// reinstalling doesn't necessarily restore prior state exactly, so
    /// the control plane requires explicit confirmation before ever
    /// dispatching this.
    RemovePackage { package: String },
    /// A disk's partition table (`parted <device> print`) -- MBR/GPT,
    /// partition list, sizes, types.
    PartitionTable { device: String },
    /// LVM physical volumes, volume groups, and logical volumes
    /// (`pvs`/`vgs`/`lvs`), combined into one report.
    LvmSummary,
    /// Current software RAID array status (`cat /proc/mdstat`) -- which
    /// arrays exist, their state, and rebuild/resync progress if any.
    RaidStatus,
    /// Mounts an existing filesystem (`mount <device> <target>`). Write,
    /// not Destructive: doesn't create or destroy anything, and is
    /// reversible via `UnmountFilesystem`.
    MountFilesystem { device: String, target: String },
    /// Grows an LVM logical volume by `size` (e.g. `"10G"`)
    /// (`lvextend -L +<size> <lv_path>`). Write, not Destructive: only
    /// adds space (fails cleanly if the volume group doesn't have enough
    /// free), never removes anything. Grows the block device only -- the
    /// filesystem on top still needs its own resize (`resize2fs`,
    /// `xfs_growfs`, ...), which this tool deliberately doesn't attempt,
    /// since picking the wrong filesystem-specific tool automatically is
    /// itself a real risk.
    ExtendLogicalVolume { lv_path: String, size: String },
    /// Unmounts a filesystem (`umount <target>`). Destructive: whatever
    /// was using that mount loses access immediately, the same reasoning
    /// `StopService`/`StopContainer` document -- the data itself is
    /// untouched, but the control plane requires explicit confirmation
    /// before ever dispatching this regardless.
    UnmountFilesystem { target: String },
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
    StopRaidArray { array_name: String },
    /// Initializes a device as an LVM physical volume (`pvcreate
    /// <device>`), wiping any existing filesystem signature on it.
    /// Destructive, irreversible, and high-risk-gated.
    CreatePhysicalVolume { device: String },
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
    RemoveLogicalVolume { lv_path: String },
    /// Removes a volume group (`vgremove -f <name>`) -- refused by `vgremove`
    /// itself if it still contains logical volumes. Destructive,
    /// irreversible, and high-risk-gated.
    RemoveVolumeGroup { name: String },
    /// Removes a device's LVM physical volume metadata (`pvremove -f
    /// <device>`). Destructive, irreversible, and high-risk-gated.
    RemovePhysicalVolume { device: String },
    /// Creates a filesystem on a device (`mkfs.<fstype> -F <device>`),
    /// destroying whatever was there before. The single most dangerous
    /// operation this platform can dispatch -- unlike `FilesystemRepair`
    /// (Catacomb), which can at worst do nothing useful, a wrong
    /// `device` here instantly and unconditionally destroys everything
    /// on it with no partial-safety case at all. Destructive,
    /// irreversible, and high-risk-gated.
    CreateFilesystem { device: String, fstype: String },
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

/// The one Linux account/group name this tool refuses to lock, delete, or
/// otherwise touch destructively, regardless of what the caller asks for.
/// There's no portable way to know every distro's other "don't touch
/// this" names (wheel, sudo, and similar vary), but `root` is universal.
pub fn is_protected_account_name(name: &str) -> bool {
    name == "root"
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
    fn protects_root_account_name() {
        assert!(is_protected_account_name("root"));
        assert!(!is_protected_account_name("deploy"));
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
}
