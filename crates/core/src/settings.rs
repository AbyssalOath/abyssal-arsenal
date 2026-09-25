/// Well-known settings keys stored in the `settings` table as JSON values.
pub const PUBLIC_REGISTRATION_ENABLED: &str = "auth.public_registration_enabled";

/// Apotheosis elevation idle window, in minutes. Admin-configurable
/// (Settings page); defaults to 20 when unset. Valid range 1-1440 (one day).
pub const APOTHEOSIS_ELEVATION_WINDOW_MINUTES: &str = "apotheosis.elevation_window_minutes";
pub const APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES: u32 = 20;

/// Gates Ossuary's highest-risk storage operations (partition table
/// create/delete, RAID array create/stop, LVM physical/volume-group/
/// logical-volume create and remove, and creating a filesystem) --
/// operations where a single wrong device path can destroy a disk
/// instantly and irrecoverably, categorically unlike anything else this
/// platform dispatches. Off by default; an admin has to deliberately turn
/// this on (Settings page) before any of those operations can be
/// dispatched at all, on top of (not instead of) the normal Destructive
/// type-to-confirm gate each one still requires individually.
pub const HIGH_RISK_STORAGE_OPS_ENABLED: &str = "ossuary.high_risk_storage_ops_enabled";

/// Gates Inquest's full host network isolation (blocks all traffic
/// except the control plane's own connection). Off by default: unlike
/// every other Destructive operation this platform dispatches, a wrong
/// edge case here (NAT, a DNS-based control-plane address that resolves
/// differently later, a multi-homed host) can sever the agent's own
/// connection back to the control plane with no remote way to undo it --
/// recovery would need physical or console access to the host. An admin
/// has to deliberately turn this on (Settings page) before it can be
/// dispatched at all, on top of (not instead of) the type-to-confirm the
/// operation still requires individually.
pub const HOST_ISOLATION_ENABLED: &str = "inquest.host_isolation_enabled";

/// Gates Thanatos's periodic background sweep -- an unattended,
/// fixed-interval task (see `crates/app/src/main.rs`) that dispatches a
/// security-log scan to every connected host, persists what it finds, and
/// can raise correlation alerts entirely on its own with nobody having
/// clicked anything. Off by default: this is different in kind from
/// Ossuary's/Inquest's high-risk gates (those guard against a single
/// catastrophic action; this guards against an admin being surprised that
/// something is reading and storing security-log content across their
/// whole fleet automatically). Manual, admin-triggered scans from the
/// Thanatos page are unaffected by this setting either way -- it only
/// controls the unattended sweep.
pub const THANATOS_MONITORING_ENABLED: &str = "thanatos.monitoring_enabled";

/// Comma-separated notification recipient addresses for Thanatos
/// correlation alerts, routed through whatever notification provider(s)
/// are configured (SMTP today). Empty by default -- an alert still gets
/// persisted and shown in the UI either way, this only controls whether
/// it's also actively pushed out.
pub const THANATOS_ALERT_RECIPIENTS: &str = "thanatos.alert_recipients";

/// Comma-or-newline-separated admin-configured paths to hash alongside
/// the agent's own small fixed FIM watch-list (Phase 7b) -- additive,
/// never a replacement: clearing this setting doesn't lose the default
/// coverage. Empty by default. Each entry is validated (`is_valid_
/// absolute_path`/`is_valid_windows_absolute_path`, per the target
/// host's `Host.os`) before being sent to that host; an entry that
/// doesn't validate for a host's platform is silently skipped for that
/// host rather than sent anyway (see `thanatos_ops::extra_fim_paths_for`).
pub const THANATOS_EXTRA_FIM_PATHS: &str = "thanatos.extra_fim_paths";

/// How many high-or-above severity events on one host within
/// `THANATOS_CORRELATION_WINDOW_MINUTES` constitute a "burst" worth
/// raising a correlation alert over (`thanatos_ops::check_and_raise_alert`).
/// Was a hardcoded constant; promoted to a setting so an operator can tune
/// sensitivity without a rebuild.
pub const THANATOS_CORRELATION_THRESHOLD: &str = "thanatos.correlation_threshold";
pub const THANATOS_CORRELATION_THRESHOLD_DEFAULT: u32 = 5;

/// The correlation check's look-back window in minutes -- also doubles as
/// how long a raised alert suppresses another one for the same host, so an
/// alert's cooldown is exactly as long as the burst window that triggered
/// it (see `thanatos_ops::check_and_raise_alert`'s doc comment).
pub const THANATOS_CORRELATION_WINDOW_MINUTES: &str = "thanatos.correlation_window_minutes";
pub const THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT: u32 = 5;

/// How often (in seconds) the unattended sweep (`spawn_thanatos_sweep`)
/// ticks when `THANATOS_MONITORING_ENABLED` is on. Read fresh at the start
/// of every tick, so lowering it takes effect within one old interval,
/// never a restart; raising it takes effect on the very next tick.
pub const THANATOS_SWEEP_INTERVAL_SECONDS: &str = "thanatos.sweep_interval_seconds";
pub const THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT: u32 = 60;

/// How many *distinct hosts* a single source IP must trigger high-or-above
/// severity events on, within `THANATOS_CORRELATION_WINDOW_MINUTES`, to
/// raise a cross-host correlation alert -- the same burst-detection idea
/// as the per-host threshold, but looking for one attacker hitting many
/// hosts at once (a credential-stuffing/lateral-movement pattern the
/// per-host check alone can't see). Reuses the same window setting as the
/// per-host check rather than a separate one, since both describe "how
/// recently is 'recently'" for the same underlying detection pipeline.
pub const THANATOS_CROSS_HOST_THRESHOLD: &str = "thanatos.cross_host_threshold";
pub const THANATOS_CROSS_HOST_THRESHOLD_DEFAULT: u32 = 3;

/// Gates Panopticon's unattended periodic *active* discovery sweep (real
/// nmap traffic against `PANOPTICON_SWEEP_TARGET`, on a long fixed
/// interval -- see `spawn_panopticon_sweep`). Off by default, same
/// reasoning as `THANATOS_MONITORING_ENABLED`: this sends real scan
/// traffic to a whole target range on its own schedule with nobody having
/// clicked anything, which can trip intrusion detection on or near that
/// target. The passive `ip neigh` refresh half of the sweep is
/// unconditional and unaffected by this setting -- it only ever reads the
/// control plane's own already-populated neighbor table, never sends
/// traffic. Manual, admin-triggered scans from the Panopticon page are
/// also unaffected either way.
pub const PANOPTICON_SWEEP_ENABLED: &str = "panopticon.sweep_enabled";

/// Target (IP, CIDR range, or hostname) the active sweep scans on each
/// tick when `PANOPTICON_SWEEP_ENABLED` is on -- validated with the same
/// `abyssal_agent_protocol::is_valid_network_target` the manual scan form
/// uses. Empty by default; the sweep no-ops on a tick where this is unset
/// even if the toggle above is on, rather than guessing a target.
pub const PANOPTICON_SWEEP_TARGET: &str = "panopticon.sweep_target";

/// Enables the passive mDNS listener (`abyssal_web::spawn_panopticon_mdns_listener`)
/// -- an ordinary UDP multicast socket join, no elevated privileges needed.
/// Off by default like every other opt-in listener in this codebase (see
/// the syslog receiver's own fail-closed-by-default posture, which this
/// mirrors): binding the socket happens once at startup, so toggling this
/// takes a server restart, not just a settings save.
pub const PANOPTICON_MDNS_ENABLED: &str = "panopticon.mdns_enabled";

/// Enables the passive ARP listener (`abyssal_web::spawn_panopticon_arp_listener`)
/// -- a raw `AF_PACKET` capture on `PANOPTICON_ARP_INTERFACE`, which needs
/// `CAP_NET_RAW` (see the Dockerfile's `setcap` and docker-compose.yml's
/// `cap_add`). Off by default. Like the mDNS listener, the capture socket
/// is opened once at startup, so toggling this or changing the interface
/// takes a server restart.
pub const PANOPTICON_ARP_ENABLED: &str = "panopticon.arp_enabled";

/// Network interface name (e.g. `eth0`) the ARP listener captures on.
/// Empty by default; the listener doesn't start at all if this is unset
/// even when `PANOPTICON_ARP_ENABLED` is on, rather than guessing an
/// interface. Behind Docker's default bridge network this only ever sees
/// the Docker bridge's own ARP traffic, not a physical LAN's -- the same
/// caveat the manual discovery scan's own page already states; host
/// networking (or running the binary directly) is required to see real
/// LAN traffic.
pub const PANOPTICON_ARP_INTERFACE: &str = "panopticon.arp_interface";

/// How many days of raw (un-rolled-up) per-poll bandwidth samples
/// (`panopticon_port_traffic_raw`) to keep before the rollup/prune loop
/// (`abyssal_web::spawn_panopticon_traffic_rollup`) deletes them.
/// Bandwidth graphs within this window read raw samples directly (full
/// 5-minute resolution); older graphs fall back to the hourly/daily
/// rollup tiers below, if enabled. Enforced at at least 2 days
/// (`panopticon_traffic.rs::MIN_RAW_RETENTION_DAYS`) regardless of what's
/// configured here -- the daily rollup needs a full elapsed day of raw
/// data still on hand to compute from when it runs.
pub const PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS: &str = "panopticon.traffic_raw_retention_days";
pub const PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS: u32 = 14;

/// How many days of hourly bandwidth rollups
/// (`panopticon_port_traffic_hourly`) to keep. `0` disables this tier
/// entirely -- the rollup loop stops computing new hourly rows and prunes
/// every existing one, giving the "fixed raw window, no rollup" behavior
/// on its own; a bandwidth graph beyond the raw retention window then has
/// nothing to show unless the daily tier is enabled instead (or as well).
pub const PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS: &str =
    "panopticon.traffic_hourly_retention_days";
pub const PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS: u32 = 90;

/// How many days of daily bandwidth rollups (`panopticon_port_traffic_daily`)
/// to keep. `0` disables this tier the same way the hourly one is
/// disabled by `0` above. Computed directly from that day's raw samples,
/// not from the hourly tier -- the two rollup tiers are independent, so
/// either can be on while the other is off (e.g. long-term daily trend
/// lines without paying for 90 days of hourly resolution nobody's
/// looking at).
pub const PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS: &str = "panopticon.traffic_daily_retention_days";
pub const PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS: u32 = 365;

// ---------------------------------------------------------------------
// Reliquary native (control-plane) backups -- GitHub issue #9. All
// admin-configurable via the Reliquary "Application Data" settings panel
// (`routes/reliquary_backup.rs`), not `/admin/settings` -- these are
// specific to one arsenal, same reasoning `THANATOS_ALERT_RECIPIENTS` etc.
// already follow for arsenal-scoped settings living outside the global
// settings page.
// ---------------------------------------------------------------------

/// Whether the unattended scheduled backup loop is on at all. Off by
/// default -- same "an admin has to deliberately opt in before an
/// unattended background job starts touching anything" posture as
/// `THANATOS_MONITORING_ENABLED`/`PANOPTICON_SWEEP_ENABLED` above, doubly
/// so here since this one writes a multi-gigabyte file to disk on its own
/// schedule.
pub const RELIQUARY_BACKUP_SCHEDULE_ENABLED: &str = "reliquary.backup_schedule_enabled";

/// Interval between scheduled backups, in hours. Checked against `0` the
/// same way `PANOPTICON_ARP_INTERFACE` guards an empty interface -- the
/// scheduler no-ops on a tick where this is `0` even if the toggle above
/// is on, rather than guessing an interval.
pub const RELIQUARY_BACKUP_SCHEDULE_INTERVAL_HOURS: &str =
    "reliquary.backup_schedule_interval_hours";
pub const RELIQUARY_BACKUP_SCHEDULE_DEFAULT_INTERVAL_HOURS: u32 = 24;

/// Keep at least this many of the most recent backups regardless of age --
/// pruning (`reliquary_backup::retention`) never deletes past this floor,
/// and never deletes the only remaining *verified* backup even if that
/// means keeping more than this number.
pub const RELIQUARY_BACKUP_RETENTION_KEEP_LAST: &str = "reliquary.backup_retention_keep_last";
pub const RELIQUARY_BACKUP_RETENTION_DEFAULT_KEEP_LAST: u32 = 7;

/// Also prune anything older than this many days, subject to the same
/// keep-last and keep-the-only-verified-backup floors above. `0` disables
/// age-based pruning entirely (count-based retention only).
pub const RELIQUARY_BACKUP_RETENTION_DAYS: &str = "reliquary.backup_retention_days";
pub const RELIQUARY_BACKUP_RETENTION_DEFAULT_DAYS: u32 = 30;

/// Directory backup archives are written to -- must be outside the
/// MariaDB data volume (documented requirement, not enforced in code: this
/// process has no visibility into the `mariadb` container's own mount
/// table to check against). Defaults to `/backups`, matching the
/// dedicated volume `docker-compose.yml` mounts there.
pub const RELIQUARY_BACKUP_DESTINATION_PATH: &str = "reliquary.backup_destination_path";
pub const RELIQUARY_BACKUP_DEFAULT_DESTINATION_PATH: &str = "/backups";

/// Which Sepulchre connection scheduled backups write to -- a UUID
/// string, or empty/unset for the local destination above (the default).
/// A manual "Backup now" always lets the operator pick per-run instead;
/// this is only the schedule's own fixed answer, since nobody's present
/// to choose each time. See docs/sepulchre.md.
pub const RELIQUARY_BACKUP_DESTINATION_CONNECTION_ID: &str =
    "reliquary.backup_destination_connection_id";

/// Whether new backups are encrypted at rest by default (the create-backup
/// form can still override this per backup). Strongly recommended on;
/// forced on regardless of this setting whenever "include encryption
/// keys" is selected for a given backup.
pub const RELIQUARY_BACKUP_ENCRYPT_BY_DEFAULT: &str = "reliquary.backup_encrypt_by_default";

/// Whether scheduled (unattended) backups include audit logs. Manual
/// backups choose this per-run; the schedule needs its own fixed answer
/// since nobody's there to pick each time. Audit logs are already part of
/// the database dump either way (see `reliquary_backup::manifest`) --
/// this only controls whether the `audit_log` table is included in a
/// dump whose other rows exclude it, for a deployment that wants its
/// backups to exclude potentially sensitive audit detail by default.
pub const RELIQUARY_BACKUP_INCLUDE_AUDIT_LOGS: &str = "reliquary.backup_include_audit_logs";

/// Device Inventory subnet grouping (GitHub issue #10) -- the prefix
/// length a device's IP is masked down to before grouping, per address
/// family. Changing either takes effect for newly-seen devices
/// immediately; existing rows' stored `network` column needs the
/// "Re-derive subnets" action on the inventory page to catch up (see
/// `docs/device-inventory.md`).
pub const PANOPTICON_SUBNET_PREFIX_V4: &str = "panopticon.subnet_prefix_v4";
pub const PANOPTICON_SUBNET_PREFIX_V4_DEFAULT: u32 = 24;
pub const PANOPTICON_SUBNET_PREFIX_V6: &str = "panopticon.subnet_prefix_v6";
pub const PANOPTICON_SUBNET_PREFIX_V6_DEFAULT: u32 = 64;

/// Below this many total devices, every subnet group's body renders open
/// by default (paginated internally); at or above it, only groups named
/// in the `?open=` query param render their rows -- see
/// `docs/device-inventory.md`'s "render budget" section. Defaults to `0`
/// (every group starts collapsed, regardless of inventory size) --
/// operators who'd rather small inventories auto-expand can raise this
/// setting explicitly.
pub const PANOPTICON_INVENTORY_RENDER_BUDGET: &str = "panopticon.inventory_render_budget";
pub const PANOPTICON_INVENTORY_RENDER_BUDGET_DEFAULT: u32 = 0;

/// Same render-budget mechanics as `PANOPTICON_INVENTORY_RENDER_BUDGET`,
/// applied to the Thanatos fleet dashboard's per-host event groups:
/// below this many total events across every group shown, every group
/// renders open by default; at or above it (or by default, since this is
/// `0`), only groups named in `?open=` render their rows. Defaults to `0`
/// (every group starts collapsed) for the same reason Panopticon's does.
pub const THANATOS_DASHBOARD_RENDER_BUDGET: &str = "thanatos.dashboard_render_budget";
pub const THANATOS_DASHBOARD_RENDER_BUDGET_DEFAULT: u32 = 0;
