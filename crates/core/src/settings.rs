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

/// Whether Mortiscope's metrics sweep also evaluates configured thresholds
/// and pushes alerts on a sustained breach. Off by default -- trend history
/// is always collected, but alerting is opt-in (it needs recipients and
/// thresholds set up first). Read fresh each sweep tick.
pub const MORTISCOPE_MONITORING_ENABLED: &str = "mortiscope.monitoring_enabled";

/// Comma-separated notification recipients for Mortiscope threshold alerts,
/// same format and routing as `THANATOS_ALERT_RECIPIENTS`.
pub const MORTISCOPE_ALERT_RECIPIENTS: &str = "mortiscope.alert_recipients";

/// How many consecutive breaching samples make a breach "sustained" (and so
/// worth alerting on) rather than a transient spike. Guards against flapping.
pub const MORTISCOPE_SUSTAINED_SAMPLES: &str = "mortiscope.sustained_samples";
pub const MORTISCOPE_SUSTAINED_SAMPLES_DEFAULT: u32 = 3;

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

/// Gates autonomous, no-human-in-the-loop dispatch of `QuarantineFile`
/// against a host the instant Thanatos's own FIM watch detects a changed
/// *per-user* `authorized_keys` file (Phase 10) -- planting/altering an
/// SSH key is a classic persistence technique with essentially no
/// legitimate reason to happen unattended. Off by default, same
/// second-gate reasoning as `HOST_ISOLATION_ENABLED`: an admin has to
/// deliberately opt in before anything gets dispatched with no human
/// clicking anything. Deliberately scoped to *only* this one FIM source,
/// not "any FIM drift" -- the rest of the watch-list (`/etc/passwd`,
/// `sshd_config`, the Windows hosts file, HKLM Run keys, ...) covers
/// files whose unattended removal could itself cause an outage or lock
/// out legitimate access; a compromised SSH key, by contrast, is safely
/// and narrowly reversible by restoring it from quarantine. See
/// `thanatos_ops::is_per_user_ssh_authorized_keys` for the exact
/// filename match.
pub const THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED: &str =
    "thanatos.auto_quarantine_ssh_keys_enabled";

/// Gates autonomous, no-human-in-the-loop dispatch of `LockUserAccount`
/// the instant the cross-host account-targeting correlation rule (Phase
/// 7d) raises a finding for a host -- an account being targeted by
/// high-severity events on several distinct hosts at once is a strong
/// credential-spray/account-targeting signal. Off by default, same
/// second-gate reasoning as `HOST_ISOLATION_ENABLED` and the setting
/// above. A real, accepted residual risk of turning this on: a
/// legitimate shared service/automation account (backups, monitoring)
/// logging in from many hosts could in principle trip the same pattern a
/// real attack would and get auto-disabled -- the existing protected-
/// account checks (`is_protected_account_name`/
/// `is_protected_windows_account_name`, refusing `root`/`Administrator`/
/// etc. regardless of this setting) already guard the worst case, but
/// this doesn't eliminate every false-positive shape, and an admin
/// enabling this should know that going in.
pub const THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED: &str = "thanatos.auto_disable_account_enabled";

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

/// Comma/space/newline-separated list of remote TCP ports an *outbound*
/// connection to which Thanatos flags as a likely reverse-shell/C2 beacon
/// (`AgentOperation::ScanSecurityEvents.c2_ports`, matched by exact numeric
/// port on both platforms). Promoted from a hardcoded agent-side list to a
/// setting so an operator can add their environment's own known-bad ports
/// without rebuilding and redeploying every agent. The default is a short,
/// high-confidence set of classic reverse-shell/RAT/backdoor ports -- kept
/// deliberately narrow (no 80/443/8080/8443 and the like) because outbound to
/// common ports is ordinary traffic and would drown the signal. Clearing it
/// disables port-based outbound flagging entirely (the event-log and
/// command-line detections are unaffected).
pub const THANATOS_C2_PORTS: &str = "thanatos.c2_ports";
pub const THANATOS_C2_PORTS_DEFAULT: &str = "1337,4444,4445,5555,6666,6667,12345,31337,31338,54321";

/// How many days of Thanatos security events to keep before the retention
/// sweep (`thanatos_ops::spawn_thanatos_retention`) prunes them -- the SIEM
/// event store's data-lifecycle policy, so `thanatos_events` stops growing
/// unbounded. Pruned strictly by age regardless of status/source. `0` disables
/// pruning entirely (keep everything). Default 90 days.
pub const THANATOS_EVENT_RETENTION_DAYS: &str = "thanatos.event_retention_days";
pub const THANATOS_EVENT_RETENTION_DAYS_DEFAULT: u32 = 90;

/// Interval (seconds) of the fast "act-now" sweep (M6 Option A,
/// `thanatos_ops::spawn_thanatos_fast_sweep`), which polls every connected host
/// for only a small curated set of high-signal events (ransomware/LOLBin
/// command lines, log clearing, process injection, Defender off) to cut
/// detection latency between the full 60s sweeps. `0` disables it (the default
/// -- it's extra endpoint load, so opt-in). When set, clamped to 5-60s. Only
/// runs while background monitoring (`THANATOS_MONITORING_ENABLED`) is also on.
pub const THANATOS_FAST_SWEEP_SECONDS: &str = "thanatos.fast_sweep_seconds";
pub const THANATOS_FAST_SWEEP_SECONDS_DEFAULT: u32 = 0;

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

/// Whether Panopticon dispatches a notification (through the same
/// `NotificationDispatcher` -- email/syslog/Slack/Teams/webhook -- Thanatos
/// uses) when discovery sees a genuinely new device (a new MAC, not just a new
/// DHCP IP for a known one) or an `Untrusted` device reappears after going
/// stale (NAC M1, "rogue-device awareness"). Off by default -- it needs
/// recipients configured and is opt-in like every other outbound alert. The
/// audit-log events fire regardless of this toggle; this only controls the
/// active push. Read fresh on each sighting.
pub const PANOPTICON_ROGUE_ALERT_ENABLED: &str = "panopticon.rogue_alert_enabled";

/// Comma/newline-separated recipients for Panopticon rogue-device alerts, same
/// format and routing as `THANATOS_ALERT_RECIPIENTS` (SMTP uses them; syslog and
/// chat webhooks fire regardless of recipients, subject to their own severity
/// gate).
pub const PANOPTICON_ROGUE_ALERT_RECIPIENTS: &str = "panopticon.rogue_alert_recipients";

/// Global kill-switch for Panopticon NAC enforcement (phase 3) -- the one
/// setting that gates *writing* to a live switch over SNMP (disabling a port
/// or moving it to a quarantine VLAN). Off by default: enforcement requires
/// this **and** the per-switch `enforcement_enabled` flag **and** the
/// operator's `network.manage` permission before any SNMP SET is issued.
/// Flipping this off doesn't revert actions already applied -- it only
/// refuses new ones (the auto-revert sweep still restores expired actions, so
/// turning it off can never strand a port in quarantine). Read fresh on every
/// enforce/revert attempt.
pub const PANOPTICON_ENFORCEMENT_ENABLED: &str = "panopticon.enforcement_enabled";

/// The VLAN id a "quarantine" action moves a port's untagged membership to
/// (Q-BRIDGE `dot1qPvid` + static egress/untagged port maps). Must be a VLAN
/// that already exists on the switch, pre-provisioned by the network admin
/// with whatever isolation (no inter-VLAN routing, captive portal, etc.) they
/// want quarantined devices to land in -- Panopticon never creates the VLAN,
/// only moves ports into it. `0` (the default) means "unset": the quarantine
/// action is refused until an admin configures a real VLAN id, since guessing
/// one could strand a device on a VLAN that doesn't exist.
pub const PANOPTICON_QUARANTINE_VLAN: &str = "panopticon.quarantine_vlan";
pub const PANOPTICON_QUARANTINE_VLAN_DEFAULT: u32 = 0;

/// Default auto-revert timeout (minutes) for a newly-applied enforcement
/// action: the port is automatically restored to service this long after it
/// was enforced, unless the operator explicitly made the action permanent.
/// A safety net against locking out a port and forgetting. `0` means "no
/// timeout by default" (actions are permanent until manually released), but
/// an operator can still pick a timeout per-action regardless of this default.
pub const PANOPTICON_ENFORCEMENT_REVERT_MINUTES: &str = "panopticon.enforcement_revert_minutes";
pub const PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT: u32 = 30;

/// NAC auto-enforcement policy engine (phase 4) mode: `off` (default),
/// `simulate` (evaluate rules and record what would happen, no writes), or
/// `active` (apply matched actions for real). Parsed by
/// `abyssal_core::PolicyMode`; anything unrecognized is treated as `off`.
/// Even in `active` mode, every write still passes the M3 gates (the global
/// `PANOPTICON_ENFORCEMENT_ENABLED` kill-switch, the per-switch opt-in, and a
/// resolvable port), so arming the policy never bypasses them.
pub const PANOPTICON_AUTO_ENFORCE_MODE: &str = "panopticon.auto_enforce_mode";

/// How recently a device's `first_seen_at` must be (minutes) for the
/// `new_unknown` policy trigger to consider it "new". Bounds the trigger to
/// genuinely-recent arrivals rather than every never-classified device that has
/// ever been on the network.
pub const PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES: &str =
    "panopticon.auto_enforce_new_window_minutes";
pub const PANOPTICON_AUTO_ENFORCE_NEW_WINDOW_MINUTES_DEFAULT: u32 = 60;

/// After any enforcement action on a port (including an operator manually
/// releasing one), the policy engine won't re-enforce that same port for this
/// many minutes. Without it, a rule would immediately re-apply an action an
/// operator just released -- the cooldown makes a manual release "stick".
pub const PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES: &str =
    "panopticon.auto_enforce_cooldown_minutes";
pub const PANOPTICON_AUTO_ENFORCE_COOLDOWN_MINUTES_DEFAULT: u32 = 60;

/// NAC phase 5: enables Panopticon's embedded RADIUS server (MAC Auth Bypass +
/// dynamic VLAN + accounting). Off by default; binds the two UDP ports below
/// only when on and an `ENCRYPTION_KEY` is configured (NAS shared secrets are
/// stored encrypted). Read once at startup.
pub const PANOPTICON_RADIUS_ENABLED: &str = "panopticon.radius_enabled";

/// UDP ports the RADIUS auth / accounting listeners bind. Defaults are the IANA
/// RADIUS ports; both are >1024 so no elevated privileges are needed.
pub const PANOPTICON_RADIUS_AUTH_PORT: &str = "panopticon.radius_auth_port";
pub const PANOPTICON_RADIUS_AUTH_PORT_DEFAULT: u32 = 1812;
pub const PANOPTICON_RADIUS_ACCT_PORT: &str = "panopticon.radius_acct_port";
pub const PANOPTICON_RADIUS_ACCT_PORT_DEFAULT: u32 = 1813;

/// VLAN assigned (via RFC 3580 tunnel attributes) to a `Trusted` device on an
/// Access-Accept. `0` (default) means "accept with no VLAN assignment" -- the
/// switch keeps the port on its configured VLAN.
pub const PANOPTICON_RADIUS_TRUSTED_VLAN: &str = "panopticon.radius_trusted_vlan";
pub const PANOPTICON_RADIUS_TRUSTED_VLAN_DEFAULT: u32 = 0;

/// What the RADIUS server does for an `Untrusted` device: `quarantine`
/// (Access-Accept onto the quarantine VLAN -- reuses `PANOPTICON_QUARANTINE_VLAN`)
/// or `reject` (Access-Reject). Default `quarantine`.
pub const PANOPTICON_RADIUS_UNTRUSTED_ACTION: &str = "panopticon.radius_untrusted_action";

/// What the RADIUS server does for a device it can't vouch for -- one not in the
/// inventory, or in it but still `Unknown` trust: `accept` (admit with no VLAN;
/// the safe default so enabling RADIUS gives identity/accounting visibility
/// without locking anyone out), `guest` (Access-Accept onto the guest VLAN
/// below), or `reject` (Access-Reject). Tighten from `accept` once you've
/// watched the sessions and classified your fleet.
pub const PANOPTICON_RADIUS_UNKNOWN_ACTION: &str = "panopticon.radius_unknown_action";

/// Guest VLAN for `unknown_action = guest`. `0` falls back to a plain accept.
pub const PANOPTICON_RADIUS_GUEST_VLAN: &str = "panopticon.radius_guest_vlan";
pub const PANOPTICON_RADIUS_GUEST_VLAN_DEFAULT: u32 = 0;

// -----------------------------------------------------------------------
// Scourge (network IDS/IPS). Every gate below is off/empty by default; the
// three `*_enabled` bools are second gates in the sense of
// `HOST_ISOLATION_ENABLED` -- an admin must deliberately enable them on the
// Settings page, re-checked fresh at every entry point on top of the normal
// permission and type-to-confirm.
// -----------------------------------------------------------------------

/// Second gate for the unattended collection sweep: when off, the sweep that
/// pulls new EVE alerts from hosts and forwards them to Thanatos does not run.
/// Off by default (like `THANATOS_MONITORING_ENABLED`).
pub const SCOURGE_MONITORING_ENABLED: &str = "scourge.monitoring_enabled";

/// Collection-sweep interval in seconds, clamped 5-60 (like
/// `THANATOS_FAST_SWEEP_SECONDS`). Re-read every tick so a change takes effect
/// without a restart.
pub const SCOURGE_SWEEP_SECONDS: &str = "scourge.sweep_seconds";
pub const SCOURGE_SWEEP_SECONDS_DEFAULT: u32 = 15;

/// How long the bounded alert CACHE (not `thanatos_events`) is kept, in days.
/// `0` disables age pruning (the hard row cap still applies).
pub const SCOURGE_EVENT_RETENTION_DAYS: &str = "scourge.event_retention_days";
pub const SCOURGE_EVENT_RETENTION_DAYS_DEFAULT: u32 = 14;

/// Minimum severity (`low`/`medium`/`high`/`critical`) a Scourge alert must
/// reach to be forwarded into Thanatos's ingest path -- so a noisy sensor can't
/// flood the SIEM. Everything is still cached locally regardless; this only
/// gates the forward.
pub const SCOURGE_MIN_FORWARD_SEVERITY: &str = "scourge.min_forward_severity";
pub const SCOURGE_MIN_FORWARD_SEVERITY_DEFAULT: &str = "medium";

/// Second gate for Scourge changing what the sensor *runs* -- applying config
/// (interfaces / HOME_NET / EXTERNAL_NET / EVE output) and ruleset changes
/// (rule updates, enabling/disabling SIDs, suppressions). Off by default: an
/// admin must deliberately allow Scourge to modify the sensor's configuration
/// and ruleset, re-checked fresh at every entry point on top of the normal
/// `scourge.manage` permission and confirmation. Install and service
/// start/stop/restart/reload are standard lifecycle (permission + confirm only,
/// not behind this gate); inline IPS and capture have their own gates.
pub const SCOURGE_CONFIG_CHANGES_ENABLED: &str = "scourge.config_changes_enabled";

/// Second gate for packet capture (privacy-sensitive) -- capture start and
/// pcap deletion are refused unless this is on.
pub const SCOURGE_CAPTURE_ENABLED: &str = "scourge.capture_enabled";

/// Second gate for inline IPS: mode switching, per-SID drop/reject promotion,
/// and always-allow list edits are all refused unless this is on. The riskiest
/// gate -- an inline drop rule can sever connectivity.
pub const SCOURGE_IPS_ENABLED: &str = "scourge.ips_enabled";

/// Host-side pcap retention caps the sweep/capture jobs enforce: age in days
/// and total size in MB of the pcap directory. `0` days disables age pruning.
pub const SCOURGE_PCAP_RETENTION_DAYS: &str = "scourge.pcap_retention_days";
pub const SCOURGE_PCAP_RETENTION_DAYS_DEFAULT: u32 = 7;
pub const SCOURGE_PCAP_MAX_TOTAL_MB: &str = "scourge.pcap_max_total_mb";
pub const SCOURGE_PCAP_MAX_TOTAL_MB_DEFAULT: u32 = 2048;

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

/// Gates the platform-wide audit-trail-to-syslog export sweep (Phase 12
/// of the Thanatos SIEM/EDR build-out) -- off by default, since this
/// continuously streams *every* `AuditEvent` this whole app records
/// (logins, RBAC changes, backups, every arsenal's containment actions,
/// ...), not just Thanatos's own security events, off-host to whatever
/// `SYSLOG_HOST` is configured. An admin has to deliberately opt in
/// before any audit data leaves this host at all -- the syslog
/// destination itself is environment-variable-configured at startup
/// (same as SMTP), but *whether it's used for this* is worth changing
/// without a redeploy, the same reasoning `THANATOS_MONITORING_ENABLED`
/// already established for the unattended Thanatos sweep.
pub const AUDIT_SYSLOG_EXPORT_ENABLED: &str = "audit.syslog_export_enabled";

/// Internal-only watermark for the audit-syslog-export sweep -- the
/// encoded `AuditCursor` (see `abyssal_database::repo::audit`) of the
/// newest row already exported, so a restart resumes forward from there
/// instead of either re-exporting everything or silently losing rows
/// written while the process was down. Never rendered on the Settings
/// page and never written by an admin -- moved forward only by the sweep
/// itself, the same "small persisted scalar" role every other `Settings`
/// value already plays, just system-written instead of admin-written (no
/// dedicated one-row table felt warranted for a single moving string).
pub const AUDIT_SYSLOG_EXPORT_CURSOR: &str = "audit.syslog_export_cursor";

// ---- Control-plane self-monitoring -------------------------------------
// The server watching itself: resource thresholds, a background-task
// liveness check, and a backup-overdue check, alerting through the same
// NotificationDispatcher the arsenals use. All opt-in (off by default),
// with safe defaults so enabling it needs no further tuning.

/// Master toggle for the control-plane self-monitoring sweep.
pub const CONTROL_PLANE_MONITORING_ENABLED: &str = "control_plane.monitoring_enabled";
/// Percent thresholds at/above which the control plane alerts on its own
/// sustained CPU / memory / disk usage.
pub const CONTROL_PLANE_CPU_THRESHOLD: &str = "control_plane.cpu_percent_threshold";
pub const CONTROL_PLANE_CPU_THRESHOLD_DEFAULT: u32 = 90;
pub const CONTROL_PLANE_MEM_THRESHOLD: &str = "control_plane.mem_percent_threshold";
pub const CONTROL_PLANE_MEM_THRESHOLD_DEFAULT: u32 = 90;
pub const CONTROL_PLANE_DISK_THRESHOLD: &str = "control_plane.disk_percent_threshold";
pub const CONTROL_PLANE_DISK_THRESHOLD_DEFAULT: u32 = 90;
/// Hours since the last successful backup after which the control plane
/// alerts that backups are overdue. `0` disables the backup-overdue check.
pub const CONTROL_PLANE_BACKUP_OVERDUE_HOURS: &str = "control_plane.backup_overdue_hours";
pub const CONTROL_PLANE_BACKUP_OVERDUE_HOURS_DEFAULT: u32 = 48;
/// Comma/newline-separated recipients for control-plane self-alerts (same
/// format as the Mortiscope/Thanatos recipient lists).
pub const CONTROL_PLANE_ALERT_RECIPIENTS: &str = "control_plane.alert_recipients";
