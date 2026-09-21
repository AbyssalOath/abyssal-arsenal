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
