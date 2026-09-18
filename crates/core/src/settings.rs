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
