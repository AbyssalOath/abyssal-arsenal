use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long since a device's `last_seen_at` before it counts as stale
/// (`NetworkDevice::is_stale`) -- shared by the inventory UI's "Stale"
/// badge and the background sweep's reappearance detection, so the two
/// never disagree about what "gone quiet" means. Generous on purpose:
/// discovery isn't guaranteed to be on a tight schedule (the active sweep
/// is opt-in and can be set to a long interval, and manual scans are
/// operator-triggered), so a device can easily go the better part of a day
/// without actually having left the network.
pub const STALE_THRESHOLD_HOURS: i64 = 24;

/// An admin-assigned classification for a discovered device -- the first
/// NAC-adjacent primitive Panopticon has: a trust flag an operator sets by
/// hand, not anything enforced against the network yet. Defaults to
/// `Unknown` for every newly-discovered device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    Unknown,
    Trusted,
    Untrusted,
}

impl TrustState {
    pub const fn as_str(self) -> &'static str {
        match self {
            TrustState::Unknown => "unknown",
            TrustState::Trusted => "trusted",
            TrustState::Untrusted => "untrusted",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            TrustState::Unknown => "Unknown",
            TrustState::Trusted => "Trusted",
            TrustState::Untrusted => "Untrusted",
        }
    }

    pub const ALL: &'static [TrustState] = &[
        TrustState::Unknown,
        TrustState::Trusted,
        TrustState::Untrusted,
    ];
}

impl std::str::FromStr for TrustState {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(TrustState::Unknown),
            "trusted" => Ok(TrustState::Trusted),
            "untrusted" => Ok(TrustState::Untrusted),
            _ => Err(()),
        }
    }
}

/// A freeform-but-curated device category an admin can assign. Stored as
/// its `as_str()` key rather than a database `ENUM` so adding a new
/// variant here never needs a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Unknown,
    Workstation,
    Server,
    Printer,
    NetworkInfrastructure,
    Iot,
    Phone,
    Other,
}

impl DeviceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            DeviceType::Unknown => "unknown",
            DeviceType::Workstation => "workstation",
            DeviceType::Server => "server",
            DeviceType::Printer => "printer",
            DeviceType::NetworkInfrastructure => "network_infrastructure",
            DeviceType::Iot => "iot",
            DeviceType::Phone => "phone",
            DeviceType::Other => "other",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            DeviceType::Unknown => "Unknown",
            DeviceType::Workstation => "Workstation",
            DeviceType::Server => "Server",
            DeviceType::Printer => "Printer",
            DeviceType::NetworkInfrastructure => "Network infrastructure",
            DeviceType::Iot => "IoT",
            DeviceType::Phone => "Phone",
            DeviceType::Other => "Other",
        }
    }

    pub const ALL: &'static [DeviceType] = &[
        DeviceType::Unknown,
        DeviceType::Workstation,
        DeviceType::Server,
        DeviceType::Printer,
        DeviceType::NetworkInfrastructure,
        DeviceType::Iot,
        DeviceType::Phone,
        DeviceType::Other,
    ];
}

impl std::str::FromStr for DeviceType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(DeviceType::Unknown),
            "workstation" => Ok(DeviceType::Workstation),
            "server" => Ok(DeviceType::Server),
            "printer" => Ok(DeviceType::Printer),
            "network_infrastructure" => Ok(DeviceType::NetworkInfrastructure),
            "iot" => Ok(DeviceType::Iot),
            "phone" => Ok(DeviceType::Phone),
            "other" => Ok(DeviceType::Other),
            _ => Err(()),
        }
    }
}

/// One open port a scan found on a device, normalized out of what used to
/// be a single freeform `open_ports` summary string so it can be queried
/// and filtered on (e.g. "which devices have 22/tcp open") instead of only
/// displayed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevicePort {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
}

/// A device discovered on the LAN by Panopticon's active discovery scan.
/// Persisted so the inventory accumulates across scans rather than only
/// showing whatever the most recent scan happened to find -- a device that
/// didn't respond to today's scan (offline, firewalled) still shows up with
/// its last-known details until an admin explicitly removes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub id: Uuid,
    pub ip_address: String,
    /// Resolved from the kernel's neighbor table (`ip neigh`) after an
    /// active scan, from a live ARP sniff, or from an SNMP switch poll --
    /// see `panopticon_ops.rs`, `panopticon_arp.rs`. Only ever populated
    /// for a device on the same local subnet as whatever saw it (the
    /// control plane itself, or a polled switch); a purely routed target
    /// an active scan reaches has no MAC to learn by any of these means.
    pub mac_address: Option<String>,
    /// Reverse-DNS name nmap resolved for this IP during the scan that
    /// found it, if any.
    pub hostname: Option<String>,
    /// Admin-assigned category; defaults to `Unknown` until someone
    /// classifies the device.
    pub device_type: DeviceType,
    /// Admin-assigned trust flag; defaults to `Unknown`. Purely advisory in
    /// this phase -- nothing reads it to make an access-control decision.
    pub trust_state: TrustState,
    /// Freeform admin notes about the device.
    pub notes: Option<String>,
    /// Open ports from the most recent scan that saw this device, one row
    /// per port/protocol rather than the joined summary string this field
    /// used to be.
    pub ports: Vec<NetworkDevicePort>,
    /// The switch this device's MAC was last found behind, per the SNMP
    /// poll's BRIDGE-MIB read (`dot1dTpFdbTable`) -- `None` until a poll
    /// happens to see this device's MAC in some switch's forwarding
    /// database. Only ever "last known": a laptop that moved to a
    /// different port, or off the network entirely, keeps showing its
    /// last-polled location until the next poll corrects or clears it.
    pub switch_id: Option<Uuid>,
    /// Human-readable port label (`ifDescr`) on `switch_id`, e.g.
    /// `"GigabitEthernet1/0/12"`.
    pub switch_port: Option<String>,
    pub switch_port_seen_at: Option<DateTime<Utc>>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

impl NetworkDevice {
    /// Best-effort manufacturer name from the MAC's OUI prefix, or `None`
    /// when there's no MAC on record or its prefix isn't in the curated
    /// table (see `crate::oui`).
    pub fn vendor(&self) -> Option<&'static str> {
        self.mac_address
            .as_deref()
            .and_then(crate::oui::lookup_vendor)
    }

    /// Whether this is never real-time presence, only "the last sighting
    /// (scan or passive refresh) that saw it responded this long ago" --
    /// see `STALE_THRESHOLD_HOURS`.
    pub fn is_stale(&self) -> bool {
        Utc::now().signed_duration_since(self.last_seen_at) > Duration::hours(STALE_THRESHOLD_HOURS)
    }
}

/// A managed switch Panopticon polls over SNMP v2c for BRIDGE-MIB
/// MAC-to-port data (`panopticon_snmp.rs`). `community_encrypted` is
/// ciphertext (`abyssal_core::crypto::EncryptionKey`) -- callers that need
/// to actually poll the switch decrypt it themselves at the point of use
/// rather than this type ever carrying a plaintext community string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanopticonSwitch {
    pub id: Uuid,
    pub name: String,
    pub ip_address: String,
    pub snmp_port: u16,
    pub community_encrypted: String,
    pub enabled: bool,
    pub last_polled_at: Option<DateTime<Utc>>,
    /// Set by the most recent poll if it failed (unreachable, wrong
    /// community, timeout); cleared on the next poll that succeeds. Shown
    /// on the switches page so a misconfigured switch doesn't fail
    /// silently in a background loop nobody's watching.
    pub last_poll_error: Option<String>,
    pub created_at: DateTime<Utc>,
}
