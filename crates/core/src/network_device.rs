use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A device discovered on the LAN by Panopticon's active discovery scan.
/// Persisted so the inventory accumulates across scans rather than only
/// showing whatever the most recent scan happened to find -- a device that
/// didn't respond to today's scan (offline, firewalled) still shows up with
/// its last-known details until an admin explicitly removes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub id: Uuid,
    pub ip_address: String,
    /// Only populated when the device is on the same local subnet as the
    /// control plane -- resolved from the kernel's neighbor table (`ip
    /// neigh`) after a scan, not from the scan itself, since discovering a
    /// MAC address for a routed target needs raw-socket ARP access the
    /// control-plane process doesn't have (see `panopticon_ops.rs`).
    pub mac_address: Option<String>,
    /// Reverse-DNS name nmap resolved for this IP during the scan that
    /// found it, if any.
    pub hostname: Option<String>,
    /// Freeform summary of open ports from the most recent scan that saw
    /// this device (e.g. `"22/tcp ssh, 80/tcp http"`) -- not a structured
    /// per-port history.
    pub open_ports: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}
