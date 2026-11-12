//! Automatic device classification (0.2.7 N3, `docs/roadmap/0.2.7.md`): puts
//! together the evidence for one device -- its DHCP fingerprint, open ports,
//! MAC vendor, hostname and managed host's OS -- for
//! `abyssal_core::classify::suggest`, and the opt-in sweep that applies
//! suggestions.
//!
//! The sweep (every 10 minutes, `panopticon.auto_classify_enabled`, off by
//! default) only touches devices still `Unknown` or classified by itself
//! (`device_type_auto`), and only with a suggestion of medium confidence or
//! better. A person's classification is never overwritten: the write itself
//! re-checks that (`repo::network_devices::set_auto_type`).

use std::collections::HashMap;
use std::time::Duration;

use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::classify::{self, Confidence, Evidence, Suggestion};
use abyssal_core::settings::PANOPTICON_AUTO_CLASSIFY_ENABLED;
use abyssal_core::{DeviceType, NetworkDevice};
use abyssal_database::repo::panopticon_fingerprints::DhcpFingerprint;
use abyssal_database::{DbPool, repo};
use uuid::Uuid;

const SWEEP_INTERVAL_SECS: u64 = 600;

/// TCP ports the latest scan found open.
fn tcp_ports(device: &NetworkDevice) -> Vec<u16> {
    device
        .ports
        .iter()
        .filter(|p| p.protocol.eq_ignore_ascii_case("tcp"))
        .map(|p| p.port)
        .collect()
}

/// The suggestion for one device from what's known about it.
pub fn suggest(
    device: &NetworkDevice,
    fingerprint: Option<&DhcpFingerprint>,
    managed_os: Option<&str>,
) -> Option<Suggestion> {
    let ports = tcp_ports(device);
    classify::suggest(&Evidence {
        vendor: device.vendor(),
        ports: &ports,
        dhcp_prl: fingerprint.and_then(|f| f.prl.as_deref()),
        dhcp_vendor_class: fingerprint.and_then(|f| f.vendor_class.as_deref()),
        hostname: device
            .hostname
            .as_deref()
            .or_else(|| fingerprint.and_then(|f| f.hostname.as_deref())),
        managed_os,
    })
}

/// [`suggest`] for one device, reading its fingerprint and managed host --
/// for the classify page.
pub async fn suggest_for(
    pool: &DbPool,
    device: &NetworkDevice,
) -> (Option<Suggestion>, Option<DhcpFingerprint>) {
    let fingerprint = match &device.mac_address {
        Some(mac) => repo::panopticon_fingerprints::find(pool, mac)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let managed_os = match device.host_id {
        Some(id) => repo::hosts::find_by_id(pool, id)
            .await
            .ok()
            .flatten()
            .and_then(|h| h.os),
        None => None,
    };
    (
        suggest(device, fingerprint.as_ref(), managed_os.as_deref()),
        fingerprint,
    )
}

/// Whether the sweep may change this device's type to `suggestion`'s.
fn should_apply(device: &NetworkDevice, suggestion: &Suggestion) -> bool {
    (device.device_type == DeviceType::Unknown || device.device_type_auto)
        && suggestion.confidence >= Confidence::Medium
        && suggestion.device_type != device.device_type
}

/// Spawns the auto-classification sweep. Cheap when off: one settings read
/// per tick.
pub fn spawn_panopticon_classify_sweep(
    pool: DbPool,
    heartbeats: crate::task_health::TaskHeartbeats,
) {
    use crate::task_health::names;
    tokio::spawn(async move {
        heartbeats
            .register(names::PANOPTICON_CLASSIFY_SWEEP, SWEEP_INTERVAL_SECS)
            .await;
        let mut interval = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            heartbeats
                .ok(names::PANOPTICON_CLASSIFY_SWEEP, SWEEP_INTERVAL_SECS)
                .await;
            let on = repo::settings::get_bool(&pool, PANOPTICON_AUTO_CLASSIFY_ENABLED, false)
                .await
                .unwrap_or(false);
            if !on {
                continue;
            }
            match run_sweep(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(changed = n, "Panopticon auto-classified devices"),
                Err(e) => tracing::error!(error = %e, "Panopticon classification sweep failed"),
            }
        }
    });
}

/// One pass: returns how many devices it classified.
async fn run_sweep(pool: &DbPool) -> anyhow::Result<usize> {
    let devices = repo::network_devices::list(pool).await?;
    let fingerprints = repo::panopticon_fingerprints::all(pool).await?;
    let host_os: HashMap<Uuid, String> = repo::hosts::list(pool)
        .await?
        .into_iter()
        .filter_map(|h| Some((h.id, h.os?)))
        .collect();

    let mut changed = 0;
    for device in &devices {
        if device.device_type != DeviceType::Unknown && !device.device_type_auto {
            continue; // a person classified it
        }
        let fingerprint = device
            .mac_address
            .as_ref()
            .and_then(|m| fingerprints.get(&m.to_ascii_lowercase()));
        let managed_os = device
            .host_id
            .and_then(|h| host_os.get(&h))
            .map(String::as_str);
        let Some(suggestion) = suggest(device, fingerprint, managed_os) else {
            continue;
        };
        if !should_apply(device, &suggestion) {
            continue;
        }
        if !repo::network_devices::set_auto_type(pool, device.id, suggestion.device_type).await? {
            continue;
        }
        changed += 1;
        let event = AuditEvent::new(AuditAction::NetworkDeviceClassified, AuditOutcome::Success)
            .resource(&device.ip_address)
            .metadata(serde_json::json!({
                "auto": true,
                "from": device.device_type.as_str(),
                "to": suggestion.device_type.as_str(),
                "os": suggestion.os,
                "confidence": suggestion.confidence.label(),
                "reasons": suggestion.reasons,
            }));
        if let Err(e) = abyssal_audit::record(pool, event).await {
            tracing::warn!(error = %e, "failed to audit an automatic classification");
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::{NetworkDevicePort, TrustState};
    use chrono::Utc;

    fn device(device_type: DeviceType, auto: bool, ports: &[u16]) -> NetworkDevice {
        NetworkDevice {
            id: Uuid::new_v4(),
            ip_address: "10.0.9.5".into(),
            network: None,
            mac_address: None,
            hostname: None,
            device_type,
            device_type_auto: auto,
            trust_state: TrustState::Unknown,
            host_id: None,
            notes: None,
            ports: ports
                .iter()
                .map(|p| NetworkDevicePort {
                    port: *p,
                    protocol: "tcp".into(),
                    service: None,
                })
                .collect(),
            switch_id: None,
            switch_port: None,
            switch_port_seen_at: None,
            first_seen_at: Utc::now(),
            last_seen_at: Utc::now(),
        }
    }

    #[test]
    fn only_unknown_or_automatic_types_change() {
        let printer_ports = [9100, 515];
        let unknown = device(DeviceType::Unknown, false, &printer_ports);
        let s = suggest(&unknown, None, None).unwrap();
        assert_eq!(s.device_type, DeviceType::Printer);
        assert!(should_apply(&unknown, &s));
        // A person said it's a server: left alone.
        let manual = device(DeviceType::Server, false, &printer_ports);
        assert!(!should_apply(&manual, &s));
        // The classifier said IoT earlier: it may correct itself.
        let auto = device(DeviceType::Iot, true, &printer_ports);
        assert!(should_apply(&auto, &s));
        // Already right: nothing to do.
        let done = device(DeviceType::Printer, true, &printer_ports);
        assert!(!should_apply(&done, &s));
    }

    #[test]
    fn low_confidence_is_shown_but_never_applied() {
        let d = device(DeviceType::Unknown, false, &[3389]);
        let s = suggest(&d, None, None).unwrap();
        assert_eq!(s.confidence, Confidence::Low);
        assert!(!should_apply(&d, &s));
    }

    #[test]
    fn udp_ports_are_not_tcp_evidence() {
        let mut d = device(DeviceType::Unknown, false, &[]);
        d.ports.push(NetworkDevicePort {
            port: 9100,
            protocol: "udp".into(),
            service: None,
        });
        assert!(suggest(&d, None, None).is_none());
    }
}
