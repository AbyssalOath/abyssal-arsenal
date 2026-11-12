//! Automatic device classification for Panopticon (0.2.7 N3, see
//! `docs/roadmap/0.2.7.md`): a suggested [`DeviceType`] and OS family for a
//! device, from evidence the control plane already has.
//!
//! Evidence, roughly strongest first:
//! - the DHCP **vendor class** (option 60) a client sends: `MSFT 5.0`,
//!   `android-dhcp-13`, a printer's or phone's own name;
//! - the DHCP **parameter request list** (option 55), which differs by OS and
//!   DHCP client;
//! - **open ports** from discovery (9100 is a printer, 88 + 389 a domain
//!   controller, 554 a camera);
//! - the MAC **vendor** (Panopticon's curated OUI table, `crate::oui`);
//! - the **hostname** (`DESKTOP-…`, `…-iPhone`, `printer-…`);
//! - whether the device is a **managed host** and which OS its agent reports.
//!
//! Each rule adds a weight to a type (and maybe an OS); the best-scoring type
//! wins, and the confidence reflects both its score and its lead over the
//! runner-up. Every rule that fired is listed as a reason, so a person can see
//! why. Pure: no I/O, so the rules are tested directly.

use crate::DeviceType;

/// How sure a suggestion is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub const fn label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// What's known about one device.
#[derive(Debug, Default, Clone, Copy)]
pub struct Evidence<'a> {
    /// MAC vendor from the OUI table.
    pub vendor: Option<&'a str>,
    /// Open TCP ports from the latest scan.
    pub ports: &'a [u16],
    /// DHCP option 55 as sent, comma-separated decimal ("1,3,6,15,…").
    pub dhcp_prl: Option<&'a str>,
    /// DHCP option 60.
    pub dhcp_vendor_class: Option<&'a str>,
    /// The device's hostname, from discovery or DHCP option 12.
    pub hostname: Option<&'a str>,
    /// The OS a managed host's agent reports (`hosts.os`: "linux",
    /// "windows", ...), when the device is linked to one.
    pub managed_os: Option<&'a str>,
}

/// A suggested classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub device_type: DeviceType,
    /// OS family, when the evidence says ("Windows", "Linux", "Apple iOS", ...).
    pub os: Option<&'static str>,
    pub confidence: Confidence,
    /// One line per piece of evidence that counted, strongest first.
    pub reasons: Vec<String>,
}

const STRONG: u32 = 3;
const MEDIUM: u32 = 2;
const WEAK: u32 = 1;

struct Tally {
    types: Vec<(DeviceType, u32)>,
    os: Vec<(&'static str, u32)>,
    reasons: Vec<(u32, String)>,
}

impl Tally {
    fn new() -> Self {
        Tally {
            types: Vec::new(),
            os: Vec::new(),
            reasons: Vec::new(),
        }
    }

    fn add(&mut self, t: Option<DeviceType>, os: Option<&'static str>, w: u32, why: String) {
        if let Some(t) = t {
            match self.types.iter_mut().find(|(k, _)| *k == t) {
                Some((_, s)) => *s += w,
                None => self.types.push((t, w)),
            }
        }
        if let Some(os) = os {
            match self.os.iter_mut().find(|(k, _)| *k == os) {
                Some((_, s)) => *s += w,
                None => self.os.push((os, w)),
            }
        }
        self.reasons.push((w, why));
    }
}

/// Parses an option-55 list into its codes.
fn prl_codes(prl: &str) -> Vec<u8> {
    prl.split(',')
        .filter_map(|c| c.trim().parse().ok())
        .collect()
}

fn vendor_class_rules(vc: &str, t: &mut Tally) {
    use DeviceType::*;
    let lower = vc.to_ascii_lowercase();
    let why = |what: &str| format!("DHCP vendor class \"{vc}\" ({what})");
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    if lower.starts_with("msft") {
        t.add(
            Some(Workstation),
            Some("Windows"),
            MEDIUM,
            why("Windows DHCP client"),
        );
    } else if lower.starts_with("android-dhcp") {
        t.add(Some(Phone), Some("Android"), STRONG, why("Android"));
    } else if has(&[
        "ip phone",
        "polycom",
        "yealink",
        "grandstream",
        "mitel",
        "avaya",
        "aastra",
        "snom",
    ]) {
        t.add(Some(Phone), None, STRONG, why("an IP phone"));
    } else if has(&[
        "jetdirect",
        "hewlett-packard",
        "brother",
        "canon",
        "epson",
        "lexmark",
        "xerox",
        "ricoh",
        "kyocera",
        "printer",
    ]) {
        t.add(Some(Printer), None, STRONG, why("a printer"));
    } else if has(&[
        "arubaap",
        "aruba",
        "cisco ap",
        "airespace",
        "ubnt",
        "ruckus",
        "meraki",
    ]) {
        t.add(
            Some(NetworkInfrastructure),
            None,
            STRONG,
            why("a wireless access point"),
        );
    } else if lower.starts_with("udhcp") {
        t.add(
            Some(Iot),
            Some("Linux"),
            WEAK,
            why("embedded Linux (BusyBox)"),
        );
    } else if lower.starts_with("dhcpcd") {
        t.add(None, Some("Linux"), WEAK, why("dhcpcd, a Linux/BSD client"));
    }
}

fn prl_rules(prl: &str, t: &mut Tally) {
    use DeviceType::*;
    let codes = prl_codes(prl);
    if codes.is_empty() {
        return;
    }
    let has = |c: u8| codes.contains(&c);
    let why = |what: &str| format!("DHCP parameter list {prl} ({what})");
    // Windows asks for its classless-route (249) and WPAD (252) options and
    // vendor-specific info (43); no other common client asks for all three.
    if has(249) && has(252) && has(43) {
        // Servers rarely use DHCP, so a Windows DHCP client is most likely
        // a PC.
        t.add(Some(Workstation), Some("Windows"), MEDIUM, why("Windows"));
    // Apple clients lead with 1,121 (subnet mask, classless routes).
    } else if codes.starts_with(&[1, 121, 3, 6, 15]) {
        // macOS also asks for NetBIOS (44, 46) and/or LDAP (95); iOS doesn't.
        if has(44) || has(46) || has(95) {
            t.add(Some(Workstation), Some("Apple macOS"), MEDIUM, why("macOS"));
        } else {
            t.add(Some(Phone), Some("Apple iOS"), MEDIUM, why("iOS/iPadOS"));
        }
    // ISC dhclient / NetworkManager on Linux: hostname (12), broadcast (28),
    // domain search (119), classless routes (121), NTP (42).
    } else if has(28) && has(119) && has(121) && has(12) {
        t.add(None, Some("Linux"), MEDIUM, why("a Linux DHCP client"));
    // Android's client: MTU (26), broadcast (28), lease (51), T1/T2 (58/59)
    // and no Windows/Apple markers.
    } else if has(26) && has(28) && has(51) && has(58) && has(59) && !has(252) {
        t.add(Some(Phone), Some("Android"), WEAK, why("probably Android"));
    }
}

fn port_rules(ports: &[u16], t: &mut Tally) {
    use DeviceType::*;
    let open = |p: u16| ports.contains(&p);
    let why = |what: &str| format!("open ports: {what}");
    if open(9100) {
        t.add(Some(Printer), None, STRONG, why("9100 (raw printing)"));
    }
    if open(515) {
        t.add(Some(Printer), None, MEDIUM, why("515 (LPD printing)"));
    }
    if open(631) && !open(22) {
        t.add(Some(Printer), None, WEAK, why("631 (IPP printing)"));
    }
    if open(88) && open(389) {
        t.add(
            Some(Server),
            Some("Windows"),
            STRONG,
            why("88 + 389 (Kerberos + LDAP: a domain controller)"),
        );
    }
    if [1433, 1521, 3306, 5432, 27017].iter().any(|p| open(*p)) {
        t.add(Some(Server), None, MEDIUM, why("a database"));
    }
    if [25, 143, 993, 110, 995].iter().any(|p| open(*p)) {
        t.add(Some(Server), None, MEDIUM, why("a mail server"));
    }
    if open(53) {
        t.add(Some(Server), None, WEAK, why("53 (DNS)"));
    }
    if open(554) {
        t.add(
            Some(Iot),
            None,
            MEDIUM,
            why("554 (RTSP: a camera or media device)"),
        );
    }
    if open(1883) || open(8883) {
        t.add(Some(Iot), None, MEDIUM, why("MQTT"));
    }
    if open(5060) || open(5061) {
        t.add(Some(Phone), None, MEDIUM, why("SIP"));
    }
    if open(8291) {
        t.add(
            Some(NetworkInfrastructure),
            None,
            STRONG,
            why("8291 (MikroTik Winbox)"),
        );
    }
    if open(3389) {
        t.add(
            Some(Workstation),
            Some("Windows"),
            WEAK,
            why("3389 (Remote Desktop)"),
        );
    }
    if open(135) || open(445) {
        t.add(
            None,
            Some("Windows"),
            WEAK,
            why("135/445 (Windows file sharing / RPC)"),
        );
    }
}

fn vendor_rules(vendor: &str, t: &mut Tally) {
    use DeviceType::*;
    let why = |what: &str| format!("MAC vendor {vendor} ({what})");
    let (ty, os, w, what): (DeviceType, Option<&'static str>, u32, &str) = match vendor {
        "HP printers" => (Printer, None, STRONG, "printers"),
        "Zebra Technologies" => (Printer, None, MEDIUM, "label printers and scanners"),
        "MikroTik" | "Fortinet" => (NetworkInfrastructure, None, STRONG, "network equipment"),
        "Ubiquiti Networks" | "Cisco" | "Cisco Linksys" => (
            NetworkInfrastructure,
            None,
            MEDIUM,
            "mostly network equipment",
        ),
        "Netgear" | "TP-Link" => (NetworkInfrastructure, None, WEAK, "often network equipment"),
        "Espressif (ESP8266/ESP32 IoT)"
        | "Nest Labs"
        | "Amazon Technologies (Alexa)"
        | "Roku"
        | "PCS Systemtechnik (Roku)"
        | "Sonos" => (Iot, None, STRONG, "IoT devices"),
        "Raspberry Pi Foundation" => (Iot, Some("Linux"), WEAK, "single-board computers"),
        "Synology" => (Server, Some("Linux"), STRONG, "NAS appliances"),
        "VMware" | "QEMU/KVM" | "Microsoft Hyper-V" | "Oracle VirtualBox" => {
            (Server, None, MEDIUM, "a virtual machine")
        }
        "Dell" | "Shenzhen Maxtang Computer" | "Realtek" => (Workstation, None, WEAK, "PCs"),
        _ => return,
    };
    t.add(Some(ty), os, w, why(what));
}

fn hostname_rules(hostname: &str, t: &mut Tally) {
    use DeviceType::*;
    let h = hostname.to_ascii_lowercase();
    let why = |what: &str| format!("hostname \"{hostname}\" ({what})");
    if h.starts_with("desktop-") || h.starts_with("laptop-") {
        t.add(
            Some(Workstation),
            Some("Windows"),
            MEDIUM,
            why("a Windows default PC name"),
        );
    } else if h.contains("macbook") || h.contains("imac") {
        t.add(Some(Workstation), Some("Apple macOS"), MEDIUM, why("a Mac"));
    } else if h.contains("iphone") || h.contains("ipad") {
        t.add(
            Some(Phone),
            Some("Apple iOS"),
            MEDIUM,
            why("an iPhone/iPad"),
        );
    } else if h.contains("android") || h.contains("galaxy") || h.contains("pixel") {
        t.add(
            Some(Phone),
            Some("Android"),
            MEDIUM,
            why("an Android phone"),
        );
    } else if h.contains("printer") || h.starts_with("prn") || h.contains("-mfp") {
        t.add(Some(Printer), None, WEAK, why("a printer name"));
    }
}

/// Suggests a classification, or `None` when nothing points anywhere.
pub fn suggest(e: &Evidence<'_>) -> Option<Suggestion> {
    let mut t = Tally::new();
    if let Some(vc) = e.dhcp_vendor_class.filter(|v| !v.trim().is_empty()) {
        vendor_class_rules(vc.trim(), &mut t);
    }
    if let Some(prl) = e.dhcp_prl {
        prl_rules(prl, &mut t);
    }
    port_rules(e.ports, &mut t);
    if let Some(v) = e.vendor {
        vendor_rules(v, &mut t);
    }
    if let Some(h) = e.hostname.filter(|h| !h.is_empty()) {
        hostname_rules(h, &mut t);
    }
    match e.managed_os {
        Some("windows") => t.add(
            Some(DeviceType::Workstation),
            Some("Windows"),
            WEAK,
            "a managed host whose agent reports Windows".into(),
        ),
        Some("linux") => t.add(
            Some(DeviceType::Server),
            Some("Linux"),
            WEAK,
            "a managed host whose agent reports Linux".into(),
        ),
        _ => {}
    }

    let mut types = t.types;
    types.sort_by_key(|t| std::cmp::Reverse(t.1));
    let (device_type, top) = *types.first()?;
    let runner_up = types.get(1).map_or(0, |(_, s)| *s);
    let lead = top - runner_up;
    let confidence = if top >= STRONG && lead >= MEDIUM {
        Confidence::High
    } else if top >= MEDIUM && lead >= WEAK {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    let mut os = t.os;
    os.sort_by_key(|o| std::cmp::Reverse(o.1));
    let mut reasons = t.reasons;
    reasons.sort_by_key(|r| std::cmp::Reverse(r.0));
    Some(Suggestion {
        device_type,
        os: os.first().map(|(o, _)| *o),
        confidence,
        reasons: reasons.into_iter().map(|(_, r)| r).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use DeviceType::*;

    fn ev<'a>() -> Evidence<'a> {
        Evidence::default()
    }

    #[test]
    fn no_evidence_no_suggestion() {
        assert_eq!(suggest(&ev()), None);
        // Evidence that only names an OS doesn't make a type.
        let e = Evidence {
            ports: &[445],
            ..ev()
        };
        assert_eq!(suggest(&e), None);
    }

    #[test]
    fn a_printer_by_port_and_vendor_is_high_confidence() {
        let e = Evidence {
            ports: &[80, 443, 9100],
            vendor: Some("HP printers"),
            ..ev()
        };
        let s = suggest(&e).unwrap();
        assert_eq!(s.device_type, Printer);
        assert_eq!(s.confidence, Confidence::High);
        assert!(s.reasons[0].contains("9100") || s.reasons[0].contains("HP printers"));
        assert_eq!(s.reasons.len(), 2);
    }

    #[test]
    fn windows_dhcp_makes_a_windows_workstation() {
        let e = Evidence {
            dhcp_vendor_class: Some("MSFT 5.0"),
            dhcp_prl: Some("1,3,6,15,31,33,43,44,46,47,119,121,249,252"),
            hostname: Some("DESKTOP-4F2K9QZ"),
            ..ev()
        };
        let s = suggest(&e).unwrap();
        assert_eq!(s.device_type, Workstation);
        assert_eq!(s.os, Some("Windows"));
        assert_eq!(s.confidence, Confidence::High);
    }

    #[test]
    fn apple_parameter_lists_tell_ios_from_macos() {
        let ios = Evidence {
            dhcp_prl: Some("1,121,3,6,15,108,114,119,252"),
            ..ev()
        };
        let s = suggest(&ios).unwrap();
        assert_eq!((s.device_type, s.os), (Phone, Some("Apple iOS")));
        let mac = Evidence {
            dhcp_prl: Some("1,121,3,6,15,108,114,119,252,95,44,46"),
            ..ev()
        };
        let s = suggest(&mac).unwrap();
        assert_eq!((s.device_type, s.os), (Workstation, Some("Apple macOS")));
    }

    #[test]
    fn a_domain_controller_is_a_windows_server() {
        let e = Evidence {
            ports: &[53, 88, 135, 389, 445, 3268],
            managed_os: Some("windows"),
            ..ev()
        };
        let s = suggest(&e).unwrap();
        assert_eq!(s.device_type, Server);
        assert_eq!(s.os, Some("Windows"));
        // The managed-Windows hint (workstation) is outweighed.
        assert_eq!(s.confidence, Confidence::High);
    }

    #[test]
    fn android_and_phones_by_vendor_class() {
        let s = suggest(&Evidence {
            dhcp_vendor_class: Some("android-dhcp-13"),
            ..ev()
        })
        .unwrap();
        assert_eq!((s.device_type, s.os), (Phone, Some("Android")));
        let s = suggest(&Evidence {
            dhcp_vendor_class: Some("Polycom-VVX411"),
            ports: &[5060],
            ..ev()
        })
        .unwrap();
        assert_eq!(s.device_type, Phone);
        assert_eq!(s.confidence, Confidence::High);
    }

    #[test]
    fn conflicting_evidence_lowers_confidence() {
        // A Cisco MAC (network gear) running SIP (a phone): Cisco makes both.
        let s = suggest(&Evidence {
            vendor: Some("Cisco"),
            ports: &[5060],
            ..ev()
        })
        .unwrap();
        assert_eq!(s.confidence, Confidence::Low);
    }

    #[test]
    fn single_weak_evidence_is_low() {
        let s = suggest(&Evidence {
            vendor: Some("Dell"),
            ..ev()
        })
        .unwrap();
        assert_eq!(s.device_type, Workstation);
        assert_eq!(s.confidence, Confidence::Low);
    }

    #[test]
    fn iot_and_virtual_machines_by_vendor() {
        let s = suggest(&Evidence {
            vendor: Some("Espressif (ESP8266/ESP32 IoT)"),
            ..ev()
        })
        .unwrap();
        assert_eq!((s.device_type, s.confidence), (Iot, Confidence::High));
        let s = suggest(&Evidence {
            vendor: Some("VMware"),
            ports: &[22, 5432],
            ..ev()
        })
        .unwrap();
        assert_eq!(s.device_type, Server);
        assert_eq!(s.confidence, Confidence::High);
    }

    #[test]
    fn a_garbage_parameter_list_is_ignored() {
        assert_eq!(
            suggest(&Evidence {
                dhcp_prl: Some("x,,y"),
                ..ev()
            }),
            None
        );
    }
}
