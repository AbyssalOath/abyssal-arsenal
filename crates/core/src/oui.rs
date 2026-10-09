//! MAC address vendor lookup from the IEEE OUI (first 3 octets). A curated
//! subset covering common device/infrastructure vendors, not the full
//! ~30k-entry IEEE registry -- consistent with this codebase's general
//! preference for a small hand-rolled table over pulling in an external
//! dataset dependency for one field (see `panopticon_ops.rs`'s nmap output
//! parser for the same reasoning). Unrecognized prefixes simply show no
//! vendor rather than erroring.
const OUI_TABLE: &[(&str, &str)] = &[
    ("000C29", "VMware"),
    ("000569", "VMware"),
    ("001C14", "VMware"),
    ("005056", "VMware"),
    ("080027", "Oracle VirtualBox"),
    ("0A0027", "Oracle VirtualBox"),
    ("00155D", "Microsoft Hyper-V"),
    ("001DD8", "Microsoft"),
    ("BC83AB", "Microsoft"),
    ("525400", "QEMU/KVM"),
    ("DCA632", "Raspberry Pi Foundation"),
    ("B827EB", "Raspberry Pi Foundation"),
    ("E45F01", "Raspberry Pi Foundation"),
    ("28CDC1", "Raspberry Pi Foundation"),
    ("D83ADD", "Raspberry Pi Foundation"),
    ("F4F5D8", "Google"),
    ("3C5AB4", "Google"),
    ("A47733", "Google"),
    ("F4F5E8", "Google"),
    ("001A11", "Google"),
    ("F0272D", "Amazon Technologies"),
    ("FC65DE", "Amazon Technologies"),
    ("74C246", "Amazon Technologies"),
    ("B47C9C", "Amazon Technologies"),
    ("00E04C", "Realtek"),
    ("001E58", "Realtek"),
    ("000D3A", "Microsoft"),
    ("0003FF", "Microsoft"),
    ("F8D0AC", "Ubiquiti Networks"),
    ("24A43C", "Ubiquiti Networks"),
    ("788A20", "Ubiquiti Networks"),
    ("DC9FDB", "Ubiquiti Networks"),
    ("002722", "Cisco"),
    ("0007EB", "Cisco"),
    ("000142", "Cisco"),
    ("001B54", "Cisco"),
    ("0050F0", "Cisco Linksys"),
    ("C4E984", "Cisco"),
    ("00904C", "Netgear"),
    ("204E7F", "Netgear"),
    ("A040A0", "Netgear"),
    ("844E00", "Netgear"),
    ("14CC20", "TP-Link"),
    ("50C7BF", "TP-Link"),
    ("EC086B", "TP-Link"),
    ("F4EC38", "TP-Link"),
    ("B0487A", "Dell"),
    ("D067E5", "Dell"),
    ("F8B156", "Dell"),
    ("A4BADB", "Dell"),
    ("3417EB", "HP"),
    ("9457A5", "HP"),
    ("6C3BE5", "HP"),
    ("D89D67", "HP"),
    ("00E081", "HP printers"),
    ("3C2AF4", "HP printers"),
    ("F40343", "Apple"),
    ("A45E60", "Apple"),
    ("BC926B", "Apple"),
    ("D0817A", "Apple"),
    ("F0189E", "Apple"),
    ("A8968A", "Apple"),
    ("3C0754", "Apple"),
    ("6C4008", "Apple"),
    ("D0037F", "Apple"),
    ("E0ACCB", "Apple"),
    ("F4F951", "Apple"),
    ("885395", "Apple"),
    ("000393", "Apple"),
    ("28E14C", "Samsung"),
    ("5C0A5B", "Samsung"),
    ("8C7712", "Samsung"),
    ("A00798", "Samsung"),
    ("CC07AB", "Samsung"),
    ("EC1F72", "Samsung"),
    ("341298", "Sonos"),
    ("5CAAFD", "Sonos"),
    ("B8E937", "Sonos"),
    ("000E58", "MikroTik"),
    ("4C5E0C", "MikroTik"),
    ("6C3B6B", "MikroTik"),
    ("B869F4", "Espressif (ESP8266/ESP32 IoT)"),
    ("240AC4", "Espressif (ESP8266/ESP32 IoT)"),
    ("3C71BF", "Espressif (ESP8266/ESP32 IoT)"),
    ("A020A6", "Espressif (ESP8266/ESP32 IoT)"),
    ("EC6260", "Amazon Technologies (Alexa)"),
    ("18B430", "Nest Labs"),
    ("D8D33A", "PCS Systemtechnik (Roku)"),
    ("B0A737", "Roku"),
    ("DC3A5E", "Roku"),
    ("000AE4", "Synology"),
    ("0011D9", "Synology"),
    ("001132", "Synology"),
    // Verified against the IEEE OUI registry (via maclookup.app) while
    // fixing Panopticon issue Phase 2a -- these specific prefixes came up
    // empty against real devices on a live internal network, unlike the
    // entries above (mostly cloud/virtualization platforms), which rarely
    // show up on a physical office/campus LAN.
    ("609532", "Zebra Technologies"),
    ("B0416F", "Shenzhen Maxtang Computer"),
    ("8CEC4B", "Dell"),
    ("94F392", "Fortinet"),
    ("184A53", "Apple"),
];

/// Where nmap keeps its copy of the full IEEE registry (~30k prefixes). The
/// Docker image installs nmap, so the control plane always has one; the
/// curated table above is checked first for its friendlier names.
const NMAP_MAC_PREFIXES: &[&str] = &[
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
];

static REGISTRY: std::sync::OnceLock<std::collections::HashMap<String, String>> =
    std::sync::OnceLock::new();

/// `nmap-mac-prefixes`: `0050F2 Microsoft`, `#` comments. 24-bit prefixes
/// only; nmap's longer MA-M/MA-S entries are skipped.
fn parse_registry(contents: &str) -> std::collections::HashMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let (prefix, vendor) = line.trim().split_once(char::is_whitespace)?;
            (prefix.len() == 6 && prefix.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| (prefix.to_ascii_uppercase(), vendor.trim().to_string()))
        })
        .filter(|(_, vendor)| !vendor.is_empty())
        .collect()
}

fn registry() -> &'static std::collections::HashMap<String, String> {
    REGISTRY.get_or_init(|| {
        NMAP_MAC_PREFIXES
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .map(|contents| parse_registry(&contents))
            .unwrap_or_default()
    })
}

/// Normalizes to bare uppercase hex (strips `:`/`-` separators) and matches
/// the first 6 hex digits (3 octets) against the curated table, then nmap's
/// full registry. Returns `None` for a malformed address, a randomized
/// (locally administered) one, or an unknown prefix.
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let normalized: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.len() < 6 {
        return None;
    }
    let prefix = &normalized[..6];
    if let Some((_, vendor)) = OUI_TABLE.iter().find(|(p, _)| *p == prefix) {
        return Some(vendor);
    }
    // Locally administered: never an IEEE assignment.
    let first = u8::from_str_radix(&prefix[..2], 16).ok()?;
    if first & 0x02 != 0 {
        return None;
    }
    registry().get(prefix).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_regardless_of_colon_or_hyphen_separators_or_case() {
        assert_eq!(
            lookup_vendor("60:95:32:06:e3:fd"),
            Some("Zebra Technologies")
        );
        assert_eq!(
            lookup_vendor("60-95-32-06-E3-FD"),
            Some("Zebra Technologies")
        );
        assert_eq!(lookup_vendor("609532FFFFFF"), Some("Zebra Technologies"));
    }

    #[test]
    fn parses_nmaps_registry_format() {
        let reg = parse_registry(
            "# comment\n002272 American Micro-Fuel Device\n00d0ef IGT\n\
             8C1F64F Some MA-M entry\nbad line\nABCDEF\n",
        );
        assert_eq!(
            reg.get("002272").map(String::as_str),
            Some("American Micro-Fuel Device")
        );
        assert_eq!(reg.get("00D0EF").map(String::as_str), Some("IGT"));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn falls_back_to_nmaps_registry_when_installed() {
        // 00:21:9b is Dell in the IEEE registry but not the curated table.
        if NMAP_MAC_PREFIXES
            .iter()
            .any(|p| std::path::Path::new(p).exists())
        {
            assert_eq!(lookup_vendor("00:21:9b:00:00:01"), Some("Dell"));
        }
    }

    #[test]
    fn unrecognized_prefix_returns_none_not_an_error() {
        assert_eq!(lookup_vendor("0c:ff:fe:00:00:00"), None);
    }

    #[test]
    fn malformed_or_short_input_returns_none() {
        assert_eq!(lookup_vendor(""), None);
        assert_eq!(lookup_vendor("60:95"), None);
    }

    #[test]
    fn a_locally_administered_randomized_mac_has_no_real_vendor() {
        // The second-least-significant bit of the first octet set (7E =
        // 0111_1110) marks a locally administered/randomized address --
        // never a real IEEE OUI assignment, so no table (however large)
        // could ever resolve one. Not in `OUI_TABLE` on purpose.
        assert_eq!(lookup_vendor("7E:10:8D:75:E6:62"), None);
    }
}
