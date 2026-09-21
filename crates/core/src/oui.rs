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
];

/// Normalizes to bare uppercase hex (strips `:`/`-` separators) and matches
/// the first 6 hex digits (3 octets) against the OUI table. Returns `None`
/// for a malformed address or a prefix outside this curated subset.
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
    OUI_TABLE
        .iter()
        .find(|(p, _)| *p == prefix)
        .map(|(_, vendor)| *vendor)
}
