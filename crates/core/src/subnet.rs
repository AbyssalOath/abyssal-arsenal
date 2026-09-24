//! Pure IPv4/IPv6 CIDR-network computation -- GitHub issue #10's device
//! inventory subnet grouping. Deliberately built on `std::net` alone
//! (`IpAddr`/`Ipv4Addr`/`Ipv6Addr` already parse and expose the bit
//! representation this needs) rather than adding `ipnetwork`/`ipnet`/
//! `cidr` as a new dependency -- masking an address down to its network
//! prefix is a handful of bitwise operations, not something that
//! justifies a new crate here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// The network `ip` falls into at `prefix_v4`/`prefix_v6` bits (whichever
/// applies to the address family), rendered as a CIDR string (e.g.
/// `"10.0.1.0/24"`, `"2001:db8::/64"`). `None` for anything that isn't a
/// parseable IP address at all -- the caller's "Unassigned / Unknown"
/// group, never a silently-dropped device.
pub fn network_of(ip: &str, prefix_v4: u8, prefix_v6: u8) -> Option<String> {
    match IpAddr::from_str(ip.trim()).ok()? {
        IpAddr::V4(addr) => Some(format!(
            "{}/{}",
            mask_v4(addr, prefix_v4.min(32)),
            prefix_v4.min(32)
        )),
        IpAddr::V6(addr) => Some(format!(
            "{}/{}",
            mask_v6(addr, prefix_v6.min(128)),
            prefix_v6.min(128)
        )),
    }
}

/// Parses a previously-rendered `network_of` string (or any `a.b.c.d/n` /
/// `xxxx::/n` CIDR literal an operator might type into a filter box) back
/// into its address family and prefix length, validating the prefix is in
/// range for that family. Used both to validate the `?subnet=` filter
/// query param and to re-derive a network string canonically (so
/// `10.0.1.5/24` and `10.0.1.0/24` normalize to the same group).
pub fn parse_cidr(input: &str) -> Option<(IpAddr, u8)> {
    let (addr_part, prefix_part) = input.trim().split_once('/')?;
    let addr = IpAddr::from_str(addr_part).ok()?;
    let prefix: u8 = prefix_part.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return None;
    }
    Some((addr, prefix))
}

/// Canonical network string for `input` (the network address, not
/// whatever host address happened to be typed) -- `None` if `input` isn't
/// a valid `address/prefix` CIDR literal at all.
pub fn normalize_cidr(input: &str) -> Option<String> {
    let (addr, prefix) = parse_cidr(input)?;
    match addr {
        IpAddr::V4(a) => Some(format!("{}/{prefix}", mask_v4(a, prefix))),
        IpAddr::V6(a) => Some(format!("{}/{prefix}", mask_v6(a, prefix))),
    }
}

/// The inclusive `(first, last)` address of the CIDR block `addr/prefix`
/// describes -- e.g. `(10.0.1.0, 10.0.1.255)` for `10.0.1.5/24`. Meant
/// for binding into `INET6_ATON(?)` on either side of a `BETWEEN`, so a
/// numeric-range query can containment-test against it -- real range
/// arithmetic, never a `LIKE` prefix match (GitHub issue #10).
pub fn subnet_bounds(addr: IpAddr, prefix: u8) -> (String, String) {
    match addr {
        IpAddr::V4(a) => {
            let prefix = prefix.min(32);
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = u32::from(a) & mask;
            let broadcast = network | !mask;
            (
                Ipv4Addr::from(network).to_string(),
                Ipv4Addr::from(broadcast).to_string(),
            )
        }
        IpAddr::V6(a) => {
            let prefix = prefix.min(128);
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = u128::from(a) & mask;
            let broadcast = network | !mask;
            (
                Ipv6Addr::from(network).to_string(),
                Ipv6Addr::from(broadcast).to_string(),
            )
        }
    }
}

fn mask_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_bounds_covers_the_whole_v4_block() {
        let (addr, prefix) = parse_cidr("10.0.1.42/24").unwrap();
        assert_eq!(
            subnet_bounds(addr, prefix),
            ("10.0.1.0".to_string(), "10.0.1.255".to_string())
        );
    }

    #[test]
    fn subnet_bounds_of_a_single_host_is_that_one_address() {
        let (addr, prefix) = parse_cidr("10.0.1.5/32").unwrap();
        assert_eq!(
            subnet_bounds(addr, prefix),
            ("10.0.1.5".to_string(), "10.0.1.5".to_string())
        );
    }

    #[test]
    fn subnet_bounds_of_slash_0_covers_the_whole_address_space() {
        let (addr, prefix) = parse_cidr("10.0.1.5/0").unwrap();
        assert_eq!(
            subnet_bounds(addr, prefix),
            ("0.0.0.0".to_string(), "255.255.255.255".to_string())
        );
    }

    #[test]
    fn subnet_bounds_covers_the_whole_v6_block() {
        let (addr, prefix) = parse_cidr("2001:db8::/126").unwrap();
        assert_eq!(
            subnet_bounds(addr, prefix),
            ("2001:db8::".to_string(), "2001:db8::3".to_string())
        );
    }

    #[test]
    fn groups_an_ipv4_address_into_its_slash_24() {
        assert_eq!(
            network_of("10.0.1.55", 24, 64),
            Some("10.0.1.0/24".to_string())
        );
    }

    #[test]
    fn groups_an_ipv6_address_into_its_slash_64() {
        assert_eq!(
            network_of("2001:db8::1234:5678", 24, 64),
            Some("2001:db8::/64".to_string())
        );
    }

    #[test]
    fn slash_0_groups_everything_of_that_family_together() {
        assert_eq!(
            network_of("10.0.1.55", 0, 64),
            Some("0.0.0.0/0".to_string())
        );
        assert_eq!(
            network_of("192.168.50.1", 0, 64),
            Some("0.0.0.0/0".to_string())
        );
    }

    #[test]
    fn slash_32_and_slash_128_are_the_host_address_itself() {
        assert_eq!(
            network_of("10.0.1.55", 32, 64),
            Some("10.0.1.55/32".to_string())
        );
        assert_eq!(
            network_of("2001:db8::1", 24, 128),
            Some("2001:db8::1/128".to_string())
        );
    }

    #[test]
    fn unparseable_input_returns_none() {
        assert_eq!(network_of("not-an-ip", 24, 64), None);
        assert_eq!(network_of("", 24, 64), None);
        assert_eq!(network_of("999.999.999.999", 24, 64), None);
    }

    #[test]
    fn a_prefix_longer_than_the_family_allows_is_clamped() {
        // Defensive: callers pass settings-derived values that should
        // already be validated, but a corrupted setting must never panic.
        assert_eq!(
            network_of("10.0.1.55", 255, 64),
            Some("10.0.1.55/32".to_string())
        );
    }

    #[test]
    fn parse_cidr_rejects_a_prefix_too_long_for_the_family() {
        assert!(parse_cidr("10.0.1.0/33").is_none());
        assert!(parse_cidr("2001:db8::/129").is_none());
    }

    #[test]
    fn parse_cidr_rejects_malformed_input() {
        assert!(parse_cidr("not-a-cidr").is_none());
        assert!(parse_cidr("10.0.1.0").is_none());
        assert!(parse_cidr("/24").is_none());
    }

    #[test]
    fn normalize_cidr_masks_a_host_address_down_to_its_network() {
        assert_eq!(
            normalize_cidr("10.0.1.55/24"),
            Some("10.0.1.0/24".to_string())
        );
    }

    #[test]
    fn normalize_cidr_is_idempotent_on_an_already_canonical_network() {
        assert_eq!(
            normalize_cidr("10.0.1.0/24"),
            Some("10.0.1.0/24".to_string())
        );
    }
}
