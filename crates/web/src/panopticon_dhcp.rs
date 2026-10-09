//! DHCP lease import: hostnames (and MACs) for networks without reverse
//! DNS. Leases come from a pasted lease file or straight from a managed
//! DHCP server's agent (`AgentOperation::DhcpLeases`), are kept
//! (`panopticon_dhcp_leases`) so later scans use them too, and fill in
//! existing inventory devices right away.
//!
//! Parsing is pure and auto-detects the format: ISC dhcpd, dnsmasq, Kea's
//! CSV, and Windows DHCP Server's `Get-DhcpServerv4Lease | Export-Csv`.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use crate::panopticon_neighbors::normalize_mac;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Isc,
    Dnsmasq,
    Kea,
    Windows,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Isc => "ISC dhcpd",
            Format::Dnsmasq => "dnsmasq",
            Format::Kea => "Kea",
            Format::Windows => "Windows DHCP Server",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// `None`: no expiry (infinite, a reservation, or not stated).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Parses a lease file, keeping only current leases (active, unexpired) for
/// IPv4 addresses.
pub fn parse(text: &str, now: DateTime<Utc>) -> Result<(Format, Vec<Lease>), String> {
    let format = detect(text).ok_or_else(|| {
        "couldn't recognize the format -- expected an ISC dhcpd.leases, dnsmasq.leases, Kea \
         leases CSV, or a Windows Get-DhcpServerv4Lease CSV export"
            .to_string()
    })?;
    let leases = match format {
        Format::Isc => parse_isc(text),
        Format::Dnsmasq => parse_dnsmasq(text),
        Format::Kea => parse_csv(text, Format::Kea),
        Format::Windows => parse_csv(text, Format::Windows),
    };
    let leases = leases
        .into_iter()
        .filter(|l| l.ip.parse::<std::net::Ipv4Addr>().is_ok())
        .filter(|l| l.expires_at.is_none_or(|t| t > now))
        .collect();
    Ok((format, leases))
}

fn detect(text: &str) -> Option<Format> {
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("# abyssal-dhcp-source"))?;
    let lower = text.to_ascii_lowercase();
    if lower.contains("lease ") && text.contains('{') {
        return Some(Format::Isc);
    }
    let header = if first.starts_with("#TYPE") {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .nth(1)?
    } else {
        first
    }
    .to_ascii_lowercase();
    if header.contains("ipaddress") && (header.contains("clientid") || header.contains("hostname"))
    {
        return Some(Format::Windows);
    }
    if header.starts_with("address,hwaddr") {
        return Some(Format::Kea);
    }
    let fields: Vec<&str> = first.split_whitespace().collect();
    if fields.len() >= 4 && fields[0].parse::<u64>().is_ok() {
        return Some(Format::Dnsmasq);
    }
    None
}

fn hostname(raw: &str) -> Option<String> {
    let h = raw.trim().trim_matches('"').trim_end_matches('.');
    (!h.is_empty() && h != "*" && !h.eq_ignore_ascii_case("null")).then(|| h.to_string())
}

fn epoch(raw: &str) -> Option<DateTime<Utc>> {
    let secs: i64 = raw.trim().parse().ok()?;
    (secs > 0)
        .then(|| Utc.timestamp_opt(secs, 0).single())
        .flatten()
}

/// `ends 4 2026/10/09 22:00:00;` / `ends epoch 1791590400; # ...` /
/// `ends never;`
fn isc_time(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("epoch ") {
        return epoch(rest.split_whitespace().next()?);
    }
    let mut parts = value.split_whitespace();
    let _weekday = parts.next()?;
    let date = parts.next()?;
    let time = parts.next()?;
    NaiveDateTime::parse_from_str(&format!("{date} {time}"), "%Y/%m/%d %H:%M:%S")
        .ok()
        .map(|t| t.and_utc())
}

/// One `lease <ip> { ... }` block while it's being read.
struct IscBlock {
    lease: Lease,
    active: bool,
}

fn parse_isc(text: &str) -> Vec<Lease> {
    // The file is an append log: a later block for the same address wins.
    let mut by_ip: std::collections::BTreeMap<String, Option<Lease>> = Default::default();
    let mut current: Option<IscBlock> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("lease ")
            && let Some(ip) = rest.split_whitespace().next()
            && rest.trim_end().ends_with('{')
        {
            current = Some(IscBlock {
                lease: Lease {
                    ip: ip.to_string(),
                    mac: None,
                    hostname: None,
                    expires_at: None,
                },
                active: true,
            });
            continue;
        }
        let Some(block) = current.as_mut() else {
            continue;
        };
        let stmt = line.trim_end_matches(';');
        if line == "}" {
            if let Some(block) = current.take() {
                let ip = block.lease.ip.clone();
                by_ip.insert(ip, block.active.then_some(block.lease));
            }
        } else if let Some(v) = stmt.strip_prefix("hardware ethernet ") {
            block.lease.mac = normalize_mac(v);
        } else if let Some(v) = stmt.strip_prefix("client-hostname ") {
            block.lease.hostname = hostname(v);
        } else if let Some(v) = stmt.strip_prefix("ends ") {
            block.lease.expires_at = if v.trim() == "never" {
                None
            } else {
                isc_time(v)
            };
        } else if let Some(v) = stmt.strip_prefix("binding state ") {
            block.active = v.trim() == "active";
        }
    }
    by_ip.into_values().flatten().collect()
}

fn parse_dnsmasq(text: &str) -> Vec<Lease> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[0] == "duid" {
                return None;
            }
            Some(Lease {
                expires_at: epoch(f[0]),
                mac: normalize_mac(f[1]),
                ip: f[2].to_string(),
                hostname: hostname(f[3]),
            })
        })
        .collect()
}

/// A CSV line, honoring double quotes (Export-Csv quotes every field).
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    out.push(field);
    out
}

/// Windows expiry: ISO 8601 (what the agent's export writes), else the
/// common US-locale `Export-Csv` form.
fn windows_time(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
        return Some(t.with_timezone(&Utc));
    }
    for fmt in [
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(t) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Some(t.and_utc());
        }
    }
    None
}

fn parse_csv(text: &str, format: Format) -> Vec<Lease> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let header: Vec<String> = csv_fields(header)
        .into_iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let col = |name: &str| header.iter().position(|h| h == name);
    let (ip, mac, host, expiry, state) = match format {
        Format::Kea => (
            col("address"),
            col("hwaddr"),
            col("hostname"),
            col("expire"),
            col("state"),
        ),
        _ => (
            col("ipaddress"),
            col("clientid"),
            col("hostname"),
            col("leaseexpirytime"),
            col("addressstate"),
        ),
    };
    let Some(ip) = ip else {
        return Vec::new();
    };
    lines
        .filter_map(|line| {
            let f = csv_fields(line);
            let get = |i: Option<usize>| i.and_then(|i| f.get(i)).map(|s| s.trim().to_string());
            let state = get(state).unwrap_or_default();
            let current = match format {
                // 0 = assigned; 1 = declined, 2 = expired-reclaimed.
                Format::Kea => state.is_empty() || state == "0",
                _ => state.is_empty() || state.to_ascii_lowercase().starts_with("active"),
            };
            if !current {
                return None;
            }
            Some(Lease {
                ip: get(Some(ip))?,
                mac: get(mac).as_deref().and_then(normalize_mac),
                hostname: get(host).as_deref().and_then(hostname),
                expires_at: match format {
                    Format::Kea => get(expiry).as_deref().and_then(epoch),
                    _ => get(expiry).as_deref().and_then(windows_time),
                },
            })
        })
        .collect()
}

/// What an import did, for the page.
pub struct ImportSummary {
    pub format: Format,
    pub current: usize,
    pub with_hostname: usize,
    pub devices_updated: usize,
}

/// Parses `text`, stores its current leases (`source` names where they came
/// from), and fills in existing inventory devices: hostnames and MACs only
/// where they're missing. Leases for addresses not in the inventory are
/// kept for when a scan finds them.
pub async fn import(
    pool: &abyssal_database::DbPool,
    source: &str,
    text: &str,
) -> Result<ImportSummary, String> {
    use abyssal_database::repo::panopticon_topology as repo;
    let (format, leases) = parse(text, Utc::now())?;
    let rows: Vec<repo::NewLease<'_>> = leases
        .iter()
        .map(|l| repo::NewLease {
            ip_address: &l.ip,
            mac_address: l.mac.as_deref(),
            hostname: l.hostname.as_deref(),
            expires_at: l.expires_at,
        })
        .collect();
    repo::upsert_leases(pool, source, &rows)
        .await
        .map_err(|e| format!("couldn't store the leases: {e}"))?;
    let mut devices_updated = 0;
    for l in &leases {
        match repo::apply_lease_to_device(pool, &l.ip, l.mac.as_deref(), l.hostname.as_deref())
            .await
        {
            Ok(true) => devices_updated += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, ip = %l.ip, "failed to apply a DHCP lease"),
        }
    }
    Ok(ImportSummary {
        format,
        current: leases.len(),
        with_hostname: leases.iter().filter(|l| l.hostname.is_some()).count(),
        devices_updated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-09T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn isc_later_blocks_win_and_only_active_unexpired_count() {
        let text = "# The format of this file is documented in the dhcpd.leases(5) manual page.\n\
            lease 192.168.1.10 {\n  starts 4 2026/10/09 10:00:00;\n  ends 4 2026/10/09 11:00:00;\n  binding state active;\n  hardware ethernet AA:BB:CC:00:00:10;\n  client-hostname \"old-name\";\n}\n\
            lease 192.168.1.10 {\n  starts 4 2026/10/09 11:00:00;\n  ends 4 2026/10/09 23:00:00;\n  binding state active;\n  hardware ethernet aa:bb:cc:00:00:10;\n  client-hostname \"laptop-01\";\n}\n\
            lease 192.168.1.11 {\n  ends epoch 1791590400; # Fri Oct 09 2026\n  binding state free;\n  hardware ethernet aa:bb:cc:00:00:11;\n}\n\
            lease 192.168.1.12 {\n  ends never;\n  binding state active;\n  hardware ethernet aa:bb:cc:00:00:12;\n}\n";
        let (format, leases) = parse(text, now()).unwrap();
        assert_eq!(format, Format::Isc);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].ip, "192.168.1.10");
        assert_eq!(
            leases[0].hostname.as_deref(),
            Some("laptop-01"),
            "the later block"
        );
        assert_eq!(leases[0].mac.as_deref(), Some("aa:bb:cc:00:00:10"));
        assert_eq!(leases[1].ip, "192.168.1.12");
        assert_eq!(leases[1].expires_at, None, "never expires");
    }

    #[test]
    fn dnsmasq_leases() {
        let text = "1791640800 aa:bb:cc:00:00:20 10.0.0.20 printer-2f 01:aa:bb:cc:00:00:20\n\
                    1791000000 aa:bb:cc:00:00:21 10.0.0.21 expired-one *\n\
                    0 aa:bb:cc:00:00:22 10.0.0.22 * *\n\
                    duid 00:01:00:01:aa:bb:cc:dd\n\
                    1791640800 2001:db8::5 ...\n";
        let (format, leases) = parse(text, now()).unwrap();
        assert_eq!(format, Format::Dnsmasq);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].hostname.as_deref(), Some("printer-2f"));
        assert_eq!(leases[1].ip, "10.0.0.22");
        assert_eq!(leases[1].hostname, None, "* means no name");
        assert_eq!(leases[1].expires_at, None, "0 = infinite");
    }

    #[test]
    fn kea_csv() {
        let text = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n\
                    10.1.0.5,aa:bb:cc:00:01:05,,3600,1791640800,1,0,0,nas.corp.local.,0,\n\
                    10.1.0.6,aa:bb:cc:00:01:06,,3600,1791640800,1,0,0,declined-box,1,\n";
        let (format, leases) = parse(text, now()).unwrap();
        assert_eq!(format, Format::Kea);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].hostname.as_deref(), Some("nas.corp.local"));
    }

    #[test]
    fn windows_export_csv() {
        let text = "#TYPE Selected.Microsoft.Management.Infrastructure.CimInstance\r\n\
            \"IPAddress\",\"ClientId\",\"HostName\",\"AddressState\",\"LeaseExpiryTime\"\r\n\
            \"10.2.0.15\",\"00-15-5d-01-02-03\",\"WKS-FINANCE-07.corp.local\",\"Active\",\"10/10/2026 8:00:00 AM\"\r\n\
            \"10.2.0.16\",\"00-15-5d-01-02-04\",\"PRN-LOBBY\",\"ActiveReservation\",\"\"\r\n\
            \"10.2.0.17\",\"00-15-5d-01-02-05\",\"old\",\"Inactive\",\"10/1/2026 8:00:00 AM\"\r\n\
            \"10.2.0.18\",\"00-15-5d-01-02-06\",\"from, the agent\",\"Active\",\"2026-10-10T08:00:00.0000000Z\"\r\n";
        let (format, leases) = parse(text, now()).unwrap();
        assert_eq!(format, Format::Windows);
        assert_eq!(leases.len(), 3);
        assert_eq!(leases[0].mac.as_deref(), Some("00:15:5d:01:02:03"));
        assert_eq!(
            leases[0].hostname.as_deref(),
            Some("WKS-FINANCE-07.corp.local")
        );
        assert!(leases[0].expires_at.is_some());
        assert_eq!(leases[1].expires_at, None, "a reservation");
        assert_eq!(
            leases[2].hostname.as_deref(),
            Some("from, the agent"),
            "quoted comma"
        );
    }

    /// What the agent's Windows script really prints (produced by running it
    /// in PowerShell with stand-in DHCP cmdlets), source line included.
    #[test]
    fn the_windows_agents_own_output() {
        let text = include_str!("../tests/fixtures/dhcp_windows_agent.csv");
        let (format, leases) = parse(text, now()).unwrap();
        assert_eq!(format, Format::Windows);
        assert_eq!(leases.len(), 3);
        assert_eq!(leases[0].ip, "10.2.0.15");
        assert_eq!(leases[0].mac.as_deref(), Some("00:15:5d:01:02:03"));
        assert!(leases[0].expires_at.is_some());
        assert_eq!(leases[1].hostname.as_deref(), Some("PRN-LOBBY"));
        assert_eq!(leases[2].hostname.as_deref(), Some("odd, name"));
    }

    #[test]
    fn rejects_what_it_doesnt_recognize() {
        assert!(parse("hello world", now()).is_err());
        assert!(parse("", now()).is_err());
    }
}
