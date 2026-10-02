//! The control plane's private CA for installs with no public domain (the
//! "Caddy, internal IP/FQDN" path): creating the CA, issuing the server
//! certificate Caddy serves, and reading back what a certificate says.
//!
//! Pure functions over PEM strings -- no filesystem, no clock beyond "now" --
//! so the control plane (which owns storage, renewal, and rotation; see
//! `abyssal_web::internal_tls`) and the agent's TLS tests share one
//! implementation.
//!
//! Why a CA and not a self-signed server certificate: a self-signed cert made
//! the usual way (`openssl req -x509`) is `CA:TRUE`, and rustls/webpki (the
//! agent's TLS stack) correctly rejects a CA certificate in the end-entity
//! position (`CaUsedAsEndEntity`). Here the CA is only ever a trust anchor and
//! Caddy serves a proper `CA:FALSE` leaf it issued.
//!
//! The CA is **name-constrained** to exactly the control plane's own
//! address(es), so even if its key leaked, a machine that trusts it would
//! accept it for nothing else. Keys are ECDSA P-256 (supported by rustls,
//! Windows SChannel, browsers, Caddy).

use std::net::IpAddr;

use anyhow::{Context, bail};
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType, SerialNumber,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// CA lifetime. Replacing the CA means every client re-trusts it, so it's
/// long; the name constraint is what limits its reach.
pub const CA_DAYS: i64 = 3650;
/// Server certificate lifetime: the longest Apple platforms accept even from
/// a private root (398 days is the cap for *publicly trusted* CAs only).
/// Renewal never needs clients to re-trust anything -- only the CA is trusted.
pub const LEAF_DAYS: i64 = 825;
/// Automatic renewal kicks in this close to the server certificate's expiry.
pub const RENEW_WITHIN_DAYS: i64 = 30;
/// At most this many addresses on one CA / certificate.
pub const MAX_ADDRESSES: usize = 8;

/// One name the control plane is reached at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    Ip(IpAddr),
    Dns(String),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Ip(ip) => write!(f, "{ip}"),
            Address::Dns(name) => f.write_str(name),
        }
    }
}

impl Address {
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let input = input.trim().trim_end_matches('.');
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Address::Ip(ip));
        }
        let name = input.to_ascii_lowercase();
        let valid_label = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        if name.is_empty() || name.len() > 253 || !name.split('.').all(valid_label) {
            bail!("'{input}' is neither an IP address nor a valid hostname");
        }
        // An all-numeric dotted name that didn't parse as an IP is a typo'd
        // IP, not a hostname -- don't silently put it on a cert as DNS.
        if name
            .split('.')
            .all(|l| l.chars().all(|c| c.is_ascii_digit()))
        {
            bail!("'{input}' looks like an IP address but isn't a valid one");
        }
        Ok(Address::Dns(name))
    }
}

/// Parses a comma/whitespace-separated list, de-duplicated, order kept.
pub fn parse_addresses(input: &str) -> anyhow::Result<Vec<Address>> {
    let mut out: Vec<Address> = Vec::new();
    for part in input
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
    {
        let address = Address::parse(part)?;
        if !out.contains(&address) {
            out.push(address);
        }
    }
    if out.is_empty() {
        bail!("at least one IP address or hostname is required");
    }
    if out.len() > MAX_ADDRESSES {
        bail!("at most {MAX_ADDRESSES} addresses are supported");
    }
    Ok(out)
}

pub fn format_addresses(addresses: &[Address]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A certificate and its private key, PEM.
#[derive(Clone)]
pub struct Material {
    /// For a server certificate: the leaf followed by the issuing CA, which
    /// is what Caddy should serve.
    pub cert_pem: String,
    pub key_pem: String,
}

fn random_serial() -> SerialNumber {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // keep it positive
    bytes[0] |= 0x01; // and without a leading zero byte
    SerialNumber::from_slice(&bytes)
}

fn short_id() -> String {
    random_serial().to_bytes()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Creates a new CA, name-constrained to `addresses`.
pub fn create_ca(addresses: &[Address]) -> anyhow::Result<Material> {
    create_ca_at(addresses, OffsetDateTime::now_utc())
}

pub fn create_ca_at(addresses: &[Address], now: OffsetDateTime) -> anyhow::Result<Material> {
    if addresses.is_empty() {
        bail!("a CA needs at least one address to be constrained to");
    }
    let key = KeyPair::generate().context("failed to generate the CA key")?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    // The random suffix keeps every CA's subject unique: a client still
    // holding an older CA would otherwise match it by name and fail with a
    // confusing bad-signature error rather than "unknown issuer". Addresses
    // aren't in the CN (X.509 caps it at 64 characters); the name
    // constraints carry them.
    dn.push(
        DnType::CommonName,
        format!("Abyssal Arsenal Internal CA {} {}", now.date(), short_id()),
    );
    dn.push(DnType::OrganizationName, "Abyssal Arsenal");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: addresses
            .iter()
            .map(|a| match a {
                Address::Ip(ip) => GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(
                    *ip,
                    if ip.is_ipv4() { 32 } else { 128 },
                )),
                Address::Dns(name) => GeneralSubtree::DnsName(name.clone()),
            })
            .collect(),
        excluded_subtrees: Vec::new(),
    });
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(CA_DAYS);
    params.serial_number = Some(random_serial());
    let cert = params
        .self_signed(&key)
        .context("failed to self-sign the CA certificate")?;
    Ok(Material {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Issues a server certificate for `addresses` from `ca`. The returned
/// `cert_pem` is the leaf followed by the CA certificate.
pub fn issue_server_cert(ca: &Material, addresses: &[Address]) -> anyhow::Result<Material> {
    issue_server_cert_at(ca, addresses, OffsetDateTime::now_utc())
}

pub fn issue_server_cert_at(
    ca: &Material,
    addresses: &[Address],
    now: OffsetDateTime,
) -> anyhow::Result<Material> {
    if addresses.is_empty() {
        bail!("a server certificate needs at least one address");
    }
    let ca_key = KeyPair::from_pem(&ca.key_pem).context("the CA key is unreadable")?;
    let ca_info = inspect(&ca.cert_pem)?;
    if !ca_info.is_ca {
        bail!("the CA certificate is not a CA");
    }
    for address in addresses {
        if !ca_info.permits(address) {
            bail!(
                "the CA is constrained to {} and can't issue for {address}",
                ca_info.permitted.join(", ")
            );
        }
    }
    let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, &ca_key)
        .context("the CA certificate is unreadable")?;

    let key = KeyPair::generate().context("failed to generate the server key")?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    let first = addresses[0].to_string();
    // Clients match on the SAN; the CN is cosmetic and capped at 64 chars.
    dn.push(
        DnType::CommonName,
        if first.len() <= 64 {
            first
        } else {
            "Abyssal Arsenal".to_string()
        },
    );
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    // ECDSA keys sign; keyEncipherment (RSA key transport) doesn't apply.
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = addresses
        .iter()
        .map(|a| {
            Ok(match a {
                Address::Ip(ip) => SanType::IpAddress(*ip),
                Address::Dns(name) => SanType::DnsName(name.clone().try_into()?),
            })
        })
        .collect::<Result<_, rcgen::Error>>()?;
    params.use_authority_key_identifier_extension = true;
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(LEAF_DAYS);
    params.serial_number = Some(random_serial());
    let leaf = params
        .signed_by(&key, &issuer)
        .context("failed to sign the server certificate")?;
    Ok(Material {
        cert_pem: format!("{}{}", leaf.pem(), first_pem_block(&ca.cert_pem)?),
        key_pem: key.serialize_pem(),
    })
}

/// What a certificate says, for display and for renewal decisions.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    /// Subject alternative names (IP addresses and DNS names), as text.
    pub sans: Vec<String>,
    /// Permitted name-constraint subtrees (CA only), as text.
    pub permitted: Vec<String>,
    /// SHA-256 of the DER, upper-case hex, no separators.
    pub fingerprint: String,
}

impl CertInfo {
    pub fn days_left(&self, now_unix: i64) -> i64 {
        (self.not_after - now_unix).div_euclid(86_400)
    }

    pub fn covers(&self, address: &Address) -> bool {
        self.sans.iter().any(|s| s == &address.to_string())
    }

    /// Whether this CA's name constraints allow issuing for `address`.
    /// An unconstrained CA permits anything.
    pub fn permits(&self, address: &Address) -> bool {
        self.permitted.is_empty()
            || self.permitted.iter().any(|p| match address {
                Address::Ip(ip) => p == &format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
                Address::Dns(name) => {
                    name == p || name.ends_with(&format!(".{}", p.trim_start_matches('.')))
                }
            })
    }

    /// The addresses this CA is constrained to, in a form `parse_addresses`
    /// accepts (CIDR suffixes stripped from host-sized IP subtrees).
    pub fn permitted_addresses(&self) -> Vec<Address> {
        self.permitted
            .iter()
            .filter_map(|p| Address::parse(p.split('/').next().unwrap_or(p)).ok())
            .collect()
    }
}

/// The first `CERTIFICATE` PEM block in `pem`.
pub fn first_pem_block(pem: &str) -> anyhow::Result<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN).context("no CERTIFICATE block")?;
    let end = pem[start..]
        .find(END)
        .context("unterminated CERTIFICATE block")?
        + start
        + END.len();
    Ok(format!("{}\n", &pem[start..end]))
}

/// Reads the first certificate in `pem`.
pub fn inspect(pem: &str) -> anyhow::Result<CertInfo> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    let (_, block) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).context("not a PEM certificate")?;
    let cert = block
        .parse_x509()
        .context("not a valid X.509 certificate")?;

    let mut sans = Vec::new();
    let mut permitted = Vec::new();
    let mut is_ca = false;
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => is_ca = bc.ca,
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(d) => sans.push(d.to_string()),
                        GeneralName::IPAddress(bytes) => {
                            if let Some(ip) = ip_from_bytes(bytes) {
                                sans.push(ip.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            ParsedExtension::NameConstraints(nc) => {
                for subtree in nc.permitted_subtrees.iter().flatten() {
                    match &subtree.base {
                        GeneralName::DNSName(d) => permitted.push(d.to_string()),
                        GeneralName::IPAddress(bytes) => {
                            if let Some(text) = cidr_from_bytes(bytes) {
                                permitted.push(text);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();
    Ok(CertInfo {
        subject,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        is_ca,
        sans,
        permitted,
        fingerprint: Sha256::digest(&block.contents)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect(),
    })
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

/// Name-constraint IP subtrees are address + mask; render as CIDR.
fn cidr_from_bytes(bytes: &[u8]) -> Option<String> {
    let half = bytes.len() / 2;
    let ip = ip_from_bytes(&bytes[..half])?;
    let prefix: u32 = bytes[half..].iter().map(|b| b.count_ones()).sum();
    Some(format!("{ip}/{prefix}"))
}

/// Whether `leaf_pem` (first block) was issued by `ca_pem`, by comparing the
/// leaf's issuer with the CA's subject and checking the signature.
pub fn issued_by(leaf_pem: &str, ca_pem: &str) -> bool {
    let parse = |pem: &str| {
        x509_parser::pem::parse_x509_pem(pem.as_bytes())
            .ok()
            .map(|(_, block)| block)
    };
    let (Some(leaf_block), Some(ca_block)) = (parse(leaf_pem), parse(ca_pem)) else {
        return false;
    };
    let (Ok(leaf), Ok(ca)) = (leaf_block.parse_x509(), ca_block.parse_x509()) else {
        return false;
    };
    leaf.issuer() == ca.subject() && leaf.verify_signature(Some(ca.public_key())).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(s: &str) -> Vec<Address> {
        parse_addresses(s).unwrap()
    }

    #[test]
    fn parses_and_dedupes_addresses() {
        let a = addrs("10.0.0.5, arsenal.corp.local\n10.0.0.5 ARSENAL.corp.local.");
        assert_eq!(
            a,
            vec![
                Address::Ip("10.0.0.5".parse().unwrap()),
                Address::Dns("arsenal.corp.local".into())
            ]
        );
        assert!(parse_addresses("").is_err());
        assert!(parse_addresses("10.0.0.300").is_err());
        assert!(parse_addresses("bad_name.local").is_err());
        assert!(parse_addresses("-x.local").is_err());
        assert!(parse_addresses(&"a.b ".repeat(3)).is_ok());
    }

    #[test]
    fn ca_is_a_constrained_ca_and_leaf_is_not() {
        let a = addrs("10.0.0.5 arsenal.corp.local");
        let ca = create_ca(&a).unwrap();
        let ca_info = inspect(&ca.cert_pem).unwrap();
        assert!(ca_info.is_ca);
        assert!(ca_info.subject.starts_with("Abyssal Arsenal Internal CA "));
        assert!(ca_info.subject.len() <= 64);
        assert_eq!(ca_info.permitted, vec!["10.0.0.5/32", "arsenal.corp.local"]);
        assert_eq!(ca_info.permitted_addresses(), a);

        let leaf = issue_server_cert(&ca, &a).unwrap();
        let info = inspect(&leaf.cert_pem).unwrap();
        assert!(!info.is_ca);
        assert_eq!(info.sans, vec!["10.0.0.5", "arsenal.corp.local"]);
        assert!(a.iter().all(|x| info.covers(x)));
        assert!(issued_by(&leaf.cert_pem, &ca.cert_pem));
        // The served chain carries the CA after the leaf.
        assert_eq!(leaf.cert_pem.matches("BEGIN CERTIFICATE").count(), 2);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!((LEAF_DAYS - 1..=LEAF_DAYS).contains(&info.days_left(now)));
    }

    #[test]
    fn refuses_to_issue_outside_the_name_constraints() {
        let ca = create_ca(&addrs("10.0.0.5")).unwrap();
        assert!(issue_server_cert(&ca, &addrs("10.0.0.6")).is_err());
        assert!(issue_server_cert(&ca, &addrs("evil.example.com")).is_err());
    }

    #[test]
    fn every_ca_has_a_unique_subject() {
        let a = addrs("10.0.0.5");
        let one = inspect(&create_ca(&a).unwrap().cert_pem).unwrap();
        let two = inspect(&create_ca(&a).unwrap().cert_pem).unwrap();
        assert_ne!(one.subject, two.subject);
        assert_ne!(one.fingerprint, two.fingerprint);
    }

    #[test]
    fn a_leaf_from_another_ca_is_not_issued_by_this_one() {
        let a = addrs("10.0.0.5");
        let ca1 = create_ca(&a).unwrap();
        let ca2 = create_ca(&a).unwrap();
        let leaf = issue_server_cert(&ca1, &a).unwrap();
        assert!(!issued_by(&leaf.cert_pem, &ca2.cert_pem));
    }

    #[test]
    fn long_fqdns_fit() {
        let host = "abyssal-arsenal-control-plane.datacenter-01.internal.corp.example.com";
        let a = addrs(host);
        let ca = create_ca(&a).unwrap();
        let leaf = issue_server_cert(&ca, &a).unwrap();
        assert!(inspect(&leaf.cert_pem).unwrap().covers(&a[0]));
    }

    /// Cross-check with OpenSSL: the chain verifies and the extensions are
    /// what clients expect. Needs `openssl`; mandatory under CI.
    #[test]
    fn openssl_agrees() {
        use std::process::Command;
        if Command::new("openssl").arg("version").output().is_err() {
            assert!(std::env::var_os("CI").is_none(), "openssl required in CI");
            return;
        }
        let dir = std::env::temp_dir().join(format!("abyssal-internal-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = addrs("10.245.10.25 arsenal.corp.local");
        let ca = create_ca(&a).unwrap();
        let leaf = issue_server_cert(&ca, &a).unwrap();
        std::fs::write(dir.join("ca.pem"), &ca.cert_pem).unwrap();
        std::fs::write(
            dir.join("leaf.pem"),
            first_pem_block(&leaf.cert_pem).unwrap(),
        )
        .unwrap();

        let verify = Command::new("openssl")
            .args(["verify", "-CAfile"])
            .arg(dir.join("ca.pem"))
            .arg(dir.join("leaf.pem"))
            .output()
            .unwrap();
        assert!(
            verify.status.success(),
            "{}",
            String::from_utf8_lossy(&verify.stdout)
        );

        let text = |f: &str| {
            String::from_utf8(
                Command::new("openssl")
                    .args(["x509", "-noout", "-text", "-in"])
                    .arg(dir.join(f))
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap()
        };
        let leaf_text = text("leaf.pem");
        assert!(leaf_text.contains("CA:FALSE"), "{leaf_text}");
        assert!(leaf_text.contains("TLS Web Server Authentication"));
        assert!(leaf_text.contains("IP Address:10.245.10.25"));
        assert!(leaf_text.contains("DNS:arsenal.corp.local"));
        let ca_text = text("ca.pem");
        assert!(ca_text.contains("CA:TRUE, pathlen:0"), "{ca_text}");
        assert!(ca_text.contains("Certificate Sign, CRL Sign"));
        assert!(ca_text.contains("IP:10.245.10.25/255.255.255.255"));

        let fp = Command::new("openssl")
            .args(["x509", "-noout", "-fingerprint", "-sha256", "-in"])
            .arg(dir.join("ca.pem"))
            .output()
            .unwrap();
        let fp = String::from_utf8_lossy(&fp.stdout).replace(':', "");
        assert!(
            fp.trim()
                .ends_with(&inspect(&ca.cert_pem).unwrap().fingerprint)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
