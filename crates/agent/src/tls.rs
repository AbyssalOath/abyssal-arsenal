//! The agent's TLS trust configuration for talking to its control plane:
//! the enrollment POST and the control-plane WebSocket (and every reconnect
//! of it) share one `rustls::ClientConfig` built here, so they can never
//! disagree about what's trusted. Self-update downloads go to GitHub, not the
//! control plane, and deliberately use the OS roots only (`Trust::os_only`):
//! a CA that exists to vouch for the control plane has no business vouching
//! for anything else.
//!
//! Trust = the host OS's native root store, plus (optionally) one CA
//! certificate the operator explicitly handed over with `--ca-cert` -- the
//! internal CA `install.sh` generates for a control plane with no public
//! domain. Nothing is ever trusted implicitly: there is no "accept any
//! certificate" mode, and the extra CA is never auto-discovered from disk
//! (a file planted next to the credentials by a less-privileged user must not
//! become a root of trust for a SYSTEM/root service). Verification itself is
//! stock rustls/webpki -- chain, validity, name, and the CA's name
//! constraints all still apply.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Trust {
    config: Arc<rustls::ClientConfig>,
}

impl Trust {
    /// Native roots, plus every certificate in `extra_ca` if given.
    pub fn load(extra_ca: Option<&Path>) -> anyhow::Result<Self> {
        let extra = match extra_ca {
            Some(path) => read_ca_file(path)?,
            None => Vec::new(),
        };
        Self::from_parts(load_native_roots(), extra)
    }

    /// The OS trust store alone -- for connections that aren't to the
    /// control plane.
    pub fn os_only() -> anyhow::Result<Self> {
        Self::from_parts(load_native_roots(), Vec::new())
    }

    /// Builds from explicit parts -- `load` minus the filesystem, so tests
    /// can pin the trust set to exactly one CA.
    pub fn from_parts(
        native: Vec<CertificateDer<'static>>,
        extra: Vec<CertificateDer<'static>>,
    ) -> anyhow::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        // A distro bundle routinely carries a few certs webpki can't parse;
        // skipping those is what reqwest's own native-roots mode does too.
        roots.add_parsable_certificates(native);
        for cert in extra {
            roots
                .add(cert)
                .context("the --ca-cert certificate isn't usable as a trust anchor")?;
        }
        if roots.is_empty() {
            bail!(
                "no trusted root certificates available: the OS trust store is empty or \
                 unreadable and no --ca-cert was given"
            );
        }

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn rustls_config(&self) -> Arc<rustls::ClientConfig> {
        self.config.clone()
    }

    /// A reqwest client using exactly this trust configuration.
    pub fn http_client(&self, builder: reqwest::ClientBuilder) -> anyhow::Result<reqwest::Client> {
        builder
            .use_preconfigured_tls((*self.config).clone())
            .build()
            .context("failed to build the HTTPS client")
    }
}

/// What `run` was started with: the trust in force, and the `--ca-cert`
/// file it came from (the file `UpdateTrustedCa` rewrites). Swappable, so a
/// pushed bundle applies from the next reconnect without a restart.
struct ProcessTrust {
    trust: Trust,
    ca_path: Option<PathBuf>,
}

static PROCESS_TRUST: RwLock<Option<ProcessTrust>> = RwLock::new(None);

pub fn set_process_trust(trust: Trust, ca_path: Option<PathBuf>) {
    *PROCESS_TRUST.write().unwrap() = Some(ProcessTrust { trust, ca_path });
}

/// The trust to use for the next connection to the control plane.
pub fn current_trust() -> Option<Trust> {
    PROCESS_TRUST
        .read()
        .unwrap()
        .as_ref()
        .map(|p| p.trust.clone())
}

/// Result of an `UpdateTrustedCa` push, reported back as JSON on stdout.
#[derive(serde::Serialize)]
pub struct TrustUpdate {
    /// `updated`, `unchanged`, or `unmanaged` (no `--ca-cert`: trust comes
    /// from the OS store and isn't the control plane's to change).
    pub status: &'static str,
    pub fingerprints: Vec<String>,
}

/// Replaces the `--ca-cert` file with `bundle_pem` and swaps it into the
/// in-memory trust. Atomic (write a sibling, then rename) so a crash can't
/// leave a half-written trust file the service then can't start with.
pub fn update_trusted_ca(bundle_pem: &str) -> anyhow::Result<TrustUpdate> {
    if !abyssal_agent_protocol::is_valid_ca_bundle(bundle_pem) {
        bail!("refusing a CA bundle that isn't 1-4 PEM certificates and nothing else");
    }
    let certs = parse_ca_pem(bundle_pem.as_bytes())?;
    let fingerprints: Vec<String> = certs.iter().map(fingerprint).collect();
    // Prove it builds a usable trust store before touching anything.
    let trust = Trust::from_parts(load_native_roots(), certs)?;

    let Some(path) = PROCESS_TRUST
        .read()
        .unwrap()
        .as_ref()
        .and_then(|p| p.ca_path.clone())
    else {
        return Ok(TrustUpdate {
            status: "unmanaged",
            fingerprints,
        });
    };

    let current = std::fs::read(&path).ok();
    if current.as_deref() == Some(bundle_pem.as_bytes()) {
        return Ok(TrustUpdate {
            status: "unchanged",
            fingerprints,
        });
    }

    let staged = path.with_extension("pem.new");
    std::fs::write(&staged, bundle_pem)
        .with_context(|| format!("failed to write {}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(windows)]
    crate::winservice::harden_binary_acls(&staged)?;
    std::fs::rename(&staged, &path)
        .with_context(|| format!("failed to replace {}", path.display()))?;

    set_process_trust(trust, Some(path));
    tracing::info!(?fingerprints, "control plane updated the trusted CA bundle");
    Ok(TrustUpdate {
        status: "updated",
        fingerprints,
    })
}

fn load_native_roots() -> Vec<CertificateDer<'static>> {
    let result = rustls_native_certs::load_native_certs();
    for e in &result.errors {
        tracing::debug!(error = %e, "skipping unreadable OS root certificate");
    }
    result.certs
}

/// Reads a PEM file of one or more CA certificates. Refuses a file that also
/// carries a private key: that's a sign the wrong file was copied (e.g. the
/// CA's `ca.key`), and it shouldn't sit on every managed host.
pub fn read_ca_file(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("could not read CA certificate {}", path.display()))?;
    parse_ca_pem(&bytes).with_context(|| format!("invalid CA certificate file {}", path.display()))
}

pub fn parse_ca_pem(bytes: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    if String::from_utf8_lossy(bytes).contains("PRIVATE KEY") {
        bail!("the file contains a private key -- pass the public CA certificate (ca.pem) only");
    }
    let certs = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("not valid PEM: {e:?}"))?;
    if certs.is_empty() {
        bail!("no PEM CERTIFICATE block found");
    }
    Ok(certs)
}

/// SHA-256 over the DER encoding, upper-case hex, no separators -- the
/// format the control plane's UI shows and the bootstrap scripts compare.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    Sha256::digest(cert.as_ref())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Accepts the forms an admin is likely to paste (`AB:CD:...`, lower case,
/// spaces) and returns the canonical one, or `None` if it isn't 32 bytes of
/// hex.
pub fn normalize_fingerprint(input: &str) -> Option<String> {
    let hex: String = input
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-'))
        .collect::<String>()
        .to_ascii_uppercase();
    (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())).then_some(hex)
}

/// The first certificate in the file is the CA being pinned.
pub fn verify_fingerprint(
    certs: &[CertificateDer<'_>],
    expected: &str,
) -> Result<(), FingerprintMismatch> {
    let actual = certs.first().map(fingerprint).unwrap_or_default();
    match normalize_fingerprint(expected) {
        Some(expected) if expected == actual => Ok(()),
        _ => Err(FingerprintMismatch {
            expected: expected.to_string(),
            actual,
        }),
    }
}

#[derive(Debug)]
pub struct FingerprintMismatch {
    pub expected: String,
    pub actual: String,
}

impl std::fmt::Display for FingerprintMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CA certificate fingerprint mismatch: expected {}, got {} -- refusing to trust it",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for FingerprintMismatch {}

/// What went wrong, coarsely enough to give an operator (or an RMM tool's
/// exit-code column) one actionable answer. The numeric codes are a stable
/// interface shared with the served `install.ps1` / `install.sh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Other,
    BadArguments,
    NotElevated,
    CaProofInvalid,
    TlsUntrusted,
    TlsCaUsedAsEndEntity,
    TlsNameMismatch,
    TlsCertificate,
    CaFingerprintMismatch,
    TokenRejected,
    NameConflict,
    Unreachable,
    ServiceSetup,
}

impl Failure {
    pub fn exit_code(self) -> i32 {
        match self {
            Failure::Other => 1,
            Failure::BadArguments => 2,
            Failure::NotElevated => 3,
            Failure::CaProofInvalid => 14,
            Failure::TlsUntrusted => 10,
            Failure::TlsCaUsedAsEndEntity => 11,
            Failure::TlsNameMismatch => 12,
            Failure::TlsCertificate => 13,
            Failure::CaFingerprintMismatch => 14,
            Failure::TokenRejected => 20,
            Failure::NameConflict => 21,
            Failure::Unreachable => 30,
            Failure::ServiceSetup => 40,
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Failure::Other => "",
            Failure::BadArguments => {
                "Check the command line: an unattended install needs SERVER= (or \
                 --control-plane-url) and AAT= (or --aat / --enrollment-token)."
            }
            Failure::NotElevated => {
                "Run it elevated: as Administrator or SYSTEM on Windows (PDQ, Intune and GPO \
                 startup scripts already are), with sudo or as root on Linux."
            }
            Failure::CaProofInvalid => {
                "The control plane couldn't prove its certificate with this install token \
                 (AAT). Either the AAT is wrong or was rotated -- copy the current one from \
                 /admin/hosts -- or something between this host and SERVER is intercepting \
                 traffic."
            }
            Failure::TlsUntrusted => {
                "The control plane's certificate isn't trusted on this host. For an internal \
                 (self-signed) control plane, use the one-liner from /admin/hosts -- it fetches \
                 and verifies the CA and passes --ca-cert -- or pass --ca-cert <ca.pem> yourself."
            }
            Failure::TlsCaUsedAsEndEntity => {
                "The control plane is serving a CA certificate as its server certificate (the \
                 old install.sh self-signed cert). Re-run ./install.sh on the control plane to \
                 replace it with a CA-issued server certificate, then re-trust the new CA."
            }
            Failure::TlsNameMismatch => {
                "The control plane's certificate doesn't cover the address in \
                 --control-plane-url. Use exactly the IP or hostname the certificate was \
                 generated for (the PUBLIC_URL in the control plane's .env)."
            }
            Failure::TlsCertificate => {
                "The control plane's certificate was rejected (expired, not yet valid, or \
                 otherwise unusable). Check this host's clock, then check the certificate at \
                 /admin/health/tls on the control plane (renewal there is automatic)."
            }
            Failure::CaFingerprintMismatch => {
                "The CA certificate doesn't match the fingerprint from /admin/hosts. Something \
                 between this host and the control plane may be intercepting traffic, or the \
                 control plane's CA was regenerated -- copy a fresh command from /admin/hosts."
            }
            Failure::TokenRejected => {
                "The enrollment token is invalid, expired (single-use tokens last 15 minutes), \
                 already used, or revoked -- or the install token (AAT) was rotated. Get a \
                 current one from /admin/hosts."
            }
            Failure::NameConflict => {
                "A host with this name is already enrolled (with the install token, even an \
                 offline one counts). Remove it from /admin/hosts, or pass --name (NAME=) with \
                 a different one."
            }
            Failure::Unreachable => {
                "Could not reach the control plane. Check the URL, DNS, and that port 443 \
                 (or the URL's port) is reachable from this host."
            }
            Failure::ServiceSetup => {
                "Enrollment succeeded but registering or starting the service failed. Re-run \
                 the same command (already-enrolled hosts skip enrollment)."
            }
        }
    }
}

/// Context marker attached to service-manager failures in `install`, so
/// `classify` can tell them apart from everything else.
#[derive(Debug)]
pub struct ServiceSetupFailed;

impl std::fmt::Display for ServiceSetupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed to register or start the agent service")
    }
}

/// Marker errors for the failures `install`/`uninstall` detect themselves,
/// rather than from a TLS or HTTP error.
#[derive(Debug)]
pub enum InstallError {
    /// A required value is missing and prompting isn't allowed.
    BadArguments(String),
    NotElevated(String),
    /// The AAT proof over the control plane's CA didn't verify.
    CaProofInvalid,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::BadArguments(msg) | InstallError::NotElevated(msg) => f.write_str(msg),
            InstallError::CaProofInvalid => f.write_str(
                "the control plane's CA certificate couldn't be verified with the install \
                 token (AAT) -- refusing to trust it",
            ),
        }
    }
}

impl std::error::Error for InstallError {}

pub fn classify(err: &anyhow::Error) -> Failure {
    if err.downcast_ref::<ServiceSetupFailed>().is_some() {
        return Failure::ServiceSetup;
    }
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<InstallError>() {
            return match e {
                InstallError::BadArguments(_) => Failure::BadArguments,
                InstallError::NotElevated(_) => Failure::NotElevated,
                InstallError::CaProofInvalid => Failure::CaProofInvalid,
            };
        }
        if cause.downcast_ref::<FingerprintMismatch>().is_some() {
            return Failure::CaFingerprintMismatch;
        }
        if let Some(rejected) = cause.downcast_ref::<crate::enroll::EnrollRejected>() {
            return match rejected.status {
                401 | 403 => Failure::TokenRejected,
                409 => Failure::NameConflict,
                _ => Failure::Other,
            };
        }
        if let Some(e) = find_rustls_error(cause) {
            return classify_rustls(e);
        }
    }
    // rustls errors don't always survive as a typed source (some layers
    // stringify them), so fall back to the rendered chain.
    let rendered = format!("{err:#}");
    if rendered.contains("CaUsedAsEndEntity") {
        return Failure::TlsCaUsedAsEndEntity;
    }
    if rendered.contains("UnknownIssuer") {
        return Failure::TlsUntrusted;
    }
    if rendered.contains("NotValidForName") {
        return Failure::TlsNameMismatch;
    }
    if rendered.contains("invalid peer certificate") {
        return Failure::TlsCertificate;
    }
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<reqwest::Error>()
            && (e.is_connect() || e.is_timeout())
        {
            return Failure::Unreachable;
        }
        if let Some(e) = cause.downcast_ref::<std::io::Error>()
            && matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::NetworkUnreachable
            )
        {
            return Failure::Unreachable;
        }
    }
    Failure::Other
}

fn find_rustls_error<'a>(
    cause: &'a (dyn std::error::Error + 'static),
) -> Option<&'a rustls::Error> {
    if let Some(e) = cause.downcast_ref::<rustls::Error>() {
        return Some(e);
    }
    // tokio-rustls surfaces handshake failures as an io::Error wrapping the
    // rustls::Error, which hyper's connector wraps in another io::Error;
    // io::Error::source() skips the wrapped value, so unwrap by hand.
    let mut current = cause;
    while let Some(inner) = current
        .downcast_ref::<std::io::Error>()
        .and_then(|io| io.get_ref())
    {
        if let Some(e) = inner.downcast_ref::<rustls::Error>() {
            return Some(e);
        }
        current = inner;
    }
    None
}

fn classify_rustls(e: &rustls::Error) -> Failure {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(C::UnknownIssuer) => Failure::TlsUntrusted,
        rustls::Error::InvalidCertificate(
            C::NotValidForName | C::NotValidForNameContext { .. },
        ) => Failure::TlsNameMismatch,
        rustls::Error::InvalidCertificate(C::Other(other))
            if format!("{other:?}").contains("CaUsedAsEndEntity") =>
        {
            Failure::TlsCaUsedAsEndEntity
        }
        rustls::Error::InvalidCertificate(_) => Failure::TlsCertificate,
        _ => Failure::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_pasted_fingerprints() {
        let canonical = "AB".repeat(32);
        assert_eq!(
            normalize_fingerprint(&"ab:".repeat(32)[..95]),
            Some(canonical.clone())
        );
        assert_eq!(normalize_fingerprint(&canonical), Some(canonical));
        assert_eq!(normalize_fingerprint("ABCD"), None);
        assert_eq!(normalize_fingerprint(&"ZZ".repeat(32)), None);
    }

    #[test]
    fn refuses_a_file_with_a_private_key() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(parse_ca_pem(pem).is_err());
    }

    #[test]
    fn refuses_a_file_with_no_certificate() {
        assert!(parse_ca_pem(b"hello").is_err());
    }

    #[test]
    fn classifies_typed_rustls_errors() {
        let io = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        let err = anyhow::Error::new(io).context("error sending request");
        assert_eq!(classify(&err), Failure::TlsUntrusted);
    }

    #[test]
    fn classifies_the_reported_ca_used_as_end_entity_message() {
        // The exact text from the failing Windows 11 enrollment.
        let err = anyhow::anyhow!(
            "error sending request for url (https://10.245.10.25/api/hosts/enroll): client error \
             (Connect): invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))"
        );
        assert_eq!(classify(&err), Failure::TlsCaUsedAsEndEntity);
        assert_eq!(Failure::TlsCaUsedAsEndEntity.exit_code(), 11);
    }

    #[test]
    fn classifies_service_setup_failures() {
        let err = anyhow::anyhow!("sc.exe failed").context(ServiceSetupFailed);
        assert_eq!(classify(&err), Failure::ServiceSetup);
    }
}
