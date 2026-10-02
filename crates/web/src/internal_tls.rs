//! The control plane's own internal TLS: the private CA and the server
//! certificate Caddy serves when there's no public domain (`install.sh` →
//! Caddy → blank domain). Everything after the first `install.sh` is managed
//! from here -- `/admin/health/tls` in the UI, the `internal_tls_sweep`
//! background task, and `abyssal-arsenal tls ...` as a break-glass CLI:
//!
//! - **Bootstrap.** `INTERNAL_TLS_ADDRESSES` (written by `install.sh`) seeds
//!   the first CA and server certificate at startup, before the app reports
//!   healthy -- which is what Caddy waits for before it starts.
//! - **Renewal.** The server certificate is re-issued from the same CA when
//!   it's within `RENEW_WITHIN_DAYS` of expiry (or no longer matches the CA's
//!   addresses), and Caddy is told to reload it. No client re-trusts anything:
//!   only the CA is trusted.
//! - **Rotation / changing addresses.** A new CA is created as *pending* and
//!   pushed, alongside the active one, to every connected agent
//!   (`AgentOperation::UpdateTrustedCa`); agents connecting later get it on
//!   connect. Only when the admin activates it does Caddy switch over -- by
//!   which point the agents already trust it. Browsers and GPO-distributed
//!   trust are the admin's to update; the pending CA is downloadable for that.
//!
//! Storage: two Docker volumes, both owned by the app's user. `ca/` (CA cert +
//! key, pending CA) is mounted only into the app; `server/` (server cert +
//! key) is also mounted read-only into Caddy. The CA key never leaves the app
//! container. The CA is name-constrained to the control plane's addresses, so
//! even a leaked key could only vouch for this server.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_hosts::{AgentProtocolStatus, HostConnectionRegistry};
use abyssal_internal_ca::{self as ca, Address, CertInfo, Material};
use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// Agents older than this can't deserialize `UpdateTrustedCa` and would drop
/// their connection if sent it -- never push to them.
const MIN_PUSH_PROTOCOL: u32 = 36;
const PUSH_TIMEOUT: Duration = Duration::from_secs(20);

/// Serializes every change to the stored certificates.
static WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Paths {
    ca_dir: PathBuf,
    server_dir: PathBuf,
}

fn paths() -> Paths {
    let root = std::env::var("INTERNAL_TLS_DIR").unwrap_or_else(|_| "/tls".to_string());
    let root = PathBuf::from(root);
    Paths {
        ca_dir: root.join("ca"),
        server_dir: root.join("server"),
    }
}

fn caddy_socket() -> PathBuf {
    std::env::var("CADDY_ADMIN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/caddy-admin/admin.sock"))
}

fn seed_addresses() -> Option<String> {
    std::env::var("INTERNAL_TLS_ADDRESSES")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

impl Paths {
    fn ca_cert(&self) -> PathBuf {
        self.ca_dir.join("ca.pem")
    }
    fn ca_key(&self) -> PathBuf {
        self.ca_dir.join("ca.key")
    }
    fn pending_cert(&self) -> PathBuf {
        self.ca_dir.join("pending-ca.pem")
    }
    fn pending_key(&self) -> PathBuf {
        self.ca_dir.join("pending-ca.key")
    }
    fn server_cert(&self) -> PathBuf {
        self.server_dir.join("cert.pem")
    }
    fn server_key(&self) -> PathBuf {
        self.server_dir.join("key.pem")
    }
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Write-then-rename so readers (Caddy, a concurrent status call) never see
/// a half-written file. Keys are 0600.
fn write_atomic(path: &Path, contents: &str, secret: bool) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let staged = path.with_extension("tmp");
    std::fs::write(&staged, contents)
        .with_context(|| format!("failed to write {}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if secret { 0o600 } else { 0o644 };
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = secret;
    std::fs::rename(&staged, path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

fn load_pair(cert: &Path, key: &Path) -> Option<Material> {
    Some(Material {
        cert_pem: read(cert)?,
        key_pem: read(key)?,
    })
}

/// Whether this control plane's TLS is ours to manage at all (otherwise
/// it's Let's Encrypt or the operator's own proxy, and nothing here applies).
pub fn is_managed() -> bool {
    paths().ca_cert().exists() || seed_addresses().is_some()
}

/// Everything the UI and the sweep need to know.
pub struct Status {
    pub managed: bool,
    pub ca: Option<CertInfo>,
    pub pending: Option<CertInfo>,
    pub server: Option<CertInfo>,
    /// The CA's addresses (its name constraints) -- the source of truth for
    /// what the server certificate should cover.
    pub addresses: Vec<Address>,
    /// Why the server certificate should be re-issued now, if it should.
    pub renewal_due: Option<String>,
    /// Problems an admin should look at (beyond a routine renewal).
    pub problems: Vec<String>,
}

pub fn status() -> Status {
    let p = paths();
    let managed = is_managed();
    let ca_pem = read(&p.ca_cert());
    let server_pem = read(&p.server_cert());
    let ca = ca_pem.as_deref().and_then(|pem| ca::inspect(pem).ok());
    let pending = read(&p.pending_cert()).and_then(|pem| ca::inspect(&pem).ok());
    let server = server_pem.as_deref().and_then(|pem| ca::inspect(pem).ok());
    let addresses = ca
        .as_ref()
        .map(CertInfo::permitted_addresses)
        .unwrap_or_default();
    let now = Utc::now().timestamp();

    let renewal_due = match (&ca_pem, &server_pem, &server) {
        (None, _, _) => None,
        (Some(_), None, _) | (Some(_), Some(_), None) => {
            Some("there is no valid server certificate yet".to_string())
        }
        (Some(ca_pem), Some(server_pem), Some(server)) => {
            if !ca::issued_by(server_pem, ca_pem) {
                Some("the server certificate wasn't issued by the active CA".to_string())
            } else if !addresses.iter().all(|a| server.covers(a)) {
                Some("the server certificate doesn't cover every CA address".to_string())
            } else if server.days_left(now) < ca::RENEW_WITHIN_DAYS {
                Some(format!(
                    "the server certificate expires in {} days",
                    server.days_left(now).max(0)
                ))
            } else {
                None
            }
        }
    };

    let mut problems = Vec::new();
    if managed && ca.is_none() {
        problems.push(
            "No internal CA exists yet -- it's created at startup from INTERNAL_TLS_ADDRESSES."
                .to_string(),
        );
    }
    if let Some(server) = &server
        && server.days_left(now) < 7
    {
        problems.push(format!(
            "The server certificate expires in {} days and hasn't been renewed -- check the \
                 internal TLS task's last error.",
            server.days_left(now).max(0)
        ));
    }
    if let Some(ca) = &ca {
        let days = ca.days_left(now);
        if days < 180 {
            problems.push(format!(
                "The internal CA expires in {days} days. Rotate it (below) well before then: \
                 every machine has to trust the new one."
            ));
        }
    }
    if let (Some(public_url), false) = (std::env::var("PUBLIC_URL").ok(), addresses.is_empty()) {
        let host = public_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split(['/', ':'])
            .next()
            .unwrap_or_default()
            .to_string();
        if let Ok(address) = Address::parse(&host)
            && !addresses.contains(&address)
        {
            problems.push(format!(
                "PUBLIC_URL ({public_url}) uses {host}, which isn't on the certificate. Links in \
                 emails will show a certificate error; update PUBLIC_URL in .env."
            ));
        }
    }

    Status {
        managed,
        ca,
        pending,
        server,
        addresses,
        renewal_due,
        problems,
    }
}

pub fn active_ca_pem() -> Option<String> {
    read(&paths().ca_cert())
}

pub fn pending_ca_pem() -> Option<String> {
    read(&paths().pending_cert())
}

/// What agents should trust right now: the active CA, plus the pending one
/// during a rotation.
pub fn trust_bundle() -> Option<String> {
    let active = active_ca_pem()?;
    Some(match pending_ca_pem() {
        Some(pending) => format!("{active}{pending}"),
        None => active,
    })
}

/// Startup: creates the CA and first server certificate when
/// `INTERNAL_TLS_ADDRESSES` is set and none exist yet, and renews the
/// server certificate if it's due. Runs before the HTTP listener binds, so a
/// fresh install's Caddy (which waits for the app to be healthy) always finds
/// a certificate to load. Returns a line to log, if anything happened.
pub async fn ensure_at_startup() -> anyhow::Result<Option<String>> {
    if !is_managed() {
        return Ok(None);
    }
    let _guard = WRITE_LOCK.lock().await;
    let p = paths();
    if !p.ca_cert().exists() {
        let seed = seed_addresses().unwrap_or_default();
        let addresses = ca::parse_addresses(&seed)
            .with_context(|| format!("INTERNAL_TLS_ADDRESSES ({seed:?}) is invalid"))?;
        let authority = ca::create_ca(&addresses)?;
        write_atomic(&p.ca_key(), &authority.key_pem, true)?;
        write_atomic(&p.ca_cert(), &authority.cert_pem, false)?;
        let server = ca::issue_server_cert(&authority, &addresses)?;
        write_server(&p, &server)?;
        let fp = ca::inspect(&authority.cert_pem)?.fingerprint;
        return Ok(Some(format!(
            "created the internal CA for {} (SHA-256 {fp}) and its server certificate",
            ca::format_addresses(&addresses)
        )));
    }
    drop(_guard);
    // Caddy may not be up yet on a cold start; it loads the file itself.
    Ok(renew_if_due(false)
        .await?
        .map(|reason| format!("renewed the internal server certificate ({reason})")))
}

fn write_server(p: &Paths, server: &Material) -> anyhow::Result<()> {
    // Key first: a reader that sees the new cert must also find its key.
    // Caddy runs as root, so 0600 owned by the app's user is fine for it.
    write_atomic(&p.server_key(), &server.key_pem, true)?;
    write_atomic(&p.server_cert(), &server.cert_pem, false)
}

/// Re-issues the server certificate if `status().renewal_due`. Returns the
/// reason when it did.
pub async fn renew_if_due(reload: bool) -> anyhow::Result<Option<String>> {
    let Some(reason) = status().renewal_due else {
        return Ok(None);
    };
    renew_server_cert(reload).await?;
    Ok(Some(reason))
}

/// Unconditionally issues a fresh server certificate from the active CA for
/// the CA's addresses, then (optionally) has Caddy load it.
pub async fn renew_server_cert(reload: bool) -> anyhow::Result<CertInfo> {
    let guard = WRITE_LOCK.lock().await;
    let p = paths();
    let authority =
        load_pair(&p.ca_cert(), &p.ca_key()).context("there is no internal CA to issue from")?;
    let addresses = ca::inspect(&authority.cert_pem)?.permitted_addresses();
    let server = ca::issue_server_cert(&authority, &addresses)?;
    write_server(&p, &server)?;
    drop(guard);
    if reload {
        reload_caddy().await?;
    }
    ca::inspect(&server.cert_pem)
}

/// Starts a rotation: a new CA for `addresses`, pending until activated.
/// Replaces any earlier pending CA.
pub async fn begin_rotation(addresses: &[Address]) -> anyhow::Result<CertInfo> {
    let _guard = WRITE_LOCK.lock().await;
    let p = paths();
    if !p.ca_cert().exists() {
        bail!("there is no internal CA to rotate");
    }
    let pending = ca::create_ca(addresses)?;
    write_atomic(&p.pending_key(), &pending.key_pem, true)?;
    write_atomic(&p.pending_cert(), &pending.cert_pem, false)?;
    ca::inspect(&pending.cert_pem)
}

pub async fn cancel_rotation() -> anyhow::Result<()> {
    let _guard = WRITE_LOCK.lock().await;
    let p = paths();
    let _ = std::fs::remove_file(p.pending_cert());
    let _ = std::fs::remove_file(p.pending_key());
    Ok(())
}

/// Makes the pending CA the active one: issues a server certificate from it,
/// has Caddy load it, and archives the old CA certificate (its key is
/// deleted -- nothing should ever be issued from it again).
pub async fn activate_rotation() -> anyhow::Result<CertInfo> {
    let guard = WRITE_LOCK.lock().await;
    let p = paths();
    let pending = load_pair(&p.pending_cert(), &p.pending_key())
        .context("there is no pending CA to activate")?;
    let info = ca::inspect(&pending.cert_pem)?;
    let server = ca::issue_server_cert(&pending, &info.permitted_addresses())?;

    if let Some(old) = read(&p.ca_cert())
        && let Ok(old_info) = ca::inspect(&old)
    {
        let retired = p.ca_dir.join("retired");
        write_atomic(
            &retired.join(format!("{}.pem", old_info.fingerprint)),
            &old,
            false,
        )?;
    }
    write_atomic(&p.ca_key(), &pending.key_pem, true)?;
    write_atomic(&p.ca_cert(), &pending.cert_pem, false)?;
    write_server(&p, &server)?;
    let _ = std::fs::remove_file(p.pending_cert());
    let _ = std::fs::remove_file(p.pending_key());
    drop(guard);
    reload_caddy().await?;
    Ok(info)
}

// --- Automatic renewal ------------------------------------------------------

const SWEEP_INTERVAL_SECS: u64 = 6 * 3600;

/// Every 6 hours: re-issues the server certificate once it's within
/// `RENEW_WITHIN_DAYS` of expiry (or no longer matches the CA) and has Caddy
/// load it. Audited either way; a failure shows on the background-task list
/// and, with self-monitoring on, raises an alert.
pub fn spawn_internal_tls_sweep(state: crate::state::AppState) {
    use crate::task_health::names::INTERNAL_TLS_SWEEP;
    tokio::spawn(async move {
        state
            .task_health
            .register(INTERNAL_TLS_SWEEP, SWEEP_INTERVAL_SECS)
            .await;
        let mut interval = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if !is_managed() {
                state
                    .task_health
                    .ok(INTERNAL_TLS_SWEEP, SWEEP_INTERVAL_SECS)
                    .await;
                continue;
            }
            let (outcome, metadata, beat) = match renew_if_due(true).await {
                Ok(None) => {
                    state
                        .task_health
                        .ok(INTERNAL_TLS_SWEEP, SWEEP_INTERVAL_SECS)
                        .await;
                    continue;
                }
                Ok(Some(reason)) => (
                    abyssal_audit::AuditOutcome::Success,
                    serde_json::json!({ "action": "auto_renew", "reason": reason }),
                    Ok(()),
                ),
                Err(e) => (
                    abyssal_audit::AuditOutcome::Failure,
                    serde_json::json!({ "action": "auto_renew", "error": format!("{e:#}") }),
                    Err(format!("{e:#}")),
                ),
            };
            let event = abyssal_audit::AuditEvent::new(
                abyssal_audit::AuditAction::ConfigurationChanged,
                outcome,
            )
            .resource("control_plane.tls")
            .metadata(metadata);
            if let Err(e) = abyssal_audit::record(&state.pool, event).await {
                tracing::error!(error = %e, "failed to audit internal TLS renewal");
            }
            match beat {
                Ok(()) => {
                    tracing::info!("renewed the internal TLS server certificate");
                    state
                        .task_health
                        .ok(INTERNAL_TLS_SWEEP, SWEEP_INTERVAL_SECS)
                        .await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "internal TLS renewal failed");
                    state
                        .task_health
                        .error(INTERNAL_TLS_SWEEP, SWEEP_INTERVAL_SECS, e)
                        .await;
                }
            }
        }
    });
}

// --- Caddy ---------------------------------------------------------------

/// Makes Caddy load the current certificate files. Caddy never re-reads
/// them on its own, and an ordinary config reload with an unchanged config
/// is a no-op; re-posting the running config with `Cache-Control:
/// must-revalidate` forces it to reprovision, which re-reads manually loaded
/// certificates. Talks to Caddy's admin API over a Unix socket on a volume
/// shared only by the two containers -- the admin API is never on a network.
pub async fn reload_caddy() -> anyhow::Result<()> {
    let socket = caddy_socket();
    let (status, config) = caddy_request(&socket, "GET", "/config/", &[], None)
        .await
        .with_context(|| {
            format!(
                "couldn't reach Caddy's admin socket at {} -- the certificate files are updated, \
                 and Caddy will pick them up on its next restart (`docker compose restart \
                 caddy`). Installs from before web-managed TLS need `./install.sh` re-run once \
                 to enable the socket.",
                socket.display()
            )
        })?;
    if status != 200 {
        bail!("Caddy's admin API answered GET /config/ with HTTP {status}");
    }
    let (status, body) = caddy_request(
        &socket,
        "POST",
        "/load",
        &[
            ("Content-Type", "application/json"),
            ("Cache-Control", "must-revalidate"),
        ],
        Some(&config),
    )
    .await?;
    if status != 200 {
        bail!(
            "Caddy refused to reload (HTTP {status}): {}",
            String::from_utf8_lossy(&body).trim()
        );
    }
    Ok(())
}

/// Minimal HTTP/1.0 over a Unix socket: one request, read to EOF. HTTP/1.0
/// keeps Go's server from using chunked encoding or keep-alive, so there's
/// nothing to decode beyond the status line.
async fn caddy_request(
    socket: &Path,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> anyhow::Result<(u16, Vec<u8>)> {
    #[cfg(unix)]
    {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::UnixStream::connect(socket),
        )
        .await
        .context("timed out connecting")??;
        let body = body.unwrap_or_default();
        let mut request = format!("{method} {path} HTTP/1.0\r\nHost: \r\n");
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(body).await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut response))
            .await
            .context("timed out waiting for Caddy")??;
        parse_http_response(&response)
    }
    #[cfg(not(unix))]
    {
        let _ = (socket, method, path, headers, body);
        bail!("Caddy's admin socket is only supported on Unix")
    }
}

fn parse_http_response(response: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response from Caddy")?;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .context("malformed HTTP status line from Caddy")?;
    Ok((status, response[split + 4..].to_vec()))
}

// --- Agents ----------------------------------------------------------------

/// The last trust push to one host.
#[derive(Clone)]
pub struct HostPush {
    /// Fingerprints of the bundle that was pushed.
    pub fingerprints: Vec<String>,
    /// `updated` / `unchanged` (agent trusts it), `unmanaged` (agent trusts
    /// the OS store, not a pushed file), `too-old`, or `failed`.
    pub status: String,
    pub detail: String,
    pub at: DateTime<Utc>,
}

impl HostPush {
    /// Whether this host is known to trust `fingerprint`.
    pub fn trusts(&self, fingerprint: &str) -> bool {
        matches!(self.status.as_str(), "updated" | "unchanged")
            && self.fingerprints.iter().any(|f| f == fingerprint)
    }
}

static PUSHES: Mutex<Option<HashMap<Uuid, HostPush>>> = Mutex::new(None);

pub fn host_push(host_id: Uuid) -> Option<HostPush> {
    PUSHES
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&host_id).cloned())
}

fn record_push(host_id: Uuid, push: HostPush) {
    PUSHES
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(host_id, push);
}

/// Sends the current trust bundle to one connected host and records how it
/// went. Called on every agent connect and from "push now".
pub async fn push_to_host(hosts: &HostConnectionRegistry, host_id: Uuid) -> HostPush {
    let Some(bundle) = trust_bundle() else {
        return HostPush {
            fingerprints: Vec::new(),
            status: "failed".to_string(),
            detail: "no internal CA".to_string(),
            at: Utc::now(),
        };
    };
    let fingerprints = bundle_fingerprints(&bundle);
    let push = |status: &str, detail: String| HostPush {
        fingerprints: fingerprints.clone(),
        status: status.to_string(),
        detail,
        at: Utc::now(),
    };

    let result = match hosts.agent_protocol_status(host_id) {
        AgentProtocolStatus::Version(v) if v >= MIN_PUSH_PROTOCOL => {
            match hosts
                .dispatch(
                    host_id,
                    AgentOperation::UpdateTrustedCa { bundle_pem: bundle },
                    PUSH_TIMEOUT,
                )
                .await
            {
                Ok(CommandOutcome::Ok(output)) => {
                    let status = serde_json::from_str::<serde_json::Value>(&output.stdout)
                        .ok()
                        .and_then(|v| v["status"].as_str().map(str::to_string))
                        .unwrap_or_else(|| "failed".to_string());
                    let detail = match status.as_str() {
                        "unmanaged" => "agent trusts the OS certificate store (installed without \
                                        --ca-cert); update that store (e.g. GPO) instead"
                            .to_string(),
                        _ => String::new(),
                    };
                    push(&status, detail)
                }
                Ok(CommandOutcome::Err(e)) => push("failed", e),
                Err(e) => push("failed", e.to_string()),
            }
        }
        AgentProtocolStatus::NotConnected => push("failed", "not connected".to_string()),
        _ => push(
            "too-old",
            "agent predates CA updates -- use 'Update agent' on /admin/hosts".to_string(),
        ),
    };
    record_push(host_id, result.clone());
    result
}

/// Pushes to every connected host concurrently.
pub async fn push_to_all(hosts: &std::sync::Arc<HostConnectionRegistry>) -> Vec<(Uuid, HostPush)> {
    let mut tasks = tokio::task::JoinSet::new();
    for id in hosts.connected_ids() {
        let hosts = hosts.clone();
        tasks.spawn(async move { (id, push_to_host(&hosts, id).await) });
    }
    let mut out = Vec::new();
    while let Some(Ok(result)) = tasks.join_next().await {
        out.push(result);
    }
    out
}

fn bundle_fingerprints(bundle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = bundle;
    while let Ok(block) = ca::first_pem_block(rest) {
        if let Ok(info) = ca::inspect(&block) {
            out.push(info.fingerprint);
        }
        let Some(pos) = rest.find("-----END CERTIFICATE-----") else {
            break;
        };
        rest = &rest[pos + "-----END CERTIFICATE-----".len()..];
    }
    out
}

/// `AB:CD:...` for display.
pub fn grouped(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_caddy_responses() {
        let (status, body) =
            parse_http_response(b"HTTP/1.0 200 OK\r\nContent-Type: x\r\n\r\n{\"a\":1}").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"a\":1}");
        assert!(parse_http_response(b"garbage").is_err());
    }

    #[test]
    fn bundle_fingerprints_cover_every_certificate() {
        let a = ca::parse_addresses("10.0.0.5").unwrap();
        let one = ca::create_ca(&a).unwrap().cert_pem;
        let two = ca::create_ca(&a).unwrap().cert_pem;
        let fps = bundle_fingerprints(&format!("{one}{two}"));
        assert_eq!(
            fps,
            vec![
                ca::inspect(&one).unwrap().fingerprint,
                ca::inspect(&two).unwrap().fingerprint
            ]
        );
    }

    /// The whole lifecycle against a temp directory: bootstrap, renewal
    /// decisions, rotation, activation (Caddy reload is expected to fail --
    /// there's no socket -- after the files are already in place).
    #[tokio::test]
    async fn lifecycle() {
        let dir = std::env::temp_dir().join(format!("abyssal-internal-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: this is the only test in the crate touching these variables.
        unsafe {
            std::env::set_var("INTERNAL_TLS_DIR", &dir);
            std::env::set_var("INTERNAL_TLS_ADDRESSES", "10.0.0.5, arsenal.corp.local");
            std::env::set_var("CADDY_ADMIN_SOCKET", dir.join("no-such.sock"));
            std::env::remove_var("PUBLIC_URL");
        }

        assert!(ensure_at_startup().await.unwrap().is_some());
        let s = status();
        assert!(
            s.managed && s.renewal_due.is_none() && s.problems.is_empty(),
            "{:?}",
            s.problems
        );
        assert_eq!(s.addresses.len(), 2);
        let first_server = s.server.unwrap().fingerprint;
        let active = s.ca.unwrap().fingerprint;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode =
                |f: &str| std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode("ca/ca.key"), 0o600);
            assert_eq!(mode("server/key.pem"), 0o600);
        }

        // A second start changes nothing.
        assert!(ensure_at_startup().await.unwrap().is_none());

        // Manual renewal: new server cert, same CA.
        renew_server_cert(false).await.unwrap();
        let s = status();
        assert_ne!(s.server.unwrap().fingerprint, first_server);
        assert_eq!(s.ca.unwrap().fingerprint, active);

        // A server cert from some other CA is due for renewal.
        let stranger = ca::create_ca(&s.addresses).unwrap();
        let foreign = ca::issue_server_cert(&stranger, &s.addresses).unwrap();
        std::fs::write(dir.join("server/cert.pem"), &foreign.cert_pem).unwrap();
        assert!(status().renewal_due.is_some());
        assert!(renew_if_due(false).await.unwrap().is_some());
        assert!(status().renewal_due.is_none());

        // Rotation to a different address set.
        let new_addresses = ca::parse_addresses("10.0.0.9").unwrap();
        let pending = begin_rotation(&new_addresses).await.unwrap();
        let bundle = trust_bundle().unwrap();
        assert_eq!(
            bundle_fingerprints(&bundle),
            vec![active.clone(), pending.fingerprint.clone()]
        );
        let err = activate_rotation().await.unwrap_err();
        assert!(format!("{err:#}").contains("admin socket"), "{err:#}");
        let s = status();
        assert_eq!(s.ca.unwrap().fingerprint, pending.fingerprint);
        assert!(s.pending.is_none());
        assert_eq!(s.addresses, new_addresses);
        assert!(s.renewal_due.is_none());
        assert!(dir.join(format!("ca/retired/{active}.pem")).exists());
        assert_eq!(
            bundle_fingerprints(&trust_bundle().unwrap()),
            vec![pending.fingerprint]
        );

        // Cancelling a rotation leaves the active CA alone.
        begin_rotation(&new_addresses).await.unwrap();
        cancel_rotation().await.unwrap();
        assert!(status().pending.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
