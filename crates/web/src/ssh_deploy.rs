//! "Quick Add Host From Network Scan" (GitHub issue #5): SSH into a
//! Panopticon-discovered device and run the agent's own already-existing
//! non-interactive install (`abyssal-agent install --control-plane-url
//! ... --enrollment-token ...`, see `crates/agent/src/main.rs` -- nothing
//! new needed on the agent side) instead of an admin doing it by hand.
//!
//! Everything here is built against the [`SshClient`]/[`SshSession`]
//! traits, not `russh` directly, so the orchestration logic
//! ([`deploy_one_host`], [`run_deploy_job`]) can be tested against a fake
//! implementation with no real network or SSH server involved -- see this
//! module's own tests. [`RusshClient`] is the one real implementation,
//! used in production.
//!
//! Credentials never touch disk or a log line: [`SshCredentials`]' fields
//! are `zeroize::Zeroizing`, the same primitive already used for exactly
//! this purpose in `crates/web/src/common.rs` and
//! `crates/agent/src/elevation.rs`. The shared [`DeployJob`] state a
//! caller polls for progress only ever holds host identity, state, and
//! (redacted) output -- never a credential.

use std::sync::Arc;
use std::time::Duration;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_database::{DbPool, repo};
use abyssal_hosts::HostConnectionRegistry;
use russh::client::{AuthResult, Handler};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Bounds every SSH TCP connect attempt -- an unreachable target must
/// never hang the whole batch. Mirrors the exact same reasoning
/// `panopticon_snmp.rs::REQUEST_TIMEOUT` already established for SNMP
/// polling.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounds one remote command (download + extract + install can be slow on
/// a poor connection, so this is generous).
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// How long to wait, after the install command reports success, for the
/// agent to actually connect back before giving up and reporting
/// [`DeployFailureReason::NeverCheckedIn`].
pub const CHECKIN_POLL_TIMEOUT: Duration = Duration::from_secs(60);
const CHECKIN_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How many hosts a single deploy job SSHes into at once.
pub const DEFAULT_CONCURRENCY: usize = 5;

// ---------------------------------------------------------------------
// Credentials -- never persisted, never logged, wiped on drop.
// ---------------------------------------------------------------------

pub enum SshAuthMethod {
    Password(Zeroizing<String>),
    PrivateKey {
        /// OpenSSH or PEM-format private key text, exactly as pasted into
        /// the credentials form.
        pem: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

pub struct SshCredentials {
    pub username: String,
    pub auth: SshAuthMethod,
    /// Piped to `sudo -S` on the remote side, never a command-line
    /// argument -- the exact mechanism `crates/agent/src/elevation.rs`
    /// already uses for the agent's own Apotheosis elevation, just
    /// triggered over SSH here instead of the agent's WebSocket. Empty is
    /// valid (an account with passwordless/NOPASSWD sudo).
    pub sudo_password: Zeroizing<String>,
}

// ---------------------------------------------------------------------
// Shell quoting -- SSH's `exec` channel takes one command string the
// remote shell parses; unlike a local `Command::arg()` there's no safe
// argv-passing option. Every value interpolated into a remote command
// goes through this first, on top of (not instead of) validating it.
// ---------------------------------------------------------------------

/// POSIX single-quote escaping: wraps in `'...'`, and any embedded `'`
/// becomes `'\''` (close the quote, an escaped literal quote, reopen).
/// Safe for any input, including empty strings and ones full of shell
/// metacharacters -- the whole point is not having to reason about which
/// characters are "safe" to leave unquoted.
pub fn shell_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// ---------------------------------------------------------------------
// Result / failure types
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<u32>,
}

impl CommandResult {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Every failure mode the issue itself names, plus the handful this
/// implementation can additionally distinguish. `message()` is what a
/// non-expert admin sees on the status page -- specific enough to
/// actually troubleshoot from, per the issue's own requirement.
#[derive(Debug, Clone, PartialEq)]
pub enum DeployFailureReason {
    ConnectionRefused,
    ConnectionTimeout,
    HostUnreachable(String),
    /// The host key doesn't match a previously-trusted one for this IP --
    /// always a hard stop, never silently bypassed.
    HostKeyChanged {
        expected: String,
        actual: String,
    },
    /// First time seeing this IP and the admin never confirmed its
    /// fingerprint (shouldn't normally happen -- the credentials step
    /// always probes and requires confirmation first -- but handled
    /// explicitly rather than assumed impossible).
    HostKeyUnconfirmed,
    AuthenticationFailed,
    SudoDenied,
    UnsupportedArchitecture(String),
    DownloadFailed(String),
    InstallFailed(String),
    /// The install command reported success, but the agent never actually
    /// connected back within `CHECKIN_POLL_TIMEOUT` -- exit code 0 alone
    /// is never treated as "done."
    NeverCheckedIn,
    Other(String),
}

impl DeployFailureReason {
    pub fn message(&self) -> String {
        match self {
            Self::ConnectionRefused => "Connection refused -- is SSH running on this host?".into(),
            Self::ConnectionTimeout => {
                "Connection timed out -- host unreachable or firewalled".into()
            }
            Self::HostUnreachable(detail) => format!("Could not reach host: {detail}"),
            Self::HostKeyChanged { expected, actual } => format!(
                "Host key changed since it was last trusted (expected {expected}, got {actual}) \
                 -- possible man-in-the-middle, or the host was reimaged. Not proceeding \
                 automatically; remove the old trusted key first if this is expected."
            ),
            Self::HostKeyUnconfirmed => {
                "Host key was never confirmed -- re-run the credentials step".into()
            }
            Self::AuthenticationFailed => {
                "SSH authentication failed -- check the username/password/key".into()
            }
            Self::SudoDenied => {
                "sudo denied -- check the sudo password and that this account has sudo privileges"
                    .into()
            }
            Self::UnsupportedArchitecture(arch) => {
                format!("No published agent build for this host's architecture ({arch})")
            }
            Self::DownloadFailed(detail) => {
                format!("Failed to download the agent release: {detail}")
            }
            Self::InstallFailed(detail) => format!("Install command failed: {detail}"),
            Self::NeverCheckedIn => {
                "Install command succeeded, but the agent never connected back -- check the \
                 host's network access to the control plane and `systemctl status abyssal-agent` \
                 on that host"
                    .into()
            }
            Self::Other(detail) => detail.clone(),
        }
    }
}

// ---------------------------------------------------------------------
// SSH abstraction -- the seam tests substitute a fake across.
// ---------------------------------------------------------------------

#[async_trait::async_trait]
pub trait SshSession: Send {
    /// Runs one command. `stdin`, if given, is written then the stream is
    /// closed (so a remote reader like `sudo -S` doesn't block forever
    /// waiting for more input).
    async fn exec(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<CommandResult, DeployFailureReason>;
}

#[async_trait::async_trait]
pub trait SshClient: Send + Sync {
    /// Connects only far enough to read the server's host key -- no
    /// authentication attempted -- and returns its fingerprint. Used by
    /// the credentials step's host-key review, before any real deploy
    /// attempt.
    async fn probe_host_key(&self, ip: &str, port: u16) -> Result<String, DeployFailureReason>;

    /// Connects, requires the presented host key to exactly match
    /// `expected_fingerprint`, authenticates, and returns a session ready
    /// to run commands.
    async fn connect(
        &self,
        ip: &str,
        port: u16,
        expected_fingerprint: &str,
        credentials: &SshCredentials,
    ) -> Result<Box<dyn SshSession>, DeployFailureReason>;
}

// ---------------------------------------------------------------------
// Real implementation
// ---------------------------------------------------------------------

/// Shared between the connecting task and the `Handler` it hands to
/// `russh::client::connect` -- the handler is moved into a background
/// task `connect()` spawns, so this is the only way to read back what it
/// saw.
#[derive(Clone, Default)]
struct HostKeyRecorder {
    seen_fingerprint: Arc<std::sync::Mutex<Option<String>>>,
}

struct FingerprintHandler {
    recorder: HostKeyRecorder,
    /// `None` during a probe (accept whatever's presented, just record
    /// it); `Some(fp)` during a real connect (only accept an exact
    /// match).
    expected: Option<String>,
}

impl Handler for FingerprintHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            return Ok(false);
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        *self
            .recorder
            .seen_fingerprint
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(fingerprint.clone());
        match &self.expected {
            None => Ok(true),
            Some(expected) => Ok(*expected == fingerprint),
        }
    }
}

fn categorize_connect_error(e: &russh::Error) -> DeployFailureReason {
    match e {
        russh::Error::IO(io_err) => match io_err.kind() {
            std::io::ErrorKind::ConnectionRefused => DeployFailureReason::ConnectionRefused,
            std::io::ErrorKind::TimedOut => DeployFailureReason::ConnectionTimeout,
            _ => DeployFailureReason::HostUnreachable(io_err.to_string()),
        },
        other => DeployFailureReason::HostUnreachable(other.to_string()),
    }
}

pub struct RusshClient;

#[async_trait::async_trait]
impl SshClient for RusshClient {
    async fn probe_host_key(&self, ip: &str, port: u16) -> Result<String, DeployFailureReason> {
        let recorder = HostKeyRecorder::default();
        let handler = FingerprintHandler {
            recorder: recorder.clone(),
            expected: None,
        };
        let config = Arc::new(russh::client::Config::default());
        let connect = russh::client::connect(config, (ip, port), handler);
        match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Err(_) => Err(DeployFailureReason::ConnectionTimeout),
            Ok(Err(e)) => Err(categorize_connect_error(&e)),
            Ok(Ok(_handle)) => recorder
                .seen_fingerprint
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .ok_or_else(|| DeployFailureReason::Other("server presented no host key".into())),
        }
    }

    async fn connect(
        &self,
        ip: &str,
        port: u16,
        expected_fingerprint: &str,
        credentials: &SshCredentials,
    ) -> Result<Box<dyn SshSession>, DeployFailureReason> {
        let recorder = HostKeyRecorder::default();
        let handler = FingerprintHandler {
            recorder: recorder.clone(),
            expected: Some(expected_fingerprint.to_string()),
        };
        let config = Arc::new(russh::client::Config::default());
        let connect = russh::client::connect(config, (ip, port), handler);
        let mut session = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Err(_) => return Err(DeployFailureReason::ConnectionTimeout),
            Ok(Err(e)) => {
                let seen = recorder
                    .seen_fingerprint
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                return Err(match seen {
                    Some(actual) if actual != expected_fingerprint => {
                        DeployFailureReason::HostKeyChanged {
                            expected: expected_fingerprint.to_string(),
                            actual,
                        }
                    }
                    _ => categorize_connect_error(&e),
                });
            }
            Ok(Ok(s)) => s,
        };

        let auth_result = match &credentials.auth {
            SshAuthMethod::Password(password) => session
                .authenticate_password(credentials.username.clone(), password.as_str().to_string())
                .await
                .map_err(|e| categorize_connect_error_generic(&e)),
            SshAuthMethod::PrivateKey { pem, passphrase } => {
                let key = PrivateKey::from_openssh(pem.as_bytes()).map_err(|e| {
                    DeployFailureReason::Other(format!("could not parse private key: {e}"))
                })?;
                let key = if key.is_encrypted() {
                    let Some(passphrase) = passphrase else {
                        return Err(DeployFailureReason::Other(
                            "private key is passphrase-protected but no passphrase was given"
                                .into(),
                        ));
                    };
                    key.decrypt(passphrase.as_bytes())
                        .map_err(|_| DeployFailureReason::AuthenticationFailed)?
                } else {
                    key
                };
                session
                    .authenticate_publickey(
                        credentials.username.clone(),
                        PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256)),
                    )
                    .await
                    .map_err(|e| categorize_connect_error_generic(&e))
            }
        }?;

        match auth_result {
            AuthResult::Success => Ok(Box::new(RusshSession {
                session: Arc::new(AsyncMutex::new(session)),
            })),
            AuthResult::Failure { .. } => Err(DeployFailureReason::AuthenticationFailed),
        }
    }
}

fn categorize_connect_error_generic(e: &russh::Error) -> DeployFailureReason {
    categorize_connect_error(e)
}

struct RusshSession {
    session: Arc<AsyncMutex<russh::client::Handle<FingerprintHandler>>>,
}

#[async_trait::async_trait]
impl SshSession for RusshSession {
    async fn exec(
        &mut self,
        command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<CommandResult, DeployFailureReason> {
        let run = async {
            let session = self.session.lock().await;
            let mut channel = session
                .channel_open_session()
                .await
                .map_err(|e| DeployFailureReason::Other(e.to_string()))?;
            channel
                .exec(true, command)
                .await
                .map_err(|e| DeployFailureReason::Other(e.to_string()))?;

            if let Some(data) = stdin {
                channel
                    .data(data)
                    .await
                    .map_err(|e| DeployFailureReason::Other(e.to_string()))?;
            }
            channel
                .eof()
                .await
                .map_err(|e| DeployFailureReason::Other(e.to_string()))?;

            let mut result = CommandResult::default();
            loop {
                let Some(msg) = channel.wait().await else {
                    break;
                };
                match msg {
                    russh::ChannelMsg::Data { data } => {
                        result.stdout.push_str(&String::from_utf8_lossy(&data));
                    }
                    russh::ChannelMsg::ExtendedData { data, .. } => {
                        result.stderr.push_str(&String::from_utf8_lossy(&data));
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        result.exit_code = Some(exit_status);
                    }
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            Ok(result)
        };

        match tokio::time::timeout(COMMAND_TIMEOUT, run).await {
            Ok(result) => result,
            Err(_) => Err(DeployFailureReason::Other(format!(
                "command timed out after {}s",
                COMMAND_TIMEOUT.as_secs()
            ))),
        }
    }
}

// ---------------------------------------------------------------------
// Deploy job -- shared in-memory state a caller polls, mirroring
// `AppState.update_status` (`crates/web/src/state.rs`,
// `update_check.rs`), the one existing precedent for live shared state
// threaded through `AppState`. Never holds a credential.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum HostDeployState {
    Pending,
    Connecting,
    Installing,
    WaitingForCheckin,
    Succeeded,
    Failed(DeployFailureReason),
}

impl HostDeployState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed(_))
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Connecting => "Connecting",
            Self::Installing => "Installing",
            Self::WaitingForCheckin => "Waiting for agent to check in",
            Self::Succeeded => "Succeeded",
            Self::Failed(_) => "Failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostDeployStatus {
    pub ip_address: String,
    pub hostname: Option<String>,
    pub state: HostDeployState,
    /// Redacted remote command output -- never includes anything from
    /// `SshCredentials`, since the credentials themselves are never
    /// placed in a command string or logged (see `deploy_one_host`).
    pub output: String,
}

pub struct DeployJob {
    pub id: Uuid,
    pub hosts: Vec<HostDeployStatus>,
}

impl DeployJob {
    pub fn is_complete(&self) -> bool {
        self.hosts.iter().all(|h| h.state.is_terminal())
    }
}

/// One host to deploy to, plus its own credential override if the admin
/// gave one (falls back to the shared credentials otherwise -- resolved
/// by the caller before this point, so `deploy_one_host` always gets a
/// single concrete `SshCredentials`).
pub struct DeployTarget {
    pub ip_address: String,
    pub hostname: Option<String>,
    pub ssh_port: u16,
    pub credentials: SshCredentials,
}

#[allow(clippy::too_many_arguments)]
async fn deploy_one_host(
    client: &dyn SshClient,
    pool: &DbPool,
    hosts_registry: &HostConnectionRegistry,
    target: &DeployTarget,
    expected_fingerprint: &str,
    control_plane_url: &str,
    enrollment_token: &str,
    agent_version: &str,
) -> (HostDeployState, String) {
    let mut output = String::new();

    let mut session = match client
        .connect(
            &target.ip_address,
            target.ssh_port,
            expected_fingerprint,
            &target.credentials,
        )
        .await
    {
        Ok(s) => s,
        Err(reason) => return (HostDeployState::Failed(reason), output),
    };

    macro_rules! run {
        ($cmd:expr) => {{
            match session.exec($cmd, None).await {
                Ok(result) => result,
                Err(reason) => return (HostDeployState::Failed(reason), output),
            }
        }};
    }

    let arch = run!("uname -m");
    output.push_str(&format!("$ uname -m\n{}\n", arch.stdout.trim()));
    let arch_name = arch.stdout.trim().to_string();
    if arch_name != "x86_64" {
        return (
            HostDeployState::Failed(DeployFailureReason::UnsupportedArchitecture(arch_name)),
            output,
        );
    }

    let asset = format!("abyssal-agent-v{agent_version}-x86_64-unknown-linux-gnu");
    let download_url = format!(
        "https://github.com/AbyssalOath/abyssal-arsenal/releases/download/v{agent_version}/{asset}.tar.gz"
    );
    let download_cmd = format!(
        "curl -fsSL -o /tmp/abyssal-agent-deploy.tar.gz {} && \
         mkdir -p /tmp/abyssal-agent-deploy && \
         tar -xzf /tmp/abyssal-agent-deploy.tar.gz -C /tmp/abyssal-agent-deploy --strip-components=1 && \
         chmod +x /tmp/abyssal-agent-deploy/abyssal-agent",
        shell_quote(&download_url)
    );
    let download = run!(&download_cmd);
    output.push_str(&format!(
        "$ curl ... (download+extract)\n{}{}\n",
        download.stdout, download.stderr
    ));
    if !download.success() {
        return (
            HostDeployState::Failed(DeployFailureReason::DownloadFailed(format!(
                "exit code {:?}: {}",
                download.exit_code,
                download.stderr.trim()
            ))),
            output,
        );
    }

    let host_name = target
        .hostname
        .clone()
        .unwrap_or_else(|| target.ip_address.clone());
    let install_cmd = format!(
        "sudo -S /tmp/abyssal-agent-deploy/abyssal-agent install --control-plane-url {} \
         --enrollment-token {} --name {} ; \
         rm -rf /tmp/abyssal-agent-deploy /tmp/abyssal-agent-deploy.tar.gz",
        shell_quote(control_plane_url),
        shell_quote(enrollment_token),
        shell_quote(&host_name)
    );
    let mut sudo_stdin = Zeroizing::new(String::with_capacity(
        target.credentials.sudo_password.len() + 1,
    ));
    sudo_stdin.push_str(&target.credentials.sudo_password);
    sudo_stdin.push('\n');
    let install = match session
        .exec(&install_cmd, Some(sudo_stdin.as_bytes()))
        .await
    {
        Ok(result) => result,
        Err(reason) => return (HostDeployState::Failed(reason), output),
    };
    drop(sudo_stdin);
    output.push_str(&format!(
        "$ sudo abyssal-agent install ...\n{}{}\n",
        install.stdout, install.stderr
    ));

    let install_stderr_lower = install.stderr.to_lowercase();
    if install_stderr_lower.contains("incorrect password")
        || install_stderr_lower.contains("sorry, try again")
    {
        return (
            HostDeployState::Failed(DeployFailureReason::SudoDenied),
            output,
        );
    }
    if !install.success() {
        return (
            HostDeployState::Failed(DeployFailureReason::InstallFailed(format!(
                "exit code {:?}: {}",
                install.exit_code,
                install.stderr.trim()
            ))),
            output,
        );
    }

    // Confirm real enrollment, not just exit code 0: poll for a host row
    // registered under the name we just told the agent to use, that has
    // actually connected back over its own WebSocket.
    let deadline = tokio::time::Instant::now() + CHECKIN_POLL_TIMEOUT;
    loop {
        if let Ok(hosts) = repo::hosts::list(pool).await
            && let Some(host) = hosts.iter().find(|h| h.name == host_name)
            && hosts_registry.is_connected(host.id)
        {
            return (HostDeployState::Succeeded, output);
        }
        if tokio::time::Instant::now() >= deadline {
            return (
                HostDeployState::Failed(DeployFailureReason::NeverCheckedIn),
                output,
            );
        }
        tokio::time::sleep(CHECKIN_POLL_INTERVAL).await;
    }
}

/// Records one `HostDeployStarted`/`HostDeploySucceeded`/`HostDeployFailed`
/// row, best-effort -- spawned separately from a deploy task's own work
/// (see `run_deploy_job`) so a slow or unreachable audit DB can never
/// delay a deploy's progress or the status page polling it.
async fn record_deploy_audit(
    pool: DbPool,
    action: AuditAction,
    outcome: AuditOutcome,
    ip_address: String,
    actor_user_id: Uuid,
    actor_username: String,
    metadata: Option<serde_json::Value>,
) {
    let mut event = AuditEvent::new(action, outcome)
        .actor(Actor {
            user_id: actor_user_id,
            username: &actor_username,
        })
        .resource(&ip_address);
    if let Some(m) = metadata {
        event = event.metadata(m);
    }
    let _ = abyssal_audit::record(&pool, event).await;
}

/// Runs a deploy across every target in `targets`, at most `concurrency`
/// at once (`tokio::sync::Semaphore`), each in its own task
/// (`tokio::task::JoinSet`) so one host's failure or hang can never block
/// or take down the others. `job` is updated in place as each host
/// progresses -- a caller elsewhere polls the same `Arc<RwLock<...>>` to
/// render a status page. Records `HostDeployStarted`/`HostDeploySucceeded`/
/// `HostDeployFailed` per host, attributed to whoever confirmed the deploy
/// (`actor_user_id`/`actor_username`) -- this is the durable record of what
/// happened; `job` itself is in-memory only and doesn't outlive the process.
#[allow(clippy::too_many_arguments)]
pub async fn run_deploy_job(
    client: Arc<dyn SshClient>,
    pool: DbPool,
    hosts_registry: Arc<HostConnectionRegistry>,
    job: Arc<tokio::sync::RwLock<DeployJob>>,
    // (target, expected host-key fingerprint, this host's own enrollment
    // token). One token per host, not one shared across the job --
    // `host_enrollment_tokens::consume` is single-use, so a token shared
    // across multiple hosts would only ever enroll the first one.
    targets: Vec<(DeployTarget, String, Zeroizing<String>)>,
    control_plane_url: String,
    agent_version: String,
    concurrency: usize,
    actor_user_id: Uuid,
    actor_username: String,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();

    for (target, expected_fingerprint, enrollment_token) in targets {
        {
            let mut job = job.write().await;
            if let Some(status) = job
                .hosts
                .iter_mut()
                .find(|h| h.ip_address == target.ip_address)
            {
                status.state = HostDeployState::Connecting;
            }
        }

        let semaphore = semaphore.clone();
        let client = client.clone();
        let pool = pool.clone();
        let hosts_registry = hosts_registry.clone();
        let job = job.clone();
        let control_plane_url = control_plane_url.clone();
        let agent_version = agent_version.clone();
        let ip_address = target.ip_address.clone();
        let actor_username = actor_username.clone();

        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await;

            // Fire-and-forget: this task's own progress (and the status
            // page polling it) must never wait on an audit write landing --
            // spawned separately rather than awaited inline.
            tokio::spawn(record_deploy_audit(
                pool.clone(),
                AuditAction::HostDeployStarted,
                AuditOutcome::Success,
                ip_address.clone(),
                actor_user_id,
                actor_username.clone(),
                None,
            ));

            let (state, output) = deploy_one_host(
                client.as_ref(),
                &pool,
                hosts_registry.as_ref(),
                &target,
                &expected_fingerprint,
                &control_plane_url,
                &enrollment_token,
                &agent_version,
            )
            .await;
            drop(enrollment_token);

            let (action, outcome, metadata) = match &state {
                HostDeployState::Succeeded => (
                    AuditAction::HostDeploySucceeded,
                    AuditOutcome::Success,
                    None,
                ),
                HostDeployState::Failed(reason) => (
                    AuditAction::HostDeployFailed,
                    AuditOutcome::Failure,
                    Some(serde_json::json!({ "reason": reason.message() })),
                ),
                // Every other state is non-terminal; `deploy_one_host` always
                // returns Succeeded or Failed, never leaves it pending.
                _ => (AuditAction::HostDeployFailed, AuditOutcome::Failure, None),
            };
            tokio::spawn(record_deploy_audit(
                pool.clone(),
                action,
                outcome,
                ip_address.clone(),
                actor_user_id,
                actor_username.clone(),
                metadata,
            ));

            let mut job = job.write().await;
            if let Some(status) = job.hosts.iter_mut().find(|h| h.ip_address == ip_address) {
                status.state = state;
                status.output = output;
            }
        });
    }

    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ---------------------------------------------------------------
    // shell_quote
    // ---------------------------------------------------------------

    #[test]
    fn shell_quote_wraps_plain_values() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_escapes_embedded_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_quote_neutralizes_injection_attempts() {
        let malicious = "; rm -rf / #";
        let quoted = shell_quote(malicious);
        // Everything is inside single quotes -- a shell treats the whole
        // thing as one literal argument, `;` included.
        assert_eq!(quoted, "'; rm -rf / #'");
    }

    #[test]
    fn shell_quote_handles_empty_string() {
        assert_eq!(shell_quote(""), "''");
    }

    // ---------------------------------------------------------------
    // Fake SshClient for orchestration-level tests -- no real network or
    // SSH server involved anywhere below.
    // ---------------------------------------------------------------

    enum FakeStep {
        ConnectError(DeployFailureReason),
        /// One exec response per call, in order; running out returns a
        /// generic success with empty output.
        Exec(Vec<Result<CommandResult, DeployFailureReason>>),
    }

    struct FakeSession {
        responses: std::vec::IntoIter<Result<CommandResult, DeployFailureReason>>,
    }

    #[async_trait::async_trait]
    impl SshSession for FakeSession {
        async fn exec(
            &mut self,
            _command: &str,
            _stdin: Option<&[u8]>,
        ) -> Result<CommandResult, DeployFailureReason> {
            self.responses
                .next()
                .unwrap_or(Ok(CommandResult::default()))
        }
    }

    struct FakeClient {
        hosts: StdMutex<HashMap<String, FakeStep>>,
        probe_fingerprint: String,
        connect_delay: Option<Duration>,
    }

    impl FakeClient {
        fn new() -> Self {
            Self {
                hosts: StdMutex::new(HashMap::new()),
                probe_fingerprint: "SHA256:fake".to_string(),
                connect_delay: None,
            }
        }

        fn with_connect_error(mut self, ip: &str, reason: DeployFailureReason) -> Self {
            self.hosts
                .get_mut()
                .unwrap()
                .insert(ip.to_string(), FakeStep::ConnectError(reason));
            self
        }

        fn with_exec_sequence(
            mut self,
            ip: &str,
            responses: Vec<Result<CommandResult, DeployFailureReason>>,
        ) -> Self {
            self.hosts
                .get_mut()
                .unwrap()
                .insert(ip.to_string(), FakeStep::Exec(responses));
            self
        }
    }

    #[async_trait::async_trait]
    impl SshClient for FakeClient {
        async fn probe_host_key(
            &self,
            _ip: &str,
            _port: u16,
        ) -> Result<String, DeployFailureReason> {
            Ok(self.probe_fingerprint.clone())
        }

        async fn connect(
            &self,
            ip: &str,
            _port: u16,
            _expected_fingerprint: &str,
            _credentials: &SshCredentials,
        ) -> Result<Box<dyn SshSession>, DeployFailureReason> {
            if let Some(delay) = self.connect_delay {
                tokio::time::sleep(delay).await;
            }
            let mut hosts = self.hosts.lock().unwrap();
            match hosts.remove(ip) {
                Some(FakeStep::ConnectError(reason)) => Err(reason),
                Some(FakeStep::Exec(responses)) => Ok(Box::new(FakeSession {
                    responses: responses.into_iter(),
                })),
                None => Ok(Box::new(FakeSession {
                    responses: Vec::new().into_iter(),
                })),
            }
        }
    }

    fn ok_result(stdout: &str) -> Result<CommandResult, DeployFailureReason> {
        Ok(CommandResult {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }

    fn err_result(exit_code: i32, stderr: &str) -> Result<CommandResult, DeployFailureReason> {
        Ok(CommandResult {
            stdout: String::new(),
            stderr: stderr.to_string(),
            exit_code: Some(exit_code as u32),
        })
    }

    fn password_creds() -> SshCredentials {
        SshCredentials {
            username: "admin".to_string(),
            auth: SshAuthMethod::Password(Zeroizing::new("hunter2".to_string())),
            sudo_password: Zeroizing::new("hunter2".to_string()),
        }
    }

    fn target(ip: &str) -> DeployTarget {
        DeployTarget {
            ip_address: ip.to_string(),
            hostname: Some(format!("host-{ip}")),
            ssh_port: 22,
            credentials: password_creds(),
        }
    }

    #[tokio::test]
    async fn connection_refused_is_reported_without_any_exec() {
        let client = FakeClient::new()
            .with_connect_error("10.0.0.1", DeployFailureReason::ConnectionRefused);
        let (state, _) = deploy_one_host_test(&client, "10.0.0.1").await;
        assert_eq!(
            state,
            HostDeployState::Failed(DeployFailureReason::ConnectionRefused)
        );
    }

    #[tokio::test]
    async fn auth_failure_is_reported() {
        let client = FakeClient::new()
            .with_connect_error("10.0.0.2", DeployFailureReason::AuthenticationFailed);
        let (state, _) = deploy_one_host_test(&client, "10.0.0.2").await;
        assert_eq!(
            state,
            HostDeployState::Failed(DeployFailureReason::AuthenticationFailed)
        );
    }

    #[tokio::test]
    async fn host_key_mismatch_is_a_hard_stop() {
        let reason = DeployFailureReason::HostKeyChanged {
            expected: "SHA256:aaa".to_string(),
            actual: "SHA256:bbb".to_string(),
        };
        let client = FakeClient::new().with_connect_error("10.0.0.3", reason.clone());
        let (state, _) = deploy_one_host_test(&client, "10.0.0.3").await;
        assert_eq!(state, HostDeployState::Failed(reason));
    }

    #[tokio::test]
    async fn unsupported_architecture_stops_before_download() {
        let client = FakeClient::new().with_exec_sequence("10.0.0.4", vec![ok_result("aarch64")]);
        let (state, output) = deploy_one_host_test(&client, "10.0.0.4").await;
        assert_eq!(
            state,
            HostDeployState::Failed(DeployFailureReason::UnsupportedArchitecture(
                "aarch64".to_string()
            ))
        );
        assert!(output.contains("aarch64"));
    }

    #[tokio::test]
    async fn download_failure_is_reported() {
        let client = FakeClient::new().with_exec_sequence(
            "10.0.0.5",
            vec![
                ok_result("x86_64"),
                err_result(22, "curl: (22) The requested URL returned error: 404"),
            ],
        );
        let (state, _) = deploy_one_host_test(&client, "10.0.0.5").await;
        assert!(matches!(
            state,
            HostDeployState::Failed(DeployFailureReason::DownloadFailed(_))
        ));
    }

    #[tokio::test]
    async fn sudo_denied_is_distinguished_from_a_generic_install_failure() {
        let client = FakeClient::new().with_exec_sequence(
            "10.0.0.6",
            vec![
                ok_result("x86_64"),
                ok_result("downloaded"),
                err_result(1, "[sudo] password for admin: Sorry, try again.\nsudo: 1 incorrect password attempt"),
            ],
        );
        let (state, _) = deploy_one_host_test(&client, "10.0.0.6").await;
        assert_eq!(
            state,
            HostDeployState::Failed(DeployFailureReason::SudoDenied)
        );
    }

    #[tokio::test]
    async fn generic_install_failure_is_reported() {
        let client = FakeClient::new().with_exec_sequence(
            "10.0.0.7",
            vec![
                ok_result("x86_64"),
                ok_result("downloaded"),
                err_result(1, "enrollment rejected by control plane"),
            ],
        );
        let (state, _) = deploy_one_host_test(&client, "10.0.0.7").await;
        assert!(matches!(
            state,
            HostDeployState::Failed(DeployFailureReason::InstallFailed(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn exit_zero_but_never_checked_in_is_not_treated_as_success() {
        // Install "succeeds" (exit 0) but no matching host ever appears
        // connected -- must not be reported as Succeeded. Paused virtual
        // time so this doesn't cost a real `CHECKIN_POLL_TIMEOUT` (60s) of
        // wall-clock time to run.
        let client = FakeClient::new().with_exec_sequence(
            "10.0.0.8",
            vec![
                ok_result("x86_64"),
                ok_result("downloaded"),
                ok_result("installed"),
            ],
        );
        let pool = unconfigured_pool();
        let hosts_registry = HostConnectionRegistry::new();
        let started = tokio::time::Instant::now();
        let (state, _) = deploy_one_host(
            &client,
            &pool,
            &hosts_registry,
            &target("10.0.0.8"),
            "SHA256:fake",
            "https://cp.example.com",
            "tok",
            "0.1.2",
        )
        .await;
        assert_eq!(
            state,
            HostDeployState::Failed(DeployFailureReason::NeverCheckedIn)
        );
        // Actually waited out the poll window (in virtual time) rather
        // than failing instantly for an unrelated reason.
        assert!(started.elapsed() >= CHECKIN_POLL_TIMEOUT);
    }

    async fn deploy_one_host_test(client: &FakeClient, ip: &str) -> (HostDeployState, String) {
        let pool = unconfigured_pool();
        let hosts_registry = HostConnectionRegistry::new();
        deploy_one_host(
            client,
            &pool,
            &hosts_registry,
            &target(ip),
            "SHA256:fake",
            "https://cp.example.com",
            "tok",
            "0.1.2",
        )
        .await
    }

    /// A `find_by_id`-style DB call is never reached on any failure path
    /// tested here (each fails before or without ever calling
    /// `repo::hosts::list`), so a pool that would panic on first real
    /// use is safe -- same trick `crates/execution/src/executor.rs`'s own
    /// tests already use.
    fn unconfigured_pool() -> DbPool {
        sqlx::mysql::MySqlPoolOptions::new()
            .connect_lazy("mysql://invalid:invalid@127.0.0.1:1/invalid")
            .expect("lazy pool construction never touches the network")
    }

    // ---------------------------------------------------------------
    // Concurrency / timeout: one hanging host must not block the others.
    // ---------------------------------------------------------------

    struct SlowThenFastClient {
        slow_ip: String,
        slow_delay: Duration,
        call_count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SshClient for SlowThenFastClient {
        async fn probe_host_key(
            &self,
            _ip: &str,
            _port: u16,
        ) -> Result<String, DeployFailureReason> {
            Ok("SHA256:fake".to_string())
        }

        async fn connect(
            &self,
            ip: &str,
            _port: u16,
            _expected_fingerprint: &str,
            _credentials: &SshCredentials,
        ) -> Result<Box<dyn SshSession>, DeployFailureReason> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if ip == self.slow_ip {
                tokio::time::sleep(self.slow_delay).await;
            }
            Ok(Box::new(FakeSession {
                responses: vec![
                    ok_result("x86_64"),
                    err_result(1, "stop here, this test only cares about connect timing"),
                ]
                .into_iter(),
            }))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn one_hung_host_does_not_block_the_others() {
        let client = Arc::new(SlowThenFastClient {
            slow_ip: "10.0.1.1".to_string(),
            slow_delay: Duration::from_secs(3600),
            call_count: AtomicUsize::new(0),
        });
        let pool = unconfigured_pool();
        let hosts_registry = Arc::new(HostConnectionRegistry::new());
        let job = Arc::new(tokio::sync::RwLock::new(DeployJob {
            id: Uuid::new_v4(),
            hosts: vec![
                HostDeployStatus {
                    ip_address: "10.0.1.1".to_string(),
                    hostname: None,
                    state: HostDeployState::Pending,
                    output: String::new(),
                },
                HostDeployStatus {
                    ip_address: "10.0.1.2".to_string(),
                    hostname: None,
                    state: HostDeployState::Pending,
                    output: String::new(),
                },
            ],
        }));
        let targets = vec![
            (
                target("10.0.1.1"),
                "SHA256:fake".to_string(),
                Zeroizing::new("tok-1".to_string()),
            ),
            (
                target("10.0.1.2"),
                "SHA256:fake".to_string(),
                Zeroizing::new("tok-2".to_string()),
            ),
        ];

        let job_clone = job.clone();
        let handle = tokio::spawn(run_deploy_job(
            client,
            pool,
            hosts_registry,
            job_clone,
            targets,
            "https://cp.example.com".to_string(),
            "0.1.2".to_string(),
            DEFAULT_CONCURRENCY,
            Uuid::new_v4(),
            "test-admin".to_string(),
        ));

        // Advance virtual time past the fast host's own path but nowhere
        // near the slow host's hour-long sleep, interleaved with repeated
        // yields so any real (non-timer) async work still gets scheduler
        // turns to unwind.
        let mut terminal = false;
        for _ in 0..50 {
            tokio::time::advance(Duration::from_millis(100)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            let snapshot = job.read().await;
            if snapshot
                .hosts
                .iter()
                .find(|h| h.ip_address == "10.0.1.2")
                .is_some_and(|h| h.state.is_terminal())
            {
                terminal = true;
                break;
            }
        }
        assert!(
            terminal,
            "fast host should have finished without waiting on the slow one"
        );

        handle.abort();
    }

    // ---------------------------------------------------------------
    // Real-network check against `RusshClient`, the actual production
    // implementation -- not the fakes above. Ignored by default (no real
    // SSH server in a normal `cargo test` run); exercised manually against
    // the local throwaway `sshd` set up on 127.0.0.1:2222 for this task
    // (key at /tmp/sshd-test/client_key, host key at
    // /tmp/sshd-test/host_key). Run with:
    //   cargo test -p abyssal-web ssh_deploy::tests::real_russh_client_against_local_sshd -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn real_russh_client_against_local_sshd() {
        let client = RusshClient;

        let fingerprint = client
            .probe_host_key("127.0.0.1", 2222)
            .await
            .expect("probe should reach the local test sshd");
        assert!(fingerprint.starts_with("SHA256:"));
        println!("probed fingerprint: {fingerprint}");

        let pem = std::fs::read_to_string("/tmp/sshd-test/client_key")
            .expect("test client key must exist -- see module comment above");
        let credentials = SshCredentials {
            username: "dschwartzad".to_string(),
            auth: SshAuthMethod::PrivateKey {
                pem: Zeroizing::new(pem),
                passphrase: None,
            },
            sudo_password: Zeroizing::new(String::new()),
        };

        let mut session = client
            .connect("127.0.0.1", 2222, &fingerprint, &credentials)
            .await
            .expect("connect+auth against the local test sshd should succeed");

        let result = session
            .exec("echo hello-from-russh && whoami", None)
            .await
            .expect("exec should succeed");
        assert!(result.success());
        assert!(result.stdout.contains("hello-from-russh"));
        assert!(result.stdout.contains("dschwartzad"));
        println!("exec stdout: {}", result.stdout);

        // A wrong expected fingerprint must be rejected, not silently
        // accepted -- the TOFU hard-stop this whole design exists for.
        let mismatch = client
            .connect("127.0.0.1", 2222, "SHA256:not-the-real-one", &credentials)
            .await;
        assert!(matches!(
            mismatch,
            Err(DeployFailureReason::HostKeyChanged { .. })
        ));
    }
}
