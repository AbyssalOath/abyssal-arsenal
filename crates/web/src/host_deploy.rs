//! The transport-neutral half of pushing the agent to a host: the job a
//! status page polls, running hosts in parallel, waiting for the agent to
//! check in, and the per-host audit trail. Split out of `ssh_deploy.rs`
//! (Linux over SSH) so Windows over SSH and over WinRM can share it; see
//! `docs/roadmap/windows-push-deploy.md` (M2). Each transport supplies one
//! future per host that does the on-host work and returns a
//! [`DeployOutcome`]; [`run_job`] does the rest.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_database::{DbPool, repo};
use abyssal_hosts::HostConnectionRegistry;
use tokio::sync::RwLock;
use uuid::Uuid;

/// How long to wait, after the install command reports success, for the
/// agent to actually connect back before giving up and reporting
/// [`DeployFailureReason::NeverCheckedIn`]. Generous on purpose: the
/// agent's own reconnect loop (`crates/agent/src/main.rs`) backs off
/// 1s/2s/4s/8s/16s/32s/60s/... after a failed connection attempt, so a
/// rough first attempt (DNS not quite ready yet, a brief network hiccup
/// right after the service starts) can genuinely take over a minute to
/// recover from before the *next* retry even fires -- a shorter timeout
/// here risks reporting `NeverCheckedIn` for a host that was actually
/// about to connect fine on its own.
pub const CHECKIN_POLL_TIMEOUT: Duration = Duration::from_secs(150);
const CHECKIN_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// How many hosts a single deploy job works on at once.
pub const DEFAULT_CONCURRENCY: usize = 5;

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

/// Where in a deploy a host failed, shown beside the reason on the status
/// page and recorded in the audit trail. Not every transport has every
/// stage: Linux over SSH has no separate verify step (its download is
/// pinned to the control plane's CA), and SSH connects and authenticates in
/// one step, so the reason decides which of those two it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployStage {
    Connect,
    Authenticate,
    Preflight,
    Download,
    Verify,
    Install,
    CheckIn,
}

impl DeployStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Authenticate => "authenticate",
            Self::Preflight => "preflight",
            Self::Download => "download",
            Self::Verify => "verify",
            Self::Install => "install",
            Self::CheckIn => "check-in",
        }
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
    /// Windows: the installer couldn't be copied to the host over SFTP.
    UploadFailed(String),
    /// Windows: the account isn't a local administrator, which installing
    /// an MSI needs.
    NotAdministrator,
    /// Windows: `%ProgramData%\Abyssal` exists but isn't locked down to
    /// SYSTEM and Administrators -- another user may have created it.
    StagingFolderUnsafe(String),
    /// Windows: the installer on the host isn't what the control plane sent
    /// (hash), or isn't signed by the configured signer.
    VerifyFailed(String),
    /// Windows: another installation kept running (msiexec 1618) through
    /// every retry.
    InstallerBusy,
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
                format!("Failed to download the agent from the control plane: {detail}")
            }
            Self::UploadFailed(detail) => {
                format!("Failed to copy the agent installer to the host: {detail}")
            }
            Self::NotAdministrator => {
                "This account isn't a local administrator on the host -- installing the agent \
                 MSI needs one"
                    .into()
            }
            Self::StagingFolderUnsafe(detail) => format!(
                "%ProgramData%\\Abyssal on the host isn't locked down to SYSTEM and \
                 Administrators ({detail}). Another user may have created it; check it, remove \
                 it if it isn't yours, then try again"
            ),
            Self::VerifyFailed(detail) => {
                format!("The installer on the host failed verification and wasn't run: {detail}")
            }
            Self::InstallerBusy => {
                "Another installation kept running on the host (msiexec 1618) through every \
                 retry -- try again once it finishes"
                    .into()
            }
            Self::InstallFailed(detail) => format!("Install command failed: {detail}"),
            Self::NeverCheckedIn => {
                "Install command succeeded, but the agent never connected back -- check the \
                 host's network access to the control plane, and the agent service on that \
                 host (`systemctl status abyssal-agent` on Linux, `Get-Service abyssal-agent` \
                 on Windows)"
                    .into()
            }
            Self::Other(detail) => detail.clone(),
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
    /// `true` when `hostname` above is really just the IP address --
    /// either the SSH session never got far enough to ask the host for
    /// its own name, or it answered with something that didn't look like
    /// a real hostname. Surfaced on the status page so an IP standing in
    /// for a hostname is something to investigate, not mistaken for a
    /// real name (see `deploy_one_host`'s hostname resolution).
    pub hostname_is_fallback: bool,
    /// Where a failed deploy stopped; `None` until then.
    pub failed_stage: Option<DeployStage>,
}

/// What one host's deploy attempt produced -- `deploy_one_host`'s return
/// type. `resolved_hostname`/`hostname_is_fallback` start from the
/// inventory's pre-deploy guess (`DeployTarget::hostname`, or the IP if
/// there wasn't one) and get replaced the moment the host answers its own
/// `hostname` command, which is ground truth in a way a pre-scan guess
/// never is.
pub struct DeployOutcome {
    pub state: HostDeployState,
    pub output: String,
    pub resolved_hostname: String,
    pub hostname_is_fallback: bool,
    /// Set with a `Failed` state: the stage it failed at.
    pub failed_stage: Option<DeployStage>,
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

/// Confirms real enrollment, not just a zero exit code: polls for a host row
/// registered under `hostname` (the name the install told the agent to use)
/// that has actually connected back over its own WebSocket, for up to
/// [`CHECKIN_POLL_TIMEOUT`]. Returns `Succeeded` or
/// `Failed(NeverCheckedIn)`.
pub async fn wait_for_checkin(
    pool: &DbPool,
    hosts_registry: &HostConnectionRegistry,
    hostname: &str,
) -> HostDeployState {
    let deadline = tokio::time::Instant::now() + CHECKIN_POLL_TIMEOUT;
    loop {
        if let Ok(hosts) = repo::hosts::list(pool).await
            && let Some(host) = hosts.iter().find(|h| h.name == hostname)
            && hosts_registry.is_connected(host.id)
        {
            return HostDeployState::Succeeded;
        }
        if tokio::time::Instant::now() >= deadline {
            return HostDeployState::Failed(DeployFailureReason::NeverCheckedIn);
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

/// Runs one deploy future per host, at most `concurrency` at once
/// (`tokio::sync::Semaphore`), each in its own task (`tokio::task::JoinSet`)
/// so one host's failure or hang can never block or take down the others.
/// `deploys` pairs each host's IP (its key in `job`) with the future that
/// deploys it; a future does nothing until its turn comes. `job` is updated
/// in place as each host progresses -- a caller elsewhere polls the same
/// `Arc<RwLock<...>>` to render a status page. Records
/// `HostDeployStarted`/`HostDeploySucceeded`/`HostDeployFailed` per host,
/// attributed to whoever confirmed the deploy (`actor_user_id`/
/// `actor_username`) -- this is the durable record of what happened; `job`
/// itself is in-memory only and doesn't outlive the process.
pub async fn run_job<F>(
    pool: DbPool,
    job: Arc<RwLock<DeployJob>>,
    deploys: Vec<(String, F)>,
    concurrency: usize,
    actor_user_id: Uuid,
    actor_username: String,
) where
    F: Future<Output = DeployOutcome> + Send + 'static,
{
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();

    for (ip_address, deploy) in deploys {
        {
            let mut job = job.write().await;
            if let Some(status) = job.hosts.iter_mut().find(|h| h.ip_address == ip_address) {
                status.state = HostDeployState::Connecting;
            }
        }

        let semaphore = semaphore.clone();
        let pool = pool.clone();
        let job = job.clone();
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

            let DeployOutcome {
                state,
                output,
                resolved_hostname,
                hostname_is_fallback,
                failed_stage,
            } = deploy.await;

            let (action, outcome, metadata) = match &state {
                HostDeployState::Succeeded => (
                    AuditAction::HostDeploySucceeded,
                    AuditOutcome::Success,
                    None,
                ),
                HostDeployState::Failed(reason) => (
                    AuditAction::HostDeployFailed,
                    AuditOutcome::Failure,
                    Some(serde_json::json!({
                        "reason": reason.message(),
                        "stage": failed_stage.map(DeployStage::label),
                    })),
                ),
                // Every other state is non-terminal; a deploy future always
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
                status.hostname = Some(resolved_hostname);
                status.hostname_is_fallback = hostname_is_fallback;
                status.failed_stage = failed_stage;
            }
        });
    }

    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_labels_are_distinct() {
        let stages = [
            DeployStage::Connect,
            DeployStage::Authenticate,
            DeployStage::Preflight,
            DeployStage::Download,
            DeployStage::Verify,
            DeployStage::Install,
            DeployStage::CheckIn,
        ];
        let labels: std::collections::HashSet<_> = stages.iter().map(|s| s.label()).collect();
        assert_eq!(labels.len(), stages.len());
    }
}
