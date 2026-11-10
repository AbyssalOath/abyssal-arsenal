//! Pushing the agent to Windows hosts (docs/roadmap/windows-push-deploy.md,
//! M3): the on-host steps, and running them over OpenSSH. WinRM (M4) is meant
//! to reuse the scripts here with its own transport.
//!
//! Per host:
//!
//! 1. **Preflight:** a local administrator (installing an MSI needs one),
//!    x64, enough free space, the OS, the host's name, and any agent already
//!    installed.
//! 2. **Staging folder:** `%ProgramData%\Abyssal` must be owned by SYSTEM or
//!    Administrators, with protected permissions granting only those two
//!    (any user can create folders under `%ProgramData%`, so one that isn't
//!    is a host problem, reported, never "fixed"). It's created locked down
//!    if missing. Each deploy gets a new random subfolder.
//! 3. **Copy** the MSI into it over SFTP. Over SSH there's no need for the
//!    host to download it: the session is already authenticated and the host
//!    key pinned, and the host would otherwise have to trust the control
//!    plane's internal CA for an HTTPS download.
//! 4. **Verify** its SHA-256 against the bytes the control plane sent, and,
//!    when a signer is configured (`AGENT_MSI_SIGNER_THUMBPRINT`), that its
//!    Authenticode signature is valid and from that signer. `msiexec` itself
//!    doesn't check signatures.
//! 5. **Token file** over SFTP, never in a command: a per-host install token
//!    (AAT format, so the agent can verify the control plane's CA through
//!    the AAT proof), minted for this deploy with a short expiry and revoked
//!    once the deploy ends, whatever the outcome.
//! 6. **Install:** `msiexec /i … /qn /norestart SERVER=… AAT_FILE=… NAME=…`.
//!    The agent reads the token file and deletes it.
//! 7. **Exit code:** 0 succeeded; 3010/1641 succeeded with a reboot pending;
//!    1638 already installed (the check-in decides); 1618 another install is
//!    running, retried with a backoff; anything else failed, with the MSI
//!    log's tail.
//! 8. **Clean up** the subfolder whatever happened, then wait for the agent
//!    to check in.
//!
//! Every PowerShell step runs as `powershell.exe -EncodedCommand`, which
//! works the same whether the host's OpenSSH default shell is `cmd` (the
//! default) or PowerShell, and needs no quoting of the script itself. No
//! script contains a secret.

use std::sync::Arc;
use std::time::Duration;

use abyssal_core::EncryptionKey;
use abyssal_core::secret::hash_token;
use abyssal_database::repo::install_tokens::NewInstallToken;
use abyssal_database::{DbPool, repo};
use abyssal_hosts::HostConnectionRegistry;
use base64::Engine;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::host_deploy::{
    CommandResult, DeployFailureReason, DeployJob, DeployOutcome, DeployStage, HostDeployState,
    wait_for_checkin,
};
use crate::ssh_deploy::{DeployTarget, SshClient, SshSession};

/// Free space the install needs on the system drive, with room to spare.
const MIN_FREE_MB: u64 = 200;
/// How long a per-host deploy token stays valid if it's never revoked (a
/// control plane restart mid-deploy).
const TOKEN_LIFETIME: chrono::Duration = chrono::Duration::hours(1);
/// Waits before retrying an install that hit msiexec 1618 (another install
/// running). Two retries, so three attempts in all.
#[cfg(not(test))]
const BUSY_RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(30), Duration::from_secs(60)];
#[cfg(test)]
const BUSY_RETRY_DELAYS: [Duration; 2] = [Duration::ZERO, Duration::ZERO];
/// The MSI's display name in Add/Remove Programs (`abyssal-agent.wxs`).
const PRODUCT_NAME: &str = "Abyssal Arsenal Agent";

// ---------------------------------------------------------------------
// The installer being pushed
// ---------------------------------------------------------------------

/// The MSI a job pushes: the exact bytes `/agent/windows-msi` serves, their
/// hash, and the signer to require, if one is configured.
pub struct AgentMsi {
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes`.
    pub sha256: String,
    pub version: Option<String>,
    /// Authenticode signer certificate thumbprint to require
    /// (`AGENT_MSI_SIGNER_THUMBPRINT`). `None`: the hash is checked, the
    /// signature isn't (release builds aren't signed yet).
    pub signer_thumbprint: Option<String>,
}

impl AgentMsi {
    pub fn new(bytes: Vec<u8>, version: Option<String>, signer_thumbprint: Option<String>) -> Self {
        let sha256 = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self {
            bytes,
            sha256,
            version,
            signer_thumbprint: signer_thumbprint
                .map(|t| t.trim().replace([' ', ':'], "").to_ascii_uppercase())
                .filter(|t| !t.is_empty()),
        }
    }

    /// The MSI the control plane serves, with the signer from the
    /// environment.
    pub async fn load(state: &crate::state::AppState) -> anyhow::Result<Self> {
        let agent = crate::routes::bootstrap::resolve_agent(state, "windows-msi")
            .await
            .map_err(|e| anyhow::anyhow!("the Windows agent MSI isn't available: {e}"))?;
        Ok(Self::new(
            agent.bytes,
            agent.version,
            std::env::var("AGENT_MSI_SIGNER_THUMBPRINT").ok(),
        ))
    }
}

// ---------------------------------------------------------------------
// On-host scripts
// ---------------------------------------------------------------------

/// A PowerShell single-quoted string literal.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The command line that runs `script`: UTF-16LE, base64, `-EncodedCommand`.
pub fn encoded_command(script: &str) -> String {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
         -EncodedCommand {}",
        base64::engine::general_purpose::STANDARD.encode(utf16)
    )
}

/// Step 1: `key=value` lines for [`parse_preflight`].
pub fn preflight_script() -> String {
    format!(
        "$ErrorActionPreference='Stop'\n\
         $p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())\n\
         \"admin=$($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))\"\n\
         \"arch=$env:PROCESSOR_ARCHITECTURE\"\n\
         $os=Get-CimInstance Win32_OperatingSystem\n\
         \"os=$($os.Caption) $($os.Version)\"\n\
         \"hostname=$([Net.Dns]::GetHostName())\"\n\
         $d=Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')\n\
         \"free_mb=$([math]::Floor($d.Free/1MB))\"\n\
         \"programdata=$env:ProgramData\"\n\
         $k=Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall' -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -eq {} }} | Select-Object -First 1\n\
         \"installed=$($k.DisplayVersion)\"\n",
        ps_quote(PRODUCT_NAME)
    )
}

#[derive(Debug, Default, PartialEq)]
pub struct Preflight {
    pub admin: bool,
    pub arch: String,
    pub os: String,
    pub hostname: String,
    pub free_mb: Option<u64>,
    pub program_data: String,
    /// The installed agent's version, if there is one.
    pub installed: Option<String>,
}

pub fn parse_preflight(stdout: &str) -> Preflight {
    let mut p = Preflight::default();
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "admin" => p.admin = value.eq_ignore_ascii_case("true"),
            "arch" => p.arch = value.to_string(),
            "os" => p.os = value.to_string(),
            "hostname" => p.hostname = value.to_string(),
            "free_mb" => p.free_mb = value.parse().ok(),
            "programdata" => p.program_data = value.to_string(),
            "installed" => p.installed = Some(value.to_string()).filter(|v| !v.is_empty()),
            _ => {}
        }
    }
    p
}

/// Exit code from [`staging_script`] when `%ProgramData%\Abyssal` isn't
/// safe to use; its stdout says why.
const UNSAFE_EXIT: u32 = 3;

/// Step 2: checks (or creates, locked down) `<programdata>\Abyssal`, then
/// creates `<programdata>\Abyssal\<subfolder>`, which must not exist yet.
pub fn staging_script(program_data: &str, subfolder: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'\n\
         $root=Join-Path {pd} 'Abyssal'\n\
         $sys=New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'\n\
         $adm=New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'\n\
         function Test-Root {{\n\
           $i=Get-Item -LiteralPath $root -Force\n\
           if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) {{ 'unsafe=it is a link'; exit {code} }}\n\
           if (-not $i.PSIsContainer) {{ 'unsafe=it is a file'; exit {code} }}\n\
           $a=Get-Acl -LiteralPath $root\n\
           $o=$a.GetOwner([Security.Principal.SecurityIdentifier])\n\
           if ($o -ne $sys -and $o -ne $adm) {{ \"unsafe=owned by $o\"; exit {code} }}\n\
           if (-not $a.AreAccessRulesProtected) {{ 'unsafe=it inherits permissions from ProgramData'; exit {code} }}\n\
           foreach ($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {{\n\
             if ($r.IdentityReference -ne $sys -and $r.IdentityReference -ne $adm) {{ \"unsafe=it grants access to $($r.IdentityReference)\"; exit {code} }}\n\
           }}\n\
         }}\n\
         if (-not (Test-Path -LiteralPath $root)) {{\n\
           New-Item -ItemType Directory -Path $root | Out-Null\n\
           $a=New-Object Security.AccessControl.DirectorySecurity\n\
           $a.SetOwner($adm)\n\
           $a.SetAccessRuleProtection($true,$false)\n\
           foreach ($s in $sys,$adm) {{ $a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($s,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))) }}\n\
           Set-Acl -LiteralPath $root -AclObject $a\n\
         }}\n\
         Test-Root\n\
         $dir=Join-Path $root {sub}\n\
         New-Item -ItemType Directory -Path $dir | Out-Null\n\
         \"dir=$dir\"\n",
        pd = ps_quote(program_data),
        sub = ps_quote(subfolder),
        code = UNSAFE_EXIT,
    )
}

/// Exit code from [`verify_script`] on a hash or signature mismatch.
const VERIFY_EXIT: u32 = 4;

/// Step 4: the MSI's SHA-256, then its signer if one is required.
pub fn verify_script(msi: &str, sha256: &str, signer_thumbprint: Option<&str>) -> String {
    let signer = match signer_thumbprint {
        Some(thumbprint) => format!(
            "$s=Get-AuthenticodeSignature -LiteralPath {msi}\n\
             if ($s.Status -ne 'Valid') {{ \"signature=$($s.Status)\"; exit {code} }}\n\
             if ($s.SignerCertificate.Thumbprint -ne {thumb}) {{ \"signer=$($s.SignerCertificate.Thumbprint)\"; exit {code} }}\n",
            msi = ps_quote(msi),
            thumb = ps_quote(thumbprint),
            code = VERIFY_EXIT,
        ),
        None => String::new(),
    };
    format!(
        "$ErrorActionPreference='Stop'\n\
         $h=(Get-FileHash -LiteralPath {msi} -Algorithm SHA256).Hash\n\
         if ($h -ne {hash}) {{ \"sha256=$h\"; exit {code} }}\n\
         {signer}'verified'\n",
        msi = ps_quote(msi),
        hash = ps_quote(sha256),
        code = VERIFY_EXIT,
    )
}

/// Step 6: runs `msiexec` and exits with its exit code. Nothing here is
/// secret: the token is only named, by its file.
pub fn install_script(msi: &str, token_file: &str, log: &str, server: &str, name: &str) -> String {
    let args = format!(
        "/i \"{msi}\" /qn /norestart SERVER=\"{server}\" AAT_FILE=\"{token_file}\" \
         NAME=\"{name}\" /l*v \"{log}\""
    );
    format!(
        "$ErrorActionPreference='Stop'\n\
         $p=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\\msiexec.exe') \
         -ArgumentList {} -Wait -PassThru\n\
         exit $p.ExitCode\n",
        ps_quote(&args)
    )
}

/// The last lines of the MSI log, for a failed install.
pub fn log_tail_script(log: &str) -> String {
    format!(
        "Get-Content -LiteralPath {} -Tail 25 -ErrorAction SilentlyContinue\n",
        ps_quote(log)
    )
}

/// Step 8: removes the deploy's subfolder (and anything left in it).
pub fn cleanup_script(dir: &str) -> String {
    format!(
        "Remove-Item -LiteralPath {} -Recurse -Force -ErrorAction SilentlyContinue\n",
        ps_quote(dir)
    )
}

/// What an `msiexec` exit code means here.
#[derive(Debug, PartialEq, Eq)]
pub enum MsiOutcome {
    Succeeded,
    /// Succeeded; Windows wants a reboot to finish (3010, 1641).
    RebootPending,
    /// 1638: this or another version is already installed. The check-in
    /// decides whether that's an agent that works.
    AlreadyInstalled,
    /// 1618: another installation is running.
    Busy,
    Failed(u32),
}

pub fn msi_outcome(code: u32) -> MsiOutcome {
    match code {
        0 => MsiOutcome::Succeeded,
        3010 | 1641 => MsiOutcome::RebootPending,
        1638 => MsiOutcome::AlreadyInstalled,
        1618 => MsiOutcome::Busy,
        other => MsiOutcome::Failed(other),
    }
}

/// `C:\ProgramData\Abyssal\x` -> `/C:/ProgramData/Abyssal/x`, the form
/// Windows OpenSSH's SFTP server takes.
pub fn sftp_path(windows_path: &str) -> String {
    format!("/{}", windows_path.replace('\\', "/"))
}

/// Whether `url` can go into the msiexec command line as `SERVER="…"`: an
/// http(s) URL with nothing that could end the quoting or be read by cmd or
/// msiexec as something else.
fn is_safe_server_url(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://"))
        && url
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":/.-_[]".contains(c))
}

// ---------------------------------------------------------------------
// One host over SSH
// ---------------------------------------------------------------------

/// Runs one PowerShell step.
async fn run_ps(
    session: &mut dyn SshSession,
    script: &str,
) -> Result<CommandResult, DeployFailureReason> {
    session.exec(&encoded_command(script), None).await
}

/// Deploys to one Windows host over SSH. `token` is this host's own
/// install token.
#[allow(clippy::too_many_arguments)]
pub async fn deploy_one_host(
    client: &dyn SshClient,
    pool: &DbPool,
    hosts_registry: &HostConnectionRegistry,
    target: &DeployTarget,
    expected_fingerprint: &str,
    control_plane_url: &str,
    token: &str,
    msi: &AgentMsi,
) -> DeployOutcome {
    let mut output = String::new();
    let mut resolved_hostname = target
        .hostname
        .clone()
        .unwrap_or_else(|| target.ip_address.clone());
    let mut hostname_is_fallback = target.hostname.is_none();
    let mut stage = DeployStage::Connect;

    macro_rules! finish {
        ($state:expr) => {{
            let state = $state;
            let failed_stage = matches!(state, HostDeployState::Failed(_)).then_some(stage);
            return DeployOutcome {
                state,
                output,
                resolved_hostname,
                hostname_is_fallback,
                failed_stage,
            };
        }};
    }

    if !is_safe_server_url(control_plane_url) {
        finish!(HostDeployState::Failed(DeployFailureReason::Other(
            format!(
                "The control plane URL ({control_plane_url}) can't be passed to the installer safely"
            )
        )));
    }

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
        Err(reason) => {
            if matches!(
                reason,
                DeployFailureReason::AuthenticationFailed
                    | DeployFailureReason::HostKeyChanged { .. }
                    | DeployFailureReason::HostKeyUnconfirmed
            ) {
                stage = DeployStage::Authenticate;
            }
            finish!(HostDeployState::Failed(reason))
        }
    };

    // 1. Preflight.
    stage = DeployStage::Preflight;
    let preflight = match run_ps(session.as_mut(), &preflight_script()).await {
        Ok(result) if result.success() => parse_preflight(&result.stdout),
        Ok(result) => finish!(HostDeployState::Failed(DeployFailureReason::Other(
            format!(
                "Preflight failed (exit code {:?}); is this a Windows host with PowerShell? {}",
                result.exit_code,
                result.stderr.trim()
            )
        ))),
        Err(reason) => finish!(HostDeployState::Failed(reason)),
    };
    output.push_str(&format!(
        "Preflight: {}, {}, {} MB free{}\n",
        preflight.os,
        preflight.arch,
        preflight
            .free_mb
            .map_or("?".to_string(), |mb| mb.to_string()),
        preflight
            .installed
            .as_ref()
            .map_or(String::new(), |v| format!(", agent {v} already installed"))
    ));
    if abyssal_agent_protocol::is_valid_hostname(&preflight.hostname) {
        resolved_hostname = preflight.hostname.clone();
        hostname_is_fallback = false;
    }
    if !preflight.admin {
        finish!(HostDeployState::Failed(
            DeployFailureReason::NotAdministrator
        ));
    }
    if !preflight.arch.eq_ignore_ascii_case("AMD64") {
        finish!(HostDeployState::Failed(
            DeployFailureReason::UnsupportedArchitecture(preflight.arch.clone())
        ));
    }
    if preflight.free_mb.is_some_and(|mb| mb < MIN_FREE_MB) {
        finish!(HostDeployState::Failed(DeployFailureReason::Other(
            format!(
                "Not enough free space on the system drive ({} MB; {MIN_FREE_MB} MB needed)",
                preflight.free_mb.unwrap_or_default()
            )
        )));
    }
    if preflight.program_data.is_empty() || preflight.program_data.contains(['"', '\'']) {
        finish!(HostDeployState::Failed(DeployFailureReason::Other(
            "The host didn't report a usable %ProgramData% folder".into()
        )));
    }

    // 2. Staging folder.
    let subfolder = format!("deploy-{}", Uuid::new_v4().simple());
    let staged = match run_ps(
        session.as_mut(),
        &staging_script(&preflight.program_data, &subfolder),
    )
    .await
    {
        Ok(result) => result,
        Err(reason) => finish!(HostDeployState::Failed(reason)),
    };
    if staged.exit_code == Some(UNSAFE_EXIT) {
        let why = staged
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("unsafe="))
            .unwrap_or("unknown")
            .trim()
            .to_string();
        finish!(HostDeployState::Failed(
            DeployFailureReason::StagingFolderUnsafe(why)
        ));
    }
    let Some(dir) = staged
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("dir="))
        .map(|d| d.trim().to_string())
        .filter(|_| staged.success())
    else {
        finish!(HostDeployState::Failed(DeployFailureReason::Other(
            format!(
                "Couldn't create the staging folder (exit code {:?}): {}",
                staged.exit_code,
                staged.stderr.trim()
            )
        )));
    };
    output.push_str(&format!("Staging folder: {dir}\n"));
    let msi_path = format!("{dir}\\AbyssalAgent.msi");
    let token_path = format!("{dir}\\token");
    let log_path = format!("{dir}\\install.log");

    // From here on, every exit cleans the subfolder up first.
    macro_rules! fail_cleanup {
        ($reason:expr) => {{
            let reason = $reason;
            let _ = run_ps(session.as_mut(), &cleanup_script(&dir)).await;
            finish!(HostDeployState::Failed(reason))
        }};
    }

    // 3. Copy the installer.
    stage = DeployStage::Download;
    if let Err(reason) = session.write_file(&sftp_path(&msi_path), &msi.bytes).await {
        fail_cleanup!(DeployFailureReason::UploadFailed(reason.message()));
    }
    output.push_str(&format!(
        "Copied the installer{} ({} bytes)\n",
        msi.version
            .as_ref()
            .map_or(String::new(), |v| format!(" v{v}")),
        msi.bytes.len()
    ));

    // 4. Verify it.
    stage = DeployStage::Verify;
    match run_ps(
        session.as_mut(),
        &verify_script(&msi_path, &msi.sha256, msi.signer_thumbprint.as_deref()),
    )
    .await
    {
        Ok(result) if result.success() => output.push_str(if msi.signer_thumbprint.is_some() {
            "Verified the SHA-256 and the signer\n"
        } else {
            "Verified the SHA-256 (no signer configured, so the signature wasn't checked)\n"
        }),
        Ok(result) if result.exit_code == Some(VERIFY_EXIT) => {
            let got = result.stdout.trim().to_string();
            fail_cleanup!(DeployFailureReason::VerifyFailed(format!(
                "expected SHA-256 {}{}, got {got}",
                msi.sha256,
                msi.signer_thumbprint
                    .as_ref()
                    .map_or(String::new(), |t| format!(" signed by {t}"))
            )));
        }
        Ok(result) => fail_cleanup!(DeployFailureReason::VerifyFailed(format!(
            "exit code {:?}: {}",
            result.exit_code,
            result.stderr.trim()
        ))),
        Err(reason) => fail_cleanup!(reason),
    }

    // 5. The token file, over SFTP.
    stage = DeployStage::Install;
    if let Err(reason) = session
        .write_file(&sftp_path(&token_path), token.as_bytes())
        .await
    {
        fail_cleanup!(DeployFailureReason::InstallFailed(format!(
            "couldn't write the token file: {}",
            reason.message()
        )));
    }

    // 6./7. Install, retrying while another install is running.
    let script = install_script(
        &msi_path,
        &token_path,
        &log_path,
        control_plane_url.trim_end_matches('/'),
        &resolved_hostname,
    );
    let mut attempt = 0;
    let outcome = loop {
        let result = match run_ps(session.as_mut(), &script).await {
            Ok(result) => result,
            Err(reason) => fail_cleanup!(reason),
        };
        let Some(code) = result.exit_code else {
            fail_cleanup!(DeployFailureReason::InstallFailed(
                "msiexec didn't report an exit code".into()
            ));
        };
        output.push_str(&format!("msiexec exit code {code}\n"));
        match msi_outcome(code) {
            MsiOutcome::Busy if attempt < BUSY_RETRY_DELAYS.len() => {
                tokio::time::sleep(BUSY_RETRY_DELAYS[attempt]).await;
                attempt += 1;
            }
            MsiOutcome::Busy => fail_cleanup!(DeployFailureReason::InstallerBusy),
            other => break other,
        }
    };
    match outcome {
        MsiOutcome::Succeeded => {}
        MsiOutcome::RebootPending => {
            output.push_str("Installed; Windows wants a reboot to finish\n");
        }
        MsiOutcome::AlreadyInstalled => {
            output.push_str("An agent was already installed; waiting for it to check in\n");
        }
        MsiOutcome::Busy => unreachable!("retried above"),
        MsiOutcome::Failed(code) => {
            let tail = run_ps(session.as_mut(), &log_tail_script(&log_path))
                .await
                .map(|r| r.stdout)
                .unwrap_or_default();
            fail_cleanup!(DeployFailureReason::InstallFailed(format!(
                "msiexec exit code {code}. End of the MSI log:\n{}",
                tail.trim()
            )));
        }
    }

    // 8. Clean up, then the check-in decides.
    let _ = run_ps(session.as_mut(), &cleanup_script(&dir)).await;
    drop(session);
    stage = DeployStage::CheckIn;
    finish!(wait_for_checkin(pool, hosts_registry, &resolved_hostname).await)
}

// ---------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------

/// Mints the single-host install token for a deploy to `ip`: AAT format, no
/// approval step (an admin is deploying it), expiring in an hour.
pub async fn mint_deploy_token(
    pool: &DbPool,
    key: Option<&EncryptionKey>,
    ip: &str,
    by: Uuid,
) -> anyhow::Result<(Uuid, Zeroizing<String>)> {
    let token = Zeroizing::new(crate::aat::new_aat());
    let sealed = crate::aat::seal(&token, key)?;
    let label = format!("Push deploy to {ip}");
    let id = repo::install_tokens::create(
        pool,
        &NewInstallToken {
            label: &label,
            token_sealed: &sealed,
            token_hash: &hash_token(&token),
            key_id: &abyssal_agent_protocol::aat::key_id(&token),
            require_approval: false,
            created_by: Some(by),
            expires_at: Some(chrono::Utc::now() + TOKEN_LIFETIME),
        },
    )
    .await?;
    Ok((id, token))
}

/// Deploys to every Windows target over SSH through `host_deploy::run_job`:
/// each host gets its own install token, revoked when its deploy ends.
#[allow(clippy::too_many_arguments)]
pub async fn run_ssh_deploy_job(
    client: Arc<dyn SshClient>,
    pool: DbPool,
    key: Option<Arc<EncryptionKey>>,
    hosts_registry: Arc<HostConnectionRegistry>,
    job: Arc<RwLock<DeployJob>>,
    // (target, expected host-key fingerprint)
    targets: Vec<(DeployTarget, String)>,
    control_plane_url: String,
    msi: Arc<AgentMsi>,
    concurrency: usize,
    actor_user_id: Uuid,
    actor_username: String,
) {
    let deploys = targets
        .into_iter()
        .map(|(target, expected_fingerprint)| {
            let client = client.clone();
            let pool = pool.clone();
            let key = key.clone();
            let hosts_registry = hosts_registry.clone();
            let control_plane_url = control_plane_url.clone();
            let msi = msi.clone();
            let ip_address = target.ip_address.clone();
            let deploy = async move {
                let (token_id, token) = match mint_deploy_token(
                    &pool,
                    key.as_deref(),
                    &target.ip_address,
                    actor_user_id,
                )
                .await
                {
                    Ok(minted) => minted,
                    Err(e) => {
                        return DeployOutcome {
                            state: HostDeployState::Failed(DeployFailureReason::Other(format!(
                                "Couldn't create an install token for this host: {e}"
                            ))),
                            output: String::new(),
                            resolved_hostname: target
                                .hostname
                                .clone()
                                .unwrap_or_else(|| target.ip_address.clone()),
                            hostname_is_fallback: target.hostname.is_none(),
                            failed_stage: Some(DeployStage::Install),
                        };
                    }
                };
                let outcome = deploy_one_host(
                    client.as_ref(),
                    &pool,
                    hosts_registry.as_ref(),
                    &target,
                    &expected_fingerprint,
                    &control_plane_url,
                    &token,
                    &msi,
                )
                .await;
                // Enrolled or not, the token's job is done.
                if let Err(e) = repo::install_tokens::revoke(&pool, token_id).await {
                    tracing::warn!(error = %e, %token_id, "couldn't revoke a push-deploy install token; it expires in an hour");
                }
                outcome
            };
            (ip_address, deploy)
        })
        .collect();
    crate::host_deploy::run_job(
        pool,
        job,
        deploys,
        concurrency,
        actor_user_id,
        actor_username,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_deploy::{SshAuthMethod, SshCredentials};
    use std::sync::Mutex as StdMutex;

    // ---------------------------------------------------------------
    // Pure pieces
    // ---------------------------------------------------------------

    fn decode(command: &str) -> String {
        let b64 = command
            .rsplit(' ')
            .next()
            .expect("an -EncodedCommand argument");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let utf16: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&utf16).unwrap()
    }

    #[test]
    fn encoded_command_round_trips() {
        let script = "'héllo' | Out-Host\n$x = \"y\"";
        let command = encoded_command(script);
        assert!(command.starts_with("powershell.exe -NoLogo -NoProfile -NonInteractive"));
        assert_eq!(decode(&command), script);
    }

    #[test]
    fn parses_preflight() {
        let p = parse_preflight(
            "admin=True\r\narch=AMD64\r\nos=Microsoft Windows Server 2022 10.0.20348\r\n\
             hostname=WS042\r\nfree_mb=51234\r\nprogramdata=C:\\ProgramData\r\ninstalled=\r\n",
        );
        assert_eq!(
            p,
            Preflight {
                admin: true,
                arch: "AMD64".into(),
                os: "Microsoft Windows Server 2022 10.0.20348".into(),
                hostname: "WS042".into(),
                free_mb: Some(51234),
                program_data: "C:\\ProgramData".into(),
                installed: None,
            }
        );
        assert!(!parse_preflight("admin=False\ninstalled=0.2.6").admin);
        assert_eq!(
            parse_preflight("installed=0.2.6").installed.as_deref(),
            Some("0.2.6")
        );
    }

    #[test]
    fn maps_msiexec_exit_codes() {
        assert_eq!(msi_outcome(0), MsiOutcome::Succeeded);
        assert_eq!(msi_outcome(3010), MsiOutcome::RebootPending);
        assert_eq!(msi_outcome(1641), MsiOutcome::RebootPending);
        assert_eq!(msi_outcome(1638), MsiOutcome::AlreadyInstalled);
        assert_eq!(msi_outcome(1618), MsiOutcome::Busy);
        assert_eq!(msi_outcome(1603), MsiOutcome::Failed(1603));
    }

    #[test]
    fn sftp_paths_and_server_urls() {
        assert_eq!(
            sftp_path("C:\\ProgramData\\Abyssal\\deploy-1\\token"),
            "/C:/ProgramData/Abyssal/deploy-1/token"
        );
        assert!(is_safe_server_url("https://cp.example.com:8443"));
        assert!(is_safe_server_url("https://[fd00::1]:8443"));
        for bad in [
            "ftp://cp",
            "https://cp\" /qn",
            "https://cp' x",
            "https://cp&calc",
            "https://cp %TEMP%",
        ] {
            assert!(!is_safe_server_url(bad), "{bad}");
        }
    }

    #[test]
    fn scripts_quote_their_values() {
        let s = staging_script("C:\\Program'Data", "deploy-1");
        assert!(s.contains("Join-Path 'C:\\Program''Data' 'Abyssal'"));
        let v = verify_script("C:\\a.msi", "ABC", Some("THUMB"));
        assert!(v.contains("Get-AuthenticodeSignature") && v.contains("'THUMB'"));
        assert!(!verify_script("C:\\a.msi", "ABC", None).contains("Authenticode"));
        let i = install_script(
            "C:\\d\\a.msi",
            "C:\\d\\token",
            "C:\\d\\l.log",
            "https://cp",
            "WS042",
        );
        assert!(i.contains("AAT_FILE=\"C:\\d\\token\""));
        assert!(i.contains("SERVER=\"https://cp\"") && i.contains("NAME=\"WS042\""));
        assert!(!i.contains("AAT=\""), "never the token itself");
    }

    #[test]
    fn signer_thumbprint_is_normalised() {
        let msi = AgentMsi::new(b"x".to_vec(), None, Some(" ab:cd ef ".into()));
        assert_eq!(msi.signer_thumbprint.as_deref(), Some("ABCDEF"));
        assert_eq!(
            msi.sha256,
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
        );
        assert_eq!(
            AgentMsi::new(vec![], None, Some("  ".into())).signer_thumbprint,
            None
        );
    }

    /// Parses `script` with PowerShell's own parser. Needs `pwsh`: skipped
    /// without it locally, required in CI (the same rule as the agent's
    /// Windows script tests).
    fn assert_parses(name: &str, script: &str) {
        if std::process::Command::new("pwsh")
            .arg("-Version")
            .output()
            .is_err()
        {
            assert!(
                std::env::var_os("CI").is_none(),
                "pwsh is required for this test in CI"
            );
            return;
        }
        let path = std::env::temp_dir().join(format!("{name}-{}.ps1", std::process::id()));
        std::fs::write(&path, script).unwrap();
        let out = std::process::Command::new("pwsh")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:SCRIPT, [ref]$t, [ref]$e); foreach ($x in $e) { $x.Message }; if ($e.Count) { exit 1 }",
            ])
            .env("SCRIPT", &path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn every_on_host_script_parses_as_powershell() {
        let dir = "C:\\ProgramData\\Abyssal\\deploy-1";
        assert_parses("wd-preflight", &preflight_script());
        assert_parses(
            "wd-staging",
            &staging_script("C:\\Program'Data", "deploy-1"),
        );
        assert_parses("wd-verify", &verify_script("C:\\a.msi", "AB", None));
        assert_parses(
            "wd-verify-signed",
            &verify_script("C:\\a.msi", "AB", Some("CD")),
        );
        assert_parses(
            "wd-install",
            &install_script(
                "C:\\a.msi",
                "C:\\t",
                "C:\\l.log",
                "https://cp:8443",
                "WS042",
            ),
        );
        assert_parses("wd-log-tail", &log_tail_script("C:\\l.log"));
        assert_parses("wd-cleanup", &cleanup_script(dir));
    }

    // ---------------------------------------------------------------
    // One host, against a fake session that answers each script
    // ---------------------------------------------------------------

    #[derive(Default)]
    struct Log {
        scripts: Vec<String>,
        files: Vec<(String, Vec<u8>)>,
    }

    /// How the fake host answers.
    #[derive(Clone)]
    struct Host {
        preflight: String,
        staging: (u32, String),
        verify_exit: u32,
        /// One per install attempt; the last repeats.
        msiexec: Vec<u32>,
    }

    impl Default for Host {
        fn default() -> Self {
            Self {
                preflight: "admin=True\narch=AMD64\nos=Windows\nhostname=WS042\nfree_mb=9000\n\
                            programdata=C:\\ProgramData\ninstalled=\n"
                    .into(),
                staging: (0, "dir=C:\\ProgramData\\Abyssal\\deploy-x\n".into()),
                verify_exit: 0,
                msiexec: vec![0],
            }
        }
    }

    struct FakeSession {
        host: Host,
        installs: usize,
        log: Arc<StdMutex<Log>>,
    }

    fn result(code: u32, stdout: &str) -> CommandResult {
        CommandResult {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: Some(code),
        }
    }

    #[async_trait::async_trait]
    impl SshSession for FakeSession {
        async fn exec(
            &mut self,
            command: &str,
            _stdin: Option<&[u8]>,
        ) -> Result<CommandResult, DeployFailureReason> {
            let script = decode(command);
            self.log.lock().unwrap().scripts.push(script.clone());
            Ok(if script.contains("WindowsPrincipal") {
                result(0, &self.host.preflight)
            } else if script.contains("Test-Root") {
                result(self.host.staging.0, &self.host.staging.1)
            } else if script.contains("Get-FileHash") {
                result(self.host.verify_exit, "sha256=DEADBEEF")
            } else if script.contains("msiexec") {
                let code = *self
                    .host
                    .msiexec
                    .get(self.installs)
                    .or(self.host.msiexec.last())
                    .unwrap();
                self.installs += 1;
                result(code, "")
            } else if script.contains("Get-Content") {
                result(
                    0,
                    "MSI (s) Product: Abyssal Arsenal Agent -- Installation failed.",
                )
            } else {
                result(0, "")
            })
        }

        async fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), DeployFailureReason> {
            self.log
                .lock()
                .unwrap()
                .files
                .push((path.to_string(), data.to_vec()));
            Ok(())
        }
    }

    struct FakeClient {
        host: Host,
        log: Arc<StdMutex<Log>>,
    }

    #[async_trait::async_trait]
    impl SshClient for FakeClient {
        async fn probe_host_key(&self, _: &str, _: u16) -> Result<String, DeployFailureReason> {
            Ok("SHA256:fake".into())
        }

        async fn connect(
            &self,
            _: &str,
            _: u16,
            _: &str,
            _: &SshCredentials,
        ) -> Result<Box<dyn SshSession>, DeployFailureReason> {
            Ok(Box::new(FakeSession {
                host: self.host.clone(),
                installs: 0,
                log: self.log.clone(),
            }))
        }
    }

    fn target() -> DeployTarget {
        DeployTarget {
            ip_address: "10.0.0.20".into(),
            hostname: None,
            ssh_port: 22,
            credentials: SshCredentials {
                username: "Administrator".into(),
                auth: SshAuthMethod::Password(Zeroizing::new("pw".into())),
                sudo_password: Zeroizing::new(String::new()),
            },
        }
    }

    fn unconfigured_pool() -> DbPool {
        sqlx::mysql::MySqlPoolOptions::new()
            .connect_lazy("mysql://invalid:invalid@127.0.0.1:1/invalid")
            .expect("lazy pool construction never touches the network")
    }

    const TOKEN: &str = "AAT1-secret-token-value";

    async fn deploy(host: Host) -> (DeployOutcome, Log) {
        let log = Arc::new(StdMutex::new(Log::default()));
        let client = FakeClient {
            host,
            log: log.clone(),
        };
        let msi = AgentMsi::new(b"MSI bytes".to_vec(), Some("0.2.6".into()), None);
        let outcome = deploy_one_host(
            &client,
            &unconfigured_pool(),
            &HostConnectionRegistry::new(),
            &target(),
            "SHA256:fake",
            "https://cp.example.com",
            TOKEN,
            &msi,
        )
        .await;
        let log = std::mem::take(&mut *log.lock().unwrap());
        (outcome, log)
    }

    fn cleaned_up(log: &Log) -> bool {
        log.scripts
            .last()
            .is_some_and(|s| s.contains("Remove-Item") && s.contains("deploy-x"))
    }

    #[tokio::test(start_paused = true)]
    async fn installs_with_the_token_only_in_a_file_then_waits_for_check_in() {
        let (outcome, log) = deploy(Host::default()).await;
        // No agent ever connects in this test, so the check-in decides.
        assert_eq!(
            outcome.state,
            HostDeployState::Failed(DeployFailureReason::NeverCheckedIn)
        );
        assert_eq!(outcome.failed_stage, Some(DeployStage::CheckIn));
        assert_eq!(outcome.resolved_hostname, "WS042");
        assert!(!outcome.hostname_is_fallback);

        assert_eq!(
            log.files,
            vec![
                (
                    "/C:/ProgramData/Abyssal/deploy-x/AbyssalAgent.msi".to_string(),
                    b"MSI bytes".to_vec()
                ),
                (
                    "/C:/ProgramData/Abyssal/deploy-x/token".to_string(),
                    TOKEN.as_bytes().to_vec()
                ),
            ]
        );
        assert!(
            log.scripts.iter().all(|s| !s.contains(TOKEN)),
            "the token must never be in a script"
        );
        assert!(!outcome.output.contains(TOKEN));
        let install = log.scripts.iter().find(|s| s.contains("msiexec")).unwrap();
        assert!(install.contains("AAT_FILE=\"C:\\ProgramData\\Abyssal\\deploy-x\\token\""));
        assert!(cleaned_up(&log));
    }

    #[tokio::test]
    async fn stops_before_installing_when_not_an_administrator() {
        let host = Host {
            preflight: Host::default()
                .preflight
                .replace("admin=True", "admin=False"),
            ..Host::default()
        };
        let (outcome, log) = deploy(host).await;
        assert_eq!(
            outcome.state,
            HostDeployState::Failed(DeployFailureReason::NotAdministrator)
        );
        assert_eq!(outcome.failed_stage, Some(DeployStage::Preflight));
        assert_eq!(log.scripts.len(), 1);
        assert!(log.files.is_empty());
    }

    #[tokio::test]
    async fn refuses_an_unsafe_staging_folder() {
        let host = Host {
            staging: (UNSAFE_EXIT, "unsafe=owned by S-1-5-21-1-2-3-1001\n".into()),
            ..Host::default()
        };
        let (outcome, log) = deploy(host).await;
        assert_eq!(
            outcome.state,
            HostDeployState::Failed(DeployFailureReason::StagingFolderUnsafe(
                "owned by S-1-5-21-1-2-3-1001".into()
            ))
        );
        assert!(log.files.is_empty(), "nothing copied into it");
    }

    #[tokio::test]
    async fn a_hash_mismatch_never_writes_the_token_or_installs() {
        let host = Host {
            verify_exit: VERIFY_EXIT,
            ..Host::default()
        };
        let (outcome, log) = deploy(host).await;
        assert!(matches!(
            outcome.state,
            HostDeployState::Failed(DeployFailureReason::VerifyFailed(_))
        ));
        assert_eq!(outcome.failed_stage, Some(DeployStage::Verify));
        assert_eq!(log.files.len(), 1, "only the MSI was copied");
        assert!(log.scripts.iter().all(|s| !s.contains("msiexec")));
        assert!(cleaned_up(&log));
    }

    #[tokio::test]
    async fn a_failed_install_reports_the_log_tail_and_cleans_up() {
        let host = Host {
            msiexec: vec![1603],
            ..Host::default()
        };
        let (outcome, log) = deploy(host).await;
        let HostDeployState::Failed(DeployFailureReason::InstallFailed(detail)) = &outcome.state
        else {
            panic!("{:?}", outcome.state);
        };
        assert!(detail.contains("1603") && detail.contains("Installation failed"));
        assert_eq!(outcome.failed_stage, Some(DeployStage::Install));
        assert!(cleaned_up(&log));
    }

    #[tokio::test]
    async fn retries_while_another_install_runs_then_gives_up() {
        let host = Host {
            msiexec: vec![1618],
            ..Host::default()
        };
        let (outcome, log) = deploy(host).await;
        assert_eq!(
            outcome.state,
            HostDeployState::Failed(DeployFailureReason::InstallerBusy)
        );
        let attempts = log.scripts.iter().filter(|s| s.contains("msiexec")).count();
        assert_eq!(attempts, 1 + BUSY_RETRY_DELAYS.len());
        assert!(cleaned_up(&log));
    }

    #[tokio::test(start_paused = true)]
    async fn busy_then_reboot_pending_counts_as_installed() {
        let host = Host {
            msiexec: vec![1618, 3010],
            ..Host::default()
        };
        let (outcome, _) = deploy(host).await;
        assert!(outcome.output.contains("wants a reboot"));
        // On to the check-in (which no agent answers here).
        assert_eq!(outcome.failed_stage, Some(DeployStage::CheckIn));
    }
}
