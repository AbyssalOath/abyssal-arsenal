//! In-place agent self-update, the in-band answer to a host showing "Agent
//! out of date" in the control plane's `/admin/hosts` list. Triggered by
//! `AgentOperation::SelfUpdate { version }` (see the variant's own doc
//! comment in `abyssal-agent-protocol`), it downloads the matching release
//! for this host's own platform from the project's GitHub releases,
//! replaces the installed binary (the same fixed, hardened path
//! `install` copies to), and bounces the host's service manager so the new
//! build takes over.
//!
//! **Where the build comes from.** From protocol 43 the control plane
//! normally sends `from_control_plane`: the agent downloads `/agent/<os>`
//! from the control plane it's connected to (TLS pinned to that control
//! plane's CA), so hosts with no internet access can update. The control
//! plane sends the archive's SHA-256 over the authenticated WebSocket and
//! anything else is refused. That trusts the control plane with the next
//! binary -- no more than it's already trusted: it can run root/SYSTEM
//! operations on this host anyway. Either way the new binary must run here
//! (`--version`, from its staged location next to the installed one) and
//! must not be older than this one before it's swapped in.
//!
//! **Trust model (GitHub).** Otherwise -- an older control plane -- the
//! wire only ever carries a *version tag*, never a URL: the download source is built here from that tag plus this binary's
//! own `std::env::consts::{OS, ARCH}`, so a control-plane message can only
//! select which published release to install, not point the agent at an
//! arbitrary host. The download is TLS-pinned to `github.com` -- the exact
//! same trust model the control-plane-side SSH deploy
//! (`crates/web/src/ssh_deploy.rs`) already relies on to fetch this same
//! artifact. The operation itself arrives over the already-authenticated
//! control-plane WebSocket.
//!
//! **Why the restart is scheduled, not immediate.** Restarting the service
//! kills this very process, so it can't happen before the success response
//! is sent back up the WebSocket -- the caller would only ever see a
//! dropped connection. Instead the swap is done synchronously (so any
//! failure is reported honestly), and the restart is handed to a short-
//! delayed, detached helper that outlives this process: a transient
//! `systemd-run` unit on Linux (deliberately outside this service's own
//! cgroup, so `systemctl restart` isn't cut off mid-flight), and a
//! detached batch script on Windows (where a running `.exe` can't be
//! overwritten in place at all, so the new binary is staged alongside and
//! swapped in only after the service has actually stopped).

use std::path::{Path, PathBuf};
use std::time::Duration;

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};
use anyhow::{Context, bail};

/// Base for the release asset download, matching `ssh_deploy.rs`'s own
/// hardcoded repo -- the single place the project's GitHub org/repo is
/// named on the agent side.
const GITHUB_DOWNLOAD_BASE: &str =
    "https://github.com/AbyssalOath/abyssal-arsenal/releases/download";

/// Generous enough for a ~10 MB release archive over a slow link, bounded
/// so a hung download can't wedge the operation forever (the control plane
/// has its own dispatch timeout on top of this).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

static CONTROL_PLANE_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Called by `run`: where `from_control_plane` updates download from.
pub fn set_control_plane_url(url: &str) {
    let _ = CONTROL_PLANE_URL.set(url.trim_end_matches('/').to_string());
}

pub async fn self_update(
    version: String,
    from_control_plane: bool,
    sha256: Option<String>,
) -> CommandOutcome {
    match run_self_update(&version, from_control_plane, sha256.as_deref()).await {
        Ok(message) => CommandOutcome::Ok(OperationOutput {
            stdout: message,
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(format!(
            "self-update to v{version} from {} failed: {e:#}",
            if from_control_plane {
                "the control plane"
            } else {
                "GitHub"
            }
        )),
    }
}

async fn run_self_update(
    version: &str,
    from_control_plane: bool,
    sha256: Option<&str>,
) -> anyhow::Result<String> {
    if !is_plausible_version(version) {
        bail!(
            "control plane sent an implausible version string ({version:?}) -- refusing to \
             build a download URL or filesystem path from it"
        );
    }
    if is_downgrade(env!("CARGO_PKG_VERSION"), version) {
        bail!(
            "this agent is already v{}, newer than v{version} -- refusing to downgrade. (The \
             control plane may not have seen the newest release yet: 'Check now' on the \
             dashboard refreshes it.) To really go back, reinstall the older version.",
            env!("CARGO_PKG_VERSION")
        );
    }

    let asset = PlatformAsset::for_this_host(version)?;

    let staging = staging_dir();
    // A stale staging dir from a previous run must never be trusted to
    // hold the right binary -- clear it before extracting into it.
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .with_context(|| format!("could not create staging dir {}", staging.display()))?;

    let (bytes, source) = if from_control_plane {
        let expected = sha256
            .filter(|h| is_sha256_hex(h))
            .context("the control plane sent no valid SHA-256 for the build")?;
        let base = CONTROL_PLANE_URL
            .get()
            .context("this agent doesn't know its control plane's URL")?;
        let url = format!("{base}/agent/{}", asset.control_plane_key());
        let bytes = download_from_control_plane(&url).await?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(expected) {
            bail!(
                "the download from {url} doesn't match the SHA-256 the control plane sent \
                 (got {actual}, expected {expected}) -- refusing to install it"
            );
        }
        (bytes, "the control plane, SHA-256 verified")
    } else {
        let url = format!("{GITHUB_DOWNLOAD_BASE}/v{version}/{}", asset.archive_name());
        (download(&url).await?, "GitHub")
    };

    let archive_path = staging.join(asset.archive_name());
    tokio::fs::write(&archive_path, &bytes)
        .await
        .with_context(|| {
            format!(
                "could not write downloaded archive to {}",
                archive_path.display()
            )
        })?;

    let new_binary = asset.extract(&staging, &archive_path).await?;

    let message = install_and_restart(&new_binary).await?;
    Ok(format!("{message} (Downloaded from {source}.)"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Asks a staged binary for its version (`abyssal-agent 0.2.3`), which also
/// proves it runs on this host. Refuses one older than this agent.
async fn check_new_binary(path: &Path) -> anyhow::Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(path).arg("--version").output(),
    )
    .await
    .context("the new binary didn't answer --version within 30s")?
    .with_context(|| format!("couldn't run the new binary at {}", path.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = parse_version_output(&stdout).with_context(|| {
        format!(
            "the new binary didn't report a version (exit {:?}): {}",
            output.status.code(),
            stdout.trim()
        )
    })?;
    if is_downgrade(env!("CARGO_PKG_VERSION"), &version) {
        bail!(
            "the downloaded build is v{version}, older than this agent (v{}) -- refusing to \
             downgrade",
            env!("CARGO_PKG_VERSION")
        );
    }
    Ok(version)
}

/// `abyssal-agent 0.2.3` -> `0.2.3`.
fn parse_version_output(stdout: &str) -> Option<String> {
    let version = stdout.lines().next()?.split_whitespace().last()?;
    parse_version(version).map(|_| version.trim_start_matches('v').to_string())
}

/// Only a version made of digits, dots, and the handful of characters a
/// real semver-ish tag can carry -- no path separators, no `..`, no
/// whitespace. This value is interpolated into a URL path segment, into
/// filesystem paths, and (on Windows) into a batch script, so it's
/// validated once, strictly, up front rather than trusted anywhere
/// downstream.
fn is_plausible_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && !version.contains("..")
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// `x.y.z` (an optional `v`, and anything after a `-`/`+` ignored).
fn parse_version(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let parsed = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(parsed)
}

/// True only when both parse and `target` is strictly older than `running`.
/// The same version is allowed: it's how an agent built from `main` before
/// a release is replaced by the released build.
fn is_downgrade(running: &str, target: &str) -> bool {
    matches!(
        (parse_version(running), parse_version(target)),
        (Some(running), Some(target)) if target < running
    )
}

struct PlatformAsset {
    /// e.g. `abyssal-agent-v0.1.3-x86_64-unknown-linux-gnu` -- both the
    /// archive's own basename (before the extension) and the top-level
    /// directory inside it, matching how `.github/workflows/release.yml`
    /// stages and names each artifact.
    stem: String,
}

impl PlatformAsset {
    fn for_this_host(version: &str) -> anyhow::Result<Self> {
        // Only x86_64 artifacts are published today (see release.yml); any
        // other arch has nothing to download, so fail clearly rather than
        // 404 halfway through.
        let arch = std::env::consts::ARCH;
        if arch != "x86_64" {
            bail!(
                "no published agent release for this architecture ({arch}) -- self-update only \
                 covers x86_64 today; rebuild and redeploy from source instead"
            );
        }

        let triple = match std::env::consts::OS {
            "linux" => "x86_64-unknown-linux-gnu",
            "windows" => "x86_64-pc-windows-msvc",
            other => bail!(
                "no published agent release for this platform ({other}) -- self-update only \
                 covers Linux and Windows today"
            ),
        };

        Ok(Self {
            stem: format!("abyssal-agent-v{version}-{triple}"),
        })
    }

    #[cfg(windows)]
    fn archive_name(&self) -> String {
        format!("{}.zip", self.stem)
    }

    #[cfg(not(windows))]
    fn archive_name(&self) -> String {
        format!("{}.tar.gz", self.stem)
    }

    /// The control plane's `/agent/<key>` for this platform's archive.
    fn control_plane_key(&self) -> &'static str {
        if cfg!(windows) { "windows" } else { "linux" }
    }

    /// The binary's basename inside the extracted archive.
    #[cfg(windows)]
    fn binary_name(&self) -> &'static str {
        "abyssal-agent.exe"
    }

    #[cfg(not(windows))]
    fn binary_name(&self) -> &'static str {
        "abyssal-agent"
    }

    /// Unpacks the downloaded archive into `staging` and returns the path
    /// to the freshly extracted agent binary. Shells out to the platform's
    /// stock archive tool (`tar`, PowerShell's `Expand-Archive`) rather
    /// than pulling in an extraction crate -- the same "use the real
    /// system tool" convention the rest of this agent follows.
    async fn extract(&self, staging: &Path, archive_path: &Path) -> anyhow::Result<PathBuf> {
        #[cfg(windows)]
        {
            let status = tokio::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command"])
                .arg(format!(
                    "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
                    archive_path.display(),
                    staging.display()
                ))
                .status()
                .await
                .context("failed to run Expand-Archive via powershell.exe")?;
            if !status.success() {
                bail!("Expand-Archive failed to unpack the downloaded release");
            }
        }

        #[cfg(not(windows))]
        {
            let status = tokio::process::Command::new("tar")
                .arg("-xzf")
                .arg(archive_path)
                .arg("-C")
                .arg(staging)
                .status()
                .await
                .context("failed to run tar -- is it installed and on PATH?")?;
            if !status.success() {
                bail!("tar failed to unpack the downloaded release");
            }
        }

        // Usually `<stem>/<binary>`, but a build an operator put on the
        // control plane may be laid out differently (or be another
        // version), so look for it.
        find_binary(staging, self.binary_name(), 3)
            .with_context(|| format!("the downloaded archive has no {} in it", self.binary_name()))
    }
}

/// The first file named `name` under `dir`, at most `depth` levels down.
fn find_binary(dir: &Path, name: &str, depth: usize) -> Option<PathBuf> {
    let direct = dir.join(name);
    if direct.is_file() {
        return Some(direct);
    }
    if depth == 0 {
        return None;
    }
    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();
    subdirs
        .iter()
        .find_map(|sub| find_binary(sub, name, depth - 1))
}

/// From the control plane, trusting what this agent trusts for it (its
/// pinned CA, or the OS roots for a publicly trusted certificate).
async fn download_from_control_plane(url: &str) -> anyhow::Result<Vec<u8>> {
    let trust = match crate::tls::current_trust() {
        Some(trust) => trust,
        None => crate::tls::Trust::os_only()?,
    };
    let client = trust
        .http_client(
            reqwest::Client::builder()
                .timeout(DOWNLOAD_TIMEOUT)
                .user_agent(concat!("abyssal-agent/", env!("CARGO_PKG_VERSION"))),
        )
        .context("failed to build the download client")?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to reach {url}"))?;
    let status = response.status();
    if !status.is_success() {
        // The control plane explains (no build for this OS, GitHub
        // unreachable, where to put one).
        let body = response.text().await.unwrap_or_default();
        bail!("{url} returned {status}: {}", body.trim());
    }
    Ok(response
        .bytes()
        .await
        .context("failed to read the downloaded build")?
        .to_vec())
}

async fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    // OS roots only: this goes to GitHub, and the control plane's own CA
    // (`--ca-cert`, which the control plane can update) must never be able
    // to vouch for where the agent's next binary comes from.
    let client = crate::tls::Trust::os_only()?
        .http_client(
            reqwest::Client::builder()
                .timeout(DOWNLOAD_TIMEOUT)
                // GitHub's release redirect chain is friendlier with a UA set;
                // reqwest follows the redirects to the object store by default.
                .user_agent(concat!("abyssal-agent/", env!("CARGO_PKG_VERSION"))),
        )
        .context("failed to build the download client")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to reach {url}"))?
        .error_for_status()
        .with_context(|| {
            format!(
                "release download returned an error status for {url} -- is that version published?"
            )
        })?;

    let bytes = response
        .bytes()
        .await
        .context("failed to read the downloaded release body")?;
    Ok(bytes.to_vec())
}

fn staging_dir() -> PathBuf {
    std::env::temp_dir().join("abyssal-agent-selfupdate")
}

// --- Platform-specific install + restart -------------------------------

#[cfg(unix)]
async fn install_and_restart(new_binary: &Path) -> anyhow::Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let target = PathBuf::from(crate::INSTALLED_BINARY_PATH);

    // Replace atomically: copy into a sibling temp file on the *same*
    // filesystem, harden it, then rename over the live path. A rename
    // swaps the directory entry to a brand-new inode -- the currently
    // running process keeps executing the old inode untouched until the
    // restart below, so there's no "text file busy"/torn-binary window.
    let staged = target.with_extension("new");
    tokio::fs::copy(new_binary, &staged)
        .await
        .with_context(|| format!("failed to stage the new binary at {}", staged.display()))?;

    let mut perms = tokio::fs::metadata(&staged).await?.permissions();
    perms.set_mode(0o755);
    tokio::fs::set_permissions(&staged, perms).await?;
    // Reuse the exact chown root:root + chmod 755 hardening the install
    // path applies, so a self-updated binary lands with the same
    // ownership/mode an operator-run `install` would produce.
    crate::harden_binary_permissions(&staged).await?;
    // Run from here, beside the installed binary: /tmp may be noexec.
    let version = match check_new_binary(&staged).await {
        Ok(version) => version,
        Err(e) => {
            let _ = tokio::fs::remove_file(&staged).await;
            return Err(e);
        }
    };

    tokio::fs::rename(&staged, &target).await.with_context(|| {
        format!(
            "failed to move the new binary into place at {}",
            target.display()
        )
    })?;

    schedule_restart_unix()?;
    let _ = tokio::fs::remove_dir_all(staging_dir()).await;

    Ok(format!(
        "Downloaded and installed abyssal-agent v{version} to {}. The agent will restart in a \
         couple of seconds and reconnect on the new build.",
        target.display()
    ))
}

/// Schedules `systemctl restart abyssal-agent` a couple of seconds out,
/// deliberately *outside* this service's own cgroup so restarting the unit
/// doesn't kill the very process asking for the restart before it lands.
/// `systemd-run` is the clean way to do that; if it isn't available, fall
/// back to a `setsid`-detached shell, and if even that can't be spawned,
/// surface the error so the caller learns the swap happened but the
/// restart didn't (the operator can restart by hand, or `Restart=always`
/// picks up the new binary on the next reconnect anyway).
#[cfg(unix)]
fn schedule_restart_unix() -> anyhow::Result<()> {
    let systemd_run = std::process::Command::new("systemd-run")
        .args([
            "--on-active=2",
            "--timer-property=AccuracySec=100ms",
            "systemctl",
            "restart",
            "abyssal-agent",
        ])
        .status();

    if let Ok(status) = systemd_run
        && status.success()
    {
        return Ok(());
    }

    // Fallback: detach a plain shell that sleeps then restarts. `setsid`
    // puts it in its own session so it isn't tied to this process's
    // controlling terminal; on a systemd host the cgroup caveat above is
    // why systemd-run is preferred, but this is still better than nothing
    // where systemd-run is absent.
    std::process::Command::new("setsid")
        .args(["sh", "-c", "sleep 2; systemctl restart abyssal-agent"])
        .spawn()
        .context(
            "binary was replaced, but scheduling the service restart failed (neither systemd-run \
             nor setsid could be started) -- restart abyssal-agent by hand to finish the update",
        )?;
    Ok(())
}

#[cfg(windows)]
async fn install_and_restart(new_binary: &Path) -> anyhow::Result<String> {
    // A running `.exe` is locked on Windows, so the live binary can't be
    // overwritten from within this process. Stage the new build alongside
    // it (hardened the same way `install` hardens the real one), then hand
    // a detached batch script the job of stopping the service, swapping the
    // file once it's actually unlocked, and starting it again.
    let target = PathBuf::from(crate::winservice::INSTALLED_BINARY_PATH);
    let staged =
        PathBuf::from(crate::winservice::INSTALLED_BINARY_DIR).join("abyssal-agent.new.exe");

    tokio::fs::copy(new_binary, &staged)
        .await
        .with_context(|| format!("failed to stage the new binary at {}", staged.display()))?;
    crate::winservice::harden_binary_acls(&staged)?;
    let version = match check_new_binary(&staged).await {
        Ok(version) => version,
        Err(e) => {
            let _ = tokio::fs::remove_file(&staged).await;
            return Err(e);
        }
    };

    let service = crate::winservice::SERVICE_NAME;
    let script_path = staging_dir().join("abyssal-agent-selfupdate.cmd");
    // Poll `sc query` until the service reports STOPPED before moving the
    // file -- `sc stop` returns before the process has actually exited, and
    // the move fails while the old .exe is still mapped. `ping -n` is the
    // console-less sleep (`timeout` needs a console this detached process
    // won't have). The script deletes itself last.
    let script = format!(
        "@echo off\r\n\
         sc stop \"{service}\"\r\n\
         :waitstop\r\n\
         sc query \"{service}\" | findstr /i \"STOPPED\" >nul\r\n\
         if errorlevel 1 (\r\n\
         ping -n 2 127.0.0.1 >nul\r\n\
         goto waitstop\r\n\
         )\r\n\
         move /y \"{staged}\" \"{target}\"\r\n\
         sc start \"{service}\"\r\n\
         del \"%~f0\"\r\n",
        service = service,
        staged = staged.display(),
        target = target.display(),
    );
    tokio::fs::write(&script_path, script)
        .await
        .with_context(|| {
            format!(
                "failed to write the updater script to {}",
                script_path.display()
            )
        })?;

    spawn_detached_windows(&script_path)?;

    Ok(format!(
        "Downloaded abyssal-agent v{version} and staged it at {}. A detached updater will stop the \
         service, swap the binary in, and start it again -- the host will briefly disconnect and \
         reconnect on the new build.",
        staged.display()
    ))
}

/// Launches the updater `.cmd` fully detached from this service process,
/// so it survives this process being killed when the service stops.
/// `DETACHED_PROCESS | CREATE_NO_WINDOW` keeps it off any console; a
/// service isn't in a kill-on-stop job object by default, so the child
/// keeps running once we stop.
#[cfg(windows)]
fn spawn_detached_windows(script_path: &Path) -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt;

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    std::process::Command::new("cmd.exe")
        .arg("/c")
        .arg(script_path)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context(
            "binary was staged, but launching the detached updater failed -- run the staged \
             abyssal-agent.new.exe's install by hand, or re-deploy the agent, to finish the update",
        )?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
async fn install_and_restart(_new_binary: &Path) -> anyhow::Result<String> {
    bail!("self-update is only supported on Linux and Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_validation_accepts_real_tags_and_rejects_junk() {
        assert!(is_plausible_version("0.1.3"));
        assert!(is_plausible_version("1.2.3-rc.1"));
        assert!(is_plausible_version("10.20.30+build.5"));

        assert!(!is_plausible_version(""));
        assert!(!is_plausible_version("../../etc/passwd"));
        assert!(!is_plausible_version("1.0/../.."));
        assert!(!is_plausible_version("1.0 && rm -rf"));
        assert!(!is_plausible_version("v1.0\nreboot"));
        assert!(!is_plausible_version(&"9".repeat(65)));
    }

    #[test]
    fn sha256_and_its_format() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_sha256_hex(&sha256_hex(b"x")));
        assert!(is_sha256_hex(&sha256_hex(b"x").to_uppercase()));
        assert!(!is_sha256_hex("abc"));
        assert!(!is_sha256_hex(&"g".repeat(64)));
    }

    #[test]
    fn reads_the_version_a_binary_reports() {
        assert_eq!(
            parse_version_output("abyssal-agent 0.2.3\n").as_deref(),
            Some("0.2.3")
        );
        assert_eq!(
            parse_version_output("abyssal-agent v1.0.0").as_deref(),
            Some("1.0.0")
        );
        assert_eq!(parse_version_output("Usage: something"), None);
        assert_eq!(parse_version_output(""), None);
    }

    #[test]
    fn finds_the_binary_wherever_the_archive_put_it() {
        let dir = std::env::temp_dir().join(format!("selfupdate-find-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let nested = dir.join("abyssal-agent-v9.9.9-x86_64-unknown-linux-gnu");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("README.md"), "").unwrap();
        assert_eq!(find_binary(&dir, "abyssal-agent", 3), None);
        std::fs::write(nested.join("abyssal-agent"), "").unwrap();
        assert_eq!(
            find_binary(&dir, "abyssal-agent", 3),
            Some(nested.join("abyssal-agent"))
        );
        assert_eq!(
            find_binary(&dir, "abyssal-agent", 0),
            None,
            "depth is bounded"
        );
        std::fs::write(dir.join("abyssal-agent"), "").unwrap();
        assert_eq!(
            find_binary(&dir, "abyssal-agent", 3),
            Some(dir.join("abyssal-agent"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_staged_binary_must_run_and_not_be_older() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("selfupdate-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fake = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let newer = fake("newer", "echo abyssal-agent 99.0.0");
        assert_eq!(check_new_binary(&newer).await.unwrap(), "99.0.0");
        let same = fake(
            "same",
            concat!("echo abyssal-agent ", env!("CARGO_PKG_VERSION")),
        );
        assert!(
            check_new_binary(&same).await.is_ok(),
            "the same version is allowed"
        );
        let older = fake("older", "echo abyssal-agent 0.0.1");
        assert!(
            check_new_binary(&older)
                .await
                .unwrap_err()
                .to_string()
                .contains("refusing to downgrade")
        );
        let broken = fake("broken", "echo not an agent; exit 1");
        assert!(check_new_binary(&broken).await.is_err());
        assert!(check_new_binary(&dir.join("missing")).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn downgrades_are_refused_and_same_or_newer_allowed() {
        assert!(is_downgrade("0.2.2", "0.2.1"));
        assert!(is_downgrade("1.0.0", "0.9.9"));
        assert!(!is_downgrade("0.2.2", "0.2.2"));
        assert!(!is_downgrade("0.2.2", "0.2.3"));
        assert!(!is_downgrade("0.2.2", "0.10.0"));
        assert!(
            !is_downgrade("0.2.2", "garbage"),
            "unparseable: not provably older"
        );
    }

    #[test]
    fn asset_names_match_the_release_workflow() {
        #[cfg(not(windows))]
        {
            let asset = PlatformAsset {
                stem: "abyssal-agent-v0.1.3-x86_64-unknown-linux-gnu".to_string(),
            };
            assert_eq!(
                asset.archive_name(),
                "abyssal-agent-v0.1.3-x86_64-unknown-linux-gnu.tar.gz"
            );
        }
        #[cfg(windows)]
        {
            let asset = PlatformAsset {
                stem: "abyssal-agent-v0.1.3-x86_64-pc-windows-msvc".to_string(),
            };
            assert_eq!(
                asset.archive_name(),
                "abyssal-agent-v0.1.3-x86_64-pc-windows-msvc.zip"
            );
        }
    }
}
