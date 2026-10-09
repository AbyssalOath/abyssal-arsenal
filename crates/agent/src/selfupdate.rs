//! In-place agent self-update, the in-band answer to a host showing "Agent
//! out of date" in the control plane's `/admin/hosts` list. Triggered by
//! `AgentOperation::SelfUpdate { version }` (see the variant's own doc
//! comment in `abyssal-agent-protocol`), it downloads the matching release
//! for this host's own platform from the project's GitHub releases,
//! replaces the installed binary (the same fixed, hardened path
//! `install` copies to), and bounces the host's service manager so the new
//! build takes over.
//!
//! **Trust model.** The wire only ever carries a *version tag*, never a
//! URL: the download source is built here from that tag plus this binary's
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

pub async fn self_update(version: String) -> CommandOutcome {
    match run_self_update(&version).await {
        Ok(message) => CommandOutcome::Ok(OperationOutput {
            stdout: message,
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(format!("self-update to v{version} failed: {e:#}")),
    }
}

async fn run_self_update(version: &str) -> anyhow::Result<String> {
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
    let url = format!("{GITHUB_DOWNLOAD_BASE}/v{version}/{}", asset.archive_name());

    let staging = staging_dir();
    // A stale staging dir from a previous run must never be trusted to
    // hold the right binary -- clear it before extracting into it.
    let _ = tokio::fs::remove_dir_all(&staging).await;
    tokio::fs::create_dir_all(&staging)
        .await
        .with_context(|| format!("could not create staging dir {}", staging.display()))?;

    let archive_path = staging.join(asset.archive_name());
    let bytes = download(&url).await?;
    tokio::fs::write(&archive_path, &bytes)
        .await
        .with_context(|| {
            format!(
                "could not write downloaded archive to {}",
                archive_path.display()
            )
        })?;

    let new_binary = asset.extract(&staging, &archive_path).await?;

    install_and_restart(&new_binary, version).await
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

        let binary = staging.join(&self.stem).join(self.binary_name());
        if tokio::fs::metadata(&binary).await.is_err() {
            bail!(
                "downloaded release did not contain the expected binary at {}",
                binary.display()
            );
        }
        Ok(binary)
    }
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
async fn install_and_restart(new_binary: &Path, version: &str) -> anyhow::Result<String> {
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
async fn install_and_restart(new_binary: &Path, version: &str) -> anyhow::Result<String> {
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
async fn install_and_restart(_new_binary: &Path, _version: &str) -> anyhow::Result<String> {
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
