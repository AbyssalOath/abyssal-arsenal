//! Time-boxed sudo elevation ("Apotheosis"). Rather than inventing our own
//! credential cache, this leans on `sudo`'s own timestamp-cache mechanism --
//! the exact thing that already implements "don't ask again for N minutes"
//! for interactive sudo use. `sudo -S -v` validates a password via PAM and
//! populates that cache without running an arbitrary command as root;
//! afterwards, privileged commands run as `sudo -n <command>` (non-
//! interactive -- fail rather than hang if the cache has somehow lapsed).
//!
//! The password itself is never persisted anywhere, not even hashed: it's
//! held only long enough to hand to `sudo`'s stdin, then actively wiped via
//! `zeroize::Zeroizing` rather than just dropped.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::process::{run_command, run_command_allow_failure, run_command_with_stdin};
use abyssal_agent_protocol::OperationOutput;

/// Used only by tests -- real elevation windows arrive per-`Elevate`-call
/// from the control plane (`AgentOperation::Elevate::idle_timeout_secs`).
#[cfg(test)]
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(20 * 60);

#[derive(Clone, Default)]
pub struct ElevationState(Arc<Mutex<Option<(Instant, Duration)>>>);

impl ElevationState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates `password` against this host's sudo/PAM stack and, on
    /// success, starts (or refreshes) the elevation window using the
    /// control-plane-supplied `idle_timeout`. The password is wiped from
    /// memory as soon as this call returns, regardless of outcome.
    pub async fn elevate(
        &self,
        password: Zeroizing<String>,
        idle_timeout: Duration,
    ) -> Result<(), String> {
        let result = run_sudo_validate(&password).await;
        // `password` (and the temporary stdin buffer inside
        // `run_sudo_validate`) are `Zeroizing`, so they're actively wiped
        // here when dropped, not just deallocated.
        drop(password);

        result?;
        *self.0.lock().await = Some((Instant::now(), idle_timeout));
        Ok(())
    }

    /// Clears elevation early and best-effort invalidates sudo's own cache
    /// too, in case its configured `timestamp_timeout` is longer than ours.
    pub async fn deescalate(&self) {
        *self.0.lock().await = None;
        let _ = Command::new("sudo").arg("-k").output().await;
    }

    /// True if currently elevated and the idle window hasn't lapsed.
    /// Refreshes the window on every successful check (sliding expiry, not
    /// a fixed one), and clears state once it has lapsed.
    pub async fn is_elevated(&self) -> bool {
        let mut guard = self.0.lock().await;
        match *guard {
            Some((last_used, idle_timeout)) if last_used.elapsed() < idle_timeout => {
                *guard = Some((Instant::now(), idle_timeout));
                true
            }
            Some(_) => {
                *guard = None;
                false
            }
            None => false,
        }
    }

    /// Human-readable status for the `ElevationStatus` operation.
    pub async fn status_text(&self) -> String {
        if self.is_elevated().await {
            let remaining = {
                let guard = self.0.lock().await;
                guard
                    .map(|(since, idle_timeout)| idle_timeout.saturating_sub(since.elapsed()))
                    .unwrap_or_default()
            };
            let minutes = remaining.as_secs() / 60;
            let seconds = remaining.as_secs() % 60;
            format!("Elevated -- expires in {minutes}m{seconds:02}s of inactivity")
        } else {
            "Not elevated".to_string()
        }
    }

    /// Runs a command, transparently going through `sudo -n` if currently
    /// elevated, or unprivileged otherwise. The one entry point operations
    /// that might need root use instead of calling `process::run_command`
    /// directly.
    pub async fn run(&self, program: &str, args: &[&str]) -> Result<OperationOutput, String> {
        if self.is_elevated().await {
            let mut sudo_args = Vec::with_capacity(args.len() + 2);
            sudo_args.push("-n");
            sudo_args.push(program);
            sudo_args.extend_from_slice(args);
            run_command("sudo", &sudo_args).await
        } else {
            run_command(program, args).await
        }
    }

    /// Like `run`, but via `process::run_command_allow_failure` -- for tools
    /// whose own exit code conventions use non-zero to mean "ran fine, found
    /// nothing" rather than "something went wrong" (`coredumpctl list` with
    /// no recorded dumps, `find` hitting one unreadable subdirectory while
    /// still finding everything else).
    pub async fn run_allow_failure(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<OperationOutput, String> {
        if self.is_elevated().await {
            let mut sudo_args = Vec::with_capacity(args.len() + 2);
            sudo_args.push("-n");
            sudo_args.push(program);
            sudo_args.extend_from_slice(args);
            run_command_allow_failure("sudo", &sudo_args).await
        } else {
            run_command_allow_failure(program, args).await
        }
    }

    /// Like `run`, but feeds `stdin_data` to the process -- e.g. writing a
    /// config file via `tee` on hosts that need to be told a value through
    /// stdin rather than an argument.
    pub async fn run_with_stdin(
        &self,
        program: &str,
        args: &[&str],
        stdin_data: &str,
    ) -> Result<OperationOutput, String> {
        if self.is_elevated().await {
            let mut sudo_args = Vec::with_capacity(args.len() + 2);
            sudo_args.push("-n");
            sudo_args.push(program);
            sudo_args.extend_from_slice(args);
            run_command_with_stdin("sudo", &sudo_args, stdin_data).await
        } else {
            run_command_with_stdin(program, args, stdin_data).await
        }
    }
}

async fn run_sudo_validate(password: &Zeroizing<String>) -> Result<(), String> {
    let mut child = Command::new("sudo")
        .args(["-S", "-v"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run sudo: {e}"))?;

    let mut stdin_line: Zeroizing<String> =
        Zeroizing::new(String::with_capacity(password.len() + 1));
    stdin_line.push_str(password);
    stdin_line.push('\n');

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open sudo stdin".to_string())?;
        write_all_ignoring_broken_pipe(stdin, stdin_line.as_bytes())
            .await
            .map_err(|e| format!("failed to send password to sudo: {e}"))?;
    }
    drop(stdin_line);

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("failed to wait for sudo: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim()
        } else {
            "authentication failed"
        };
        return Err(format!("sudo: {detail}"));
    }

    Ok(())
}

/// Sudo can close stdin before we finish writing if it rejects the attempt
/// quickly; treat a broken pipe as "sudo already decided," not a hard error
/// -- the real answer comes from its exit status, checked by the caller.
async fn write_all_ignoring_broken_pipe(
    stdin: &mut tokio::process::ChildStdin,
    bytes: &[u8],
) -> io::Result<()> {
    match stdin.write_all(bytes).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn not_elevated_by_default() {
        let state = ElevationState::new();
        assert!(!state.is_elevated().await);
        assert_eq!(state.status_text().await, "Not elevated");
    }

    #[tokio::test]
    async fn deescalate_clears_elevation() {
        let state = ElevationState::new();
        // Simulate a successful elevation without invoking real sudo.
        *state.0.lock().await = Some((Instant::now(), DEFAULT_IDLE_TIMEOUT));
        assert!(state.is_elevated().await);

        state.deescalate().await;
        assert!(!state.is_elevated().await);
    }

    #[tokio::test]
    async fn idle_window_expires() {
        let state = ElevationState::new();
        // Backdate the "last used" timestamp past the idle window.
        *state.0.lock().await = Instant::now()
            .checked_sub(DEFAULT_IDLE_TIMEOUT + Duration::from_secs(1))
            .map(|t| (t, DEFAULT_IDLE_TIMEOUT));
        assert!(!state.is_elevated().await);
    }

    #[tokio::test]
    async fn checking_status_refreshes_the_window() {
        let state = ElevationState::new();
        *state.0.lock().await = Some((
            Instant::now() - Duration::from_secs(60),
            DEFAULT_IDLE_TIMEOUT,
        ));
        assert!(state.is_elevated().await);
        let (refreshed, _) = state.0.lock().await.unwrap();
        assert!(refreshed.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn configured_idle_timeout_is_used_over_the_default() {
        let state = ElevationState::new();
        // A short custom window backdated past itself but within the
        // default -- proves the per-elevation duration is what's checked,
        // not the module default.
        *state.0.lock().await = Some((
            Instant::now() - Duration::from_secs(5),
            Duration::from_secs(1),
        ));
        assert!(!state.is_elevated().await);
    }
}
