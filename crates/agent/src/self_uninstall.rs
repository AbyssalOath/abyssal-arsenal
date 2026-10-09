//! `UninstallAgent`: removing a host on the control plane uninstalls its
//! agent. This process is the service being removed, so it only *schedules*
//! the uninstall -- in a detached process that outlives the service stopping
//! -- and replies first. The uninstall itself is the same `uninstall` an
//! admin would run (or `msiexec /x` for an MSI install).

use std::path::PathBuf;
use std::sync::OnceLock;

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

static CREDENTIALS_FILE: OnceLock<PathBuf> = OnceLock::new();

/// Called by `run` so a scheduled uninstall removes the credentials this
/// agent actually uses, not just the default path.
pub fn set_credentials_file(path: PathBuf) {
    let _ = CREDENTIALS_FILE.set(path);
}

fn credentials_file() -> PathBuf {
    CREDENTIALS_FILE
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(crate::DEFAULT_CREDENTIALS_FILE))
}

pub async fn uninstall_agent(purge: bool) -> CommandOutcome {
    match schedule(purge) {
        Ok(message) => CommandOutcome::Ok(OperationOutput {
            stdout: message,
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(format!("couldn't uninstall the agent: {e:#}")),
    }
}

/// The `uninstall` arguments the detached process runs.
fn uninstall_args(purge: bool, credentials: &std::path::Path) -> Vec<String> {
    let mut args = vec![
        "uninstall".to_string(),
        "--non-interactive".to_string(),
        "--credentials-file".to_string(),
        credentials.display().to_string(),
    ];
    if purge {
        args.push("--purge".to_string());
    }
    args
}

#[cfg(unix)]
fn schedule(purge: bool) -> anyhow::Result<String> {
    use anyhow::Context;

    if !crate::running_as_root() {
        anyhow::bail!(
            "this agent isn't running as root (it was started by hand?), so it can't remove its \
             own service -- run `sudo abyssal-agent uninstall --purge` on the host"
        );
    }
    let exe = std::env::current_exe().context("couldn't find this agent's own binary")?;
    let args = uninstall_args(purge, &credentials_file());

    // systemd-run puts it in its own transient unit, outside this service's
    // cgroup, so stopping abyssal-agent doesn't kill it partway through.
    let systemd_run = std::process::Command::new("systemd-run")
        .args(["--on-active=2", "--timer-property=AccuracySec=100ms"])
        .arg(&exe)
        .args(&args)
        .status();
    if !matches!(systemd_run, Ok(status) if status.success()) {
        let quoted: Vec<String> = std::iter::once(exe.display().to_string())
            .chain(args)
            .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
            .collect();
        let mut child = std::process::Command::new("setsid")
            .args(["sh", "-c", &format!("sleep 2; {}", quoted.join(" "))])
            .spawn()
            .context("neither systemd-run nor setsid could start the uninstall")?;
        // Reap it if this process outlives it (no service to stop).
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    Ok(format!(
        "Uninstalling abyssal-agent{} in a couple of seconds; this host will disconnect.",
        if purge {
            " and removing its enrollment"
        } else {
            ""
        }
    ))
}

#[cfg(windows)]
fn schedule(purge: bool) -> anyhow::Result<String> {
    use anyhow::Context;
    use std::os::windows::process::CommandExt;

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    // An MSI install must be removed by Windows Installer, or Apps &
    // features keeps listing a broken product. Its uninstall runs the
    // agent's own `uninstall` (PURGE=1 adds --purge).
    let command = if crate::winservice::is_msi_managed() {
        let code = crate::winservice::msi_product_code().context(
            "this agent was installed with the MSI, but its Apps & features entry wasn't found \
             -- uninstall it from Apps & features",
        )?;
        format!(
            "msiexec.exe /x {code} /qn /norestart{}",
            if purge { " PURGE=1" } else { "" }
        )
    } else {
        let exe = std::env::current_exe().context("couldn't find this agent's own binary")?;
        let args: Vec<String> = uninstall_args(purge, &credentials_file())
            .into_iter()
            .map(|a| format!("\"{a}\""))
            .collect();
        format!("\"{}\" {}", exe.display(), args.join(" "))
    };
    // `ping -n 3` is the console-less two-second sleep, so the reply gets
    // out before the service stops.
    std::process::Command::new("cmd.exe")
        .raw_arg(format!("/d /c ping -n 3 127.0.0.1 >nul & {command}"))
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context("couldn't start the uninstall")?;
    Ok(format!(
        "Uninstalling abyssal-agent{} in a couple of seconds; this host will disconnect.",
        if purge {
            " and removing its enrollment"
        } else {
            ""
        }
    ))
}

#[cfg(not(any(unix, windows)))]
fn schedule(_purge: bool) -> anyhow::Result<String> {
    anyhow::bail!("uninstalling isn't supported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_runs_non_interactively_against_the_right_credentials() {
        let args = uninstall_args(
            true,
            std::path::Path::new("/etc/abyssal-agent/credentials.json"),
        );
        assert_eq!(
            args,
            [
                "uninstall",
                "--non-interactive",
                "--credentials-file",
                "/etc/abyssal-agent/credentials.json",
                "--purge"
            ]
        );
        assert!(!uninstall_args(false, std::path::Path::new("x")).contains(&"--purge".to_string()));
    }
}
