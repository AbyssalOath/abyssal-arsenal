mod apothecary;
mod catacomb;
mod cryptkeeper;
mod defleshing;
mod elevation;
mod enroll;
mod firewall;
mod grimoire;
mod incarnation;
mod init_system;
mod inquest;
mod mortiscope;
mod necropolis;
mod necropsy;
mod network;
mod obituary;
mod ops;
mod ossuary;
mod parish;
mod postmortem;
mod process;
mod reanimation;
mod reliquary;
mod resurrection;
mod sepulchre;
mod thanatos;
mod transport;
mod vivisection;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};

const DEFAULT_CREDENTIALS_FILE: &str = "/etc/abyssal-agent/credentials.json";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/abyssal-agent.service";

#[derive(Parser)]
#[command(
    name = "abyssal-agent",
    version,
    about = "Abyssal Arsenal managed-host agent"
)]
struct Cli {
    /// Defaults to `install` (interactive setup) when run with no
    /// subcommand at all -- see that command's own help.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll (on first run) and connect to the control plane, serving
    /// commands until interrupted. Safe to run repeatedly / under a
    /// supervisor like systemd — once credentials exist, `--enrollment-token`
    /// is ignored. This is what the systemd service `install` sets up
    /// actually runs; run it directly yourself only for manual/scripted
    /// setups.
    Run {
        /// Base HTTP(S) URL of the control plane, e.g. https://arsenal.example.com
        #[arg(long)]
        control_plane_url: String,
        /// One-time enrollment token from /admin/hosts. Only needed the
        /// first time this host connects. Generated tokens are
        /// base64url and can start with `-`; `allow_hyphen_values`
        /// keeps clap from mistaking that for a flag of its own.
        #[arg(long, allow_hyphen_values = true)]
        enrollment_token: Option<String>,
        /// Display name to register this host as. Defaults to the contents
        /// of /etc/hostname.
        #[arg(long)]
        name: Option<String>,
        /// Where to persist credentials after enrollment.
        #[arg(long, default_value = DEFAULT_CREDENTIALS_FILE)]
        credentials_file: PathBuf,
    },
    /// Interactively enrolls this host and installs/enables a systemd
    /// service for it, prompting for anything not already given as a flag
    /// -- the seamless "just run it" path. Needs root (to write the
    /// credentials file and manage the systemd service); if not already
    /// running as one, offers to re-exec itself under `sudo` rather than
    /// failing partway through. Safe to re-run: an already-enrolled host
    /// skips straight to the service setup.
    Install {
        #[arg(long)]
        control_plane_url: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        enrollment_token: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = DEFAULT_CREDENTIALS_FILE)]
        credentials_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Run {
            control_plane_url,
            enrollment_token,
            name,
            credentials_file,
        }) => run(control_plane_url, enrollment_token, name, credentials_file).await,
        Some(Command::Install {
            control_plane_url,
            enrollment_token,
            name,
            credentials_file,
        }) => install(control_plane_url, enrollment_token, name, credentials_file).await,
        None => install(None, None, None, PathBuf::from(DEFAULT_CREDENTIALS_FILE)).await,
    }
}

async fn run(
    control_plane_url: String,
    enrollment_token: Option<String>,
    name: Option<String>,
    credentials_file: PathBuf,
) -> anyhow::Result<()> {
    let credentials = enroll::load_or_enroll(
        &control_plane_url,
        enrollment_token,
        name,
        &credentials_file,
    )
    .await?;
    let ws_url = transport::to_ws_url(&control_plane_url)?;

    // Constructed once, outside the reconnect loop: a dropped/reconnected
    // WebSocket shouldn't clear root access on its own -- only the idle
    // timeout, an explicit de-escalate, or the process actually exiting
    // should.
    let elevation = elevation::ElevationState::new();

    let mut backoff = Duration::from_secs(1);
    loop {
        match transport::connect_and_serve(&ws_url, &credentials.credential, &elevation).await {
            Ok(()) => tracing::warn!("connection to control plane closed; reconnecting"),
            Err(e) => tracing::error!(error = %e, "connection error; retrying"),
        }
        tracing::info!(delay = ?backoff, "reconnecting after backoff");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// The interactive/seamless install path: enroll (if not already), then
/// write and enable a systemd unit so the agent survives a reboot without
/// the operator having to hand-author one -- see `crates/agent/README.md`
/// for the manual equivalent this mirrors exactly.
async fn install(
    control_plane_url: Option<String>,
    enrollment_token: Option<String>,
    name: Option<String>,
    credentials_file: PathBuf,
) -> anyhow::Result<()> {
    println!("Abyssal Arsenal agent setup\n");

    ensure_root_or_reexec()?;

    let already_enrolled = tokio::fs::metadata(&credentials_file).await.is_ok();
    if already_enrolled {
        println!(
            "Found existing credentials at {} -- skipping enrollment.",
            credentials_file.display()
        );
    }

    let control_plane_url = match control_plane_url {
        Some(url) => url,
        None => prompt("Control plane URL (e.g. https://arsenal.example.com): ")?,
    };

    let enrollment_token = if already_enrolled {
        None
    } else {
        match enrollment_token {
            Some(token) => Some(token),
            None => Some(prompt("Enrollment token (from /admin/hosts): ")?),
        }
    };

    let credentials = enroll::load_or_enroll(
        &control_plane_url,
        enrollment_token,
        name,
        &credentials_file,
    )
    .await?;
    println!("Enrolled as host {}", credentials.host_id);

    if init_system::detect().await != init_system::InitSystem::Systemd {
        println!(
            "\nNo systemd detected on this host -- skipping service setup. Run it directly \
             (`abyssal-agent run --control-plane-url {control_plane_url}`) under whatever \
             supervisor this host actually uses instead."
        );
        return Ok(());
    }

    install_systemd_service(&control_plane_url, &credentials_file).await?;

    println!(
        "\nDone. abyssal-agent is enrolled and running as a systemd service.\n\
         Check on it any time with: systemctl status abyssal-agent"
    );
    Ok(())
}

fn prompt(label: &str) -> anyhow::Result<String> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context(
        "failed to read from stdin -- pass this as a flag instead if running non-interactively",
    )?;
    let value = line.trim().to_string();
    if value.is_empty() {
        anyhow::bail!("a value is required");
    }
    Ok(value)
}

/// Same shape as `prompt`, but accepts an empty answer as `default_yes`
/// instead of erroring -- for a yes/no confirmation, not a required value.
fn prompt_yes_no(label: &str, default_yes: bool) -> anyhow::Result<bool> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context(
        "failed to read from stdin -- re-run this as root instead if running non-interactively",
    )?;
    let answer = line.trim().to_lowercase();
    if answer.is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(answer.as_str(), "y" | "yes"))
}

/// True on Unix once the effective UID is 0. Always false on any other
/// target -- `abyssal-agent` only ever runs on Linux hosts in practice, so
/// this is just a defensive fallback rather than real cross-platform
/// support.
fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid() takes no arguments, touches no memory, and
        // cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// `install` needs root (to write the credentials file and manage the
/// systemd service). Rather than failing outright, offer to re-exec
/// under `sudo` -- same interactive prompt-then-`exec sudo "$0" "$@"`
/// pattern already familiar from plenty of install scripts. `exec()`
/// replaces this process image entirely (never returns on success), so
/// the re-exec'd process picks up exactly where this one would have,
/// just with EUID 0 -- `running_as_root()` short-circuits immediately on
/// its next call, no risk of looping.
fn ensure_root_or_reexec() -> anyhow::Result<()> {
    if running_as_root() {
        return Ok(());
    }

    println!("Root privileges are required to enroll this host and manage its systemd service.");
    if !prompt_yes_no("Run this with sudo now? [Y/n]: ", true)? {
        anyhow::bail!("root is required to continue -- re-run with sudo");
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let current_exe =
            std::env::current_exe().context("could not determine this binary's own path")?;
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

        // Only returns if sudo itself couldn't even be started (not
        // installed, not on PATH, ...) -- a successful exec never returns
        // here at all.
        let err = std::process::Command::new("sudo")
            .arg(&current_exe)
            .args(&args)
            .exec();
        Err(err).context("failed to re-exec with sudo -- is sudo installed and on PATH?")
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("automatic sudo re-exec is only supported on Unix; re-run this as root")
    }
}

async fn install_systemd_service(
    control_plane_url: &str,
    credentials_file: &Path,
) -> anyhow::Result<()> {
    let binary_path =
        std::env::current_exe().context("could not determine this binary's own path")?;

    let mut exec_start = format!(
        "{} run --control-plane-url {control_plane_url}",
        binary_path.display()
    );
    if credentials_file != Path::new(DEFAULT_CREDENTIALS_FILE) {
        exec_start.push_str(&format!(
            " --credentials-file {}",
            credentials_file.display()
        ));
    }

    let unit = format!(
        "[Unit]\n\
         Description=Abyssal Arsenal agent\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={exec_start}\n\
         Restart=always\n\
         RestartSec=5\n\
         User=root\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );

    if tokio::fs::metadata(SYSTEMD_UNIT_PATH).await.is_ok() {
        println!("Overwriting existing {SYSTEMD_UNIT_PATH}");
    }
    tokio::fs::write(SYSTEMD_UNIT_PATH, unit)
        .await
        .with_context(|| {
            format!("failed to write {SYSTEMD_UNIT_PATH} -- this needs root, re-run with sudo")
        })?;
    println!("Wrote {SYSTEMD_UNIT_PATH}");

    run_systemctl(&["daemon-reload"]).await?;
    run_systemctl(&["enable", "--now", "abyssal-agent"]).await?;
    println!("Enabled and started the abyssal-agent service");

    Ok(())
}

async fn run_systemctl(args: &[&str]) -> anyhow::Result<()> {
    let status = tokio::process::Command::new("systemctl")
        .args(args)
        .status()
        .await
        .context("failed to run systemctl -- is this host actually managed by systemd?")?;
    if !status.success() {
        anyhow::bail!("systemctl {} failed", args.join(" "));
    }
    Ok(())
}
