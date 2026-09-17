mod elevation;
mod enroll;
mod firewall;
mod init_system;
mod network;
mod ops;
mod postmortem;
mod process;
mod transport;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "abyssal-agent",
    version,
    about = "Abyssal Arsenal managed-host agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll (on first run) and connect to the control plane, serving
    /// commands until interrupted. Safe to run repeatedly / under a
    /// supervisor like systemd — once credentials exist, `--enrollment-token`
    /// is ignored.
    Run {
        /// Base HTTP(S) URL of the control plane, e.g. https://arsenal.example.com
        #[arg(long)]
        control_plane_url: String,
        /// One-time enrollment token from /admin/hosts. Only needed the
        /// first time this host connects.
        #[arg(long)]
        enrollment_token: Option<String>,
        /// Display name to register this host as. Defaults to the contents
        /// of /etc/hostname.
        #[arg(long)]
        name: Option<String>,
        /// Where to persist credentials after enrollment.
        #[arg(long, default_value = "/etc/abyssal-agent/credentials.json")]
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
        Command::Run {
            control_plane_url,
            enrollment_token,
            name,
            credentials_file,
        } => run(control_plane_url, enrollment_token, name, credentials_file).await,
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
