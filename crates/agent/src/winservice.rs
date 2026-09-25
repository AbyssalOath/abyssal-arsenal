//! Windows Service Control Manager integration -- lets `abyssal-agent`
//! register and run as a native Windows service (`LocalSystem`), the
//! same role systemd plays on Linux (see `install_systemd_service` in
//! `main.rs`, which this mirrors). `LocalSystem` already has full Event
//! Log/registry read access, so there's no elevation-on-demand
//! equivalent needed here the way Linux's sudo-based `ElevationState`
//! provides for privileged reads/writes -- a deliberate model
//! divergence, not a gap: see `crates/agent/README.md`.
//!
//! Two halves: `install_service` (called once, from the `install`
//! command, to register the service with the SCM) and `run_as_service`
//! (what the registered service's executable path actually points at,
//! invoked by the SCM on every subsequent boot).
//!
//! Shutdown here is exactly as abrupt as the systemd path already is:
//! neither this codebase's `run()` reconnect loop nor its Linux systemd
//! unit install any graceful-shutdown handling today (`systemctl stop`
//! just SIGTERMs the process, which the OS handles by terminating it
//! immediately since no signal handler is registered anywhere in this
//! crate) -- reporting `SERVICE_STOPPED` back to the SCM and exiting the
//! process on a stop control is the equivalent here, not a regression
//! from the Linux path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "abyssal-agent";
const SERVICE_DISPLAY_NAME: &str = "Abyssal Arsenal Agent";
const SERVICE_DESCRIPTION: &str =
    "Connects this host to its Abyssal Arsenal control plane and serves managed-host operations.";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Where the interactive `install` command's own copy of the binary
/// lives -- `Program Files`, not `ProgramData` (already used for
/// `credentials.json`): the former is where Windows itself blocks
/// standard-user write access by default, the latter is meant for data,
/// not executables. See `install_agent_binary`'s doc comment for why
/// this needs to be a fixed, hardened path at all.
const INSTALLED_BINARY_DIR: &str = r"C:\Program Files\AbyssalAgent";
const INSTALLED_BINARY_PATH: &str = r"C:\Program Files\AbyssalAgent\abyssal-agent.exe";

define_windows_service!(ffi_service_main, service_main);

/// Registers (or, on a re-run, reconfigures) `abyssal-agent run <args>`
/// as an auto-start `LocalSystem` service and starts it immediately --
/// the Windows analog of `install_systemd_service`'s write-unit +
/// `daemon-reload` + `enable --now`. `launch_arguments` bakes in
/// `--control-plane-url` (and `--credentials-file`, if non-default) the
/// same way the systemd unit's `ExecStart` line does, since neither
/// platform persists the control-plane URL anywhere credentials do.
pub fn install_service(control_plane_url: &str, credentials_file: &Path) -> anyhow::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let executable_path = install_agent_binary()?;
    let mut launch_arguments = vec![
        OsString::from("run"),
        OsString::from("--control-plane-url"),
        OsString::from(control_plane_url),
    ];
    if credentials_file != Path::new(crate::DEFAULT_CREDENTIALS_FILE) {
        launch_arguments.push(OsString::from("--credentials-file"));
        launch_arguments.push(credentials_file.as_os_str().to_owned());
    }

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments,
        dependencies: vec![],
        account_name: None, // None == LocalSystem
        account_password: None,
    };

    if let Ok(existing) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    ) {
        existing.change_config(&service_info)?;
        let _ = existing.start::<&str>(&[]);
        return Ok(());
    }

    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service.set_description(SERVICE_DESCRIPTION)?;
    service.start::<&str>(&[])?;
    Ok(())
}

/// Copies the currently-running binary to a fixed, hardened system
/// location (`INSTALLED_BINARY_PATH`) if it isn't already running from
/// there, then re-asserts its ACLs, and returns that canonical path for
/// the SCM's `executable_path` to use.
///
/// A `LocalSystem` service must never point at a binary sitting wherever
/// the operator happened to download/extract it to (a Downloads folder,
/// a home directory) -- that location is typically writable by their own
/// standard-user account. Left as `current_exe()` verbatim, that account
/// (or anything that compromises it) could silently replace the binary,
/// and the next service (re)start would run attacker-controlled code as
/// `LocalSystem` -- the exact privilege-escalation shape a local
/// vulnerability scan flagged against this pattern on the Linux side
/// (see `install_agent_binary` in `crates/agent/src/main.rs`, which this
/// mirrors). Skips the copy (but still re-hardens ACLs, so a repair-run
/// re-asserts them) when already running from `INSTALLED_BINARY_PATH`.
fn install_agent_binary() -> anyhow::Result<PathBuf> {
    let current_exe =
        std::env::current_exe().context("could not determine this binary's own path")?;
    let target = PathBuf::from(INSTALLED_BINARY_PATH);

    if current_exe != target {
        std::fs::create_dir_all(INSTALLED_BINARY_DIR)
            .with_context(|| format!("failed to create {INSTALLED_BINARY_DIR}"))?;
        std::fs::copy(&current_exe, &target).with_context(|| {
            format!("failed to install the agent binary to {}", target.display())
        })?;
        println!("Installed binary to {}", target.display());
    }

    harden_binary_acls(&target)?;
    Ok(target)
}

/// Strips inherited ACL entries and grants full control only to `SYSTEM`
/// and `Administrators`, read-and-execute to `Users` -- explicit, not
/// relied on implicitly from "`Program Files` already blocks standard-
/// user writes by default": stating the property directly here means it
/// holds even if the parent directory's own ACLs are ever looser than
/// expected, and matches the literal remediation a security scan would
/// recommend for this vulnerability class. Shelled out to `icacls`
/// (matching this codebase's existing "shell out to a real system tool"
/// convention, the same reasoning every other Windows-specific data
/// source/action in this crate already follows) rather than raw ACL
/// FFI. Well-known SIDs (`S-1-5-18` = SYSTEM, `S-1-5-32-544` =
/// Administrators, `S-1-5-32-545` = Users) are used instead of group
/// names, which are themselves localized on a non-English Windows
/// install.
fn harden_binary_acls(path: &Path) -> anyhow::Result<()> {
    let path_str = path.to_string_lossy();
    let status = std::process::Command::new("icacls")
        .arg(path_str.as_ref())
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:F")
        .arg("*S-1-5-32-544:F")
        .arg("*S-1-5-32-545:RX")
        .status()
        .context("failed to run icacls -- is it available on this system?")?;
    if !status.success() {
        anyhow::bail!("icacls hardening of {} failed", path.display());
    }
    Ok(())
}

/// Entry point when launched by the SCM (not interactively) -- this is
/// what the registered `executable_path` above actually runs on every
/// subsequent boot. Blocks for the lifetime of the service; returns an
/// error immediately (without blocking) when there's no SCM control
/// pipe available, i.e. when the binary was launched directly rather
/// than by the SCM -- callers use that to fall back to the ordinary
/// interactive `run()` path.
pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        tracing::error!(error = %e, "Windows service run failed");
    }
}

fn run_service(arguments: Vec<OsString>) -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // The SCM invokes this executable with exactly the `launch_arguments`
    // `install_service` registered, the same shape clap's own `Cli` parses
    // from a normal interactive launch -- reuse that parsing rather than
    // duplicating it, so the two never drift out of sync.
    let mut full_args = vec![OsString::from(SERVICE_NAME)];
    full_args.extend(arguments);
    let cli = <crate::Cli as clap::Parser>::parse_from(full_args);

    // Runs on this dedicated OS thread the SCM handed the service,
    // reusing the same async `run()` reconnect loop the interactive path
    // uses -- identical backoff/reconnect behavior on both platforms.
    let runtime = tokio::runtime::Runtime::new()?;
    let handle = runtime.spawn(async move {
        if let Some(crate::Command::Run {
            control_plane_url,
            enrollment_token,
            name,
            credentials_file,
        }) = cli.command
        {
            let _ = crate::run(control_plane_url, enrollment_token, name, credentials_file).await;
        }
    });

    // `run()` never returns on its own (infinite reconnect loop) -- the
    // only way out of this thread is the stop signal below, matching
    // systemd's own SIGTERM-only shutdown for this agent today.
    loop {
        match shutdown_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(()) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if handle.is_finished() {
                    break;
                }
            }
        }
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
