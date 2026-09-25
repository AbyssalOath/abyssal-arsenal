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
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

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

    let executable_path = std::env::current_exe()?;
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
