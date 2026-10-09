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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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
pub(crate) const INSTALLED_BINARY_DIR: &str = r"C:\Program Files\AbyssalAgent";
pub(crate) const INSTALLED_BINARY_PATH: &str = r"C:\Program Files\AbyssalAgent\abyssal-agent.exe";

define_windows_service!(ffi_service_main, service_main);

/// Set once the SCM has started this process as the service: from then on
/// log output goes to [`LOG_FILE`] instead of stderr, which a service
/// doesn't have.
static SERVICE_MODE: AtomicBool = AtomicBool::new(false);

/// The service's log, beside `credentials.json` -- the only place to see why
/// it stopped or can't reach the control plane. Rotated once at
/// [`LOG_MAX_BYTES`] to `agent.log.1`, so it can't grow without bound.
pub(crate) const LOG_FILE: &str = r"C:\ProgramData\abyssal-agent\agent.log";
const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Appends one line to [`LOG_FILE`], best-effort -- for failures outside the
/// service (an unattended install), which have no tracing writer pointed
/// there.
pub(crate) fn append_log(line: &str) {
    if let Some(dir) = Path::new(LOG_FILE).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
    {
        let _ = writeln!(file, "{} {line}", chrono::Utc::now().to_rfc3339());
    }
}

/// `tracing_subscriber`'s writer for every event: stderr normally, the
/// service log file once in service mode. Falls back to stderr (i.e.
/// nowhere) rather than failing the event if the file can't be opened.
pub(crate) fn log_writer() -> Box<dyn Write> {
    if SERVICE_MODE.load(Ordering::Relaxed) {
        if std::fs::metadata(LOG_FILE).is_ok_and(|m| m.len() > LOG_MAX_BYTES) {
            let _ = std::fs::rename(LOG_FILE, format!("{LOG_FILE}.1"));
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_FILE)
        {
            return Box::new(file);
        }
    }
    Box::new(std::io::stderr())
}

/// Registers (or, on a re-run, reconfigures) `abyssal-agent run <args>`
/// as an auto-start `LocalSystem` service and starts it immediately --
/// the Windows analog of `install_systemd_service`'s write-unit +
/// `daemon-reload` + `enable --now`. `launch_arguments` bakes in
/// `--control-plane-url` (and `--credentials-file`, if non-default) the
/// same way the systemd unit's `ExecStart` line does, since neither
/// platform persists the control-plane URL anywhere credentials do.
pub fn install_service(
    control_plane_url: &str,
    credentials_file: &Path,
    ca_cert: Option<&Path>,
) -> anyhow::Result<()> {
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
    if let Some(ca_cert) = ca_cert {
        launch_arguments.push(OsString::from("--ca-cert"));
        launch_arguments.push(ca_cert.as_os_str().to_owned());
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

/// The Apps & features ("Add/Remove Programs") entry for an exe install --
/// what a CrowdStrike-style `/install` leaves so a tech finds the agent where
/// they'd look. An MSI install has Windows Installer's own entry instead.
const ARP_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AbyssalArsenalAgent";
/// Holds `ManagedByMsi = 1` while the MSI owns this install.
const AGENT_KEY: &str = r"SOFTWARE\AbyssalArsenal\Agent";

fn hklm() -> winreg::RegKey {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
}

/// Written/updated by every exe `/install`, so the version shown stays
/// current across upgrades.
pub fn register_uninstall_entry() -> anyhow::Result<()> {
    let (key, _) = hklm()
        .create_subkey(ARP_KEY)
        .context("failed to create the Apps & features entry")?;
    let exe = INSTALLED_BINARY_PATH;
    let size_kb = std::fs::metadata(exe).map(|m| m.len() / 1024).unwrap_or(0) as u32;
    key.set_value("DisplayName", &"Abyssal Arsenal Agent")?;
    key.set_value("DisplayVersion", &env!("CARGO_PKG_VERSION"))?;
    key.set_value("Publisher", &"Abyssal Arsenal")?;
    key.set_value("DisplayIcon", &exe)?;
    key.set_value("InstallLocation", &INSTALLED_BINARY_DIR)?;
    key.set_value(
        "InstallDate",
        &chrono::Local::now().format("%Y%m%d").to_string(),
    )?;
    key.set_value("UninstallString", &format!("\"{exe}\" /uninstall"))?;
    key.set_value(
        "QuietUninstallString",
        &format!("\"{exe}\" /uninstall /quiet"),
    )?;
    key.set_value("EstimatedSize", &size_kb)?;
    key.set_value("NoModify", &1u32)?;
    key.set_value("NoRepair", &1u32)?;
    Ok(())
}

/// Best-effort: nothing to do if it isn't there.
pub fn remove_uninstall_entry() {
    let _ = hklm().delete_subkey_all(ARP_KEY);
}

/// Recorded by the MSI's install action (`install --msi`), cleared by its
/// uninstall action.
pub fn set_msi_managed(managed: bool) -> anyhow::Result<()> {
    if managed {
        let (key, _) = hklm().create_subkey(AGENT_KEY)?;
        key.set_value("ManagedByMsi", &1u32)?;
    } else if let Ok(key) = hklm().open_subkey_with_flags(AGENT_KEY, winreg::enums::KEY_SET_VALUE) {
        let _ = key.delete_value("ManagedByMsi");
    }
    Ok(())
}

pub fn is_msi_managed() -> bool {
    hklm()
        .open_subkey(AGENT_KEY)
        .and_then(|key| key.get_value::<u32, _>("ManagedByMsi"))
        .is_ok_and(|v| v == 1)
}

/// The installed MSI's ProductCode (`{GUID}`), found by its Apps & features
/// entry, so the agent can have Windows Installer remove it. The MSI
/// generates a new ProductCode per build, so it can't be a constant.
pub fn msi_product_code() -> Option<String> {
    let uninstall = hklm()
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        .ok()?;
    uninstall.enum_keys().flatten().find(|name| {
        name.starts_with('{')
            && uninstall.open_subkey(name).is_ok_and(|key| {
                key.get_value::<String, _>("DisplayName")
                    .is_ok_and(|n| n == "Abyssal Arsenal Agent")
                    && key
                        .get_value::<u32, _>("WindowsInstaller")
                        .is_ok_and(|v| v == 1)
            })
    })
}

/// Stops the service (waiting up to 30s for it to exit) and deletes it.
/// Nothing to do if it isn't registered.
pub fn uninstall_service() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let Ok(service) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) else {
        return Ok(());
    };
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        for _ in 0..60 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    service
        .delete()
        .context("failed to delete the abyssal-agent service")?;
    println!("Removed the abyssal-agent service.");
    Ok(())
}

/// Removes `INSTALLED_BINARY_DIR`. A running .exe can't delete itself, so
/// when this *is* the installed copy (the usual `/uninstall` case), the
/// removal is handed to a detached `cmd` that waits for this process to exit.
pub fn remove_installed_binary() -> anyhow::Result<()> {
    let dir = Path::new(INSTALLED_BINARY_DIR);
    if !dir.exists() {
        return Ok(());
    }
    if is_installed_binary(&std::env::current_exe()?) {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::process::Command::new("cmd.exe")
            .raw_arg(format!(
                "/d /c ping -n 4 127.0.0.1 >nul & rmdir /s /q \"{INSTALLED_BINARY_DIR}\""
            ))
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .context("failed to schedule removal of the agent binary")?;
        println!("{INSTALLED_BINARY_DIR} will be removed once this process exits.");
    } else {
        std::fs::remove_dir_all(dir)
            .with_context(|| format!("failed to remove {INSTALLED_BINARY_DIR}"))?;
        println!("Removed {INSTALLED_BINARY_DIR}.");
    }
    Ok(())
}

/// Windows paths are case-insensitive; `current_exe()` may not match the
/// constant's casing (and under the MSI, it *is* the installed copy).
fn is_installed_binary(path: &Path) -> bool {
    path.to_string_lossy()
        .eq_ignore_ascii_case(INSTALLED_BINARY_PATH)
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

    if !is_installed_binary(&current_exe) {
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
pub(crate) fn harden_binary_acls(path: &Path) -> anyhow::Result<()> {
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

/// `_arguments` are the service *start* parameters (`sc start abyssal-agent
/// <params>`, normally just the service name), not the command line
/// `install_service` registered -- that one is this process's own
/// `std::env::args_os()`, and is what's parsed below. Parsing the start
/// parameters instead once handed clap `abyssal-agent abyssal-agent`, which
/// it rejected by exiting the process outright: the SCM's error 1067.
fn service_main(_arguments: Vec<OsString>) {
    SERVICE_MODE.store(true, Ordering::Relaxed);
    if let Err(e) = run_service() {
        tracing::error!(error = %format!("{e:#}"), "Windows service run failed");
    }
}

fn run_service() -> anyhow::Result<()> {
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
    let set_state = |state: ServiceState, exit_code: ServiceExitCode| {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };

    // try_parse, never parse: clap's own error path calls `exit()`, which
    // would kill the process without ever reporting Stopped to the SCM.
    let cli = match <crate::Cli as clap::Parser>::try_parse_from(std::env::args_os()) {
        Ok(cli) => cli,
        Err(e) => {
            tracing::error!(error = %e, "invalid service command line -- re-run install");
            set_state(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(2))?;
            return Ok(());
        }
    };
    let Some(crate::Command::Run {
        control_plane_url,
        enrollment_token,
        name,
        credentials_file,
        ca_cert,
    }) = cli.command
    else {
        tracing::error!("service command line isn't `run ...` -- re-run install");
        set_state(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(2))?;
        return Ok(());
    };

    set_state(ServiceState::Running, ServiceExitCode::Win32(0))?;
    tracing::info!(%control_plane_url, "abyssal-agent service started");

    // Runs on this dedicated OS thread the SCM handed the service,
    // reusing the same async `run()` reconnect loop the interactive path
    // uses -- identical backoff/reconnect behavior on both platforms.
    let runtime = tokio::runtime::Runtime::new()?;
    let handle = runtime.spawn(crate::run(
        control_plane_url,
        enrollment_token,
        name,
        credentials_file,
        ca_cert,
    ));

    // `run()` only returns on a setup failure (unreadable CA, no
    // credentials, ...) -- its reconnect loop is otherwise infinite, so the
    // usual way out is the stop signal below.
    loop {
        match shutdown_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) if handle.is_finished() => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }

    let exit_code = if handle.is_finished() {
        match runtime.block_on(handle) {
            Ok(Err(e)) => {
                tracing::error!(error = %format!("{e:#}"), "agent stopped");
                let code = crate::tls::classify(&e).exit_code();
                ServiceExitCode::ServiceSpecific(code.max(1) as u32)
            }
            Err(e) => {
                tracing::error!(error = %e, "agent task panicked");
                ServiceExitCode::ServiceSpecific(1)
            }
            Ok(Ok(())) => ServiceExitCode::Win32(0),
        }
    } else {
        ServiceExitCode::Win32(0)
    };
    runtime.shutdown_timeout(Duration::from_secs(2));
    set_state(ServiceState::Stopped, exit_code)?;
    Ok(())
}
