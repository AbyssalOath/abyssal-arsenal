//! Linux package management across whichever tool is actually present on
//! this host. There is no single standard Linux package manager --
//! Debian/Ubuntu run apt, Fedora/RHEL run dnf (older releases yum),
//! openSUSE runs zypper, Arch runs pacman. Rather than assuming one,
//! detect and dispatch to whichever applies -- the same "detect the tool
//! present, don't assume one" approach `firewall.rs` and `init_system.rs`
//! already use for the same underlying reason.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::{command_exists, present, truncate_lines};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Zypper,
}

impl Backend {
    fn label(self) -> &'static str {
        match self {
            Backend::Apt => "apt",
            Backend::Dnf => "dnf",
            Backend::Yum => "yum",
            Backend::Pacman => "pacman",
            Backend::Zypper => "zypper",
        }
    }
}

/// Checked in an order that reflects which distro families are more
/// common among the hosts this app targets; on a real system only one of
/// these will ever be present at all.
async fn detect() -> Option<Backend> {
    if command_exists("apt-get").await {
        return Some(Backend::Apt);
    }
    if command_exists("dnf").await {
        return Some(Backend::Dnf);
    }
    if command_exists("yum").await {
        return Some(Backend::Yum);
    }
    if command_exists("pacman").await {
        return Some(Backend::Pacman);
    }
    if command_exists("zypper").await {
        return Some(Backend::Zypper);
    }
    None
}

const NO_BACKEND: &str = "No package manager detected (checked apt, dnf, yum, pacman, zypper).";

fn tag(backend: Backend, result: Result<OperationOutput, String>) -> CommandOutcome {
    match result {
        Ok(mut output) => {
            output.stdout = format!(
                "[backend: {}]\n{}",
                backend.label(),
                output.stdout.trim_end()
            );
            CommandOutcome::Ok(output)
        }
        Err(e) => CommandOutcome::Err(format!("[backend: {}] {e}", backend.label())),
    }
}

/// Same tagging as `tag()`, but for calls that go through
/// `run_allow_failure` (a non-zero exit isn't necessarily an error for
/// these backends -- see `list_upgradable`) and so need `present()`'s
/// empty-output fallback applied before tagging.
fn tag_allow_failure(
    backend: Backend,
    result: Result<OperationOutput, String>,
    empty_message: &str,
) -> CommandOutcome {
    match result {
        Ok(output) => tag(backend, Ok(present(output, empty_message))),
        Err(e) => CommandOutcome::Err(format!("[backend: {}] {e}", backend.label())),
    }
}

fn validate_package(name: &str) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_package_name(name) {
        return Err(format!("refusing invalid package name: {name}"));
    }
    Ok(())
}

fn validate_query(query: &str) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_search_query(query) {
        return Err(format!("refusing invalid search query: {query}"));
    }
    Ok(())
}

/// Header line + 500 packages -- a full system package list can easily
/// run into the thousands.
const PACKAGE_LIST_LINES: usize = 501;

pub async fn list_installed_packages(elevation: &ElevationState) -> CommandOutcome {
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => elevation.run("apt", &["list", "--installed"]).await,
        // dnf5 (now the default on current Fedora) parses the classic
        // `dnf list installed` positional keyword as a literal package
        // name, not a filter -- confirmed live against a real dnf5 host,
        // where it silently returned "No matching packages to list"
        // instead of the actual package list. `--installed` works on
        // both dnf5 and dnf4.
        Backend::Dnf => elevation.run("dnf", &["list", "--installed"]).await,
        Backend::Yum => elevation.run("yum", &["list", "installed"]).await,
        Backend::Pacman => elevation.run("pacman", &["-Q"]).await,
        Backend::Zypper => {
            elevation
                .run("zypper", &["packages", "--installed-only"])
                .await
        }
    };
    match result {
        Ok(output) => tag(backend, Ok(truncate_lines(output, PACKAGE_LIST_LINES))),
        Err(e) => CommandOutcome::Err(format!("[backend: {}] {e}", backend.label())),
    }
}

pub async fn search_package(query: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_query(&query) {
        return CommandOutcome::Err(e);
    }
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => {
            elevation
                .run("apt-cache", &["search", query.as_str()])
                .await
        }
        Backend::Dnf => elevation.run("dnf", &["search", query.as_str()]).await,
        Backend::Yum => elevation.run("yum", &["search", query.as_str()]).await,
        Backend::Pacman => elevation.run("pacman", &["-Ss", query.as_str()]).await,
        Backend::Zypper => elevation.run("zypper", &["search", query.as_str()]).await,
    };
    match result {
        Ok(output) => tag(backend, Ok(truncate_lines(output, PACKAGE_LIST_LINES))),
        Err(e) => CommandOutcome::Err(format!("[backend: {}] {e}", backend.label())),
    }
}

pub async fn package_info(package: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_package(&package) {
        return CommandOutcome::Err(e);
    }
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => {
            elevation
                .run("apt-cache", &["show", package.as_str()])
                .await
        }
        Backend::Dnf => elevation.run("dnf", &["info", package.as_str()]).await,
        Backend::Yum => elevation.run("yum", &["info", package.as_str()]).await,
        Backend::Pacman => elevation.run("pacman", &["-Si", package.as_str()]).await,
        Backend::Zypper => elevation.run("zypper", &["info", package.as_str()]).await,
    };
    tag(backend, result)
}

/// `dnf`/`yum check-update` use exit code 100 specifically to mean
/// "updates are available" (0 means none, 1 means a real error) -- not a
/// simple success/failure signal, so every backend here goes through
/// `run_allow_failure` for consistency even though not all of them share
/// that exact quirk.
pub async fn list_upgradable(elevation: &ElevationState) -> CommandOutcome {
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => {
            elevation
                .run_allow_failure("apt", &["list", "--upgradable"])
                .await
        }
        Backend::Dnf => elevation.run_allow_failure("dnf", &["check-update"]).await,
        Backend::Yum => elevation.run_allow_failure("yum", &["check-update"]).await,
        Backend::Pacman => elevation.run_allow_failure("pacman", &["-Qu"]).await,
        Backend::Zypper => {
            elevation
                .run_allow_failure("zypper", &["list-updates"])
                .await
        }
    };
    tag_allow_failure(backend, result, "No upgrades available.")
}

/// Write -- refreshes repo metadata only, never installs/removes/changes
/// a package. On Arch specifically, this is `pacman -Sy` *without* `-u`:
/// a metadata-only sync, deliberately not the full `-Syu` upgrade Arch's
/// own docs ask you to always pair it with -- `InstallPackage`/
/// `UpgradePackage` each sync their own target when they run, so nothing
/// here leaves the system in the "partial upgrade" state that warning is
/// actually about.
pub async fn refresh_package_index(elevation: &ElevationState) -> CommandOutcome {
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => elevation.run("apt-get", &["update"]).await,
        Backend::Dnf => elevation.run("dnf", &["makecache"]).await,
        Backend::Yum => elevation.run("yum", &["makecache"]).await,
        Backend::Pacman => elevation.run("pacman", &["-Sy"]).await,
        Backend::Zypper => elevation.run("zypper", &["refresh"]).await,
    };
    tag(backend, result)
}

pub async fn install_package(package: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_package(&package) {
        return CommandOutcome::Err(e);
    }
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => {
            elevation
                .run("apt-get", &["install", "-y", package.as_str()])
                .await
        }
        Backend::Dnf => {
            elevation
                .run("dnf", &["install", "-y", package.as_str()])
                .await
        }
        Backend::Yum => {
            elevation
                .run("yum", &["install", "-y", package.as_str()])
                .await
        }
        Backend::Pacman => {
            elevation
                .run("pacman", &["-S", "--noconfirm", package.as_str()])
                .await
        }
        Backend::Zypper => {
            elevation
                .run("zypper", &["install", "-y", package.as_str()])
                .await
        }
    };
    tag(backend, result)
}

pub async fn upgrade_package(package: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_package(&package) {
        return CommandOutcome::Err(e);
    }
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => {
            elevation
                .run(
                    "apt-get",
                    &["install", "--only-upgrade", "-y", package.as_str()],
                )
                .await
        }
        Backend::Dnf => {
            elevation
                .run("dnf", &["upgrade", "-y", package.as_str()])
                .await
        }
        Backend::Yum => {
            elevation
                .run("yum", &["upgrade", "-y", package.as_str()])
                .await
        }
        Backend::Pacman => {
            // Installing an already-installed package to its latest
            // synced version *is* how you upgrade a single package on
            // Arch -- there's no separate "upgrade just this one" verb.
            elevation
                .run("pacman", &["-S", "--noconfirm", package.as_str()])
                .await
        }
        Backend::Zypper => {
            elevation
                .run("zypper", &["update", "-y", package.as_str()])
                .await
        }
    };
    tag(backend, result)
}

pub async fn remove_package(package: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_package(&package) {
        return CommandOutcome::Err(e);
    }
    let Some(backend) = detect().await else {
        return CommandOutcome::Err(NO_BACKEND.to_string());
    };
    let result = match backend {
        Backend::Apt => {
            elevation
                .run("apt-get", &["remove", "-y", package.as_str()])
                .await
        }
        Backend::Dnf => {
            elevation
                .run("dnf", &["remove", "-y", package.as_str()])
                .await
        }
        Backend::Yum => {
            elevation
                .run("yum", &["remove", "-y", package.as_str()])
                .await
        }
        Backend::Pacman => {
            elevation
                .run("pacman", &["-R", "--noconfirm", package.as_str()])
                .await
        }
        Backend::Zypper => {
            elevation
                .run("zypper", &["remove", "-y", package.as_str()])
                .await
        }
    };
    tag(backend, result)
}
