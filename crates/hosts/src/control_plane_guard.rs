//! Guardrails for the agent running on the control plane's own server.
//!
//! The control plane can manage the machine it runs on (the way Puppet,
//! Salt or Wazuh manage their own server), but a handful of operations
//! would cut the branch it's sitting on: isolating the host, putting it
//! behind the inline IPS, closing its own ports, stopping Docker or its own
//! containers, or reformatting the disk Docker keeps its data on. Every one
//! of those would take the web UI down with it, and the UI is the only way
//! to undo them.
//!
//! [`check`] is a pure function of the operation and what's known about the
//! server, so it's unit tested here; `HostConnectionRegistry::dispatch`
//! calls it for any host flagged as the control plane, which means it also
//! covers the code paths that dispatch without going through the executor.
//! Where the agent can't tell whether something is safe (a disk layout it
//! doesn't recognize, a container referred to by ID, a `pgrep` pattern), it
//! fails closed. Anything refused here can still be done from a shell on the
//! server, deliberately.

use std::collections::BTreeSet;

use abyssal_agent_protocol::AgentOperation;

/// What's known about the control plane's server. Ports come from the
/// deployment (Caddy's 80/443, the app's `HTTP_PORT`, the `PUBLIC_URL`
/// port, SSH); the device is whichever one holds `/var/lib/docker`, as the
/// agent reported it (`None` until it has).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlPlaneProtection {
    pub ports: BTreeSet<u16>,
    pub docker_device: Option<String>,
}

impl ControlPlaneProtection {
    pub fn new(ports: impl IntoIterator<Item = u16>, docker_device: Option<String>) -> Self {
        Self {
            ports: ports.into_iter().collect(),
            docker_device,
        }
    }
}

const PREFIX: &str = "Refused on the control plane's own server";

/// Docker, the units it needs, and this agent.
pub const PROTECTED_UNITS: &[&str] = &["docker", "containerd", "abyssal-agent"];
/// Processes that make up the running control plane.
pub const PROTECTED_PROCESSES: &[&str] = &[
    "dockerd",
    "containerd",
    "containerd-shim",
    "containerd-shim-runc-v2",
    "docker-proxy",
    "abyssal-arsenal",
    "abyssal-agent",
    "mariadbd",
    "mysqld",
    "caddy",
];
/// Mount points whose loss (or being mounted over) hides Docker's data.
pub const PROTECTED_MOUNTS: &[&str] = &["/", "/var", "/var/lib", "/var/lib/docker"];
/// Paths that must not be quarantined away.
pub const PROTECTED_PATH_PREFIXES: &[&str] = &[
    "/var/lib/docker",
    "/var/lib/containerd",
    "/usr/bin/docker",
    "/usr/bin/dockerd",
    "/usr/bin/containerd",
    "/usr/bin/runc",
    "/usr/local/bin/abyssal-agent",
    "/etc/abyssal-agent",
    "/var/lib/abyssal-agent",
];

/// `Ok(())` when `operation` is safe to run on the control plane's server,
/// otherwise the reason it isn't, written for the admin who asked.
pub fn check(
    operation: &AgentOperation,
    protection: &ControlPlaneProtection,
) -> Result<(), String> {
    use AgentOperation as Op;
    match operation {
        Op::IsolateHost => Err(format!(
            "{PREFIX}: isolating this host would cut every agent and every browser off from \
             the control plane, and the web UI is how isolation is lifted."
        )),
        Op::ScourgeSetMode { ips: true } => Err(format!(
            "{PREFIX}: inline IPS mode sends every packet through Suricata first, so a bad rule \
             or a stopped Suricata would cut off the control plane. IDS mode (alerts only) and \
             packet captures are fine here; for inline protection, put a sensor in front of this \
             server instead."
        )),
        Op::FirewallEnable => Err(format!(
            "{PREFIX}: turning the firewall on can default to denying everything incoming, \
             including {}. Allow those ports first, then enable it from a shell on the server.",
            port_list(&protection.ports)
        )),
        Op::FirewallDenyPort { port, .. } | Op::FirewallRemovePort { port, .. }
            if protection.ports.contains(port) =>
        {
            Err(format!(
                "{PREFIX}: port {port} is one the control plane needs ({}). Closing it would \
                 cut off the web UI or the agents.",
                port_list(&protection.ports)
            ))
        }
        Op::InterfaceSetState {
            interface,
            up: false,
        } => Err(format!(
            "{PREFIX}: bringing {} down could take the control plane off the network, and the \
             web UI is how it would be brought back up.",
            if interface.trim().is_empty() {
                "an interface"
            } else {
                interface.as_str()
            }
        )),
        Op::StopService { unit } | Op::RestartService { unit } | Op::DisableService { unit }
            if is_protected_unit(unit) =>
        {
            Err(format!(
                "{PREFIX}: {unit} runs the control plane itself (Docker and its containers, or \
                 this server's agent). Stopping, restarting or disabling it would take the web UI \
                 down. Do it from a shell on the server."
            ))
        }
        Op::StopContainer { container }
        | Op::RestartContainer { container }
        | Op::RemoveContainer { container } => check_container(container),
        Op::SignalByName {
            name,
            dry_run: false,
            ..
        } => check_process_pattern(name),
        Op::SendSignal { pid: 1, .. } => Err(format!(
            "{PREFIX}: PID 1 is the init system; signalling it can take the whole server down."
        )),
        Op::UpgradePackage { package } | Op::RemovePackage { package }
            if is_container_runtime_package(package) =>
        {
            Err(format!(
                "{PREFIX}: {package} is part of the container runtime the control plane runs on. \
                 Upgrading or removing it stops every container, including this one. Do it from \
                 a shell on the server, during a maintenance window."
            ))
        }
        Op::QuarantineFile { path } if is_protected_path(path) => Err(format!(
            "{PREFIX}: {path} belongs to Docker or this server's agent, which the control plane \
             runs on."
        )),
        Op::UnmountFilesystem { target } if is_protected_mount(target, protection) => Err(format!(
            "{PREFIX}: {target} holds Docker's data, including the control plane's database. \
             Unmounting it would stop the control plane."
        )),
        Op::MountFilesystem { target, .. } if is_protected_mount(target, protection) => {
            Err(format!(
                "{PREFIX}: mounting over {target} would hide Docker's data, including the control \
                 plane's database."
            ))
        }
        Op::RemoveMountUnit { mount_point, .. } if is_protected_mount(mount_point, protection) => {
            Err(format!(
                "{PREFIX}: {mount_point} holds Docker's data, including the control plane's \
                 database."
            ))
        }
        Op::CreatePartition { device, .. } | Op::DeletePartition { device, .. } => {
            check_disk(protection, std::slice::from_ref(device), "repartitioning")
        }
        Op::CreateFilesystem { device, .. } => {
            check_disk(protection, std::slice::from_ref(device), "formatting")
        }
        Op::FilesystemRepair { device } => check_disk(
            protection,
            std::slice::from_ref(device),
            "repairing a mounted filesystem on",
        ),
        Op::CreatePhysicalVolume { device } | Op::RemovePhysicalVolume { device } => check_disk(
            protection,
            std::slice::from_ref(device),
            "changing LVM physical volumes on",
        ),
        Op::CreateRaidArray { devices, .. } => {
            check_disk(protection, devices, "building a RAID array from")
        }
        Op::CreateVolumeGroup {
            physical_volumes, ..
        } => check_disk(protection, physical_volumes, "building a volume group from"),
        Op::RemoveLogicalVolume { .. } | Op::RemoveVolumeGroup { .. } => {
            check_layered(protection, Layer::Lvm, "removing LVM volumes")
        }
        Op::StopRaidArray { .. } => check_layered(protection, Layer::Raid, "stopping RAID arrays"),
        _ => Ok(()),
    }
}

/// For a signal sent by PID: refuses when the process (by its name, as
/// `process_name_from_ps` reads it) is part of the running control plane.
/// Exact names here -- unlike a `pgrep` pattern, this is the one process
/// the PID is.
pub fn check_process_name(pid: u32, name: &str) -> Result<(), String> {
    let lower = name.to_ascii_lowercase();
    let protected = PROTECTED_PROCESSES.contains(&lower.as_str())
        || lower.starts_with("abyssal")
        || lower.starts_with("containerd-shim");
    if protected {
        return Err(format!(
            "{PREFIX}: PID {pid} is {name}, part of the running control plane. Signalling it \
             would take the web UI down."
        ));
    }
    Ok(())
}

/// The process name from the agent's `ProcessDetail` output: `ps -o
/// pid,ppid,user,stat,%cpu,%mem,etime,lstart,cmd` -- seven fields, a
/// five-word start time, then the command line, whose first word's basename
/// is the name (`/usr/bin/dockerd -H fd://` -> `dockerd`). `None` if there's
/// no such process or the line doesn't parse.
pub fn process_name_from_ps(output: &str) -> Option<String> {
    let line = output.lines().skip(1).find(|l| !l.trim().is_empty())?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let command = fields.get(12)?;
    let name = command.rsplit('/').next()?.trim_end_matches(':');
    (!name.is_empty()).then(|| name.to_string())
}

/// What `check` refuses, in a sentence, for a page that's about to offer
/// some of it.
pub fn summary(protection: &ControlPlaneProtection) -> String {
    let disk = match protection.docker_device.as_deref() {
        Some(device) => format!("the disk holding Docker's data ({device})"),
        None => "any disk, until this agent reports which one holds Docker's data".to_string(),
    };
    format!(
        "isolating it; inline IPS; closing {}; turning the firewall on; taking an interface \
         down; stopping, restarting or disabling {}; stopping or removing the abyssal \
         containers; signalling {}; upgrading or removing the container runtime; quarantining \
         Docker's files; and partitioning, formatting or unmounting {disk}",
        port_list(&protection.ports),
        PROTECTED_UNITS.join(", "),
        "dockerd, containerd, MariaDB, Caddy or the abyssal processes",
    )
}

fn port_list(ports: &BTreeSet<u16>) -> String {
    let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
    if ports.is_empty() {
        "its own ports".into()
    } else {
        format!("ports {}", ports.join(", "))
    }
}

fn is_protected_unit(unit: &str) -> bool {
    let unit = unit.trim().to_ascii_lowercase();
    let base = unit
        .strip_suffix(".service")
        .or_else(|| unit.strip_suffix(".socket"))
        .unwrap_or(&unit);
    PROTECTED_UNITS.contains(&base)
}

fn check_container(container: &str) -> Result<(), String> {
    let name = container
        .trim()
        .trim_start_matches('/')
        .to_ascii_lowercase();
    if name.starts_with("abyssal") {
        return Err(format!(
            "{PREFIX}: {container} is one of the control plane's own containers. Stopping, \
             restarting or removing it takes the web UI down; use `docker compose` in the \
             deployment directory instead."
        ));
    }
    // An ID could be one of ours; there's no way to tell from here.
    if name.len() >= 6 && name.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "{PREFIX}: {container} looks like a container ID, which might be one of the control \
             plane's own containers. Refer to the container by name instead."
        ));
    }
    Ok(())
}

/// The agent runs `pgrep <name>`, an unanchored regex, so a short or
/// wildcard pattern can match far more than it looks like.
fn check_process_pattern(name: &str) -> Result<(), String> {
    let pattern = name.trim().to_ascii_lowercase();
    let is_regex = pattern.chars().any(|c| {
        matches!(
            c,
            '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '|' | '^' | '$' | '\\' | '{' | '}'
        )
    });
    let hits = PROTECTED_PROCESSES
        .iter()
        .find(|p| p.contains(pattern.as_str()) || pattern.contains(**p));
    if let Some(hit) = hits {
        return Err(format!(
            "{PREFIX}: \"{name}\" matches {hit}, part of the running control plane. Signalling \
             it would take the web UI down."
        ));
    }
    if is_regex {
        return Err(format!(
            "{PREFIX}: \"{name}\" is a pattern, and could match the control plane's own \
             processes (Docker, MariaDB, Caddy, the agent). Use an exact process name, or a \
             dry run to see what it matches and then signal by PID."
        ));
    }
    Ok(())
}

fn is_container_runtime_package(package: &str) -> bool {
    let package = package.trim().to_ascii_lowercase();
    // Strip an architecture or version suffix ("docker-ce:amd64", "runc=1.1").
    let package = package.split([':', '=', '@']).next().unwrap_or_default();
    package.starts_with("docker")
        || package.starts_with("containerd")
        || package.starts_with("moby")
        || package == "runc"
        || package == "crun"
}

fn is_protected_path(path: &str) -> bool {
    let path = normalize_path(path);
    PROTECTED_PATH_PREFIXES.iter().any(|prefix| {
        path == *prefix
            || path.starts_with(&format!("{prefix}/"))
            || path.starts_with(&format!("{prefix}-"))
    })
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    let mut out = String::with_capacity(trimmed.len());
    for part in trimmed.split('/').filter(|p| !p.is_empty() && *p != ".") {
        out.push('/');
        out.push_str(part);
    }
    if out.is_empty() { "/".into() } else { out }
}

fn is_protected_mount(target: &str, protection: &ControlPlaneProtection) -> bool {
    let target = normalize_path(target);
    if PROTECTED_MOUNTS.contains(&target.as_str()) {
        return true;
    }
    // Unmounting by device rather than mount point.
    protection
        .docker_device
        .as_deref()
        .is_some_and(|dev| related_devices(dev).contains(&target))
}

/// `/dev/sda2` -> `/dev/sda`, `/dev/nvme0n1p3` -> `/dev/nvme0n1`,
/// `/dev/mmcblk0p1` -> `/dev/mmcblk0`. `None` for anything that isn't a
/// plain partition (a whole disk, LVM, md, a loop device...).
fn parent_disk(device: &str) -> Option<String> {
    let name = device.strip_prefix("/dev/")?;
    if name.contains('/') || name.starts_with("dm-") || name.starts_with("md") {
        return None;
    }
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        let (disk, part) = name.rsplit_once('p')?;
        let disk_ok = disk.chars().last().is_some_and(|c| c.is_ascii_digit());
        let part_ok = !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
        return (disk_ok && part_ok).then(|| format!("/dev/{disk}"));
    }
    let disk = name.trim_end_matches(|c: char| c.is_ascii_digit());
    (disk.len() < name.len() && !disk.is_empty()).then(|| format!("/dev/{disk}"))
}

/// `/dev/sda`, `/dev/vdb`, `/dev/xvda`, `/dev/nvme0n1`, `/dev/mmcblk0`.
/// Anything else (`/dev/root`, a ZFS dataset...) isn't recognized.
fn is_whole_disk(device: &str) -> bool {
    let Some(name) = device.strip_prefix("/dev/") else {
        return false;
    };
    let letters_after = |prefix: &str| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_lowercase()))
    };
    let nvme = name
        .strip_prefix("nvme")
        .and_then(|rest| rest.split_once('n'))
        .is_some_and(|(ctrl, ns)| {
            !ctrl.is_empty()
                && !ns.is_empty()
                && ctrl.chars().all(|c| c.is_ascii_digit())
                && ns.chars().all(|c| c.is_ascii_digit())
        });
    let mmc = name
        .strip_prefix("mmcblk")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));
    letters_after("sd")
        || letters_after("vd")
        || letters_after("xvd")
        || letters_after("hd")
        || nvme
        || mmc
}

/// The protected device and the disk it's on.
fn related_devices(device: &str) -> Vec<String> {
    let device = normalize_path(device);
    let mut related = vec![device.clone()];
    related.extend(parent_disk(&device));
    related
}

#[derive(PartialEq)]
enum Layer {
    Lvm,
    Raid,
}

fn layer_of(device: &str) -> Option<Layer> {
    if device.starts_with("/dev/mapper/") || device.starts_with("/dev/dm-") {
        Some(Layer::Lvm)
    } else if device.starts_with("/dev/md") {
        Some(Layer::Raid)
    } else {
        None
    }
}

/// A plain partition or disk Docker's data is on is protected along with its
/// disk; anything else (LVM, RAID, unknown) protects every disk, since the
/// physical devices underneath it aren't known here.
fn check_disk(
    protection: &ControlPlaneProtection,
    devices: &[String],
    action: &str,
) -> Result<(), String> {
    let Some(docker_device) = protection.docker_device.as_deref() else {
        return Err(format!(
            "{PREFIX}: {action} disks is refused until the agent has reported which device holds \
             Docker's data (/var/lib/docker), so the control plane's own disk can't be touched \
             by mistake. Reconnect the agent, or do this from a shell on the server."
        ));
    };
    let docker_device = normalize_path(docker_device);
    let plain = parent_disk(&docker_device).is_some() || is_whole_disk(&docker_device);
    if !plain {
        return Err(format!(
            "{PREFIX}: Docker's data is on {docker_device}, whose physical disks aren't known \
             here, so {action} any disk is refused on this server. Do it from a shell on the \
             server."
        ));
    }
    let related = related_devices(&docker_device);
    for device in devices {
        let device = normalize_path(device);
        if related.contains(&device) || parent_disk(&device).is_some_and(|d| d == docker_device) {
            return Err(format!(
                "{PREFIX}: {device} holds Docker's data ({docker_device}), including the control \
                 plane's database. {} it would destroy the control plane.",
                capitalize(action)
            ));
        }
    }
    Ok(())
}

fn check_layered(
    protection: &ControlPlaneProtection,
    layer: Layer,
    action: &str,
) -> Result<(), String> {
    match protection.docker_device.as_deref().map(normalize_path) {
        Some(dev) if layer_of(&dev) != Some(layer) => Ok(()),
        Some(dev) => Err(format!(
            "{PREFIX}: Docker's data is on {dev}, so {action} is refused on this server. Do it \
             from a shell on the server."
        )),
        None => Err(format!(
            "{PREFIX}: {action} is refused until the agent has reported which device holds \
             Docker's data (/var/lib/docker)."
        )),
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The device holding `/var/lib/docker`, from the `df -h` output of the
/// agent's `ResourceUsage` (which also has a `free -h` section, skipped
/// because none of its lines end in a mount point): the filesystem whose mount point is the longest
/// prefix of it.
pub fn docker_device_from_df(df: &str) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for line in df.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(device), Some(mount)) = (fields.first(), fields.last()) else {
            continue;
        };
        if !mount.starts_with('/') || fields.len() < 6 {
            continue;
        }
        let covers = *mount == "/"
            || "/var/lib/docker" == *mount
            || "/var/lib/docker".starts_with(&format!("{mount}/"));
        if covers && best.as_ref().is_none_or(|(len, _)| mount.len() > *len) {
            best = Some((mount.len(), (*device).to_string()));
        }
    }
    best.map(|(_, device)| device)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protection(device: Option<&str>) -> ControlPlaneProtection {
        ControlPlaneProtection::new([22, 80, 443, 8080], device.map(str::to_string))
    }

    fn refused(op: AgentOperation, p: &ControlPlaneProtection) -> bool {
        check(&op, p).is_err()
    }

    #[test]
    fn isolation_and_inline_ips_are_refused_but_ids_is_fine() {
        let p = protection(Some("/dev/sda2"));
        assert!(refused(AgentOperation::IsolateHost, &p));
        assert!(refused(AgentOperation::ScourgeSetMode { ips: true }, &p));
        assert!(!refused(AgentOperation::ScourgeSetMode { ips: false }, &p));
        assert!(!refused(AgentOperation::Ping, &p));
    }

    #[test]
    fn only_the_control_planes_ports_are_protected() {
        let p = protection(None);
        let deny = |port| AgentOperation::FirewallDenyPort {
            port,
            protocol: "tcp".into(),
        };
        assert!(refused(deny(443), &p));
        assert!(refused(deny(8080), &p));
        assert!(refused(
            AgentOperation::FirewallRemovePort {
                port: 22,
                protocol: "tcp".into()
            },
            &p
        ));
        assert!(!refused(deny(3389), &p));
        assert!(!refused(
            AgentOperation::FirewallAllowPort {
                port: 443,
                protocol: "tcp".into()
            },
            &p
        ));
        assert!(refused(AgentOperation::FirewallEnable, &p));
    }

    #[test]
    fn docker_units_and_containers_are_protected() {
        let p = protection(None);
        for unit in [
            "docker",
            "docker.service",
            "docker.socket",
            "containerd",
            "abyssal-agent",
        ] {
            assert!(
                refused(AgentOperation::StopService { unit: unit.into() }, &p),
                "{unit}"
            );
        }
        assert!(!refused(
            AgentOperation::StopService {
                unit: "nginx".into()
            },
            &p
        ));
        assert!(!refused(
            AgentOperation::StartService {
                unit: "docker".into()
            },
            &p
        ));

        for c in [
            "abyssal-arsenal-app",
            "abyssal-arsenal-db",
            "/abyssal-arsenal-caddy",
            "3f2a9c1b7d4e",
        ] {
            assert!(
                refused(
                    AgentOperation::StopContainer {
                        container: c.into()
                    },
                    &p
                ),
                "{c}"
            );
        }
        assert!(!refused(
            AgentOperation::RestartContainer {
                container: "grafana".into()
            },
            &p
        ));
    }

    #[test]
    fn signals_that_could_hit_the_control_plane_are_refused() {
        let p = protection(None);
        let sig = |name: &str, dry_run| AgentOperation::SignalByName {
            name: name.into(),
            signal: "TERM".into(),
            dry_run,
        };
        assert!(refused(sig("dockerd", false), &p));
        assert!(refused(sig("docker", false), &p));
        assert!(refused(sig("maria", false), &p));
        assert!(refused(sig("d", false), &p));
        assert!(refused(sig("ng.*x", false), &p));
        assert!(!refused(sig("nginx", false), &p));
        assert!(!refused(sig("dockerd", true), &p), "dry runs only list");
        assert!(refused(
            AgentOperation::SendSignal {
                pid: 1,
                signal: "KILL".into()
            },
            &p
        ));
    }

    #[test]
    fn container_runtime_packages_are_protected() {
        let p = protection(None);
        for pkg in [
            "docker-ce",
            "docker.io",
            "containerd.io",
            "moby-engine",
            "runc",
            "docker-ce:amd64",
        ] {
            assert!(
                refused(
                    AgentOperation::UpgradePackage {
                        package: pkg.into()
                    },
                    &p
                ),
                "{pkg}"
            );
            assert!(
                refused(
                    AgentOperation::RemovePackage {
                        package: pkg.into()
                    },
                    &p
                ),
                "{pkg}"
            );
        }
        assert!(!refused(
            AgentOperation::UpgradePackage {
                package: "openssl".into()
            },
            &p
        ));
        assert!(!refused(
            AgentOperation::InstallPackage {
                package: "docker-ce".into()
            },
            &p
        ));
    }

    #[test]
    fn docker_data_paths_cannot_be_quarantined() {
        let p = protection(None);
        assert!(refused(
            AgentOperation::QuarantineFile {
                path: "/usr/bin/dockerd".into()
            },
            &p
        ));
        assert!(refused(
            AgentOperation::QuarantineFile {
                path: "/var/lib/docker/volumes/x".into()
            },
            &p
        ));
        assert!(refused(
            AgentOperation::QuarantineFile {
                path: "/usr/bin/containerd-shim".into()
            },
            &p
        ));
        assert!(!refused(
            AgentOperation::QuarantineFile {
                path: "/tmp/evil".into()
            },
            &p
        ));
        assert!(!refused(
            AgentOperation::QuarantineFile {
                path: "/var/lib/dockerish".into()
            },
            &p
        ));
    }

    #[test]
    fn docker_mounts_are_protected() {
        let p = protection(Some("/dev/sda2"));
        for target in ["/", "/var", "/var/lib/docker/", "//var//lib", "/dev/sda2"] {
            assert!(
                refused(
                    AgentOperation::UnmountFilesystem {
                        target: target.into()
                    },
                    &p
                ),
                "{target}"
            );
        }
        assert!(!refused(
            AgentOperation::UnmountFilesystem {
                target: "/mnt/backup".into()
            },
            &p
        ));
        assert!(refused(
            AgentOperation::MountFilesystem {
                device: "/dev/sdb1".into(),
                target: "/var/lib/docker".into()
            },
            &p
        ));
        assert!(!refused(
            AgentOperation::MountFilesystem {
                device: "/dev/sdb1".into(),
                target: "/mnt/data".into()
            },
            &p
        ));
    }

    #[test]
    fn signals_by_pid_check_the_process_it_is() {
        assert!(check_process_name(812, "dockerd").is_err());
        assert!(check_process_name(9, "containerd-shim-runc-v2").is_err());
        assert!(check_process_name(9, "abyssal-arsenal").is_err());
        assert!(check_process_name(9, "mariadbd").is_err());
        assert!(check_process_name(9, "nginx").is_ok());
        assert!(
            check_process_name(9, "docker-compose-helper").is_ok(),
            "exact, unlike patterns"
        );
    }

    #[test]
    fn reads_the_process_name_from_ps() {
        let ps = "    PID    PPID USER     STAT %CPU %MEM     ELAPSED                  STARTED CMD\n\
                  \x20   812       1 root     Ssl   0.3  1.2  2-03:04:05 Thu Oct  9 10:00:00 2026 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock\n";
        assert_eq!(process_name_from_ps(ps).as_deref(), Some("dockerd"));
        let caddy = "PID PPID USER STAT %CPU %MEM ELAPSED STARTED CMD\n\
                     2210 2190 1000 Ssl 0.0 0.1 05:00 Thu Oct 9 10:00:00 2026 caddy run --config /etc/caddy/Caddyfile\n";
        assert_eq!(process_name_from_ps(caddy).as_deref(), Some("caddy"));
        assert_eq!(
            process_name_from_ps("PID PPID USER STAT %CPU %MEM ELAPSED STARTED CMD\n"),
            None,
            "no such process"
        );
        assert_eq!(process_name_from_ps(""), None);
    }

    #[test]
    fn parent_disks() {
        assert_eq!(parent_disk("/dev/sda2").as_deref(), Some("/dev/sda"));
        assert_eq!(parent_disk("/dev/vdb10").as_deref(), Some("/dev/vdb"));
        assert_eq!(
            parent_disk("/dev/nvme0n1p3").as_deref(),
            Some("/dev/nvme0n1")
        );
        assert_eq!(
            parent_disk("/dev/mmcblk0p1").as_deref(),
            Some("/dev/mmcblk0")
        );
        assert_eq!(parent_disk("/dev/nvme0n1"), None);
        assert_eq!(parent_disk("/dev/sda"), None);
        assert_eq!(parent_disk("/dev/mapper/fedora-root"), None);
        assert_eq!(parent_disk("/dev/md0"), None);
    }

    #[test]
    fn the_docker_disk_is_protected_and_others_are_not() {
        let p = protection(Some("/dev/nvme0n1p3"));
        let fmt = |d: &str| AgentOperation::CreateFilesystem {
            device: d.into(),
            fstype: "ext4".into(),
        };
        assert!(refused(fmt("/dev/nvme0n1p3"), &p));
        assert!(refused(fmt("/dev/nvme0n1"), &p));
        assert!(!refused(fmt("/dev/nvme1n1p1"), &p));
        assert!(
            !refused(fmt("/dev/nvme0n1p4"), &p),
            "another partition on the same disk"
        );
        assert!(refused(
            AgentOperation::DeletePartition {
                device: "/dev/nvme0n1".into(),
                partition_number: 4
            },
            &p
        ));
        assert!(refused(
            AgentOperation::CreateRaidArray {
                array_name: "md9".into(),
                level: "1".into(),
                devices: vec!["/dev/sdb".into(), "/dev/nvme0n1".into()]
            },
            &p
        ));
        assert!(!refused(
            AgentOperation::RemoveVolumeGroup {
                name: "data".into()
            },
            &p
        ));
        assert!(!refused(
            AgentOperation::StopRaidArray {
                array_name: "md9".into()
            },
            &p
        ));
    }

    #[test]
    fn unknown_or_layered_docker_storage_fails_closed() {
        let unknown = protection(None);
        let lvm = protection(Some("/dev/mapper/fedora-root"));
        let md = protection(Some("/dev/md0"));
        let fmt = AgentOperation::CreateFilesystem {
            device: "/dev/sdz1".into(),
            fstype: "ext4".into(),
        };
        assert!(refused(fmt.clone(), &unknown));
        assert!(refused(fmt.clone(), &lvm));
        assert!(refused(fmt.clone(), &md));
        assert!(refused(fmt, &protection(Some("/dev/root"))));
        assert!(refused(
            AgentOperation::RemoveVolumeGroup {
                name: "data".into()
            },
            &lvm
        ));
        assert!(refused(
            AgentOperation::RemoveLogicalVolume {
                lv_path: "/dev/data/x".into()
            },
            &unknown
        ));
        assert!(!refused(
            AgentOperation::RemoveLogicalVolume {
                lv_path: "/dev/data/x".into()
            },
            &md
        ));
        assert!(refused(
            AgentOperation::StopRaidArray {
                array_name: "md1".into()
            },
            &md
        ));
    }

    #[test]
    fn docker_device_comes_from_the_longest_matching_mount() {
        let df = "Filesystem      Size  Used Avail Use% Mounted on\n\
                  /dev/nvme0n1p3  476G  200G  270G  43% /\n\
                  tmpfs            16G     0   16G   0% /tmp\n\
                  /dev/nvme0n1p2  974M  300M  607M  34% /boot\n\
                  /dev/sdb1       1.8T  1.0T  800G  56% /var/lib\n";
        assert_eq!(docker_device_from_df(df).as_deref(), Some("/dev/sdb1"));

        let root_only = "Filesystem Size Used Avail Use% Mounted on\n/dev/mapper/fedora-root 70G 10G 60G 15% /\n";
        assert_eq!(
            docker_device_from_df(root_only).as_deref(),
            Some("/dev/mapper/fedora-root")
        );
        let dockerish = "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 1G 1G 1G 1% /\n/dev/sdc1 1G 1G 1G 1% /var/lib/dockerish\n";
        assert_eq!(
            docker_device_from_df(dockerish).as_deref(),
            Some("/dev/sda1")
        );
        assert_eq!(docker_device_from_df(""), None);

        let resource_usage = "== Memory ==\n               total        used        free      shared  buff/cache   available\n\
                              Mem:            31Gi        12Gi       2.0Gi       1.0Gi        18Gi        19Gi\n\
                              == Disk ==\nFilesystem      Size  Used Avail Use% Mounted on\n\
                              /dev/vda1        40G   12G   28G  30% /\n";
        assert_eq!(
            docker_device_from_df(resource_usage).as_deref(),
            Some("/dev/vda1")
        );
    }
}
