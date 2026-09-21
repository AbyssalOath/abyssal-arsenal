//! Panopticon's control-plane-side logic: the on-demand active discovery
//! scan (`DiscoveryScanOperation`, run through `Executor::execute` --
//! the in-process counterpart to every other arsenal's `execute_on_host`,
//! see that trait's doc comment) and its unattended counterpart,
//! `spawn_panopticon_sweep` -- continuous background discovery following
//! the same shape `spawn_elevation_expiry_sweep`/`thanatos_ops::
//! spawn_thanatos_sweep` establish (system-initiated, no `AuthContext` to
//! check permissions against, so it bypasses `Executor` and talks to the
//! lower-level primitives directly). Device inventory listing and the
//! topology view are plain reads straight off `repo::network_devices`,
//! handled directly in `routes/panopticon.rs`.

use std::collections::HashMap;
use std::time::Duration as StdDuration;

use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::TrustState;
use abyssal_core::settings::{PANOPTICON_SWEEP_ENABLED, PANOPTICON_SWEEP_TARGET};
use abyssal_core::{NetworkDevice, NetworkDevicePort, Permission};
use abyssal_database::{DbPool, repo};
use abyssal_execution::{
    ExecutionError, Operation, OperationKind, OperationOutput, OperationParams, run_command,
};

const NMAP_NOT_INSTALLED: &str = "nmap is not installed in the control plane's own environment \
     -- rebuild the Docker image (it's included by default) or install it \
     alongside `abyssal-arsenal` if running the binary directly.";

async fn command_exists(program: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(program)
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

struct ParsedHost {
    ip: String,
    hostname: Option<String>,
    ports: Vec<NetworkDevicePort>,
}

/// Hand-rolled parser for nmap's normal (non-XML) text output -- consistent
/// with this codebase's general preference for loose, line-based parsing of
/// real tool output over pulling in an XML dependency for one field.
fn parse_nmap_output(output: &str) -> Vec<ParsedHost> {
    let mut hosts = Vec::new();
    let mut current: Option<ParsedHost> = None;

    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("Nmap scan report for ") {
            if let Some(h) = current.take() {
                hosts.push(h);
            }
            let (hostname, ip) = match rest.rfind('(') {
                Some(open) => {
                    let hostname = rest[..open].trim().to_string();
                    let ip = rest[open + 1..].trim_end_matches(')').trim().to_string();
                    (Some(hostname), ip)
                }
                None => (None, rest.trim().to_string()),
            };
            if ip.parse::<std::net::IpAddr>().is_ok() {
                current = Some(ParsedHost {
                    ip,
                    hostname,
                    ports: Vec::new(),
                });
            }
            continue;
        }

        let Some(host) = current.as_mut() else {
            continue;
        };
        let mut tokens = line.split_whitespace();
        let (Some(port_proto), Some(state)) = (tokens.next(), tokens.next()) else {
            continue;
        };
        if state == "open"
            && let Some((port_str, protocol)) = port_proto.split_once('/')
            && let Ok(port) = port_str.parse::<u16>()
        {
            let service = tokens.next().filter(|s| !s.is_empty());
            host.ports.push(NetworkDevicePort {
                port,
                protocol: protocol.to_string(),
                service: service.map(str::to_string),
            });
        }
    }
    if let Some(h) = current.take() {
        hosts.push(h);
    }
    hosts
}

/// Best-effort MAC lookup from the control plane's own kernel neighbor
/// table (populated automatically by ordinary IP traffic, including the
/// TCP connect scan that just ran) -- the only way to learn a MAC address
/// without raw-socket ARP access, which this unprivileged process doesn't
/// have. Only ever has entries for devices on the same local subnet as the
/// control plane; anything routed shows no MAC, which is expected, not an
/// error. Also the entirety of the passive refresh's own discovery source
/// (see `run_passive_refresh`) -- it never sends traffic of its own, only
/// reads whatever the kernel already knows.
pub(crate) async fn neighbor_mac_table() -> HashMap<String, String> {
    let mut table = HashMap::new();
    let Ok(output) = run_command("ip", &["neigh", "show"]).await else {
        return table;
    };
    for line in output.stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(ip) = tokens.first() else { continue };
        if let Some(pos) = tokens.iter().position(|&t| t == "lladdr")
            && let Some(mac) = tokens.get(pos + 1)
        {
            table.insert(ip.to_string(), mac.to_string());
        }
    }
    table
}

/// After a sighting (from either the active scan or the passive neighbor
/// refresh) has just been recorded for `ip`, using that device's state
/// from *before* the write (`prior`, `None` if it didn't exist yet before
/// this sighting), emits an audit event for a brand-new device or a known
/// `Untrusted` device that just reappeared after having gone stale --
/// the "seed of alerting" Panopticon's continuous discovery exists to
/// provide. Deliberately edge-triggered rather than level-triggered: an
/// `Untrusted` device that stays continuously visible only gets audited
/// once, on the sighting that ends a gap, not on every tick it remains
/// present -- otherwise a persistently-connected untrusted device would
/// spam the audit log once per sweep interval forever.
pub(crate) async fn audit_sighting(
    pool: &DbPool,
    ip: &str,
    prior: Option<NetworkDevice>,
) -> anyhow::Result<()> {
    match prior {
        None => {
            abyssal_audit::record(
                pool,
                AuditEvent::new(AuditAction::NetworkDeviceDiscovered, AuditOutcome::Success)
                    .resource(ip),
            )
            .await
        }
        Some(device) if device.trust_state == TrustState::Untrusted && device.is_stale() => {
            abyssal_audit::record(
                pool,
                AuditEvent::new(
                    AuditAction::NetworkUntrustedDeviceSeen,
                    AuditOutcome::Success,
                )
                .resource(ip),
            )
            .await
        }
        _ => Ok(()),
    }
}

struct DiscoveryOutcome {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    upserted: usize,
}

/// Runs an nmap TCP connect scan (`-sT`, no raw sockets needed -- this
/// process runs unprivileged) against `target`, upserts every discovered
/// device (and its open ports) into the inventory, and emits an audit
/// event for anything `audit_sighting` flags as newly discovered or a
/// reappearing `Untrusted` device. Shared by the on-demand, admin-
/// triggered scan (`DiscoveryScanOperation`, gated by `Executor`'s
/// permission/confirm/audit machinery) and the unattended active sweep
/// (`spawn_panopticon_sweep`, which has no `AuthContext` to gate against
/// and bypasses `Executor` entirely) -- the only difference between them
/// is *how* this gets invoked, not what it does.
async fn run_discovery_scan(
    pool: &DbPool,
    target: &str,
    ports: Option<&str>,
) -> Result<DiscoveryOutcome, ExecutionError> {
    if !command_exists("nmap").await {
        return Err(ExecutionError::Failed(NMAP_NOT_INSTALLED.to_string()));
    }

    let mut args: Vec<&str> = vec!["-sT"];
    if let Some(spec) = ports {
        args.push("-p");
        args.push(spec);
    }
    args.push(target);

    let output = run_command("nmap", &args).await?;
    let discovered = parse_nmap_output(&output.stdout);
    let neighbors = neighbor_mac_table().await;

    let mut upserted = 0usize;
    for host in &discovered {
        let mac = neighbors.get(&host.ip).map(String::as_str);
        let prior = match repo::network_devices::find_by_ip(pool, &host.ip).await {
            Ok(prior) => prior,
            Err(e) => {
                tracing::warn!(error = %e, ip = %host.ip, "failed to look up prior state for discovered device");
                None
            }
        };

        match repo::network_devices::upsert(pool, &host.ip, mac, host.hostname.as_deref()).await {
            Ok(device_id) => {
                if let Err(e) =
                    repo::network_device_ports::replace_for_device(pool, device_id, &host.ports)
                        .await
                {
                    tracing::warn!(error = %e, ip = %host.ip, "failed to record open ports for discovered device");
                }
                if let Err(e) = audit_sighting(pool, &host.ip, prior).await {
                    tracing::warn!(error = %e, ip = %host.ip, "failed to record audit event for discovered device");
                }
                upserted += 1;
            }
            Err(e) => {
                tracing::warn!(error = %e, ip = %host.ip, "failed to upsert discovered device");
            }
        }
    }

    Ok(DiscoveryOutcome {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.exit_code,
        upserted,
    })
}

/// `target`/`ports` are validated by the caller (`routes/panopticon.rs`)
/// with the same `abyssal_agent_protocol::is_valid_network_target`/
/// `is_valid_port_spec` validators Necrolink's own network scan uses,
/// before this is ever constructed.
pub struct DiscoveryScanOperation {
    pub pool: DbPool,
    pub target: String,
    pub ports: Option<String>,
}

#[async_trait::async_trait]
impl Operation for DiscoveryScanOperation {
    fn name(&self) -> &str {
        "panopticon.discovery_scan"
    }

    fn kind(&self) -> OperationKind {
        // Matches Necrolink's own `NetworkScan`: this sends real traffic to
        // a target the operator names, which can trip intrusion detection
        // on or between here and there -- the same reasoning, not a
        // system-mutation risk.
        OperationKind::Destructive
    }

    fn required_permission(&self) -> Permission {
        Permission::NetworkScan
    }

    async fn run(&self, _params: &OperationParams) -> Result<OperationOutput, ExecutionError> {
        let outcome = run_discovery_scan(&self.pool, &self.target, self.ports.as_deref()).await?;
        Ok(OperationOutput {
            stdout: format!(
                "Discovered {} device(s); added to the inventory.\n\n{}",
                outcome.upserted, outcome.stdout
            ),
            stderr: outcome.stderr,
            exit_code: outcome.exit_code,
        })
    }
}

/// Passive discovery/refresh: reads the control plane's own kernel
/// neighbor table (whatever `ip neigh` already knows from ordinary IP
/// traffic the OS has already seen) and records a sighting for every
/// entry. Never sends any traffic of its own -- unlike the active sweep,
/// this always runs, unconditionally, regardless of
/// `PANOPTICON_SWEEP_ENABLED`, and is how a device that never responds to
/// an active scan (firewalled, but still talking to something on this
/// subnet) can still show up in the inventory.
async fn run_passive_refresh(pool: &DbPool) {
    let neighbors = neighbor_mac_table().await;
    for (ip, mac) in neighbors {
        let prior = match repo::network_devices::find_by_ip(pool, &ip).await {
            Ok(prior) => prior,
            Err(e) => {
                tracing::warn!(error = %e, ip = %ip, "passive refresh failed to look up prior device state");
                continue;
            }
        };
        if let Err(e) = repo::network_devices::touch(pool, &ip, &mac).await {
            tracing::warn!(error = %e, ip = %ip, "passive refresh failed to record sighting");
            continue;
        }
        if let Err(e) = audit_sighting(pool, &ip, prior).await {
            tracing::warn!(error = %e, ip = %ip, "passive refresh failed to record audit event");
        }
    }
}

/// Frequent, since it's just a local, traffic-free read of the kernel's
/// already-populated neighbor table.
const PASSIVE_REFRESH_INTERVAL: StdDuration = StdDuration::from_secs(60);
/// Long relative to the passive refresh -- unlike it, this sends real scan
/// traffic to a whole target range, so it ticks far less often.
const ACTIVE_SWEEP_INTERVAL: StdDuration = StdDuration::from_secs(30 * 60);

/// Spawns Panopticon's unattended continuous discovery -- the counterpart
/// to `spawn_elevation_expiry_sweep`/`thanatos_ops::spawn_thanatos_sweep`
/// in `crates/app/src/main.rs`, following the same shape (system-
/// initiated `tokio::spawn`'d fixed-interval loops with no `AuthContext`
/// to check permissions against). Two independent loops:
///
/// - Passive refresh, every `PASSIVE_REFRESH_INTERVAL`, unconditional --
///   see `run_passive_refresh`.
/// - Active nmap sweep, every `ACTIVE_SWEEP_INTERVAL`, only when
///   `PANOPTICON_SWEEP_ENABLED` is on and `PANOPTICON_SWEEP_TARGET` is
///   set -- both re-checked fresh every tick, so toggling either in
///   Settings takes effect on the next tick, not after a restart.
pub fn spawn_panopticon_sweep(pool: DbPool) {
    let passive_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASSIVE_REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            run_passive_refresh(&passive_pool).await;
        }
    });

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(ACTIVE_SWEEP_INTERVAL);
        loop {
            interval.tick().await;

            let enabled =
                match repo::settings::get_bool(&pool, PANOPTICON_SWEEP_ENABLED, false).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "failed to read Panopticon sweep setting");
                        continue;
                    }
                };
            if !enabled {
                continue;
            }

            let target = match repo::settings::get_string(&pool, PANOPTICON_SWEEP_TARGET, "").await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "failed to read Panopticon sweep target");
                    continue;
                }
            };
            let target = target.trim();
            if target.is_empty() {
                continue;
            }

            match run_discovery_scan(&pool, target, None).await {
                Ok(outcome) => {
                    tracing::info!(
                        target = %target,
                        upserted = outcome.upserted,
                        "Panopticon active sweep completed"
                    );
                }
                Err(e) => {
                    tracing::warn!(target = %target, error = %e, "Panopticon active sweep failed");
                }
            }
        }
    });
}
