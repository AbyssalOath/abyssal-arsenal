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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration as StdDuration;

use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::TrustState;
use abyssal_core::settings::{PANOPTICON_SWEEP_ENABLED, PANOPTICON_SWEEP_TARGET};
use abyssal_core::{NetworkDevice, NetworkDevicePort, Permission};
use abyssal_database::{DbPool, repo};
use abyssal_execution::{
    ExecutionError, Executor, Operation, OperationKind, OperationOutput, OperationParams,
    run_command,
};
use abyssal_rbac::AuthContext;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

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

/// Parses `getent hosts <ip>`'s stdout -- the first line's second
/// whitespace-separated field is the resolved hostname (its canonical PTR
/// name, or the first matching `/etc/hosts` entry, since `getent hosts`
/// checks both). A trailing `.` (a fully-qualified DNS name) is stripped
/// for consistency with nmap's own hostname formatting. Split out from
/// `reverse_dns_lookup` purely so this parsing has a unit test independent
/// of actually running `getent`.
fn parse_getent_hosts_output(stdout: &str) -> Option<String> {
    let hostname = stdout.lines().next()?.split_whitespace().nth(1)?;
    if hostname.is_empty() {
        None
    } else {
        Some(hostname.trim_end_matches('.').to_string())
    }
}

/// Reverse-DNS (PTR) fallback for when nmap's own hostname detection
/// returns nothing -- the common case on an internal network without
/// working reverse DNS, not the exception (see `parse_nmap_output`'s doc
/// comment). Shells out to `getent hosts`, part of glibc and already
/// present in essentially every Linux base image, rather than adding a
/// new DNS-resolution dependency -- consistent with this module's existing
/// preference for real OS tools (`ip neigh`, `nmap`) over a library for
/// one lookup. Silently returns `None` if `getent` isn't installed or the
/// lookup fails; this is a nice-to-have fallback, not a hard requirement,
/// so it never turns into a scan failure.
async fn reverse_dns_lookup(ip: &str) -> Option<String> {
    if !command_exists("getent").await {
        return None;
    }
    let output = run_command("getent", &["hosts", ip]).await.ok()?;
    parse_getent_hosts_output(&output.stdout)
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

/// One device this scan found, already upserted into the inventory --
/// enough for the "Quick Add Host From Network Scan" picker
/// (`routes/panopticon.rs`) to render checkboxes without re-parsing nmap's
/// text output itself.
#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
}

struct DiscoveryOutcome {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    upserted: usize,
    discovered: Vec<DiscoveredHost>,
}

/// How many individual hosts nmap will attempt for this target -- the same
/// literal address-by-address enumeration nmap itself performs for a CIDR
/// range (including the network and broadcast addresses; nmap doesn't
/// infer subnet semantics from a bare CIDR notation, it just expands the
/// range). A non-CIDR target (single IP or hostname -- the only other
/// forms `is_valid_network_target` accepts) is always exactly one host.
/// Used to size a scan's progress bar before the first host has even
/// finished.
pub fn target_host_count(target: &str) -> usize {
    match target.split_once('/') {
        Some((_, prefix)) => match prefix.parse::<u32>() {
            Ok(p) if p <= 32 => 1usize << (32 - p),
            _ => 1,
        },
        None => 1,
    }
}

/// Runs nmap with its stdout read incrementally rather than collected only
/// after the process exits, so `hosts_scanned` can advance in real time as
/// each "Nmap scan report for ..." line arrives -- nmap prints one the
/// moment it finishes probing a host, well before the whole scan
/// completes. This is the only thing that changes versus a plain
/// `run_command("nmap", args)`: same flags, same single nmap process (not
/// one process per host, which would lose nmap's own internal scheduling
/// efficiency for no benefit), just read differently. stderr is drained
/// concurrently on its own task -- reading stdout and stderr sequentially
/// risks a deadlock if nmap fills one pipe's OS buffer while nothing is
/// draining it.
async fn run_nmap_streaming(
    args: &[&str],
    hosts_scanned: &Arc<AtomicUsize>,
) -> Result<OperationOutput, ExecutionError> {
    let mut child = Command::new("nmap")
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ExecutionError::Failed(format!("failed to spawn nmap: {e}")))?;

    let stdout = child.stdout.take().expect("stdout was requested as piped");
    let stderr = child.stderr.take().expect("stderr was requested as piped");

    let hosts_scanned = hosts_scanned.clone();
    let stdout_task = tokio::spawn(async move {
        let mut collected = String::new();
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.starts_with("Nmap scan report for ") {
                hosts_scanned.fetch_add(1, Ordering::Relaxed);
            }
            collected.push_str(&line);
            collected.push('\n');
        }
        collected
    });
    let stderr_task = tokio::spawn(async move {
        let mut collected = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut collected).await;
        collected
    });

    let status = child
        .wait()
        .await
        .map_err(|e| ExecutionError::Failed(format!("nmap did not exit cleanly: {e}")))?;
    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();

    Ok(OperationOutput {
        stdout,
        stderr,
        exit_code: status.code(),
    })
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
    hosts_scanned: &Arc<AtomicUsize>,
) -> Result<DiscoveryOutcome, ExecutionError> {
    if !command_exists("nmap").await {
        return Err(ExecutionError::Failed(NMAP_NOT_INSTALLED.to_string()));
    }

    // -T4 ("Aggressive") instead of nmap's own default (-T3, "Normal") --
    // nmap's own docs recommend -T4 for exactly this case, a fast and
    // reliable network you control. Without it, a subnet with many
    // silent/unreachable addresses (the common case for anything larger
    // than a small, fully-populated LAN segment) spends most of its time
    // waiting out -T3's much more conservative per-host RTT timeout on
    // hosts that were never going to answer, which is what makes the
    // progress bar sit still for a long stretch rather than moving
    // steadily -- confirmed against a real deploy, not just a guess.
    let mut args: Vec<&str> = vec!["-sT", "-T4"];
    if let Some(spec) = ports {
        args.push("-p");
        args.push(spec);
    }
    args.push(target);

    let output = run_nmap_streaming(&args, hosts_scanned).await?;
    let discovered = parse_nmap_output(&output.stdout);
    let neighbors = neighbor_mac_table().await;

    let mut upserted = 0usize;
    let mut discovered_hosts = Vec::with_capacity(discovered.len());
    for host in &discovered {
        let mac = neighbors.get(&host.ip).map(String::as_str);
        let prior = match repo::network_devices::find_by_ip(pool, &host.ip).await {
            Ok(prior) => prior,
            Err(e) => {
                tracing::warn!(error = %e, ip = %host.ip, "failed to look up prior state for discovered device");
                None
            }
        };

        // nmap's own hostname detection needs the target to have a PTR
        // record configured *and* be looked up in a way nmap does on its
        // own -- neither is reliable on a typical internal network. Fall
        // back to an explicit reverse-DNS lookup before giving up on a
        // hostname entirely.
        let hostname = match &host.hostname {
            Some(h) => Some(h.clone()),
            None => reverse_dns_lookup(&host.ip).await,
        };

        match repo::network_devices::upsert(pool, &host.ip, mac, hostname.as_deref()).await {
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
                discovered_hosts.push(DiscoveredHost {
                    ip: host.ip.clone(),
                    hostname,
                    mac: mac.map(str::to_string),
                });
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
        discovered: discovered_hosts,
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
    /// Side channel for the structured per-device results -- `Operation`'s
    /// `run()` can only return `OperationOutput` (shared with the agent
    /// wire protocol via `abyssal_agent_protocol`, so it isn't something
    /// this one caller can extend just for itself). The caller
    /// (`routes/panopticon.rs::scan`) reads this back after `execute()`
    /// returns to render the "Quick Add Host" picker without re-parsing
    /// `OperationOutput.stdout`.
    pub discovered_sink: std::sync::Arc<std::sync::Mutex<Vec<DiscoveredHost>>>,
    /// Another side channel, this one live rather than read-after-the-fact
    /// -- the caller polls this while `run()` is still in progress to
    /// drive a progress bar (`routes/panopticon_scan.rs`'s `ScanJob`).
    /// Incremented from inside `run_nmap_streaming` as each host's report
    /// line arrives, well before the whole scan finishes.
    pub hosts_scanned: Arc<AtomicUsize>,
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
        let outcome = run_discovery_scan(
            &self.pool,
            &self.target,
            self.ports.as_deref(),
            &self.hosts_scanned,
        )
        .await?;
        if let Ok(mut sink) = self.discovered_sink.lock() {
            *sink = outcome.discovered;
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanJobStatus {
    Running,
    Complete,
    Failed,
}

/// Backs the scan progress page (`routes/panopticon_scan.rs`). An
/// on-demand discovery scan runs as a detached background task
/// (`run_scan_job`) instead of blocking the HTTP request that triggered
/// it, purely so the browser has something to poll while it's still in
/// progress -- the exact same reason `ssh_deploy::DeployJob` already
/// exists, and this mirrors its shape.
pub struct ScanJob {
    pub id: Uuid,
    pub target: String,
    pub hosts_total: usize,
    pub hosts_scanned: Arc<AtomicUsize>,
    pub status: ScanJobStatus,
    /// Set when this was a one-click rescan of an already-known target
    /// (see `routes/panopticon.rs::has_scan_history`) -- shown once the
    /// job's results page renders.
    pub rescan_notice: Option<String>,
    pub discovered: Vec<DiscoveredHost>,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

impl ScanJob {
    pub fn new(
        id: Uuid,
        target: String,
        hosts_total: usize,
        rescan_notice: Option<String>,
    ) -> Self {
        Self {
            id,
            target,
            hosts_total,
            hosts_scanned: Arc::new(AtomicUsize::new(0)),
            status: ScanJobStatus::Running,
            rescan_notice,
            discovered: Vec::new(),
            result_label: None,
            result_output: None,
            result_error: None,
        }
    }

    /// 0-100, clamped so a scan can never report more than 100% even if
    /// nmap ends up reporting slightly more "scan report" lines than
    /// `target_host_count`'s upfront estimate (can happen for edge cases
    /// in how nmap itself expands a target).
    pub fn percent(&self) -> u8 {
        if self.hosts_total == 0 {
            return 100;
        }
        let scanned = self
            .hosts_scanned
            .load(Ordering::Relaxed)
            .min(self.hosts_total);
        ((scanned * 100) / self.hosts_total) as u8
    }
}

/// Runs one discovery scan job to completion, updating `job` throughout --
/// the detached-background-task counterpart to what `routes/panopticon.rs
/// ::scan` used to do inline before the scan progress bar existed. Still
/// goes through `Executor::execute` (permission re-check, confirm
/// requirement, audit logging) exactly as before; the only thing that
/// changed is *when* this runs relative to the HTTP request that
/// triggered it.
pub async fn run_scan_job(
    executor: Arc<Executor>,
    pool: DbPool,
    ctx: AuthContext,
    job: Arc<RwLock<ScanJob>>,
    target: String,
    ports: Option<String>,
) {
    let hosts_scanned = job.read().await.hosts_scanned.clone();
    let discovered_sink = Arc::new(std::sync::Mutex::new(Vec::new()));
    let op = DiscoveryScanOperation {
        pool,
        target: target.clone(),
        ports,
        discovered_sink: discovered_sink.clone(),
        hosts_scanned,
    };

    let result = executor
        .execute(
            &ctx,
            &op,
            OperationParams {
                confirm: true,
                ..Default::default()
            },
            CancellationToken::new(),
            None,
        )
        .await;

    let mut job = job.write().await;
    match result {
        Ok(output) => {
            job.discovered = discovered_sink
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            job.result_label = Some(if job.rescan_notice.is_some() {
                format!("Rescan complete: {target}")
            } else {
                format!("Discovery Scan ({target})")
            });
            job.result_output = Some(output.stdout);
            job.status = ScanJobStatus::Complete;
        }
        Err(e) => {
            job.result_label = Some(if job.rescan_notice.is_some() {
                format!("Rescan of {target} failed")
            } else {
                format!("Discovery Scan ({target})")
            });
            job.result_error = Some(e.to_string());
            job.status = ScanJobStatus::Failed;
        }
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

            // The background sweep has no admin watching a progress bar --
            // this counter is written to but never read.
            let hosts_scanned = Arc::new(AtomicUsize::new(0));
            match run_discovery_scan(&pool, target, None, &hosts_scanned).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------
    // parse_nmap_output -- never had a unit test before this, despite
    // being the one place a real scanner-output-schema regression (a
    // format change in a future nmap version, e.g.) would first show up.
    // -------------------------------------------------------------

    const SAMPLE_NMAP_OUTPUT: &str = "\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-22 10:00 UTC
Nmap scan report for router.lan (10.245.20.1)
Host is up (0.0020s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap scan report for 10.245.20.53
Host is up (0.0031s latency).
PORT    STATE SERVICE
22/tcp  open  ssh

Nmap done: 2 IP addresses (2 hosts up) scanned in 3.21 seconds
";

    #[test]
    fn parses_hostname_ip_and_open_ports_together() {
        let hosts = parse_nmap_output(SAMPLE_NMAP_OUTPUT);
        assert_eq!(hosts.len(), 2);

        assert_eq!(hosts[0].ip, "10.245.20.1");
        assert_eq!(hosts[0].hostname.as_deref(), Some("router.lan"));
        assert_eq!(hosts[0].ports.len(), 3);
        assert_eq!(hosts[0].ports[0].port, 22);
        assert_eq!(hosts[0].ports[0].protocol, "tcp");
        assert_eq!(hosts[0].ports[0].service.as_deref(), Some("ssh"));
    }

    #[test]
    fn a_host_with_no_ptr_record_has_no_hostname() {
        let hosts = parse_nmap_output(SAMPLE_NMAP_OUTPUT);
        assert_eq!(hosts[1].ip, "10.245.20.53");
        assert_eq!(hosts[1].hostname, None);
        assert_eq!(hosts[1].ports.len(), 1);
    }

    #[test]
    fn closed_and_filtered_ports_are_not_recorded_as_open() {
        let output = "Nmap scan report for 10.0.0.1\n\
             PORT    STATE    SERVICE\n\
             22/tcp  open     ssh\n\
             23/tcp  closed   telnet\n\
             25/tcp  filtered smtp\n";
        let hosts = parse_nmap_output(output);
        assert_eq!(hosts[0].ports.len(), 1);
        assert_eq!(hosts[0].ports[0].port, 22);
    }

    #[test]
    fn empty_output_yields_no_hosts() {
        assert!(parse_nmap_output("").is_empty());
    }

    // -------------------------------------------------------------
    // parse_getent_hosts_output -- the PTR-lookup fallback for hosts
    // nmap's own hostname detection didn't resolve.
    // -------------------------------------------------------------

    #[test]
    fn parses_a_resolved_getent_hosts_line() {
        assert_eq!(
            parse_getent_hosts_output("10.245.20.1     router.lan\n"),
            Some("router.lan".to_string())
        );
    }

    #[test]
    fn strips_a_trailing_fqdn_dot() {
        assert_eq!(
            parse_getent_hosts_output("10.245.20.1     router.lan.\n"),
            Some("router.lan".to_string())
        );
    }

    #[test]
    fn empty_getent_output_means_no_hostname() {
        assert_eq!(parse_getent_hosts_output(""), None);
    }

    #[test]
    fn only_takes_the_first_matching_line() {
        assert_eq!(
            parse_getent_hosts_output("10.245.20.1  router.lan  router\n10.245.20.1  alias.lan\n"),
            Some("router.lan".to_string())
        );
    }

    // -------------------------------------------------------------
    // target_host_count -- sizes the scan progress bar before the first
    // host has even finished (Phase 4a).
    // -------------------------------------------------------------

    #[test]
    fn a_single_ip_or_hostname_is_exactly_one_host() {
        assert_eq!(target_host_count("10.245.20.1"), 1);
        assert_eq!(target_host_count("router.example.lan"), 1);
    }

    #[test]
    fn a_slash_24_is_256_hosts() {
        assert_eq!(target_host_count("10.245.20.0/24"), 256);
    }

    #[test]
    fn a_slash_32_is_one_host() {
        assert_eq!(target_host_count("10.245.20.1/32"), 1);
    }

    #[test]
    fn a_slash_16_is_65536_hosts() {
        assert_eq!(target_host_count("10.245.0.0/16"), 65536);
    }

    #[test]
    fn a_malformed_prefix_falls_back_to_one_host_rather_than_panicking() {
        assert_eq!(target_host_count("10.245.20.0/not-a-number"), 1);
        assert_eq!(target_host_count("10.245.20.0/99"), 1);
    }

    // -------------------------------------------------------------
    // ScanJob::percent -- must never show over 100%, and must not divide
    // by zero for a target this codebase can't actually produce (defense
    // in depth, not a real scenario `target_host_count` produces).
    // -------------------------------------------------------------

    #[test]
    fn percent_reflects_hosts_scanned_over_hosts_total() {
        let job = ScanJob::new(Uuid::new_v4(), "10.0.0.0/24".to_string(), 256, None);
        job.hosts_scanned.store(64, Ordering::Relaxed);
        assert_eq!(job.percent(), 25);
    }

    #[test]
    fn percent_never_overshoots_100_even_if_more_hosts_report_than_expected() {
        let job = ScanJob::new(Uuid::new_v4(), "10.0.0.1".to_string(), 1, None);
        // A single-host target that somehow yields more than one "Nmap
        // scan report for" line (nmap resolving a hostname to multiple
        // addresses, e.g.) must still read as 100%, not 200%.
        job.hosts_scanned.store(3, Ordering::Relaxed);
        assert_eq!(job.percent(), 100);
    }

    #[test]
    fn percent_is_100_for_a_zero_host_total() {
        let job = ScanJob::new(Uuid::new_v4(), "".to_string(), 0, None);
        assert_eq!(job.percent(), 100);
    }

    // -------------------------------------------------------------
    // run_nmap_streaming -- a real nmap process, not a fake. Ignored by
    // default like `ssh_deploy`'s own real-network check; run with:
    //   cargo test -p abyssal-web panopticon_ops::tests::run_nmap_streaming -- --ignored
    // -------------------------------------------------------------

    #[tokio::test]
    #[ignore]
    async fn run_nmap_streaming_counts_every_host_in_a_real_scan() {
        if !command_exists("nmap").await {
            eprintln!("skipping: nmap not installed in this environment");
            return;
        }
        let counter = Arc::new(AtomicUsize::new(0));
        // Loopback /30 -- 4 addresses, always reachable, no real network
        // traffic leaves this machine.
        let target = "127.0.0.1/30";
        let expected = target_host_count(target);
        let output = run_nmap_streaming(&["-sT", target], &counter)
            .await
            .expect("a real nmap invocation against loopback should succeed");
        assert!(output.stdout.contains("Nmap scan report for"));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            expected,
            "the live progress counter should match every host nmap actually reported on"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn run_nmap_streaming_handles_a_full_slash_24_without_overshooting() {
        // The task's own ask: confirm a /24 (or larger) doesn't stall or
        // overshoot 100%. 127.0.0.0/24 -- 256 loopback addresses -- is
        // the same size as a real subnet scan without sending any actual
        // network traffic off this machine.
        if !command_exists("nmap").await {
            eprintln!("skipping: nmap not installed in this environment");
            return;
        }
        let target = "127.0.0.0/24";
        let expected = target_host_count(target);
        assert_eq!(expected, 256);

        // Exercises `ScanJob::percent()` the same way the live status
        // endpoint would see it, not just the raw counter.
        let job = ScanJob::new(Uuid::new_v4(), target.to_string(), expected, None);
        let shared_counter = job.hosts_scanned.clone();

        let output = run_nmap_streaming(&["-sT", target], &shared_counter)
            .await
            .expect("a real nmap invocation against a loopback /24 should succeed");

        assert_eq!(job.hosts_scanned.load(Ordering::Relaxed), 256);
        assert_eq!(job.percent(), 100);
        assert_eq!(output.stdout.matches("Nmap scan report for").count(), 256);
    }
}
