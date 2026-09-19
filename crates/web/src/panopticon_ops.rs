//! Panopticon's one genuine system-level operation: an active network
//! discovery scan, run directly from the control plane's own process
//! (`abyssal_execution::Executor::execute` -- the in-process counterpart to
//! every other arsenal's `execute_on_host`, see that trait's doc comment).
//! Device inventory listing and the topology view are plain reads straight
//! off `repo::network_devices`, handled directly in `routes/panopticon.rs`
//! -- only the scan itself runs a real command and needs the permission
//! /confirm/audit/timeout machinery `Executor` provides.

use std::collections::HashMap;

use abyssal_core::Permission;
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
    ports: Vec<String>,
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
        if state == "open" && port_proto.contains('/') {
            let service = tokens.next().unwrap_or("");
            host.ports
                .push(format!("{port_proto} {service}").trim().to_string());
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
/// error.
async fn neighbor_mac_table() -> HashMap<String, String> {
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

/// Runs an nmap TCP connect scan (`-sT`, no raw sockets needed -- this
/// process runs unprivileged) against `target`, then upserts every
/// discovered device into the inventory. `target`/`ports` are validated by
/// the caller (`routes/panopticon.rs`) with the same
/// `abyssal_agent_protocol::is_valid_network_target`/`is_valid_port_spec`
/// validators Necrolink's own network scan uses, before this is ever
/// constructed.
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
        if !command_exists("nmap").await {
            return Err(ExecutionError::Failed(NMAP_NOT_INSTALLED.to_string()));
        }

        let mut args: Vec<&str> = vec!["-sT"];
        if let Some(spec) = &self.ports {
            args.push("-p");
            args.push(spec);
        }
        args.push(&self.target);

        let output = run_command("nmap", &args).await?;
        let discovered = parse_nmap_output(&output.stdout);
        let neighbors = neighbor_mac_table().await;

        let mut upserted = 0usize;
        for host in &discovered {
            let mac = neighbors.get(&host.ip).map(String::as_str);
            let open_ports = if host.ports.is_empty() {
                None
            } else {
                Some(host.ports.join(", "))
            };
            match repo::network_devices::upsert(
                &self.pool,
                &host.ip,
                mac,
                host.hostname.as_deref(),
                open_ports.as_deref(),
            )
            .await
            {
                Ok(()) => upserted += 1,
                Err(e) => {
                    tracing::warn!(error = %e, ip = %host.ip, "failed to upsert discovered device");
                }
            }
        }

        Ok(OperationOutput {
            stdout: format!(
                "Discovered {upserted} device(s); added to the inventory.\n\n{}",
                output.stdout
            ),
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }
}
