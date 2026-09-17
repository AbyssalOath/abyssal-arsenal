//! Necrolink's operations: network interfaces, routes, DNS, connectivity
//! diagnostics, sockets, network configuration, and (as of the scanning
//! pass) active network scanning. `ip`/`ss`/`ping`/`getent` are universal
//! across distros, so most of this file doesn't need the detect-don't-
//! assume treatment `firewall.rs`/`init_system.rs` needed -- DNS
//! resolution is the one exception (systemd-resolved vs. plain
//! `/etc/resolv.conf`), handled inline below rather than with a whole
//! detection module, since it's a single yes/no fallback rather than
//! several distinct backends.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::{command_exists, run_command};

pub async fn interfaces() -> CommandOutcome {
    match run_command("ip", &["addr", "show"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn routes() -> CommandOutcome {
    match run_command("ip", &["route", "show"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Prefers `resolvectl status` when systemd-resolved is actually usable;
/// falls back to reading `/etc/resolv.conf` directly, which reflects the
/// effective resolver configuration regardless of what manages it and is
/// present on every Linux host.
pub async fn dns_config() -> CommandOutcome {
    if command_exists("resolvectl").await {
        if let Ok(output) = run_command("resolvectl", &["status"]).await {
            return CommandOutcome::Ok(output);
        }
    }

    match tokio::fs::read_to_string("/etc/resolv.conf").await {
        Ok(contents) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("[source: /etc/resolv.conf]\n{}", contents.trim_end()),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(format!("failed to read /etc/resolv.conf: {e}")),
    }
}

/// All active TCP/UDP sockets (`ss -tuanp`), not just listening ones --
/// complements Cadavault's `ListeningPorts` (attack-surface focus) with a
/// diagnostics-focused "what's actually connected right now" view.
pub async fn active_connections() -> CommandOutcome {
    match run_command("ss", &["-tuanp"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn connectivity_check(target: String) -> CommandOutcome {
    // Defense in depth: the control plane already validates this before
    // dispatching, but this agent is the actual execution boundary and
    // never trusts a wire value on that basis alone.
    if !abyssal_agent_protocol::is_valid_network_target(&target) {
        return CommandOutcome::Err(format!("refusing to check invalid target: {target}"));
    }

    let ping = run_command("ping", &["-c", "4", "-W", "2", &target]).await;
    let dns = run_command("getent", &["hosts", &target]).await;

    // Only fail the whole op if *both* sub-checks couldn't even run --
    // a target that pings but doesn't resolve (or vice versa) is still a
    // real, useful result, not an error.
    if ping.is_err() && dns.is_err() {
        return CommandOutcome::Err(format!("both ping and DNS lookup failed for {target}"));
    }

    let mut stdout = String::from("== Ping ==\n");
    match &ping {
        Ok(o) => stdout.push_str(o.stdout.trim_end()),
        Err(e) => stdout.push_str(&format!("(failed: {e})")),
    }
    stdout.push_str("\n\n== DNS lookup ==\n");
    match &dns {
        Ok(o) if !o.stdout.trim().is_empty() => stdout.push_str(o.stdout.trim_end()),
        Ok(_) => stdout.push_str("(no records found)"),
        Err(e) => stdout.push_str(&format!("(failed: {e})")),
    }

    CommandOutcome::Ok(OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

pub async fn interface_set_state(
    interface: String,
    up: bool,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_interface_name(&interface) {
        return CommandOutcome::Err(format!("refusing invalid interface name: {interface}"));
    }

    let state = if up { "up" } else { "down" };
    match elevation
        .run("ip", &["link", "set", &interface, state])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

const NMAP_NOT_INSTALLED: &str = "nmap is not installed on this host -- install it (e.g. \
     `dnf install nmap` / `apt install nmap` / `apk add nmap`) to use network scanning.";

pub async fn network_scan(
    target: String,
    ports: Option<String>,
    elevation: &ElevationState,
) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_network_target(&target) {
        return CommandOutcome::Err(format!("refusing to scan invalid target: {target}"));
    }
    if let Some(spec) = &ports {
        if !abyssal_agent_protocol::is_valid_port_spec(spec) {
            return CommandOutcome::Err(format!("refusing invalid port spec: {spec}"));
        }
    }
    if !command_exists("nmap").await {
        return CommandOutcome::Err(NMAP_NOT_INSTALLED.to_string());
    }

    // TCP connect scan (-sT): doesn't need raw sockets, so this works
    // whether or not the host is currently Apotheosis-elevated, unlike a
    // SYN scan (-sS), which needs root.
    let mut args: Vec<&str> = vec!["-sT"];
    if let Some(spec) = &ports {
        args.push("-p");
        args.push(spec);
    }
    args.push(&target);

    match elevation.run("nmap", &args).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}
