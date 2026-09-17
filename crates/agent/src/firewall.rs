//! Firewall management across whichever tool is actually present on this
//! host. There is no single standard Linux firewall interface -- Fedora/RHEL
//! systems run firewalld, Debian/Ubuntu systems commonly run ufw, and either
//! can also just be raw nftables or iptables with no frontend at all. Rather
//! than assuming one, detect and dispatch to whichever applies, the same way
//! the original bash toolbox detected a package manager instead of assuming
//! `apt`.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::command_exists;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Firewalld,
    Ufw,
    Nftables,
    Iptables,
}

impl Backend {
    fn label(self) -> &'static str {
        match self {
            Backend::Firewalld => "firewalld",
            Backend::Ufw => "ufw",
            Backend::Nftables => "nftables",
            Backend::Iptables => "iptables",
        }
    }
}

/// Picks the first available tool in order of "most likely to be the
/// intended frontend": firewalld and ufw are managed frontends with stable,
/// well-known CLIs; raw nftables/iptables are the fallback when neither is
/// installed.
async fn detect() -> Option<Backend> {
    if command_exists("firewall-cmd").await {
        return Some(Backend::Firewalld);
    }
    if command_exists("ufw").await {
        return Some(Backend::Ufw);
    }
    if command_exists("nft").await {
        return Some(Backend::Nftables);
    }
    if command_exists("iptables").await {
        return Some(Backend::Iptables);
    }
    None
}

const NO_BACKEND: &str =
    "No firewall management tool detected (checked firewalld, ufw, nftables, iptables).";

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

pub async fn status(elevation: &ElevationState) -> CommandOutcome {
    match detect().await {
        Some(Backend::Firewalld) => {
            let state = match elevation.run("firewall-cmd", &["--state"]).await {
                Ok(o) => o.stdout.trim().to_string(),
                Err(e) => return CommandOutcome::Err(format!("[backend: firewalld] {e}")),
            };
            match elevation.run("firewall-cmd", &["--list-all"]).await {
                Ok(mut list) => {
                    list.stdout = format!("state: {state}\n\n{}", list.stdout.trim_end());
                    tag(Backend::Firewalld, Ok(list))
                }
                Err(e) => CommandOutcome::Err(format!("[backend: firewalld] {e}")),
            }
        }
        Some(Backend::Ufw) => tag(
            Backend::Ufw,
            elevation.run("ufw", &["status", "verbose"]).await,
        ),
        Some(Backend::Nftables) => tag(
            Backend::Nftables,
            elevation.run("nft", &["list", "ruleset"]).await,
        ),
        Some(Backend::Iptables) => tag(
            Backend::Iptables,
            elevation.run("iptables", &["-L", "-n", "-v"]).await,
        ),
        None => CommandOutcome::Err(NO_BACKEND.to_string()),
    }
}

pub async fn allow_port(port: u16, protocol: &str, elevation: &ElevationState) -> CommandOutcome {
    // Defense in depth: the control plane already validates this before
    // dispatching, but this agent is the actual execution boundary and never
    // trusts a wire value on that basis alone.
    if !abyssal_agent_protocol::is_valid_port_protocol(port, protocol) {
        return CommandOutcome::Err(format!(
            "refusing invalid port/protocol: {port}/{protocol} (port must be 1-65535, protocol tcp or udp)"
        ));
    }

    match detect().await {
        Some(Backend::Firewalld) => {
            let add_arg = format!("--add-port={port}/{protocol}");
            if let Err(e) = elevation
                .run("firewall-cmd", &["--permanent", &add_arg])
                .await
            {
                return CommandOutcome::Err(format!("[backend: firewalld] {e}"));
            }
            tag(
                Backend::Firewalld,
                elevation.run("firewall-cmd", &["--reload"]).await,
            )
        }
        Some(Backend::Ufw) => {
            let rule = format!("{port}/{protocol}");
            tag(Backend::Ufw, elevation.run("ufw", &["allow", &rule]).await)
        }
        Some(Backend::Iptables) => {
            let port_str = port.to_string();
            tag(
                Backend::Iptables,
                elevation
                    .run(
                        "iptables",
                        &[
                            "-A", "INPUT", "-p", protocol, "--dport", &port_str, "-j", "ACCEPT",
                        ],
                    )
                    .await,
            )
        }
        Some(Backend::Nftables) => CommandOutcome::Err(
            "Direct nftables rule management isn't supported -- the ruleset's table/chain layout \
             varies too much per host to add a rule safely without knowing it. Use firewalld or \
             ufw, or add the rule manually."
                .to_string(),
        ),
        None => CommandOutcome::Err(NO_BACKEND.to_string()),
    }
}

pub async fn enable(elevation: &ElevationState) -> CommandOutcome {
    match detect().await {
        Some(Backend::Firewalld) => tag(
            Backend::Firewalld,
            elevation
                .run("systemctl", &["enable", "--now", "firewalld"])
                .await,
        ),
        Some(Backend::Ufw) => tag(
            Backend::Ufw,
            elevation.run("ufw", &["--force", "enable"]).await,
        ),
        Some(Backend::Nftables) | Some(Backend::Iptables) => CommandOutcome::Err(
            "Enabling isn't a well-defined single action for raw nftables/iptables (there's no \
             on/off switch, only rule sets and default policies) -- this operation only supports \
             firewalld and ufw."
                .to_string(),
        ),
        None => CommandOutcome::Err(NO_BACKEND.to_string()),
    }
}
