//! The control plane's own server as a managed host: `install.sh` enrolls an
//! agent on it with a token from [`mint_enrollment_token`], which flags the
//! host, and `abyssal_hosts::control_plane_guard` then refuses what would
//! take the control plane down. This module feeds that guard what it needs
//! to know about the server.

use abyssal_core::secret::{generate_token, hash_token};
use abyssal_database::{DbPool, repo};
use abyssal_hosts::HostConnectionRegistry;
use abyssal_hosts::control_plane_guard::docker_device_from_df;
use abyssal_hosts::protocol::{AgentOperation, CommandOutcome};
use std::time::Duration;
use uuid::Uuid;

/// Long enough for `install.sh` to download the agent and run it, short
/// enough that a token left in a terminal's scrollback is soon useless.
const TOKEN_TTL_MINUTES: i64 = 15;

/// The ports the control plane can't do without: SSH, Caddy's HTTP/HTTPS,
/// the app's own port (inside the container and as published), the
/// `PUBLIC_URL` port, RADIUS for Panopticon's NAC, plus anything in
/// `CONTROL_PLANE_PORTS` (a comma-separated list, for a non-standard SSH
/// port, say).
pub fn protected_ports() -> Vec<u16> {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let mut ports = vec![22, 80, 443, 8080, 1812, 1813];
    ports.extend(env("HTTP_PORT").and_then(|p| p.trim().parse::<u16>().ok()));
    ports.extend(env("PUBLIC_URL").and_then(|u| url_port(&u)));
    if let Some(extra) = env("CONTROL_PLANE_PORTS") {
        ports.extend(
            extra
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok()),
        );
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The explicit or scheme-default port of a URL.
fn url_port(url: &str) -> Option<u16> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    // Bracketed IPv6 ("[::1]:8443") has colons of its own.
    let port = match authority.rsplit_once(']') {
        Some((_, after)) => after.strip_prefix(':'),
        None => authority.rsplit_once(':').map(|(_, p)| p),
    };
    match port {
        Some(p) => p.parse().ok(),
        None => match scheme.to_ascii_lowercase().as_str() {
            "https" => Some(443),
            "http" => Some(80),
            _ => None,
        },
    }
}

/// At startup: which hosts are the control plane, and its ports.
pub async fn load(pool: &DbPool, hosts: &HostConnectionRegistry) -> anyhow::Result<()> {
    hosts.set_protected_ports(protected_ports());
    for id in repo::hosts::control_plane_ids(pool).await? {
        hosts.set_control_plane(id, true);
    }
    Ok(())
}

/// A single-use enrollment token that flags the host enrolling with it as
/// the control plane's own server.
pub async fn mint_enrollment_token(pool: &DbPool) -> anyhow::Result<String> {
    let token = generate_token();
    repo::host_enrollment_tokens::create_control_plane(
        pool,
        &hash_token(&token),
        chrono::Duration::minutes(TOKEN_TTL_MINUTES),
    )
    .await?;
    Ok(token)
}

/// Asks the control plane's agent which device holds `/var/lib/docker`, so
/// the guard knows which disk to protect. Until it answers (or if it can't),
/// destructive disk operations on the server are refused outright.
pub async fn probe_docker_device(hosts: &HostConnectionRegistry, host_id: Uuid) {
    match hosts
        .dispatch(
            host_id,
            AgentOperation::ResourceUsage,
            Duration::from_secs(30),
        )
        .await
    {
        Ok(CommandOutcome::Ok(output)) => {
            let device = docker_device_from_df(&output.stdout);
            tracing::info!(%host_id, ?device, "control plane's own host: Docker's data is on this device");
            hosts.set_docker_device(device);
        }
        Ok(CommandOutcome::Err(e)) => {
            tracing::warn!(%host_id, error = %e, "couldn't find the control plane's Docker device; disk operations on it stay refused");
        }
        Err(e) => {
            tracing::warn!(%host_id, error = %e, "couldn't find the control plane's Docker device; disk operations on it stay refused");
        }
    }
}

/// What a host page shows when the host is the control plane's own server:
/// what's refused there (`control_plane_guard::summary`), and the specifics
/// the free-text forms need (which ports, which services...).
pub struct PageNote {
    pub summary: String,
    pub ports: String,
    pub units: String,
    pub processes: String,
    pub docker_device: String,
}

pub fn page_note(hosts: &HostConnectionRegistry, host_id: Uuid) -> Option<PageNote> {
    use abyssal_hosts::control_plane_guard as guard;
    if !hosts.is_control_plane(host_id) {
        return None;
    }
    let protection = hosts.protection();
    Some(PageNote {
        summary: guard::summary(&protection),
        ports: protection
            .ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        units: guard::PROTECTED_UNITS.join(", "),
        processes: guard::PROTECTED_PROCESSES.join(", "),
        docker_device: protection
            .docker_device
            .unwrap_or_else(|| "not reported yet".to_string()),
    })
}

/// Why `operation` would be refused on `host_id`, for disabling a button
/// before it's clicked (`dispatch` enforces it regardless).
pub fn refusal(
    hosts: &HostConnectionRegistry,
    host_id: Uuid,
    operation: &AgentOperation,
) -> Option<String> {
    hosts.guard(host_id, operation).err()
}

/// A signal by PID on the control plane's server: the PID is checked
/// against the process it actually is (`ProcessDetail`), since the guard
/// alone can't know. Fails closed -- if the process can't be identified,
/// the signal isn't sent.
pub async fn check_signal(
    hosts: &HostConnectionRegistry,
    host_id: Uuid,
    pid: u32,
) -> Result<(), String> {
    use abyssal_hosts::control_plane_guard as guard;
    if !hosts.is_control_plane(host_id) {
        return Ok(());
    }
    let outcome = hosts
        .dispatch(
            host_id,
            AgentOperation::ProcessDetail { pid },
            Duration::from_secs(15),
        )
        .await;
    let name = match outcome {
        Ok(CommandOutcome::Ok(output)) => guard::process_name_from_ps(&output.stdout),
        _ => None,
    };
    match name {
        Some(name) => guard::check_process_name(pid, &name),
        None => Err(format!(
            "Refused on the control plane's own server: couldn't confirm which process PID {pid} \
             is, so it might be part of the control plane. Check it with a dry run or from a shell."
        )),
    }
}

/// Records a refusal made before the executor (`check_signal`) the same way
/// the executor records the guard's: a failed `SYSTEM_COMMAND_EXECUTED`.
pub async fn audit_refusal(
    pool: &DbPool,
    ctx: &abyssal_rbac::AuthContext,
    host_name: &str,
    operation: &AgentOperation,
    reason: &str,
) {
    use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
    let event = AuditEvent::new(AuditAction::SystemCommandExecuted, AuditOutcome::Failure)
        .actor(Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource(host_name)
        .metadata(serde_json::json!({
            "detail": reason,
            "operation": operation.label(),
        }));
    if let Err(e) = abyssal_audit::record(pool, event).await {
        tracing::error!(error = %e, "failed to record a control-plane refusal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_ports() {
        assert_eq!(url_port("https://arsenal.corp"), Some(443));
        assert_eq!(url_port("http://10.0.0.5/"), Some(80));
        assert_eq!(url_port("https://arsenal.corp:8443/x"), Some(8443));
        assert_eq!(url_port("https://[fd00::5]:9443"), Some(9443));
        assert_eq!(url_port("https://[fd00::5]"), Some(443));
        assert_eq!(url_port("arsenal.corp"), None);
    }
}
