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
