//! The dashboard's unattended fleet-health sweep: polls
//! `AgentOperation::FailedServices` (Mortiscope) on an interval and
//! persists one snapshot row per host, so "hosts needing attention" is a
//! cheap read instead of dispatching to every agent on every dashboard
//! load. Same shape as `thanatos_ops::spawn_thanatos_sweep` -- system-
//! initiated, so it bypasses `Executor::execute_on_host` and dispatches
//! directly through `HostConnectionRegistry`, since there's no
//! `AuthContext` to check permissions against.

use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_database::repo;

use crate::state::AppState;

const SWEEP_INTERVAL: Duration = Duration::from_secs(300);
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Parses `systemctl --failed --no-pager` output by reading its own
/// trailing summary line ("N loaded units listed.") rather than counting
/// rows -- robust against the header row, the "No systemd on this host"
/// informational message a non-systemd host returns instead, and any
/// future formatting changes to the unit rows themselves.
fn count_failed_units(stdout: &str) -> i32 {
    for line in stdout.lines().rev() {
        if let Some(rest) = line.trim().strip_suffix("loaded units listed.") {
            if let Ok(n) = rest.trim().parse::<i32>() {
                return n;
            }
        }
    }
    0
}

pub fn spawn_health_sweep(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;

            let hosts = match repo::hosts::list(&state.pool).await {
                Ok(hosts) => hosts,
                Err(e) => {
                    tracing::error!(error = %e, "health sweep failed to list hosts");
                    continue;
                }
            };

            for host in hosts {
                if !host.is_active() || !state.hosts.is_connected(host.id) {
                    continue;
                }

                let outcome = state
                    .hosts
                    .dispatch(host.id, AgentOperation::FailedServices, DISPATCH_TIMEOUT)
                    .await;

                let (failed_unit_count, error) = match outcome {
                    Ok(CommandOutcome::Ok(output)) => (count_failed_units(&output.stdout), None),
                    Ok(CommandOutcome::Err(message)) => (0, Some(message)),
                    Err(e) => (0, Some(e.to_string())),
                };

                if let Err(e) = repo::host_health::upsert(
                    &state.pool,
                    host.id,
                    failed_unit_count,
                    error.as_deref(),
                )
                .await
                {
                    tracing::error!(host = %host.name, error = %e, "health sweep failed to persist snapshot");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_failed_units_from_trailing_summary_line() {
        let stdout = "  UNIT            LOAD   ACTIVE SUB    DESCRIPTION\n\
                       ● foo.service     loaded failed failed Foo\n\
                       ● bar.service     loaded failed failed Bar\n\
                       \n\
                       2 loaded units listed.\n";
        assert_eq!(count_failed_units(stdout), 2);
    }

    #[test]
    fn zero_failed_units_when_clean() {
        assert_eq!(count_failed_units("0 loaded units listed.\n"), 0);
    }

    #[test]
    fn zero_on_non_systemd_informational_message() {
        let stdout = "No systemd on this host -- failed-unit reporting only applies to systemd.";
        assert_eq!(count_failed_units(stdout), 0);
    }
}
