//! Gravekeeper background work: the daily delegation re-check.
//!
//! The roadmap requires the service-account delegation check to run "on save
//! and every day after" -- the on-save half lives in `routes::gravekeeper`.
//! This sweep is the every-day half: for each domain that has a stored service
//! account, it decrypts the sealed password, re-runs `DirectoryTestDelegation`
//! against the write DC, and refreshes the stored result, so a domain that was
//! writable but whose account has since been added to a privileged group (or
//! disabled) is flipped back to read-only without anyone having to notice. A DC
//! that's briefly unreachable, or a control plane with no `ENCRYPTION_KEY`,
//! leaves the stored state untouched rather than flapping it to "failed".
//!
//! Each check also records when the account's password expires (for the
//! warning on the domain pages), and first settles any password rotation whose
//! outcome was unclear ([`resolve_pending_password`]).

use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_database::repo;

use crate::routes::gravekeeper::DelegationResult;
use crate::state::AppState;

/// Daily (the delegation check is a once-a-day freshness check, not a monitor).
const RECHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;
const DELEGATION_TIMEOUT: Duration = Duration::from_secs(90);

pub fn spawn_gravekeeper_delegation_recheck(state: AppState) {
    use crate::task_health::names;
    tokio::spawn(async move {
        state
            .task_health
            .register(names::GRAVEKEEPER_DELEGATION_RECHECK, RECHECK_INTERVAL_SECS)
            .await;
        // Let the fleet connect before the first pass.
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            if let Err(e) = run_once(&state).await {
                tracing::error!(error = %e, "gravekeeper delegation re-check failed");
                state
                    .task_health
                    .error(
                        names::GRAVEKEEPER_DELEGATION_RECHECK,
                        RECHECK_INTERVAL_SECS,
                        e.to_string(),
                    )
                    .await;
            } else {
                state
                    .task_health
                    .ok(names::GRAVEKEEPER_DELEGATION_RECHECK, RECHECK_INTERVAL_SECS)
                    .await;
            }
            tokio::time::sleep(Duration::from_secs(RECHECK_INTERVAL_SECS)).await;
        }
    });
}

/// How an unsettled password rotation came out.
pub enum PendingPassword {
    /// No rotation was pending.
    None,
    /// The new password works: AD accepted it, and it is now the stored one.
    Promoted,
    /// The new password doesn't work and the current one does: AD never
    /// changed it, so the new one was discarded.
    Abandoned,
    /// Couldn't tell (the DC is unreachable, or neither password worked);
    /// both are kept for the next try.
    Unresolved,
}

/// Settles a rotation whose outcome is unclear by trying the passwords on the
/// write DC. The **new** one is tried first: it can only work if AD accepted
/// it, whereas the old one can keep working for a while after a change
/// (Windows accepts an old password for a short grace period on some network
/// sign-ins), so trying it first could wrongly discard a password AD is now
/// using.
pub async fn resolve_pending_password(state: &AppState, domain_id: uuid::Uuid) -> PendingPassword {
    let Ok(Some(cred)) = repo::directory::credential(&state.pool, domain_id).await else {
        return PendingPassword::Unresolved;
    };
    let Some(pending_sealed) = cred.pending_sealed else {
        return PendingPassword::None;
    };
    let (Some(key), Some(write_dc)) = (state.encryption_key.clone(), cred.write_dc_host_id) else {
        return PendingPassword::Unresolved;
    };
    let (Ok(pending), Ok(current)) = (
        key.decrypt(&pending_sealed),
        key.decrypt(&cred.service_account_sealed),
    ) else {
        return PendingPassword::Unresolved;
    };
    let check = |password: String| {
        let operation = AgentOperation::DirectoryTestDelegation {
            domain_dns: cred.dns_name.clone(),
            service_account_upn: cred.service_account_upn.clone(),
            password,
        };
        async move {
            match state
                .hosts
                .dispatch(write_dc, operation, DELEGATION_TIMEOUT)
                .await
            {
                Ok(CommandOutcome::Ok(out)) => SignIn::Works(out.stdout),
                Ok(CommandOutcome::Err(_)) => SignIn::Refused,
                Err(_) => SignIn::Unreachable,
            }
        }
    };

    match check(pending.to_string()).await {
        SignIn::Works(stdout) => {
            if repo::directory::complete_password_rotation(&state.pool, domain_id)
                .await
                .is_err()
            {
                return PendingPassword::Unresolved;
            }
            if let Ok(result) = serde_json::from_str::<DelegationResult>(stdout.trim()) {
                let _ = repo::directory::record_password_expiry(
                    &state.pool,
                    domain_id,
                    result.password_expiry(),
                )
                .await;
            }
            tracing::info!(domain = %cred.dns_name, "service-account password rotation settled: new password kept");
            PendingPassword::Promoted
        }
        SignIn::Unreachable => PendingPassword::Unresolved,
        SignIn::Refused => match check(current.to_string()).await {
            SignIn::Works(_) => {
                if repo::directory::abandon_password_rotation(&state.pool, domain_id)
                    .await
                    .is_err()
                {
                    return PendingPassword::Unresolved;
                }
                tracing::info!(domain = %cred.dns_name, "service-account password rotation settled: AD kept the old password");
                PendingPassword::Abandoned
            }
            SignIn::Refused | SignIn::Unreachable => {
                tracing::warn!(domain = %cred.dns_name, "service-account password rotation still unsettled: neither password signed in");
                PendingPassword::Unresolved
            }
        },
    }
}

/// One sign-in attempt by the delegation check.
enum SignIn {
    Works(String),
    Refused,
    Unreachable,
}

async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let Some(key) = state.encryption_key.clone() else {
        // No key to decrypt the stored credentials with -- nothing to do, and
        // not an error state for the task.
        return Ok(());
    };

    for mut domain in repo::directory::with_service_account(&state.pool).await? {
        if domain.pending_sealed.is_some() {
            resolve_pending_password(state, domain.id).await;
            // Re-read: the stored password may have just changed.
            match repo::directory::credential(&state.pool, domain.id).await? {
                Some(fresh) => domain = fresh,
                None => continue,
            }
        }
        let Some(write_dc) = domain.write_dc_host_id else {
            continue;
        };
        if !state.hosts.is_connected(write_dc) {
            continue; // can't check right now; leave the stored state alone
        }
        let password = match key.decrypt(&domain.service_account_sealed) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(domain = %domain.dns_name, error = %e, "couldn't decrypt stored service-account credential");
                continue;
            }
        };

        let outcome = state
            .hosts
            .dispatch(
                write_dc,
                AgentOperation::DirectoryTestDelegation {
                    domain_dns: domain.dns_name.clone(),
                    service_account_upn: domain.service_account_upn.clone(),
                    password: password.to_string(),
                },
                DELEGATION_TIMEOUT,
            )
            .await;

        let stdout = match outcome {
            Ok(CommandOutcome::Ok(out)) => out.stdout,
            // Agent-side error or an unreachable DC: don't flip the stored
            // state, just move on and try again tomorrow.
            Ok(CommandOutcome::Err(e)) => {
                tracing::warn!(domain = %domain.dns_name, error = %e, "delegation re-check errored on the DC");
                continue;
            }
            Err(e) => {
                tracing::warn!(domain = %domain.dns_name, error = %e, "delegation re-check could not be dispatched");
                continue;
            }
        };

        let result: DelegationResult = match serde_json::from_str(stdout.trim()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(domain = %domain.dns_name, error = %e, "couldn't parse delegation re-check result");
                continue;
            }
        };

        if let Err(e) = repo::directory::record_password_expiry(
            &state.pool,
            domain.id,
            result.password_expiry(),
        )
        .await
        {
            tracing::error!(domain = %domain.dns_name, error = %e, "couldn't store the service-account password expiry");
        }

        let passed = result.ok && result.account_found && result.overprivileged_groups.is_empty();
        let detail = serde_json::json!({
            "manageable_ous": result.manageable_ous,
            "overprivileged_groups": result.overprivileged_groups,
            "account_found": result.account_found,
            "source": "daily_recheck",
        })
        .to_string();

        if passed {
            if let Err(e) =
                repo::directory::record_delegation_success(&state.pool, domain.id, &detail).await
            {
                tracing::error!(domain = %domain.dns_name, error = %e, "couldn't store delegation re-check success");
            }
        } else {
            tracing::warn!(
                domain = %domain.dns_name,
                overprivileged = ?result.overprivileged_groups,
                "delegation re-check no longer passes -- marking the domain read-only"
            );
            if let Err(e) =
                repo::directory::record_delegation_failure(&state.pool, domain.id, &detail).await
            {
                tracing::error!(domain = %domain.dns_name, error = %e, "couldn't store delegation re-check failure");
            }
        }
    }
    Ok(())
}
