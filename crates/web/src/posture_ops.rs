//! Running Cadavault's posture checks (docs/roadmap/0.2.4.md, section 1):
//! ask the agent for its facts (`PostureFacts`), evaluate them with the
//! `abyssal-posture` catalog, store the run, and pass failed checks to the
//! syslog/SIEM export when it's on. Also the optional daily run
//! (`spawn_posture_schedule`).

use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome, PostureFactsReport};
use abyssal_core::settings::{AUDIT_SYSLOG_EXPORT_ENABLED, CADAVAULT_POSTURE_DAILY};
use abyssal_core::{Host, Permission};
use abyssal_database::repo;
use abyssal_database::repo::posture::NewResult;
use abyssal_execution::OperationKind;
use abyssal_notifications::{NotificationMessage, Severity};
use abyssal_posture::{Status, Tally};
use uuid::Uuid;

use crate::state::AppState;

/// Windows' collection (secedit, auditpol, the Defender and BitLocker
/// cmdlets) takes a while on a busy machine.
const TIMEOUT: Duration = Duration::from_secs(180);

/// Who asked for a run.
pub enum RunBy<'a> {
    User(&'a abyssal_rbac::AuthContext),
    Schedule,
}

/// Runs the checks on `host` and stores the result. `Err` is a message for
/// the page (agent too old, offline, couldn't collect).
pub async fn run(state: &AppState, host: &Host, by: RunBy<'_>) -> Result<Uuid, String> {
    let stdout = match &by {
        RunBy::User(ctx) => state
            .executor
            .execute_on_host(
                ctx,
                &state.hosts,
                host.id,
                &host.name,
                AgentOperation::PostureFacts,
                Permission::SecurityView,
                OperationKind::Read,
                false,
                TIMEOUT,
                None,
                state.elevation.is_elevated(host.id),
            )
            .await
            .map(|o| o.stdout)
            .map_err(|e| e.to_string())?,
        RunBy::Schedule => match state
            .hosts
            .dispatch(host.id, AgentOperation::PostureFacts, TIMEOUT)
            .await
        {
            Ok(CommandOutcome::Ok(o)) => o.stdout,
            Ok(CommandOutcome::Err(e)) => return Err(e),
            Err(e) => return Err(e.to_string()),
        },
    };
    let report: PostureFactsReport = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("the agent's posture facts couldn't be read: {e}"))?;
    let results = abyssal_posture::evaluate(&report).ok_or_else(|| {
        format!(
            "no posture checks for this host's platform ({})",
            report.platform
        )
    })?;
    let tally = Tally::of(results.iter().map(|r| r.outcome.status));
    let rows: Vec<NewResult> = results
        .iter()
        .map(|r| NewResult {
            check_id: r.check.id,
            status: r.outcome.status.as_str(),
            evidence: &r.outcome.evidence,
        })
        .collect();
    let started_by = match &by {
        RunBy::User(ctx) => ctx.user.username.clone(),
        RunBy::Schedule => "schedule".to_string(),
    };
    let run_id = repo::posture::insert_run(
        &state.pool,
        host.id,
        &report.platform,
        &started_by,
        tally.passed as i32,
        tally.failed as i32,
        tally.not_applicable as i32,
        tally.score(),
        &rows,
    )
    .await
    .map_err(|e| format!("couldn't store the run: {e}"))?;

    export_failed(state, host, run_id, &results).await;
    Ok(run_id)
}

/// Sends each failed check to the syslog/SIEM export (`scope=posture`), if
/// the audit export is on, so it can be alerted on.
async fn export_failed(
    state: &AppState,
    host: &Host,
    run_id: Uuid,
    results: &[abyssal_posture::CheckResult],
) {
    let enabled = repo::settings::get_bool(&state.pool, AUDIT_SYSLOG_EXPORT_ENABLED, false)
        .await
        .unwrap_or(false);
    if !enabled {
        return;
    }
    for r in results
        .iter()
        .filter(|r| r.outcome.status == Status::Failed)
    {
        state
            .notifications
            .dispatch(&NotificationMessage {
                subject: format!("[Posture] {} failed on {}", r.check.id, host.name),
                body: siem_line(host, run_id, r),
                severity: Severity::Warning,
                recipients: Vec::new(),
            })
            .await;
    }
}

/// One failed check as `key=value` pairs, quoted where needed.
fn siem_line(host: &Host, run_id: Uuid, r: &abyssal_posture::CheckResult) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    format!(
        "scope=posture host={} host_id={} check={} status=failed category={} title={} evidence={} run={}",
        q(&host.name),
        host.id,
        r.check.id,
        q(r.check.category),
        q(r.check.title),
        q(&r.outcome.evidence),
        run_id
    )
}

/// How often the schedule looks for hosts due a run.
const SCHEDULE_TICK_SECS: u64 = 3600;
const FIRST_TICK_DELAY: Duration = Duration::from_secs(120);

/// When daily runs are on (Settings), runs the checks on every connected
/// host whose last run is more than a day old. Hosts whose agent predates
/// `PostureFacts` are skipped.
pub fn spawn_posture_schedule(state: AppState) {
    use crate::task_health::names::POSTURE_SCHEDULE;
    tokio::spawn(async move {
        state
            .task_health
            .register(POSTURE_SCHEDULE, SCHEDULE_TICK_SECS)
            .await;
        // The first look waits for agents to reconnect after a control-plane
        // restart; at startup every host would look offline.
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + FIRST_TICK_DELAY,
            Duration::from_secs(SCHEDULE_TICK_SECS),
        );
        loop {
            interval.tick().await;
            state
                .task_health
                .ok(POSTURE_SCHEDULE, SCHEDULE_TICK_SECS)
                .await;
            let enabled = repo::settings::get_bool(&state.pool, CADAVAULT_POSTURE_DAILY, false)
                .await
                .unwrap_or(false);
            if !enabled {
                continue;
            }
            if let Err(e) = run_due(&state).await {
                tracing::warn!(error = %e, "scheduled posture runs failed");
                state
                    .task_health
                    .error(POSTURE_SCHEDULE, SCHEDULE_TICK_SECS, e.to_string())
                    .await;
            }
        }
    });
}

async fn run_due(state: &AppState) -> anyhow::Result<()> {
    let last = repo::posture::last_run_times(&state.pool).await?;
    let day_ago = chrono::Utc::now() - chrono::Duration::hours(23);
    for host in repo::hosts::list(&state.pool).await? {
        if !host.is_active()
            || host.pending_approval
            || !state.hosts.is_connected(host.id)
            || !state.hosts.supports(host.id, &AgentOperation::PostureFacts)
        {
            continue;
        }
        let due = last
            .iter()
            .find(|(id, _)| *id == host.id)
            .is_none_or(|(_, at)| *at < day_ago);
        if !due {
            continue;
        }
        if let Err(e) = run(state, &host, RunBy::Schedule).await {
            tracing::warn!(host = %host.name, error = %e, "scheduled posture run failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siem_line_quotes_free_text() {
        let host = Host {
            id: Uuid::nil(),
            name: "web \"01\"".into(),
            credential_hash: String::new(),
            enrolled_at: chrono::Utc::now(),
            last_seen_at: None,
            last_seen_ip: None,
            os: None,
            agent_version: None,
            pending_approval: false,
            is_control_plane: false,
            offline_ack_at: None,
            offline_ack_by: None,
            revoked_at: None,
        };
        let check = abyssal_posture::find("AA-LNX-SSH-002").unwrap();
        let r = abyssal_posture::CheckResult {
            check,
            outcome: abyssal_posture::failed("PasswordAuthentication = yes"),
        };
        let line = siem_line(&host, Uuid::nil(), &r);
        assert!(
            line.starts_with("scope=posture host=\"web \\\"01\\\"\""),
            "{line}"
        );
        assert!(line.contains("check=AA-LNX-SSH-002 status=failed"));
        assert!(line.contains("evidence=\"PasswordAuthentication = yes\""));
    }
}
