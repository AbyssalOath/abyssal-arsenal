//! "Update all out-of-date agents": one job that runs `Update agent` on
//! every connected host whose agent is older than this control plane, a few
//! at a time, and follows each one until it's back on its new build.
//!
//! In memory only, like `deploy_jobs` and `scan_jobs`: a job is minutes of
//! progress tracking, and each host's update is in the audit trail anyway
//! (the same `SYSTEM_COMMAND_EXECUTED` record a single "Update agent"
//! writes).

use std::sync::Arc;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{Host, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use chrono::{DateTime, Utc};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

use crate::state::AppState;

/// Hosts updating at once: each downloads ~10 MB from the control plane.
const PARALLEL: usize = 4;
/// How long to wait for an updated agent to reconnect.
const RECONNECT_WAIT: Duration = Duration::from_secs(120);
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    Queued,
    Updating,
    Restarting,
    Updated,
    /// The update was accepted but the agent hasn't reconnected yet.
    NotBackYet,
    Failed,
    Skipped,
}

impl UpdateState {
    pub fn label(self) -> &'static str {
        match self {
            UpdateState::Queued => "Queued",
            UpdateState::Updating => "Updating",
            UpdateState::Restarting => "Restarting",
            UpdateState::Updated => "Updated",
            UpdateState::NotBackYet => "Not back yet",
            UpdateState::Failed => "Failed",
            UpdateState::Skipped => "Skipped",
        }
    }

    pub fn badge_class(self) -> &'static str {
        match self {
            UpdateState::Queued => "badge-muted",
            UpdateState::Updating | UpdateState::Restarting => "badge-elevated",
            UpdateState::Updated => "badge-success",
            UpdateState::NotBackYet => "badge-warning",
            UpdateState::Failed => "badge-danger",
            UpdateState::Skipped => "badge-muted",
        }
    }

    pub fn is_final(self) -> bool {
        !matches!(
            self,
            UpdateState::Queued | UpdateState::Updating | UpdateState::Restarting
        )
    }
}

#[derive(Debug, Clone)]
pub struct HostUpdate {
    pub host_id: Uuid,
    pub name: String,
    pub os: String,
    pub from_version: String,
    pub state: UpdateState,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct AgentUpdateJob {
    pub id: Uuid,
    pub started_by: String,
    pub started_at: DateTime<Utc>,
    pub hosts: Vec<HostUpdate>,
}

impl AgentUpdateJob {
    pub fn finished(&self) -> bool {
        self.hosts.iter().all(|h| h.state.is_final())
    }

    pub fn count(&self, state: UpdateState) -> usize {
        self.hosts.iter().filter(|h| h.state == state).count()
    }
}

/// Whether `host`'s agent is older than this control plane: a different
/// protocol, or an older version number.
fn is_out_of_date(state: &AppState, host: &Host) -> bool {
    use crate::update_check::{CURRENT_VERSION, parse_version};
    if state.hosts.agent_protocol_mismatch(host.id) {
        return true;
    }
    matches!(
        (
            host.agent_version.as_deref().and_then(parse_version),
            parse_version(CURRENT_VERSION),
        ),
        (Some(agent), Some(current)) if agent < current
    )
}

/// The smallest `SelfUpdate` there is, to ask whether an agent understands
/// self-update at all.
fn any_self_update() -> AgentOperation {
    AgentOperation::SelfUpdate {
        version: String::new(),
        from_control_plane: false,
        sha256: None,
    }
}

/// Every active host whose agent is out of date, in the state a new job
/// starts them in: connected ones queued, the rest skipped with the reason.
/// Hosts that are offline count only if they're known to be out of date
/// (their last-reported version is older).
pub async fn out_of_date_hosts(state: &AppState) -> anyhow::Result<Vec<HostUpdate>> {
    // What an agent that can only update from GitHub would get.
    let newest_release = crate::update_check::agent_release_version(state).await;
    let from_control_plane = AgentOperation::SelfUpdate {
        version: String::new(),
        from_control_plane: true,
        sha256: None,
    };
    let mut out = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if !host.is_active() || host.pending_approval || !is_out_of_date(state, &host) {
            continue;
        }
        let (update_state, detail) = if !state.hosts.is_connected(host.id) {
            (
                UpdateState::Skipped,
                "Offline -- update it once it's back.".to_string(),
            )
        } else if !state.hosts.supports(host.id, &any_self_update()) {
            (
                UpdateState::Skipped,
                "Too old to update itself -- re-deploy it (bootstrap one-liner or SSH quick-add)."
                    .to_string(),
            )
        } else if !state.hosts.supports(host.id, &from_control_plane)
            && host.agent_version.as_deref() == Some(newest_release.as_str())
        {
            // Reinstalling the same release wouldn't change anything; this
            // control plane is ahead of every published build.
            (
                UpdateState::Skipped,
                format!(
                    "Already on v{newest_release}, the newest published release -- nothing \
                     newer to install until this control plane's version is released."
                ),
            )
        } else {
            (UpdateState::Queued, String::new())
        };
        out.push(HostUpdate {
            host_id: host.id,
            name: host.name.clone(),
            os: host.os.clone().unwrap_or_default(),
            from_version: host
                .agent_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            state: update_state,
            detail,
        });
    }
    Ok(out)
}

/// How many connected hosts a job would update right now -- for the button.
pub async fn updatable_count(state: &AppState) -> usize {
    out_of_date_hosts(state)
        .await
        .map(|hosts| {
            hosts
                .iter()
                .filter(|h| h.state == UpdateState::Queued)
                .count()
        })
        .unwrap_or(0)
}

async fn set(job: &RwLock<AgentUpdateJob>, index: usize, state: UpdateState, detail: String) {
    let mut job = job.write().await;
    job.hosts[index].state = state;
    job.hosts[index].detail = detail;
}

/// Runs the job: `PARALLEL` hosts at a time, each through the same
/// `self_update_operation` + `execute_on_host` as a single "Update agent"
/// (so the same permission check, audit record, version gate and
/// no-downgrade rule), then waiting for the agent to come back.
pub async fn run(state: AppState, ctx: AuthContext, job: Arc<RwLock<AgentUpdateJob>>) {
    let queued: Vec<(usize, Uuid)> = job
        .read()
        .await
        .hosts
        .iter()
        .enumerate()
        .filter(|(_, h)| h.state == UpdateState::Queued)
        .map(|(i, h)| (i, h.host_id))
        .collect();

    let slots = Arc::new(Semaphore::new(PARALLEL));
    let mut tasks = tokio::task::JoinSet::new();
    for (index, host_id) in queued {
        let (state, ctx, job, slots) = (state.clone(), ctx.clone(), job.clone(), slots.clone());
        tasks.spawn(async move {
            let Ok(_slot) = slots.acquire_owned().await else {
                return;
            };
            update_one(&state, &ctx, &job, index, host_id).await;
        });
    }
    while tasks.join_next().await.is_some() {}
}

async fn update_one(
    state: &AppState,
    ctx: &AuthContext,
    job: &RwLock<AgentUpdateJob>,
    index: usize,
    host_id: Uuid,
) {
    set(job, index, UpdateState::Updating, String::new()).await;

    let host = match repo::hosts::find_by_id(&state.pool, host_id).await {
        Ok(Some(host)) if host.is_active() => host,
        Ok(_) => {
            set(
                job,
                index,
                UpdateState::Skipped,
                "Removed or revoked meanwhile.".into(),
            )
            .await;
            return;
        }
        Err(e) => {
            set(
                job,
                index,
                UpdateState::Failed,
                format!("Couldn't load the host: {e}"),
            )
            .await;
            return;
        }
    };
    let (operation, version) = match crate::routes::hosts::self_update_operation(state, &host).await
    {
        Ok(planned) => planned,
        Err(message) => {
            set(job, index, UpdateState::Skipped, message).await;
            return;
        }
    };

    let before = state.hosts.connection_epoch(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &format!("Update agent -- {}", host.name),
            operation,
            Permission::HostsManage,
            OperationKind::Write,
            false,
            DISPATCH_TIMEOUT,
            None,
            state.elevation.is_elevated(host_id),
        )
        .await;
    if let Err(e) = result {
        set(job, index, UpdateState::Failed, e.to_string()).await;
        return;
    }

    set(
        job,
        index,
        UpdateState::Restarting,
        format!("Installed {version}; waiting for it to reconnect."),
    )
    .await;
    let (final_state, detail) = wait_for_reconnect(state, host_id, before).await;
    set(job, index, final_state, detail).await;
}

/// Waits for the host to connect again on a new connection, then reports
/// the version it came back with.
async fn wait_for_reconnect(
    state: &AppState,
    host_id: Uuid,
    before: Option<u64>,
) -> (UpdateState, String) {
    let deadline = tokio::time::Instant::now() + RECONNECT_WAIT;
    while tokio::time::Instant::now() < deadline {
        let now = state.hosts.connection_epoch(host_id);
        if now.is_some() && now != before {
            let version = repo::hosts::find_by_id(&state.pool, host_id)
                .await
                .ok()
                .flatten()
                .and_then(|h| h.agent_version)
                .unwrap_or_else(|| "unknown".to_string());
            let detail = if state.hosts.agent_protocol_mismatch(host_id) {
                format!(
                    "Back on v{version}, but its protocol still doesn't match this control \
                     plane's -- the published build may be older than this control plane."
                )
            } else {
                format!("Back on v{version}.")
            };
            return (UpdateState::Updated, detail);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    (
        UpdateState::NotBackYet,
        format!(
            "The update was accepted, but the agent hasn't reconnected within {}s. Check the \
             host (its service may need starting by hand).",
            RECONNECT_WAIT.as_secs()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(states: &[UpdateState]) -> AgentUpdateJob {
        AgentUpdateJob {
            id: Uuid::new_v4(),
            started_by: "admin".into(),
            started_at: Utc::now(),
            hosts: states
                .iter()
                .map(|s| HostUpdate {
                    host_id: Uuid::new_v4(),
                    name: "h".into(),
                    os: "linux".into(),
                    from_version: "0.2.1".into(),
                    state: *s,
                    detail: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_job_finishes_when_every_host_is_final() {
        use UpdateState::*;
        assert!(!job(&[Updated, Restarting]).finished());
        assert!(!job(&[Queued]).finished());
        assert!(job(&[Updated, Failed, Skipped, NotBackYet]).finished());
        assert!(job(&[]).finished());
        assert_eq!(job(&[Updated, Updated, Failed]).count(Updated), 2);
    }

    #[test]
    fn the_probe_needs_only_what_self_update_ever_needed() {
        // Any agent that understands self-update at all qualifies; whether
        // it downloads from the control plane is decided per host later.
        assert_eq!(any_self_update().min_protocol(), 24);
    }
}
