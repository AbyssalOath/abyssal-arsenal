use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, RawQuery, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{WorkflowContextRow, maybe_elevate, require_csrf, workflow_context_rows};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::pagination;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, PostmortemHostGroup, PostmortemHostTemplate, PostmortemTemplate, SuggestedActionView,
};
use crate::theme;

/// How many host groups the group list shows per page -- same constant
/// Panopticon's Device Inventory and Thanatos's dashboard use.
const GROUPS_PER_PAGE: u32 = 25;

/// Landing page for this arsenal: a paginated, collapsible-per-host group
/// list (GitHub issue #10's grouped-dashboard pattern) instead of a flat
/// host-link list -- each group's body is just the read-only quick-check
/// buttons (nothing per-host to paginate inside, since these are live
/// agent reads, not stored rows), collapsed by default for the same
/// reason every other dropdown in this app now defaults closed.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    RawQuery(raw): RawQuery,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/postmortem/{host_id}")).into_response());
    }

    let query = pagination::parse_group_list_query(raw.as_deref());

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(
        &ctx,
        &theme::current(&jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(&jar),
    )
    .await?;

    let mut connected_hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            connected_hosts.push(host);
        }
    }

    let open_set: std::collections::HashSet<&str> = query.open.iter().map(String::as_str).collect();
    let group_total = connected_hosts.len() as u64;
    let group_page_requested = query.group_page.unwrap_or(1).max(1);
    let group_page_num = if pagination::Page::<()>::page_out_of_range(
        group_page_requested,
        GROUPS_PER_PAGE,
        group_total,
    ) {
        pagination::total_pages(group_total, GROUPS_PER_PAGE)
    } else {
        group_page_requested
    };
    let group_offset = pagination::offset(group_page_num, GROUPS_PER_PAGE) as usize;
    let group_page_meta: pagination::Page<()> =
        pagination::Page::new(vec![], group_page_num, GROUPS_PER_PAGE, group_total);
    let group_list_page = Some(pagination::numbered_page_info(&group_page_meta, |p| {
        query.with_group_page(p).href("/arsenals/postmortem")
    }));

    let groups = connected_hosts
        .iter()
        .skip(group_offset)
        .take(GROUPS_PER_PAGE as usize)
        .map(|host| {
            let host_id_str = host.id.to_string();
            let is_open = open_set.contains(host_id_str.as_str());
            let open_href =
                (!is_open).then(|| query.with_open(&host_id_str).href("/arsenals/postmortem"));
            PostmortemHostGroup {
                host_id: host_id_str,
                host_name: host.name.clone(),
                is_open,
                open_href,
            }
        })
        .collect();

    let tpl = PostmortemTemplate {
        base,
        groups,
        group_list_page,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

async fn render_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
) -> Result<Response, WebError> {
    render_host_with_context(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        Vec::new(),
        Vec::new(),
    )
    .await
}

/// Same as `render_host`, but also renders a "Suggested Next Steps" section
/// from the workflow registry's matches against this result -- see
/// `run_read_op`'s `workflow` parameter, the source of every non-empty
/// `suggested_actions` this ever gets called with.
#[allow(clippy::too_many_arguments)]
async fn render_host_with_suggestions(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    suggested_actions: Vec<SuggestedActionView>,
) -> Result<Response, WebError> {
    render_host_with_context(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        Vec::new(),
    )
    .await
}

/// Same as `render_host`, but also shows a banner naming which
/// workflow-registry context fields (if any) arrived in the query string
/// -- Thanatos's `persisted_count` doesn't map to a field any read op
/// here takes, so the banner is all Phase 6 adds here.
#[allow(clippy::too_many_arguments)]
async fn render_host_with_context(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    suggested_actions: Vec<SuggestedActionView>,
    context: Vec<WorkflowContextRow>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let arrived_via_suggestion = !context.is_empty();
    let selected_host_id = if arrived_via_suggestion {
        Some(host_id)
    } else {
        host_context::current(jar)
    };

    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        selected_host_id,
    )
    .await?;

    let tpl = PostmortemHostTemplate {
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        context,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    let jar = match host_context::carry_forward_cookie(host_id, arrived_via_suggestion) {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn show_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    render_host_with_context(
        &state,
        &jar,
        &ctx,
        host_id,
        None,
        None,
        None,
        Vec::new(),
        workflow_context_rows(&query),
    )
    .await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

/// Feeds a read op's structured result into the workflow registry --
/// `source_action` is the registry's `source_action` key, `count_field`
/// the JSON field name a `registry.json` entry's condition checks, and
/// `empty_sentinels` the exact "nothing found" string(s) the matching
/// agent-side function (`crates/agent/src/postmortem.rs`) can return when
/// its filtered line count is genuinely zero -- compared verbatim rather
/// than guessed at, since a naive "count non-empty lines" would otherwise
/// count that one sentinel sentence itself as a single (wrong) event. More
/// than one sentinel is needed for ops with more than one code path (e.g.
/// `core_dumps` says "(no output)" via `coredumpctl` on a systemd host,
/// but a distinct sentence on the `find`-based fallback path).
struct WorkflowCount {
    source_action: &'static str,
    count_field: &'static str,
    empty_sentinels: &'static [&'static str],
}

/// Every op in this arsenal is `Read` -- forensic examination means looking,
/// not changing anything -- so all seven handlers below share this one
/// dispatch helper, same shape as every other arsenal's `run_read_op`.
/// `workflow`, when given, turns this read's line count into a
/// "Suggested Next Steps" entry via the workflow registry (see
/// `crates/workflows/registry.json`'s Postmortem-sourced entries) --
/// `None` for the four ops that don't currently feed any registry rule.
#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    workflow: Option<WorkflowCount>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            // `crate::process::present` (agent-side) substitutes stderr's
            // text for an empty stdout so a genuine command failure (e.g.
            // "Operation not permitted" reading a restricted kernel ring
            // buffer while unelevated) still shows *something* useful
            // instead of a blank box -- detectable here because that's
            // the one case where the two fields end up holding the exact
            // same non-empty text (the original `stderr` survives that
            // substitution unchanged). Never claim a workflow count off
            // of a surfaced error: skip the suggestion entirely rather
            // than misreading an error message as "1 event found."
            let stderr_was_substituted = {
                let stdout = output.stdout.trim();
                !stdout.is_empty() && stdout == output.stderr.trim()
            };
            let suggested_actions = if let Some(w) = workflow
                && !stderr_was_substituted
            {
                let trimmed = output.stdout.trim();
                let count = if w.empty_sentinels.contains(&trimmed) {
                    0
                } else {
                    output
                        .stdout
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .count()
                };
                let entry = serde_json::json!({ w.count_field: count });
                crate::common::suggested_actions_for(
                    state,
                    "postmortem",
                    w.source_action,
                    std::slice::from_ref(&entry),
                    host_id,
                )
                .await
            } else {
                Vec::new()
            };
            render_host_with_suggestions(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
                suggested_actions,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

pub async fn boot_history(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::BootHistory,
        "Boot History",
        None,
    )
    .await
}

pub async fn kernel_ring_buffer(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::KernelRingBuffer,
        "Kernel Ring Buffer",
        None,
    )
    .await
}

pub async fn system_journal_errors(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::SystemJournalErrors,
        "System Journal Errors",
        None,
    )
    .await
}

pub async fn failed_login_attempts(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FailedLoginAttempts,
        "Failed Login Attempts",
        Some(WorkflowCount {
            source_action: "failed_login_attempts",
            count_field: "failed_login_count",
            empty_sentinels: &["No failed login attempts found in the recent log window."],
        }),
    )
    .await
}

pub async fn oom_kill_events(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::OomKillEvents,
        "OOM-Kill Events",
        Some(WorkflowCount {
            source_action: "oom_kill_events",
            count_field: "oom_kill_count",
            empty_sentinels: &["No OOM-kill events found in the kernel ring buffer."],
        }),
    )
    .await
}

pub async fn core_dumps(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::CoreDumps,
        "Core Dumps",
        Some(WorkflowCount {
            source_action: "core_dumps",
            count_field: "core_dump_count",
            empty_sentinels: &[
                "(no output)",
                "No core dump artifacts found under /var/crash or /var/lib/systemd/coredump.",
            ],
        }),
    )
    .await
}

#[derive(Deserialize)]
pub struct RecentlyModifiedFilesForm {
    csrf_token: String,
    hours: u32,
}

pub async fn recently_modified_files(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RecentlyModifiedFilesForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !abyssal_agent_protocol::is_valid_lookback_hours(form.hours) {
        return Err(WebError(AppError::Validation(
            "Enter a lookback window between 1 and 720 hours (30 days).".into(),
        )));
    }

    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RecentlyModifiedFiles { hours: form.hours },
        &format!("Recently Modified Files (last {}h)", form.hours),
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct ElevateForm {
    csrf_token: String,
    sudo_password: String,
}

pub async fn elevate(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ElevateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsElevate)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.sudo_password.trim().is_empty() {
        return Err(WebError(AppError::Validation(
            "Enter a sudo password to elevate.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match maybe_elevate(&state, &ctx, host_id, &host.name, Some(form.sudo_password)).await {
        Ok(warning) => {
            let message = format!("{}Elevated.", warning.unwrap_or(""));
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                Some(message),
                None,
            )
            .await
        }
        Err(e) => {
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                None,
                Some(e),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn failed_logins_found_suggests_thanatos() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "failed_login_count": 3 });
        let targets: Vec<String> = registry
            .evaluate("postmortem", "failed_login_attempts", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"thanatos".to_string()));
    }

    #[test]
    fn no_failed_logins_suggests_nothing() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "failed_login_count": 0 });
        assert!(
            registry
                .evaluate("postmortem", "failed_login_attempts", &entry)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn core_dumps_found_suggests_inquest() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "core_dump_count": 1 });
        let targets: Vec<String> = registry
            .evaluate("postmortem", "core_dumps", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"inquest".to_string()));
    }

    #[test]
    fn oom_kills_found_suggests_inquest() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "oom_kill_count": 2 });
        let targets: Vec<String> = registry
            .evaluate("postmortem", "oom_kill_events", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"inquest".to_string()));
    }
}
