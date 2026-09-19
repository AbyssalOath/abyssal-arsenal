use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, workflow_context_rows, WorkflowContextRow};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, MortiscopeHostRow, MortiscopeHostTemplate, MortiscopeTemplate, SuggestedActionView,
};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    if let Some(host_id) = host_context::current(&jar) {
        if state.hosts.is_connected(host_id) {
            return Ok(Redirect::to(&format!("/arsenals/mortiscope/{host_id}")).into_response());
        }
    }

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

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(MortiscopeHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = MortiscopeTemplate { base, hosts };
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
    render_host_with_suggestions(
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
/// from the workflow registry's matches against this result (see
/// `top_processes_by_cpu` below, the one action that currently produces
/// any), and shows a banner naming which workflow-registry context fields
/// (if any) arrived in the query string -- nothing on this landing page
/// has a field a passed `device` maps to (every read op here takes no
/// arguments), so the banner is all Phase 6 adds here.
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

    let tpl = MortiscopeHostTemplate {
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
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    render_host_with_suggestions(
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

/// Every op in this arsenal is `Read` -- pure monitoring, no state ever
/// changes -- so all six handlers below share this one dispatch helper,
/// same shape as every other arsenal's `run_read_op`.
#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
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
            Permission::SystemsView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
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

pub async fn load_average(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::LoadAverage,
        "Load Average",
    )
    .await
}

/// Parses the top row of `ps -eo pid,ppid,user,%cpu,%mem,comm
/// --sort=-%cpu`'s output (already sorted highest-CPU-first) into a
/// structured `{pid, comm, cpu_percent}` result. Purely additive -- the
/// rendered text output is unchanged, this is only consumed by the
/// workflow registry below. Returns `None` if there's no parseable data
/// row (e.g. output truncation) rather than guessing.
fn top_cpu_process_entry(stdout: &str) -> Option<serde_json::Value> {
    stdout.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return None;
        }
        let pid: u64 = fields[0].parse().ok()?;
        let cpu_percent: f64 = fields[3].parse().ok()?;
        Some(serde_json::json!({
            "pid": pid,
            "comm": fields[5],
            "cpu_percent": cpu_percent,
        }))
    })
}

pub async fn top_processes_by_cpu(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Top Processes by CPU -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::TopProcessesByCpu,
            Permission::SystemsView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let entry = top_cpu_process_entry(&output.stdout);
            let suggested_actions = crate::common::suggested_actions_for(
                &state,
                "mortiscope",
                "top_process_by_cpu",
                &entry.into_iter().collect::<Vec<_>>(),
                host_id,
            )
            .await;
            render_host_with_suggestions(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
                suggested_actions,
                Vec::new(),
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

pub async fn top_processes_by_memory(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::TopProcessesByMemory,
        "Top Processes by Memory",
    )
    .await
}

pub async fn memory_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::MemoryDetail,
        "Memory Detail",
    )
    .await
}

pub async fn disk_io_stats(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::DiskIoStats,
        "Disk I/O Stats",
    )
    .await
}

pub async fn failed_services(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FailedServices,
        "Failed Services",
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
    use super::*;

    #[test]
    fn parses_top_cpu_process() {
        let stdout = "    PID    PPID USER        %CPU %MEM COMMAND\n   1234       1 root        95.2  1.2 stress-ng\n   5678       1 root        10.0  0.5 sshd\n";
        let entry = top_cpu_process_entry(stdout).unwrap();

        assert_eq!(
            entry,
            serde_json::json!({ "pid": 1234, "comm": "stress-ng", "cpu_percent": 95.2 })
        );
    }

    #[test]
    fn header_only_output_returns_none() {
        assert_eq!(
            top_cpu_process_entry("    PID    PPID USER        %CPU %MEM COMMAND\n"),
            None
        );
    }

    #[test]
    fn high_cpu_process_suggests_vivisection_and_reanimation() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "pid": 1234, "comm": "stress-ng", "cpu_percent": 95.2 });

        let matches = registry
            .evaluate("mortiscope", "top_process_by_cpu", &entry)
            .matches;
        let targets: Vec<&str> = matches.iter().map(|m| m.target_arsenal.as_str()).collect();

        assert!(targets.contains(&"vivisection"));
        assert!(targets.contains(&"reanimation"));
    }

    #[test]
    fn low_cpu_process_suggests_nothing() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "pid": 1234, "comm": "idle-task", "cpu_percent": 12.0 });

        assert!(registry
            .evaluate("mortiscope", "top_process_by_cpu", &entry)
            .matches
            .is_empty());
    }
}
