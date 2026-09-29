use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{
    WorkflowContextRow, maybe_elevate, require_csrf, urlencoding_encode, workflow_context_rows,
};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, ProcessRow, ReanimationHostRow, ReanimationHostTemplate, ReanimationOverviewRow,
    ReanimationOverviewTemplate, ReanimationTemplate, SuggestedActionView,
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

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/reanimation/{host_id}")).into_response());
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
            hosts.push(ReanimationHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = ReanimationTemplate { base, hosts };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Parses the top row of `TopProcessesByCpu` output
/// (`pid ppid user %cpu %mem comm`, CPU-sorted) into `(pid, comm, cpu, mem)`.
fn parse_top_process(stdout: &str) -> Option<(String, String, String, String)> {
    stdout.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            return None;
        }
        f[0].parse::<u32>().ok()?;
        Some((
            f[0].to_string(),
            f[5..].join(" "),
            f[3].to_string(),
            f[4].to_string(),
        ))
    })
}

/// Fleet process hub: the top CPU-consuming process on each connected host,
/// live-polled, each linking to that host's Reanimation page (PID pre-filled)
/// so you can act. The source-side complement to Mortiscope's fleet overview.
pub async fn overview(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    let mut rows = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if !host.is_active() || !state.hosts.is_connected(host.id) {
            continue;
        }
        let elevated = state.elevation.is_elevated(host.id);
        let res = state
            .executor
            .execute_on_host(
                &ctx,
                &state.hosts,
                host.id,
                &host.name,
                AgentOperation::TopProcessesByCpu,
                Permission::SystemsView,
                OperationKind::Read,
                false,
                Duration::from_secs(8),
                None,
                elevated,
            )
            .await;

        let mut row = ReanimationOverviewRow {
            host_id: host.id.to_string(),
            host_name: host.name.clone(),
            has_data: false,
            pid: String::new(),
            comm: String::new(),
            cpu: String::new(),
            mem: String::new(),
            note: String::new(),
        };
        match res {
            Ok(o) => match parse_top_process(&o.stdout) {
                Some((pid, comm, cpu, mem)) => {
                    row.has_data = true;
                    row.pid = pid;
                    row.comm = comm;
                    row.cpu = cpu;
                    row.mem = mem;
                }
                None => row.note = "No process data".to_string(),
            },
            Err(e) => row.note = e.to_string(),
        }
        rows.push(row);
    }
    let total = rows.len();

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
    let tpl = ReanimationOverviewTemplate { base, rows, total };
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
        None,
        Vec::new(),
        Vec::new(),
    )
    .await
}

/// Same as `render_host`, but also shows a banner naming which
/// workflow-registry context fields (if any) arrived in the query string,
/// and pre-fills the Process Detail PID field with `prefill_pid` when a
/// suggestion carried one -- the user still has to click "run."
#[allow(clippy::too_many_arguments)]
async fn render_host_with_context(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    context: Vec<WorkflowContextRow>,
    prefill_pid: Option<String>,
    processes: Vec<ProcessRow>,
    suggested_actions: Vec<SuggestedActionView>,
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

    let tpl = ReanimationHostTemplate {
        can_manage: ctx.has(Permission::SystemsManage),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
        context,
        prefill_pid,
        processes,
        suggested_actions,
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
    let context = workflow_context_rows(&query);
    let prefill_pid = query.get("pid").cloned();
    render_host_with_context(
        &state,
        &jar,
        &ctx,
        host_id,
        None,
        None,
        None,
        context,
        prefill_pid,
        Vec::new(),
        Vec::new(),
    )
    .await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

/// Parses the structured `ps -eo pid,ppid,user,stat,pcpu,pmem,comm` output
/// into table rows, flagging zombies by their state code (`Z`).
fn parse_process_list(stdout: &str) -> Vec<ProcessRow> {
    stdout
        .lines()
        .skip(1) // header row
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?;
            let ppid = fields.next()?;
            let user = fields.next()?;
            let stat = fields.next()?;
            let cpu = fields.next()?;
            let mem = fields.next()?;
            let comm = fields.collect::<Vec<_>>().join(" ");
            if comm.is_empty() {
                return None;
            }
            Some(ProcessRow {
                pid: pid.to_string(),
                ppid: ppid.to_string(),
                user: user.to_string(),
                stat: stat.to_string(),
                cpu: cpu.to_string(),
                mem: mem.to_string(),
                comm,
                is_zombie: stat.starts_with('Z'),
            })
        })
        .collect()
}

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

pub async fn list_processes(
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
    let result_label = Some(format!("Processes -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ListProcesses,
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
            let processes = parse_process_list(&output.stdout);
            let zombie_count = processes.iter().filter(|p| p.is_zombie).count();
            let entry = serde_json::json!({ "zombie_count": zombie_count });
            let suggested_actions = crate::common::suggested_actions_for(
                &state,
                "reanimation",
                "list_processes",
                std::slice::from_ref(&entry),
                host_id,
            )
            .await;
            render_host_with_context(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                None,
                None,
                Vec::new(),
                None,
                processes,
                suggested_actions,
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

#[derive(Deserialize)]
pub struct PidForm {
    csrf_token: String,
    pid: u32,
}

fn validate_pid(pid: u32) -> Result<u32, WebError> {
    if !abyssal_agent_protocol::is_valid_pid(pid) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid, non-protected process ID.".into(),
        )));
    }
    Ok(pid)
}

pub async fn process_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PidForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ProcessDetail { pid },
        &format!("Process Detail ({pid})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct ReniceForm {
    csrf_token: String,
    pid: u32,
    priority: i32,
}

fn validate_priority(priority: i32) -> Result<i32, WebError> {
    if !abyssal_agent_protocol::is_valid_nice_priority(priority) {
        return Err(WebError(AppError::Validation(
            "Nice priority must be between -20 and 19.".into(),
        )));
    }
    Ok(priority)
}

/// `Write`, no confirmation required -- renicing is reversible.
pub async fn renice_priority(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ReniceForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    let priority = validate_priority(form.priority)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Renice ({pid} -> {priority}) -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::RenicePriority { pid, priority },
            Permission::SystemsManage,
            OperationKind::Write,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                &state,
                &jar,
                &ctx,
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

#[derive(Deserialize)]
pub struct SignalQuery {
    pid: u32,
    signal: String,
}

fn validate_signal(signal: &str) -> Result<String, WebError> {
    if !abyssal_agent_protocol::is_valid_signal_name(signal) {
        return Err(WebError(AppError::Validation(
            "That isn't one of the supported signals.".into(),
        )));
    }
    Ok(signal.to_string())
}

/// Terminating or interrupting signals go through the Destructive
/// type-to-confirm gate; reversible ones (HUP reload, CONT resume, STOP
/// suspend, USR1/USR2) are a plain Write. Normalizes case and a `SIG` prefix
/// first so the classification doesn't depend on how the value was written.
fn signal_is_destructive(signal: &str) -> bool {
    let s = signal.to_ascii_uppercase();
    let s = s.strip_prefix("SIG").unwrap_or(&s);
    matches!(s, "TERM" | "KILL" | "QUIT" | "INT")
}

fn validate_process_name(name: &str) -> Result<String, WebError> {
    if !abyssal_agent_protocol::is_valid_process_name(name) {
        return Err(WebError(AppError::Validation(
            "Enter a process name without spaces (and not starting with '-').".into(),
        )));
    }
    Ok(name.to_string())
}

pub async fn signal_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SignalQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;

    let pid = validate_pid(q.pid)?;
    let signal = validate_signal(&q.signal)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
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

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Send signal".to_string(),
        message: format!(
            "This will send SIG{signal} to process {pid} on \"{}\". Any signal is an \
             intentional interruption of whatever that process is doing.",
            host.name
        ),
        action_url: format!(
            "/arsenals/reanimation/{host_id}/signal?pid={pid}&signal={}",
            urlencoding_encode(&signal)
        ),
        cancel_url: format!("/arsenals/reanimation/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "process ID".to_string(),
            expected: pid.to_string(),
        }),
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct SignalForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn send_signal(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SignalQuery>,
    Form(form): Form<SignalForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let pid = validate_pid(q.pid)?;
    let signal = validate_signal(&q.signal)?;

    // Graduated risk: terminating/interrupting signals need the typed
    // confirmation; reversible ones (reload/resume/suspend/app-defined) are a
    // plain Write, so a per-row Pause/Resume is one click.
    let destructive = signal_is_destructive(&signal);
    if destructive {
        if !form.confirm {
            return Err(WebError(AppError::Validation(
                "Send signal was not confirmed.".into(),
            )));
        }
        crate::common::require_typed_confirmation(&form.confirm_text, &pid.to_string())?;
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!(
        "Send Signal (SIG{signal} -> {pid}) -- {}",
        host.name
    ));

    let kind = if destructive {
        OperationKind::Destructive
    } else {
        OperationKind::Write
    };
    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SendSignal { pid, signal },
            Permission::SystemsManage,
            kind,
            destructive,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                &state,
                &jar,
                &ctx,
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

pub async fn process_open_files(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PidForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ProcessOpenFiles { pid },
        &format!("Open Files ({pid})"),
    )
    .await
}

pub async fn process_limits(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PidForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ProcessLimits { pid },
        &format!("Limits & Info ({pid})"),
    )
    .await
}

/// Reads the leading count from the zombie report's first line ("N
/// zombie/defunct process(es):" or "No zombie..."), defaulting to 0.
fn parse_zombie_count(stdout: &str) -> i64 {
    stdout
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .and_then(|t| t.parse::<i64>().ok())
        .unwrap_or(0)
}

pub async fn zombie_report(
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
    let result_label = Some(format!("Zombie Report -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ZombieReport,
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
            let entry = serde_json::json!({ "zombie_count": parse_zombie_count(&output.stdout) });
            let suggested_actions = crate::common::suggested_actions_for(
                &state,
                "reanimation",
                "zombie_report",
                std::slice::from_ref(&entry),
                host_id,
            )
            .await;
            render_host_with_context(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
                Vec::new(),
                None,
                Vec::new(),
                suggested_actions,
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

#[derive(Deserialize)]
pub struct IoPriorityForm {
    csrf_token: String,
    pid: u32,
    class: u8,
    #[serde(default)]
    level: u8,
}

pub async fn set_io_priority(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<IoPriorityForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    if !abyssal_agent_protocol::is_valid_ionice_class(form.class)
        || !abyssal_agent_protocol::is_valid_ionice_level(form.level)
    {
        return Err(WebError(AppError::Validation(
            "Choose an I/O class (1-3) and level (0-7).".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("I/O Priority ({pid}) -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SetIoPriority {
                pid,
                class: form.class,
                level: form.level,
            },
            Permission::SystemsManage,
            OperationKind::Write,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                &state,
                &jar,
                &ctx,
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

#[derive(Deserialize)]
pub struct OomScoreForm {
    csrf_token: String,
    pid: u32,
    adj: i32,
}

pub async fn set_oom_score_adj(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<OomScoreForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let pid = validate_pid(form.pid)?;
    if !abyssal_agent_protocol::is_valid_oom_score_adj(form.adj) {
        return Err(WebError(AppError::Validation(
            "OOM score adjustment must be between -1000 and 1000.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!(
        "OOM Score Adj ({pid} -> {}) -- {}",
        form.adj, host.name
    ));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SetOomScoreAdj { pid, adj: form.adj },
            Permission::SystemsManage,
            OperationKind::Write,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                &state,
                &jar,
                &ctx,
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

#[derive(Deserialize)]
pub struct SignalByNameQuery {
    name: String,
    signal: String,
}

/// Confirmation page for signal-by-name: dispatches a dry-run to preview which
/// processes would be hit, then shows them. Destructive signals additionally
/// require typing the name back; reversible ones just need the Confirm click,
/// since seeing the match list is the real safeguard for a bulk action.
pub async fn signal_by_name_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SignalByNameQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    let name = validate_process_name(&q.name)?;
    let signal = validate_signal(&q.signal)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Preview via a dry run (a read) so the operator sees the matches first.
    let elevated = state.elevation.is_elevated(host_id);
    let preview = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SignalByName {
                name: name.clone(),
                signal: signal.clone(),
                dry_run: true,
            },
            Permission::SystemsView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await;
    let preview_text = match preview {
        Ok(output) => output.stdout,
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            return render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some(format!("Signal by name ({name})")),
                None,
                Some(e.to_string()),
            )
            .await;
        }
    };

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
    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let type_to_confirm = if signal_is_destructive(&signal) {
        Some(crate::templates::TypeToConfirm {
            label: "process name".to_string(),
            expected: name.clone(),
        })
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: format!("Send SIG{signal} to processes named \u{201c}{name}\u{201d}"),
        message: format!(
            "On \"{}\":\n\n{preview_text}\n\nThe agent re-resolves the matches when the signal is sent, so the exact set may differ slightly.",
            host.name
        ),
        action_url: format!(
            "/arsenals/reanimation/{host_id}/signal-by-name?name={}&signal={}",
            urlencoding_encode(&name),
            urlencoding_encode(&signal)
        ),
        cancel_url: format!("/arsenals/reanimation/{host_id}"),
        escalate_host_id,
        type_to_confirm,
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn signal_by_name(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SignalByNameQuery>,
    Form(form): Form<SignalForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let name = validate_process_name(&q.name)?;
    let signal = validate_signal(&q.signal)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Signal by name was not confirmed.".into(),
        )));
    }
    let destructive = signal_is_destructive(&signal);
    if destructive {
        crate::common::require_typed_confirmation(&form.confirm_text, &name)?;
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!(
        "Signal by name (SIG{signal} -> {name}) -- {}",
        host.name
    ));

    let kind = if destructive {
        OperationKind::Destructive
    } else {
        OperationKind::Write
    };
    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SignalByName {
                name,
                signal,
                dry_run: false,
            },
            Permission::SystemsManage,
            kind,
            destructive,
            Duration::from_secs(20),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                &state,
                &jar,
                &ctx,
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
    fn parses_process_rows_and_flags_zombies() {
        let stdout = "    PID    PPID USER     STAT %CPU %MEM COMMAND\n\
                       1234       1 root     R    92.0  1.2 stress-ng\n\
                       5678    1234 alice    Z     0.0  0.0 defunct-child\n\
                       9012       1 root     Ssl   0.1  4.5 postgres\n";
        let rows = parse_process_list(stdout);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].pid, "1234");
        assert_eq!(rows[0].comm, "stress-ng");
        assert!(!rows[0].is_zombie);
        assert!(rows[1].is_zombie);
        assert!(!rows[2].is_zombie);
    }

    #[test]
    fn parses_top_process_row_for_the_fleet_hub() {
        let stdout = "    PID    PPID USER     %CPU %MEM COMMAND\n\
                       4242       1 root     87.5  3.1 stress-ng\n\
                       9000       1 alice     0.2  1.0 sshd\n";
        let (pid, comm, cpu, mem) = parse_top_process(stdout).unwrap();
        assert_eq!(pid, "4242");
        assert_eq!(comm, "stress-ng");
        assert_eq!(cpu, "87.5");
        assert_eq!(mem, "3.1");
        // Header-only output yields nothing.
        assert!(parse_top_process("    PID    PPID USER     %CPU %MEM COMMAND\n").is_none());
    }

    #[test]
    fn signal_risk_is_graduated() {
        // Terminating/interrupting -> Destructive (typed confirm).
        for s in ["TERM", "KILL", "QUIT", "INT"] {
            assert!(signal_is_destructive(s), "{s} should be destructive");
        }
        // Reversible/benign -> Write (one-click).
        for s in ["HUP", "CONT", "STOP", "USR1", "USR2"] {
            assert!(!signal_is_destructive(s), "{s} should be a plain write");
        }
        // Normalizes case and a SIG prefix.
        assert!(signal_is_destructive("sigkill"));
        assert!(!signal_is_destructive("SIGCONT"));
    }

    #[test]
    fn parses_zombie_count_from_report_first_line() {
        assert_eq!(
            parse_zombie_count("3 zombie/defunct process(es):\n  pid 1 ..."),
            3
        );
        assert_eq!(parse_zombie_count("No zombie/defunct processes found."), 0);
    }

    #[test]
    fn zombie_report_also_suggests_postmortem() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let hit = serde_json::json!({ "zombie_count": 1 });
        let targets: Vec<String> = registry
            .evaluate("reanimation", "zombie_report", &hit)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"postmortem".to_string()));
    }

    #[test]
    fn zombies_suggest_postmortem() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let hit = serde_json::json!({ "zombie_count": 2 });
        let targets: Vec<String> = registry
            .evaluate("reanimation", "list_processes", &hit)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"postmortem".to_string()));

        let clean = serde_json::json!({ "zombie_count": 0 });
        assert!(
            registry
                .evaluate("reanimation", "list_processes", &clean)
                .matches
                .is_empty()
        );
    }
}
