use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::settings::{
    MORTISCOPE_ALERT_RECIPIENTS, MORTISCOPE_MONITORING_ENABLED, MORTISCOPE_SUSTAINED_SAMPLES,
    MORTISCOPE_SUSTAINED_SAMPLES_DEFAULT,
};
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

use crate::common::{WorkflowContextRow, maybe_elevate, require_csrf, workflow_context_rows};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::mortiscope_ops::{TREND_METRICS, evaluate_thresholds, metric_label};
use crate::state::AppState;
use crate::templates::{
    BaseCtx, MortiscopeHostRow, MortiscopeHostTemplate, MortiscopeTemplate, MortiscopeThresholdRow,
    MortiscopeThresholdsTemplate, MortiscopeTrendRow, SuggestedActionView,
};
use crate::theme;

/// How many recent samples a trend sparkline plots.
const TREND_SAMPLES: i64 = 40;

use crate::common::sparkline_points;

/// Loads the recent trend for each swept metric, skipping ones with no samples
/// yet (e.g. before the first sweep). Read on every host-page render, so it's a
/// handful of small indexed queries.
async fn load_trends(pool: &abyssal_database::DbPool, host_id: Uuid) -> Vec<MortiscopeTrendRow> {
    let mut rows = Vec::new();
    for (metric, label, unit) in TREND_METRICS {
        let samples = match abyssal_database::repo::host_metrics::recent(
            pool,
            host_id,
            metric,
            TREND_SAMPLES,
        )
        .await
        {
            Ok(s) if !s.is_empty() => s,
            _ => continue,
        };
        let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
        let latest = format!("{:.1}{unit}", values[values.len() - 1]);
        rows.push(MortiscopeTrendRow {
            label: label.to_string(),
            latest,
            sparkline_points: sparkline_points(&values, 120.0, 24.0),
            samples: values.len(),
        });
    }
    rows
}

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
        return Ok(Redirect::to(&format!("/arsenals/mortiscope/{host_id}")).into_response());
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
                is_control_plane: host.is_control_plane,
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

    let trends = load_trends(&state.pool, host_id).await;

    let tpl = MortiscopeHostTemplate {
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        control_plane: crate::control_plane::page_note(&state.hosts, host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        context,
        trends,
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

/// Like `run_read_op`, but parses the output into a structured entry and feeds
/// it to the workflow registry so a high reading can suggest where to act. The
/// rendered text output is unchanged; `parse` returning `None` (nothing
/// parseable) just means no suggestions, same as a below-threshold reading.
#[allow(clippy::too_many_arguments)]
async fn run_read_structured(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    source_action: &str,
    parse: fn(&str) -> Option<serde_json::Value>,
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
            let entries: Vec<serde_json::Value> = parse(&output.stdout).into_iter().collect();
            let suggested_actions = crate::common::suggested_actions_for(
                state,
                "mortiscope",
                source_action,
                &entries,
                host_id,
            )
            .await;
            render_host_with_suggestions(
                state,
                jar,
                ctx,
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

/// Parses `uptime`'s three load-average figures, and -- when the agent
/// appended it -- the CPU core count, into a structured entry. `load_per_core`
/// is only present when the core count is known (a newer agent), so a
/// threshold on it simply never matches against an older agent's output rather
/// than misfiring. Assumes the C-locale `.` decimal form a non-interactive
/// shell produces.
pub(crate) fn parse_load_average(stdout: &str) -> Option<serde_json::Value> {
    let after = stdout.split("load average:").nth(1)?;
    let nums: Vec<f64> = after
        .split(',')
        .filter_map(|t| t.split_whitespace().next())
        .filter_map(|t| t.parse::<f64>().ok())
        .collect();
    if nums.len() < 3 {
        return None;
    }
    let mut entry = serde_json::json!({
        "load_1": nums[0],
        "load_5": nums[1],
        "load_15": nums[2],
    });
    let cores = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("CPU cores:"))
        .and_then(|c| c.trim().parse::<f64>().ok());
    if let Some(c) = cores
        && c > 0.0
    {
        entry["cpu_cores"] = serde_json::json!(c as u64);
        // Round to two decimals so a threshold comparison is stable.
        entry["load_per_core"] = serde_json::json!((nums[0] / c * 100.0).round() / 100.0);
    }
    Some(entry)
}

/// Parses `/proc/meminfo` into used-memory and swap-used percentages plus
/// available memory. Percentages are whole numbers, matching how the workflow
/// thresholds are written.
pub(crate) fn parse_memory_detail(stdout: &str) -> Option<serde_json::Value> {
    let kv = |key: &str| -> Option<f64> {
        stdout.lines().find_map(|line| {
            let mut it = line.split(':');
            if it.next()?.trim() == key {
                it.next()?.split_whitespace().next()?.parse::<f64>().ok()
            } else {
                None
            }
        })
    };
    let total = kv("MemTotal")?;
    let available = kv("MemAvailable")?;
    if total <= 0.0 {
        return None;
    }
    let used_percent = ((total - available) / total * 100.0).round() as u64;
    let swap_total = kv("SwapTotal").unwrap_or(0.0);
    let swap_free = kv("SwapFree").unwrap_or(0.0);
    let swap_used_percent = if swap_total > 0.0 {
        ((swap_total - swap_free) / swap_total * 100.0).round() as u64
    } else {
        0
    };
    Some(serde_json::json!({
        "mem_used_percent": used_percent,
        "mem_available_kb": available as u64,
        "swap_used_percent": swap_used_percent,
    }))
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
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::LoadAverage,
        "Load Average",
        "load_average",
        parse_load_average,
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

/// The memory counterpart to `top_cpu_process_entry`: the top row of `ps ...
/// --sort=-%mem` as `{pid, comm, mem_percent}` (the `%mem` column is field 4).
fn top_mem_process_entry(stdout: &str) -> Option<serde_json::Value> {
    stdout.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return None;
        }
        let pid: u64 = fields[0].parse().ok()?;
        let mem_percent: f64 = fields[4].parse().ok()?;
        Some(serde_json::json!({
            "pid": pid,
            "comm": fields[5],
            "mem_percent": mem_percent,
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
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::TopProcessesByCpu,
        "Top Processes by CPU",
        "top_process_by_cpu",
        top_cpu_process_entry,
    )
    .await
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
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::TopProcessesByMemory,
        "Top Processes by Memory",
        "top_process_by_memory",
        top_mem_process_entry,
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
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::MemoryDetail,
        "Memory Detail",
        "memory_detail",
        parse_memory_detail,
    )
    .await
}

/// Parses the CPU utilization report's `busy:`/`iowait:` percentages.
pub(crate) fn parse_cpu_utilization(stdout: &str) -> Option<serde_json::Value> {
    let val = |label: &str| {
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix(label))
            .and_then(|v| v.trim().trim_end_matches('%').trim().parse::<f64>().ok())
    };
    let busy = val("busy:")?;
    Some(serde_json::json!({
        "cpu_busy_percent": busy,
        "cpu_iowait_percent": val("iowait:").unwrap_or(0.0),
    }))
}

/// Parses the network throughput report's `total:` line into KB/s figures.
fn parse_network_throughput(stdout: &str) -> Option<serde_json::Value> {
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("total:"))?;
    let after = |kw: &str| {
        line.split_whitespace()
            .skip_while(|t| *t != kw)
            .nth(1)
            .and_then(|v| v.parse::<f64>().ok())
    };
    Some(serde_json::json!({
        "net_rx_kbps": after("rx")?,
        "net_tx_kbps": after("tx")?,
    }))
}

/// Parses the `Max temperature: N C` line the thermal reading emits.
fn parse_thermal_sensors(stdout: &str) -> Option<serde_json::Value> {
    let line = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Max temperature:"))?;
    let c = line.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(serde_json::json!({ "max_temp_c": c }))
}

/// Parses the PSI report's memory/io/cpu `some avg10` figures, omitting any
/// that were `n/a` (unavailable on this kernel). Returns `None` if none parsed.
fn parse_memory_pressure(stdout: &str) -> Option<serde_json::Value> {
    let val = |label: &str| {
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix(label))
            .and_then(|v| v.trim().parse::<f64>().ok())
    };
    let (mem, io, cpu) = (val("memory:"), val("io:"), val("cpu:"));
    if mem.is_none() && io.is_none() && cpu.is_none() {
        return None;
    }
    let mut entry = serde_json::Map::new();
    if let Some(m) = mem {
        entry.insert("mem_pressure_some_avg10".into(), serde_json::json!(m));
    }
    if let Some(i) = io {
        entry.insert("io_pressure_some_avg10".into(), serde_json::json!(i));
    }
    if let Some(c) = cpu {
        entry.insert("cpu_pressure_some_avg10".into(), serde_json::json!(c));
    }
    Some(serde_json::Value::Object(entry))
}

pub async fn cpu_utilization(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::CpuUtilization,
        "CPU Utilization",
        "cpu_utilization",
        parse_cpu_utilization,
    )
    .await
}

pub async fn network_throughput(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::NetworkThroughput,
        "Network Throughput",
        "network_throughput",
        parse_network_throughput,
    )
    .await
}

pub async fn thermal_sensors(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ThermalSensors,
        "Thermal Sensors",
        "thermal_sensors",
        parse_thermal_sensors,
    )
    .await
}

pub async fn memory_pressure(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_structured(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::MemoryPressure,
        "Memory Pressure",
        "memory_pressure",
        parse_memory_pressure,
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

// ---- M4: threshold configuration & alerting -----------------------------

fn valid_metric(metric: &str) -> bool {
    TREND_METRICS.iter().any(|(k, _, _)| *k == metric)
}

fn valid_comparator(c: &str) -> bool {
    c == "ge" || c == "le"
}

fn valid_severity(s: &str) -> bool {
    matches!(s, "info" | "warning" | "critical")
}

/// Renders the monitoring/thresholds management page, with an optional
/// result message from the action that just ran.
async fn render_thresholds(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    result_message: Option<String>,
) -> Result<Response, WebError> {
    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        host_context::current(jar),
    )
    .await?;

    let monitoring_enabled =
        repo::settings::get_bool(&state.pool, MORTISCOPE_MONITORING_ENABLED, false)
            .await
            .unwrap_or(false);
    let recipients = repo::settings::get_string(&state.pool, MORTISCOPE_ALERT_RECIPIENTS, "")
        .await
        .unwrap_or_default();
    let sustained_samples = repo::settings::get_u32(
        &state.pool,
        MORTISCOPE_SUSTAINED_SAMPLES,
        MORTISCOPE_SUSTAINED_SAMPLES_DEFAULT,
    )
    .await
    .unwrap_or(MORTISCOPE_SUSTAINED_SAMPLES_DEFAULT);

    let thresholds = repo::monitoring::list_thresholds(&state.pool)
        .await?
        .into_iter()
        .map(|t| MortiscopeThresholdRow {
            id: t.id.to_string(),
            metric_label: metric_label(&t.metric).to_string(),
            comparator_label: if t.comparator == "le" {
                "\u{2264}"
            } else {
                "\u{2265}"
            }
            .to_string(),
            threshold: format!("{}", t.threshold),
            severity: t.severity,
            enabled: t.enabled,
        })
        .collect();

    let metric_options = TREND_METRICS
        .iter()
        .map(|(k, l, _)| (k.to_string(), l.to_string()))
        .collect();

    let tpl = MortiscopeThresholdsTemplate {
        can_manage: ctx.has(Permission::SystemsManage),
        base,
        monitoring_enabled,
        recipients,
        sustained_samples,
        thresholds,
        metric_options,
        result_message,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn thresholds_page(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    render_thresholds(&state, &jar, &ctx, None).await
}

#[derive(Deserialize)]
pub struct AddThresholdForm {
    csrf_token: String,
    metric: String,
    comparator: String,
    threshold: f64,
    severity: String,
}

pub async fn add_threshold(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<AddThresholdForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !valid_metric(&form.metric)
        || !valid_comparator(&form.comparator)
        || !valid_severity(&form.severity)
        || !form.threshold.is_finite()
    {
        return Err(WebError(AppError::Validation(
            "Choose a valid metric, comparator (>= or <=), severity, and a numeric threshold."
                .into(),
        )));
    }

    repo::monitoring::create_threshold(
        &state.pool,
        &form.metric,
        &form.comparator,
        form.threshold,
        &form.severity,
    )
    .await?;
    render_thresholds(
        &state,
        &jar,
        &ctx,
        Some(format!("Added a {} threshold.", metric_label(&form.metric))),
    )
    .await
}

#[derive(Deserialize)]
pub struct DeleteThresholdForm {
    csrf_token: String,
}

pub async fn delete_threshold(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<DeleteThresholdForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    repo::monitoring::delete_threshold(&state.pool, id).await?;
    render_thresholds(&state, &jar, &ctx, Some("Deleted threshold.".to_string())).await
}

#[derive(Deserialize)]
pub struct MonitoringToggleForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn monitoring_toggle(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<MonitoringToggleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    repo::settings::set(
        &state.pool,
        MORTISCOPE_MONITORING_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;
    let msg = if form.enabled {
        "Threshold alerting enabled."
    } else {
        "Threshold alerting disabled."
    };
    render_thresholds(&state, &jar, &ctx, Some(msg.to_string())).await
}

#[derive(Deserialize)]
pub struct MonitoringConfigForm {
    csrf_token: String,
    #[serde(default)]
    recipients: String,
    sustained_samples: u32,
}

pub async fn monitoring_config(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<MonitoringConfigForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let sustained = form.sustained_samples.clamp(1, 60);
    repo::settings::set(
        &state.pool,
        MORTISCOPE_ALERT_RECIPIENTS,
        serde_json::json!(form.recipients.trim()),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        MORTISCOPE_SUSTAINED_SAMPLES,
        serde_json::json!(sustained),
        Some(ctx.user.id),
    )
    .await?;
    render_thresholds(
        &state,
        &jar,
        &ctx,
        Some("Monitoring settings saved.".to_string()),
    )
    .await
}

pub async fn evaluate_now(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let msg = match evaluate_thresholds(&state).await {
        Ok(n) => format!("Evaluated thresholds against connected hosts: {n} new alert(s) fired."),
        Err(e) => format!("Evaluation failed: {e}"),
    };
    render_thresholds(&state, &jar, &ctx, Some(msg)).await
}

// ---- M5: fleet monitoring overview --------------------------------------

/// A metric cell's evaluation: its display string, colour badge, and a rank
/// used to roll a host up to its worst cell and to sort hosts worst-first.
/// Ranks: 0 no-data, 1 ok, 2 info-breach, 3 warning, 4 critical.
struct CellEval {
    value: String,
    badge: String,
    rank: u8,
}

fn eval_cell(
    value: Option<f64>,
    unit: &str,
    metric: &str,
    thresholds: &[abyssal_database::repo::monitoring::Threshold],
) -> CellEval {
    let Some(v) = value else {
        return CellEval {
            value: "\u{2014}".to_string(),
            badge: String::new(),
            rank: 0,
        };
    };
    let worst = thresholds
        .iter()
        .filter(|t| {
            t.metric == metric && crate::mortiscope_ops::breaches(v, &t.comparator, t.threshold)
        })
        .max_by_key(|t| crate::mortiscope_ops::severity_rank(&t.severity));
    let (badge, rank) = match worst.map(|t| t.severity.as_str()) {
        Some("critical") => ("badge-danger", 4),
        Some("warning") => ("badge-warning", 3),
        Some(_) => ("badge-muted", 2),
        None => ("badge-success", 1),
    };
    CellEval {
        value: format!("{v:.1}{unit}"),
        badge: badge.to_string(),
        rank,
    }
}

fn status_from_rank(rank: u8) -> (&'static str, &'static str) {
    match rank {
        4 => ("critical", "badge-danger"),
        3 => ("warning", "badge-warning"),
        2 => ("info", "badge-muted"),
        1 => ("ok", "badge-success"),
        _ => ("no data", "badge-muted"),
    }
}

pub async fn overview(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    let thresholds = repo::monitoring::list_enabled_thresholds(&state.pool).await?;
    let monitoring_enabled =
        repo::settings::get_bool(&state.pool, MORTISCOPE_MONITORING_ENABLED, false)
            .await
            .unwrap_or(false);

    // latest value per (host, metric), grouped by host.
    let mut latest: HashMap<Uuid, HashMap<String, f64>> = HashMap::new();
    for l in repo::host_metrics::latest_per_host_metric(&state.pool).await? {
        latest
            .entry(l.host_id)
            .or_default()
            .insert(l.metric, l.value);
    }

    let (mut critical, mut warning, mut ok, mut no_data) = (0usize, 0usize, 0usize, 0usize);
    let mut rows = Vec::new();
    let mut suggested_actions = Vec::new();
    let mut seen_urls = std::collections::HashSet::new();

    for host in repo::hosts::list(&state.pool).await? {
        if !host.is_active() {
            continue;
        }
        let values = latest.get(&host.id);
        let get = |metric: &str| values.and_then(|m| m.get(metric).copied());

        let mut cells = Vec::new();
        let mut worst_rank = 0u8;
        for (metric, _label, unit) in TREND_METRICS {
            let cell = eval_cell(get(metric), unit, metric, &thresholds);
            worst_rank = worst_rank.max(cell.rank);
            cells.push(crate::templates::MortiscopeOverviewCell {
                value: cell.value,
                badge_class: cell.badge,
            });
        }

        match worst_rank {
            4 => critical += 1,
            2 | 3 => warning += 1,
            1 => ok += 1,
            _ => no_data += 1,
        }
        let (status_label, status_badge_class) = status_from_rank(worst_rank);

        // Aggregate this host's registry suggestions from synthetic entries
        // built from its latest values -- the registry's own thresholds gate
        // which fire, so only genuinely-high metrics produce a suggestion.
        for action in overview_suggestions(&state, host.id, values).await {
            if seen_urls.insert(action.url.clone()) {
                suggested_actions.push(action);
            }
        }

        rows.push((
            worst_rank,
            crate::templates::MortiscopeOverviewRow {
                host_id: host.id.to_string(),
                host_name: host.name,
                cells,
                status_label: status_label.to_string(),
                status_badge_class: status_badge_class.to_string(),
            },
        ));
    }

    // Worst hosts first, then by name for stability.
    rows.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.host_name.cmp(&b.1.host_name))
    });
    let rows: Vec<_> = rows.into_iter().map(|(_, r)| r).collect();
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

    let tpl = crate::templates::MortiscopeOverviewTemplate {
        base,
        metric_labels: TREND_METRICS
            .iter()
            .map(|(_, l, _)| l.to_string())
            .collect(),
        rows,
        total,
        critical,
        warning,
        ok,
        no_data,
        monitoring_enabled,
        suggested_actions,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Evaluates a host's latest values against the mortiscope workflow registry,
/// building the same synthetic entries the on-demand read handlers would, and
/// returns the matched suggestions for that host.
async fn overview_suggestions(
    state: &AppState,
    host_id: Uuid,
    values: Option<&HashMap<String, f64>>,
) -> Vec<SuggestedActionView> {
    let Some(values) = values else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // Synthetic per-metric entries in the same shape the on-demand read
    // handlers produce, so the overview reuses the exact workflow-registry
    // edges instead of duplicating any thresholds.
    let mut synthetic: Vec<(&'static str, serde_json::Value)> = Vec::new();
    if let Some(v) = values.get(crate::mortiscope_ops::METRIC_LOAD_PER_CORE) {
        synthetic.push(("load_average", serde_json::json!({ "load_per_core": v })));
    }
    if let Some(v) = values.get(crate::mortiscope_ops::METRIC_CPU_BUSY) {
        synthetic.push((
            "cpu_utilization",
            serde_json::json!({ "cpu_busy_percent": v }),
        ));
    }
    let mem = values.get(crate::mortiscope_ops::METRIC_MEM_USED);
    let swap = values.get(crate::mortiscope_ops::METRIC_SWAP_USED);
    if mem.is_some() || swap.is_some() {
        synthetic.push((
            "memory_detail",
            serde_json::json!({
                "mem_used_percent": mem.copied().unwrap_or(0.0),
                "swap_used_percent": swap.copied().unwrap_or(0.0),
            }),
        ));
    }

    for (action, entry) in synthetic {
        out.extend(
            crate::common::suggested_actions_for(
                state,
                "mortiscope",
                action,
                std::slice::from_ref(&entry),
                host_id,
            )
            .await,
        );
    }
    out
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

        assert!(
            registry
                .evaluate("mortiscope", "top_process_by_cpu", &entry)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn parses_load_average_with_and_without_core_count() {
        let with_cores =
            " 14:03:52 up 3 days,  2:11,  2 users,  load average: 5.20, 3.10, 1.05\nCPU cores: 2";
        let entry = parse_load_average(with_cores).unwrap();
        assert_eq!(entry["load_1"], serde_json::json!(5.20));
        assert_eq!(entry["load_15"], serde_json::json!(1.05));
        assert_eq!(entry["cpu_cores"], serde_json::json!(2));
        assert_eq!(entry["load_per_core"], serde_json::json!(2.6));

        // Older agent: no core count line, so no per-core field (a threshold on
        // it then simply never matches rather than misfiring).
        let no_cores = " 14:03:52 up 3 days,  2:11,  2 users,  load average: 5.20, 3.10, 1.05";
        let entry = parse_load_average(no_cores).unwrap();
        assert_eq!(entry["load_1"], serde_json::json!(5.20));
        assert!(entry.get("load_per_core").is_none());
    }

    #[test]
    fn parses_memory_detail_percentages() {
        let meminfo = "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    200 kB\nSwapTotal:       1000 kB\nSwapFree:        600 kB\n";
        let entry = parse_memory_detail(meminfo).unwrap();
        // (1000 - 200) / 1000 = 80%
        assert_eq!(entry["mem_used_percent"], serde_json::json!(80));
        assert_eq!(entry["mem_available_kb"], serde_json::json!(200));
        // (1000 - 600) / 1000 = 40%
        assert_eq!(entry["swap_used_percent"], serde_json::json!(40));
    }

    #[test]
    fn memory_detail_with_no_swap_reports_zero_swap_used() {
        let meminfo = "MemTotal:       1000 kB\nMemAvailable:    500 kB\nSwapTotal:          0 kB\nSwapFree:           0 kB\n";
        let entry = parse_memory_detail(meminfo).unwrap();
        assert_eq!(entry["swap_used_percent"], serde_json::json!(0));
    }

    #[test]
    fn parses_top_memory_process() {
        let stdout = "    PID    PPID USER        %CPU %MEM COMMAND\n   4321       1 root         2.0 61.5 postgres\n";
        let entry = top_mem_process_entry(stdout).unwrap();
        assert_eq!(
            entry,
            serde_json::json!({ "pid": 4321, "comm": "postgres", "mem_percent": 61.5 })
        );
    }

    #[test]
    fn high_load_per_core_suggests_vivisection() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "load_1": 5.2, "cpu_cores": 2, "load_per_core": 2.6 });
        let targets: Vec<String> = registry
            .evaluate("mortiscope", "load_average", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"vivisection".to_string()));

        // Below one-per-core: quiet.
        let ok = serde_json::json!({ "load_1": 0.5, "cpu_cores": 4, "load_per_core": 0.13 });
        assert!(
            registry
                .evaluate("mortiscope", "load_average", &ok)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn high_memory_and_swap_suggest_vivisection() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let hot = serde_json::json!({ "mem_used_percent": 94, "swap_used_percent": 70 });
        let matches = registry
            .evaluate("mortiscope", "memory_detail", &hot)
            .matches;
        // Both the memory and swap thresholds point at Vivisection.
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.target_arsenal == "vivisection"));

        let ok = serde_json::json!({ "mem_used_percent": 40, "swap_used_percent": 0 });
        assert!(
            registry
                .evaluate("mortiscope", "memory_detail", &ok)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn high_memory_process_suggests_reanimation() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "pid": 4321, "comm": "postgres", "mem_percent": 61.5 });
        let targets: Vec<String> = registry
            .evaluate("mortiscope", "top_process_by_memory", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"reanimation".to_string()));
    }

    #[test]
    fn parses_cpu_utilization() {
        let out = "CPU utilization (sampled over 500ms):\n  busy: 37.5%\n  iowait: 2.1%";
        let entry = parse_cpu_utilization(out).unwrap();
        assert_eq!(entry["cpu_busy_percent"], serde_json::json!(37.5));
        assert_eq!(entry["cpu_iowait_percent"], serde_json::json!(2.1));
    }

    #[test]
    fn parses_network_throughput_total_line() {
        let out = "Network throughput (sampled over 500ms):\n  total: rx 123.4 KB/s, tx 56.7 KB/s\n  eth0: rx 123.4 KB/s, tx 56.7 KB/s";
        let entry = parse_network_throughput(out).unwrap();
        assert_eq!(entry["net_rx_kbps"], serde_json::json!(123.4));
        assert_eq!(entry["net_tx_kbps"], serde_json::json!(56.7));
    }

    #[test]
    fn parses_thermal_max_temp() {
        let out = "Max temperature: 82.0 C\n\nThermal zones:\n  x86_pkg_temp: 82.0 C";
        assert_eq!(
            parse_thermal_sensors(out).unwrap()["max_temp_c"],
            serde_json::json!(82.0)
        );
        // No max line (e.g. sensors present but unparseable) -> None.
        assert!(parse_thermal_sensors("some sensors output").is_none());
    }

    #[test]
    fn parses_memory_pressure_and_skips_unavailable() {
        let out =
            "Pressure Stall Information (some, avg10 %):\n  memory: 24.50\n  io: 3.20\n  cpu: n/a";
        let entry = parse_memory_pressure(out).unwrap();
        assert_eq!(entry["mem_pressure_some_avg10"], serde_json::json!(24.5));
        assert_eq!(entry["io_pressure_some_avg10"], serde_json::json!(3.2));
        assert!(entry.get("cpu_pressure_some_avg10").is_none());

        // PSI entirely unavailable -> None (no suggestions).
        assert!(
            parse_memory_pressure(
                "Pressure Stall Information not available (kernel < 4.20 or CONFIG_PSI disabled)."
            )
            .is_none()
        );
    }

    #[test]
    fn cpu_utilization_workflows_fire_on_busy_and_iowait() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();

        let busy = serde_json::json!({ "cpu_busy_percent": 95.0, "cpu_iowait_percent": 1.0 });
        let t: Vec<String> = registry
            .evaluate("mortiscope", "cpu_utilization", &busy)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(t.contains(&"vivisection".to_string()));

        // High iowait points at storage, not CPU.
        let io = serde_json::json!({ "cpu_busy_percent": 40.0, "cpu_iowait_percent": 45.0 });
        let t: Vec<String> = registry
            .evaluate("mortiscope", "cpu_utilization", &io)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(t.contains(&"necropsy".to_string()));
    }

    fn threshold(
        metric: &str,
        comparator: &str,
        value: f64,
        severity: &str,
    ) -> abyssal_database::repo::monitoring::Threshold {
        abyssal_database::repo::monitoring::Threshold {
            id: uuid::Uuid::nil(),
            metric: metric.to_string(),
            comparator: comparator.to_string(),
            threshold: value,
            severity: severity.to_string(),
            enabled: true,
        }
    }

    #[test]
    fn overview_cell_colours_by_worst_breached_threshold() {
        let ths = vec![
            threshold("cpu_busy_percent", "ge", 80.0, "warning"),
            threshold("cpu_busy_percent", "ge", 95.0, "critical"),
        ];
        // 96% breaches both -> critical wins.
        assert_eq!(eval_cell(Some(96.0), "%", "cpu_busy_percent", &ths).rank, 4);
        // 85% breaches only the warning.
        assert_eq!(eval_cell(Some(85.0), "%", "cpu_busy_percent", &ths).rank, 3);
        // 40% breaches neither -> ok.
        let ok = eval_cell(Some(40.0), "%", "cpu_busy_percent", &ths);
        assert_eq!(ok.rank, 1);
        assert_eq!(ok.badge, "badge-success");
        // No sample -> no data.
        let nd = eval_cell(None, "%", "cpu_busy_percent", &ths);
        assert_eq!(nd.rank, 0);
        assert_eq!(nd.value, "\u{2014}");
    }

    #[test]
    fn overview_status_labels_track_rank() {
        assert_eq!(status_from_rank(4), ("critical", "badge-danger"));
        assert_eq!(status_from_rank(1), ("ok", "badge-success"));
        assert_eq!(status_from_rank(0), ("no data", "badge-muted"));
    }

    #[test]
    fn sparkline_maps_values_into_the_box_and_inverts_y() {
        // Rising values should descend in SVG space (y grows downward).
        let pts = sparkline_points(&[0.0, 5.0, 10.0], 100.0, 20.0);
        assert_eq!(pts, "0.0,20.0 50.0,10.0 100.0,0.0");
    }

    #[test]
    fn sparkline_needs_at_least_two_points() {
        assert_eq!(sparkline_points(&[], 100.0, 20.0), "");
        assert_eq!(sparkline_points(&[5.0], 100.0, 20.0), "");
    }

    #[test]
    fn sparkline_flat_series_does_not_divide_by_zero() {
        // Constant values must not panic; they draw a flat line at the bottom.
        let pts = sparkline_points(&[3.0, 3.0, 3.0], 100.0, 20.0);
        assert_eq!(pts, "0.0,20.0 50.0,20.0 100.0,20.0");
    }

    #[test]
    fn hot_host_suggests_necropsy_and_pressure_suggests_vivisection() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();

        let hot = serde_json::json!({ "max_temp_c": 85.0 });
        assert!(
            registry
                .evaluate("mortiscope", "thermal_sensors", &hot)
                .matches
                .iter()
                .any(|m| m.target_arsenal == "necropsy")
        );

        let pressure = serde_json::json!({ "mem_pressure_some_avg10": 25.0 });
        assert!(
            registry
                .evaluate("mortiscope", "memory_pressure", &pressure)
                .matches
                .iter()
                .any(|m| m.target_arsenal == "vivisection")
        );
    }
}
