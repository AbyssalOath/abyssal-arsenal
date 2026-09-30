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
    BaseCtx, ResurrectionFleetRow, ResurrectionFleetTemplate, ResurrectionHostRow,
    ResurrectionHostTemplate, ResurrectionTemplate, ResurrectionTriageTemplate,
    SuggestedActionView, TriageCategoryRow,
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
        return Ok(Redirect::to(&format!("/arsenals/resurrection/{host_id}")).into_response());
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
            hosts.push(ResurrectionHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = ResurrectionTemplate { base, hosts };
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
/// `read_only_filesystems` below, the one action that currently produces
/// any), and shows a banner naming which workflow-registry context fields
/// (if any) arrived in the query string -- Necropsy's `device` doesn't map
/// to a field this arsenal's no-argument read ops take, so the banner is
/// all Phase 6 adds here.
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
    render_host_full(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        context,
        Vec::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn render_host_full(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    suggested_actions: Vec<SuggestedActionView>,
    context: Vec<WorkflowContextRow>,
    failed_units: Vec<crate::templates::FailedUnitRow>,
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

    let tpl = ResurrectionHostTemplate {
        can_manage: ctx.has(Permission::SystemsManage),
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
        failed_units,
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

/// Shared body for the recovery reads: runs a `SystemsView` read, parses its
/// output into structured entries, feeds them to the workflow registry, and
/// renders the page with the text output and any "Suggested Next Steps".
#[allow(clippy::too_many_arguments)]
async fn run_structured_read(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    source_action: &str,
    parse: fn(&str) -> Vec<serde_json::Value>,
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
            let entries = parse(&output.stdout);
            let suggested_actions = crate::common::suggested_actions_for(
                state,
                "resurrection",
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

/// Parses `journalctl -b -1 -p err`'s output into `{boot_error_count}`,
/// counting real error lines while skipping journalctl markers (`-- ... --`)
/// and the "(no output)" placeholder.
fn parse_previous_boot_errors(stdout: &str) -> Vec<serde_json::Value> {
    let count = stdout
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && t != "(no output)" && !t.starts_with("-- ")
        })
        .count();
    vec![serde_json::json!({ "boot_error_count": count })]
}

/// Parses `systemctl is-system-running`'s one-word output into
/// `{system_state, is_degraded}` (anything but `running` is degraded).
fn parse_system_running_state(stdout: &str) -> Vec<serde_json::Value> {
    let state = stdout
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if state.is_empty() || state == "(no output)" {
        return Vec::new();
    }
    vec![serde_json::json!({
        "system_state": state,
        "is_degraded": state != "running",
    })]
}

pub async fn previous_boot_errors(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_structured_read(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::PreviousBootErrors,
        "Previous Boot Errors",
        "previous_boot_errors",
        parse_previous_boot_errors,
    )
    .await
}

pub async fn system_running_state(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_structured_read(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::SystemRunningState,
        "System Running State",
        "system_running_state",
        parse_system_running_state,
    )
    .await
}

/// Parses `systemctl list-units --failed --plain` output into failed-unit
/// rows (UNIT LOAD ACTIVE SUB DESCRIPTION), skipping the "No failed units."
/// placeholder and any line without enough columns.
fn parse_failed_units(stdout: &str) -> Vec<crate::templates::FailedUnitRow> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed == "No failed units." {
                return None;
            }
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                return None;
            }
            Some(crate::templates::FailedUnitRow {
                unit: f[0].to_string(),
                active: f[2].to_string(),
                sub: f[3].to_string(),
                description: f.get(4..).map(|rest| rest.join(" ")).unwrap_or_default(),
            })
        })
        .collect()
}

/// Parses `df -Ph` output into `{mount_point, usage_percent}` per filesystem.
/// The workflow registry applies the "critical" threshold, so every row is
/// emitted here.
fn parse_disk_space(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .skip(1) // header row
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            let pct: u64 = f
                .iter()
                .find(|x| x.ends_with('%'))?
                .trim_end_matches('%')
                .parse()
                .ok()?;
            let mount = f.last()?;
            Some(serde_json::json!({ "mount_point": mount, "usage_percent": pct }))
        })
        .collect()
}

/// Parses the agent's `fstab_status:` line into `{fstab_ok}`. No workflow edge
/// (there's no good cross-arsenal target for a broken fstab), but M4's triage
/// report reads the field.
fn parse_fstab_check(stdout: &str) -> Vec<serde_json::Value> {
    let ok = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("fstab_status:"))
        .map(|v| v.trim() == "ok")
        .unwrap_or(true);
    vec![serde_json::json!({ "fstab_ok": ok })]
}

pub async fn disk_space_critical(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_structured_read(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::DiskSpaceCritical,
        "Disk Space",
        "disk_space_critical",
        parse_disk_space,
    )
    .await
}

pub async fn fstab_check(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_structured_read(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FstabCheck,
        "Fstab Check",
        "fstab_check",
        parse_fstab_check,
    )
    .await
}

pub async fn list_failed_units(
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
    let result_label = Some(format!("Failed Units -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ListFailedUnits,
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
            let failed_units = parse_failed_units(&output.stdout);
            let entry = serde_json::json!({ "failed_unit_count": failed_units.len() });
            let suggested_actions = crate::common::suggested_actions_for(
                &state,
                "resurrection",
                "list_failed_units",
                std::slice::from_ref(&entry),
                host_id,
            )
            .await;
            // Show the table when we parsed rows; otherwise the raw message.
            let output_text = if failed_units.is_empty() {
                Some(output.stdout)
            } else {
                None
            };
            render_host_full(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                output_text,
                None,
                suggested_actions,
                Vec::new(),
                failed_units,
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
pub struct RecoverUnitForm {
    csrf_token: String,
    unit: String,
}

pub async fn recover_unit(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RecoverUnitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let unit = form.unit.trim().to_string();
    if !abyssal_agent_protocol::is_valid_unit_name(&unit) {
        return Err(WebError(AppError::Validation(
            "Enter a valid systemd unit name.".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RecoverUnit { unit: unit.clone() },
        &format!("Recover Unit ({unit})"),
    )
    .await
}

/// Parses `findmnt --raw --noheadings --options ro --output
/// TARGET,SOURCE,FSTYPE,OPTIONS`'s output -- one line per currently
/// read-only mount -- into structured `{mount_point, source, fstype}`
/// results. Purely additive -- the rendered text output is unchanged, this
/// is only consumed by the workflow registry below. A row that doesn't
/// parse cleanly is skipped rather than failing the page. No output at all
/// means no read-only mounts, which is the common case.
fn read_only_filesystem_entries(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // A real findmnt TARGET is an absolute path; this also skips the
            // "No filesystems are currently mounted read-only." placeholder so
            // it never parses as a bogus mount (which would falsely fire the
            // read-only workflow edge).
            if fields.len() < 3 || !fields[0].starts_with('/') {
                return None;
            }
            Some(serde_json::json!({
                "mount_point": fields[0],
                "source": fields[1],
                "fstype": fields[2],
            }))
        })
        .collect()
}

pub async fn read_only_filesystems(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_structured_read(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ReadOnlyFilesystems,
        "Read-Only Filesystems",
        "read_only_filesystems",
        read_only_filesystem_entries,
    )
    .await
}

/// Shared by Reload systemd / Reset Failed Units: `Write`, no confirmation
/// required.
#[allow(clippy::too_many_arguments)]
async fn run_write_op(
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
            Permission::SystemsManage,
            OperationKind::Write,
            false,
            Duration::from_secs(30),
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

pub async fn reload_systemd_daemon(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ReloadSystemdDaemon,
        "Reload systemd Daemon",
    )
    .await
}

pub async fn reset_failed_units(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ResetFailedUnits,
        "Reset Failed Units",
    )
    .await
}

#[derive(Deserialize)]
pub struct RemountQuery {
    target: String,
}

fn validate_target(target: &str) -> Result<String, WebError> {
    let target = target.trim().to_string();
    if !abyssal_agent_protocol::is_valid_mount_target(&target) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid absolute mount path.".into(),
        )));
    }
    Ok(target)
}

pub async fn remount_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RemountQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;

    let target = validate_target(&q.target)?;

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
        title: "Remount read-write".to_string(),
        message: format!(
            "This will remount \"{target}\" read-write on \"{}\". If it was forced read-only \
             because of a real disk I/O error, resuming writes can make any underlying \
             corruption worse.",
            host.name
        ),
        action_url: format!(
            "/arsenals/resurrection/{host_id}/remount?target={}",
            urlencoding_encode(&target)
        ),
        cancel_url: format!("/arsenals/resurrection/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "mount path".to_string(),
            expected: target.clone(),
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
pub struct RemountForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn remount_read_write(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RemountQuery>,
    Form(form): Form<RemountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Remount was not confirmed.".into(),
        )));
    }

    let target = validate_target(&q.target)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &target)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Remount Read-Write ({target}) -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::RemountReadWrite { target },
            Permission::SystemsManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(30),
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

// ---- M5: fleet recovery console ----------------------------------------

/// Rolls a host's light recovery poll up to a status (rank 3 critical, 2
/// warning, 1 ok, 0 unavailable), a one-line detail, and the
/// `(source_action, entries)` pairs to evaluate for suggestions. Pure.
#[allow(clippy::type_complexity)]
fn fleet_status(
    system: &Result<String, String>,
    failed: &Result<String, String>,
    read_only: &Result<String, String>,
    disk: &Result<String, String>,
) -> (
    u8,
    &'static str,
    &'static str,
    String,
    Vec<(&'static str, Vec<serde_json::Value>)>,
) {
    let mut entries = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    let mut rank = 1u8; // ok
    let mut all_unavailable = true;

    if let Ok(out) = system {
        all_unavailable = false;
        let e = parse_system_running_state(out);
        if e.first()
            .is_some_and(|v| v["is_degraded"] == serde_json::json!(true))
        {
            rank = rank.max(2);
            problems.push("degraded".into());
        }
        entries.push(("system_running_state", e));
    }
    if let Ok(out) = failed {
        all_unavailable = false;
        let n = parse_failed_units(out).len();
        if n > 0 {
            rank = rank.max(2);
            problems.push(format!("{n} failed unit(s)"));
        }
        entries.push((
            "list_failed_units",
            vec![serde_json::json!({ "failed_unit_count": n })],
        ));
    }
    if let Ok(out) = read_only {
        all_unavailable = false;
        let e = read_only_filesystem_entries(out);
        if !e.is_empty() {
            rank = rank.max(3);
            problems.push(format!("{} read-only mount(s)", e.len()));
        }
        entries.push(("read_only_filesystems", e));
    }
    if let Ok(out) = disk {
        all_unavailable = false;
        let all = parse_disk_space(out);
        let full = all
            .iter()
            .filter(|v| v["usage_percent"].as_u64().unwrap_or(0) >= 90)
            .count();
        if full > 0 {
            rank = rank.max(3);
            problems.push(format!("{full} filesystem(s) at/over 90%"));
        }
        entries.push(("disk_space_critical", all));
    }

    if all_unavailable {
        return (
            0,
            "unavailable",
            "badge-muted",
            "Unreachable".into(),
            entries,
        );
    }
    let (label, badge) = match rank {
        3 => ("critical", "badge-danger"),
        2 => ("warning", "badge-warning"),
        _ => ("ok", "badge-success"),
    };
    let detail = if problems.is_empty() {
        "No issues detected".to_string()
    } else {
        problems.join("; ")
    };
    (rank, label, badge, detail, entries)
}

pub async fn fleet(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    let (mut critical, mut warning, mut ok, mut unavailable) = (0usize, 0usize, 0usize, 0usize);
    let mut rows: Vec<(u8, ResurrectionFleetRow)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut suggested_actions = Vec::new();

    for host in repo::hosts::list(&state.pool).await? {
        if !host.is_active() || !state.hosts.is_connected(host.id) {
            continue;
        }
        // A light core poll (not the full 6-check triage) to keep the fleet
        // view responsive.
        let system = run_read_capture(
            &state,
            &ctx,
            host.id,
            &host.name,
            AgentOperation::SystemRunningState,
        )
        .await;
        let failed = run_read_capture(
            &state,
            &ctx,
            host.id,
            &host.name,
            AgentOperation::ListFailedUnits,
        )
        .await;
        let read_only = run_read_capture(
            &state,
            &ctx,
            host.id,
            &host.name,
            AgentOperation::ReadOnlyFilesystems,
        )
        .await;
        let disk = run_read_capture(
            &state,
            &ctx,
            host.id,
            &host.name,
            AgentOperation::DiskSpaceCritical,
        )
        .await;

        let (rank, label, badge, detail, entries) =
            fleet_status(&system, &failed, &read_only, &disk);
        match rank {
            3 => critical += 1,
            2 => warning += 1,
            1 => ok += 1,
            _ => unavailable += 1,
        }
        for (action, action_entries) in &entries {
            for a in crate::common::suggested_actions_for(
                &state,
                "resurrection",
                action,
                action_entries,
                host.id,
            )
            .await
            {
                if seen.insert(a.url.clone()) {
                    suggested_actions.push(a);
                }
            }
        }
        rows.push((
            rank,
            ResurrectionFleetRow {
                host_id: host.id.to_string(),
                host_name: host.name,
                status_label: label.to_string(),
                status_badge_class: badge.to_string(),
                detail,
            },
        ));
    }

    rows.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.host_name.cmp(&b.1.host_name))
    });
    let rows: Vec<ResurrectionFleetRow> = rows.into_iter().map(|(_, r)| r).collect();
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
    let tpl = ResurrectionFleetTemplate {
        base,
        rows,
        total,
        critical,
        warning,
        ok,
        unavailable,
        suggested_actions,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

// ---- M4: recoverability triage report ----------------------------------

struct TriageScore {
    percent: u8,
    label: String,
    badge_class: String,
    ok: usize,
    warning: usize,
    critical: usize,
    unavailable: usize,
}

fn triage_row(name: &str, status: &str, badge: &str, summary: String) -> TriageCategoryRow {
    TriageCategoryRow {
        name: name.to_string(),
        status_label: status.to_string(),
        status_badge_class: badge.to_string(),
        summary,
    }
}

/// Rolls each recovery read's raw output up into a category row, plus the
/// `(source_action, entries)` pairs to evaluate for suggestions. Pure, so the
/// scoring is unit-tested without a live host. Each argument is the captured
/// stdout of a read, or the error if it couldn't run (an `unavailable` row).
#[allow(clippy::type_complexity)]
fn assemble_triage(
    system: &Result<String, String>,
    failed: &Result<String, String>,
    read_only: &Result<String, String>,
    boot: &Result<String, String>,
    disk: &Result<String, String>,
    fstab: &Result<String, String>,
) -> (
    Vec<TriageCategoryRow>,
    Vec<(&'static str, Vec<serde_json::Value>)>,
) {
    let mut rows = Vec::new();
    let mut entries: Vec<(&'static str, Vec<serde_json::Value>)> = Vec::new();
    let unavail = |name: &str, e: &str| {
        triage_row(
            name,
            "unavailable",
            "badge-muted",
            format!("Unavailable: {e}"),
        )
    };

    // System state -- degraded is a warning.
    rows.push(match system {
        Ok(out) => {
            let e = parse_system_running_state(out);
            entries.push(("system_running_state", e.clone()));
            match e.first() {
                None => triage_row(
                    "System state",
                    "unavailable",
                    "badge-muted",
                    "No state reported".into(),
                ),
                Some(v) if v["is_degraded"] == serde_json::json!(true) => triage_row(
                    "System state",
                    "warning",
                    "badge-warning",
                    v["system_state"].as_str().unwrap_or("degraded").to_string(),
                ),
                Some(_) => triage_row("System state", "ok", "badge-success", "running".into()),
            }
        }
        Err(e) => unavail("System state", e),
    });

    // Failed units -- warning.
    rows.push(match failed {
        Ok(out) => {
            let n = parse_failed_units(out).len();
            entries.push((
                "list_failed_units",
                vec![serde_json::json!({ "failed_unit_count": n })],
            ));
            if n == 0 {
                triage_row("Failed units", "ok", "badge-success", "None".into())
            } else {
                triage_row(
                    "Failed units",
                    "warning",
                    "badge-warning",
                    format!("{n} failed unit(s)"),
                )
            }
        }
        Err(e) => unavail("Failed units", e),
    });

    // Read-only filesystems -- critical (can't write).
    rows.push(match read_only {
        Ok(out) => {
            let e = read_only_filesystem_entries(out);
            let n = e.len();
            entries.push(("read_only_filesystems", e));
            if n == 0 {
                triage_row(
                    "Read-only filesystems",
                    "ok",
                    "badge-success",
                    "None".into(),
                )
            } else {
                triage_row(
                    "Read-only filesystems",
                    "critical",
                    "badge-danger",
                    format!("{n} read-only mount(s)"),
                )
            }
        }
        Err(e) => unavail("Read-only filesystems", e),
    });

    // Boot errors -- warning.
    rows.push(match boot {
        Ok(out) => {
            let e = parse_previous_boot_errors(out);
            let count = e
                .first()
                .and_then(|v| v["boot_error_count"].as_u64())
                .unwrap_or(0);
            entries.push(("previous_boot_errors", e));
            if count == 0 {
                triage_row("Previous boot", "ok", "badge-success", "No errors".into())
            } else {
                triage_row(
                    "Previous boot",
                    "warning",
                    "badge-warning",
                    format!("{count} error line(s)"),
                )
            }
        }
        Err(e) => unavail("Previous boot", e),
    });

    // Disk space -- critical when any filesystem is >=90%.
    rows.push(match disk {
        Ok(out) => {
            let all = parse_disk_space(out);
            let full: Vec<_> = all
                .iter()
                .filter(|v| v["usage_percent"].as_u64().unwrap_or(0) >= 90)
                .cloned()
                .collect();
            let n = full.len();
            entries.push(("disk_space_critical", all));
            if n == 0 {
                triage_row(
                    "Disk space",
                    "ok",
                    "badge-success",
                    "No filesystem over 90%".into(),
                )
            } else {
                triage_row(
                    "Disk space",
                    "critical",
                    "badge-danger",
                    format!("{n} filesystem(s) at/over 90%"),
                )
            }
        }
        Err(e) => unavail("Disk space", e),
    });

    // Fstab -- critical if broken (no cross-arsenal edge).
    rows.push(match fstab {
        Ok(out) => {
            let ok = parse_fstab_check(out)
                .first()
                .and_then(|v| v["fstab_ok"].as_bool())
                .unwrap_or(true);
            if ok {
                triage_row("fstab", "ok", "badge-success", "Valid".into())
            } else {
                triage_row(
                    "fstab",
                    "critical",
                    "badge-danger",
                    "Problems detected".into(),
                )
            }
        }
        Err(e) => unavail("fstab", e),
    });

    (rows, entries)
}

/// Weighted score: ok = 1, warning = 0.5, critical = 0; `unavailable` rows are
/// excluded from the denominator.
fn score_triage(rows: &[TriageCategoryRow]) -> TriageScore {
    let (mut ok, mut warning, mut critical, mut unavailable) = (0usize, 0usize, 0usize, 0usize);
    for r in rows {
        match r.status_label.as_str() {
            "ok" => ok += 1,
            "warning" => warning += 1,
            "critical" => critical += 1,
            _ => unavailable += 1,
        }
    }
    let applicable = ok + warning + critical;
    let percent = if applicable == 0 {
        0
    } else {
        ((ok as f64 + warning as f64 * 0.5) / applicable as f64 * 100.0).round() as u8
    };
    let (label, badge_class) = if applicable == 0 {
        ("No data", "badge-muted")
    } else if percent >= 85 {
        ("Healthy", "badge-success")
    } else if percent >= 60 {
        ("Degraded", "badge-warning")
    } else {
        ("Critical", "badge-danger")
    };
    TriageScore {
        percent,
        label: label.to_string(),
        badge_class: badge_class.to_string(),
        ok,
        warning,
        critical,
        unavailable,
    }
}

async fn run_read_capture(
    state: &AppState,
    ctx: &AuthContext,
    host_id: Uuid,
    host_name: &str,
    operation: AgentOperation,
) -> Result<String, String> {
    let elevated = state.elevation.is_elevated(host_id);
    state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            host_name,
            operation,
            Permission::SystemsView,
            OperationKind::Read,
            false,
            Duration::from_secs(15),
            None,
            elevated,
        )
        .await
        .map(|o| o.stdout)
        .map_err(|e| e.to_string())
}

pub async fn triage(
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

    let system = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::SystemRunningState,
    )
    .await;
    let failed = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::ListFailedUnits,
    )
    .await;
    let read_only = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::ReadOnlyFilesystems,
    )
    .await;
    let boot = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::PreviousBootErrors,
    )
    .await;
    let disk = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::DiskSpaceCritical,
    )
    .await;
    let fstab = run_read_capture(
        &state,
        &ctx,
        host_id,
        &host.name,
        AgentOperation::FstabCheck,
    )
    .await;

    let (categories, entries) = assemble_triage(&system, &failed, &read_only, &boot, &disk, &fstab);
    let score = score_triage(&categories);

    // Aggregate each sub-check's registry suggestions (deduped).
    let mut seen = std::collections::HashSet::new();
    let mut suggested_actions = Vec::new();
    for (action, action_entries) in &entries {
        for a in crate::common::suggested_actions_for(
            &state,
            "resurrection",
            action,
            action_entries,
            host_id,
        )
        .await
        {
            if seen.insert(a.url.clone()) {
                suggested_actions.push(a);
            }
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
    let tpl = ResurrectionTriageTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        score_percent: score.percent,
        score_label: score.label,
        score_badge_class: score.badge_class,
        ok: score.ok,
        warning: score.warning,
        critical: score.critical,
        unavailable: score.unavailable,
        categories,
        suggested_actions,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_status_ranks_hosts() {
        let ok_disk =
            "Filesystem Size Used Avail Capacity Mounted on\n/dev/sda1 20G 5G 15G 25% /\n";
        // Healthy host.
        let (rank, label, _, _, _) = fleet_status(
            &Ok("running".into()),
            &Ok("No failed units.".into()),
            &Ok("No filesystems are currently mounted read-only.".into()),
            &Ok(ok_disk.into()),
        );
        assert_eq!((rank, label), (1, "ok"));

        // Read-only mount -> critical.
        let (rank, label, _, detail, _) = fleet_status(
            &Ok("running".into()),
            &Ok("No failed units.".into()),
            &Ok("/mnt /dev/sdb1 ext4 ro\n".into()),
            &Ok(ok_disk.into()),
        );
        assert_eq!((rank, label), (3, "critical"));
        assert!(detail.contains("read-only"));

        // Degraded only -> warning.
        let (rank, label, _, _, _) = fleet_status(
            &Ok("degraded".into()),
            &Ok("No failed units.".into()),
            &Ok("No filesystems are currently mounted read-only.".into()),
            &Ok(ok_disk.into()),
        );
        assert_eq!((rank, label), (2, "warning"));

        // All polls failed -> unavailable.
        let (rank, label, _, _, _) = fleet_status(
            &Err("x".into()),
            &Err("x".into()),
            &Err("x".into()),
            &Err("x".into()),
        );
        assert_eq!((rank, label), (0, "unavailable"));
    }

    #[test]
    fn triage_scores_a_healthy_host_well() {
        let ok_disk =
            "Filesystem Size Used Avail Capacity Mounted on\n/dev/sda1 20G 5G 15G 25% /\n";
        let (rows, _) = assemble_triage(
            &Ok("running".into()),
            &Ok("No failed units.".into()),
            &Ok("No filesystems are currently mounted read-only.".into()),
            &Ok("(no output)".into()),
            &Ok(ok_disk.into()),
            &Ok("fstab_status: ok\n".into()),
        );
        // read_only parser yields nothing from the "no read-only" message.
        let score = score_triage(&rows);
        assert_eq!(score.critical, 0);
        assert!(score.percent >= 85);
        assert_eq!(score.label, "Healthy");
    }

    #[test]
    fn triage_flags_and_aggregates_for_a_broken_host() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let bad_disk =
            "Filesystem Size Used Avail Capacity Mounted on\n/dev/sda1 20G 19G 1G 96% /\n";
        let (rows, entries) = assemble_triage(
            &Ok("degraded".into()),
            &Ok("nginx.service loaded failed failed Web\n".into()),
            &Ok("/mnt/data /dev/sdb1 ext4 ro,relatime\n".into()),
            &Ok("kernel: oops\n".into()),
            &Ok(bad_disk.into()),
            &Ok("fstab_status: problems\n".into()),
        );
        let score = score_triage(&rows);
        assert!(
            score.critical >= 2,
            "read-only + disk + fstab should be critical"
        );
        assert_eq!(score.label, "Critical");

        // Aggregating entries should surface downstream arsenals.
        let mut targets = std::collections::HashSet::new();
        for (action, action_entries) in &entries {
            for e in action_entries {
                for m in registry.evaluate("resurrection", action, e).matches {
                    targets.insert(m.target_arsenal);
                }
            }
        }
        assert!(targets.contains("incarnation")); // failed units
        assert!(targets.contains("defleshing")); // disk full
        assert!(targets.contains("postmortem")); // boot errors / degraded
    }

    #[test]
    fn triage_excludes_unavailable_from_the_score() {
        let (rows, _) = assemble_triage(
            &Err("offline".into()),
            &Err("offline".into()),
            &Ok("No filesystems are currently mounted read-only.".into()),
            &Err("offline".into()),
            &Err("offline".into()),
            &Err("offline".into()),
        );
        let score = score_triage(&rows);
        // Only read-only fs is applicable and it's ok -> 100%.
        assert_eq!(score.percent, 100);
        assert_eq!(score.ok, 1);
        assert_eq!(score.unavailable, 5);
    }

    #[test]
    fn parses_disk_space_usage() {
        let out = "Filesystem Size Used Avail Capacity Mounted on\n\
                   /dev/sda1 20G 19G 1G 95% /\n\
                   tmpfs 1G 0 1G 0% /run\n";
        let rows = parse_disk_space(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["mount_point"], serde_json::json!("/"));
        assert_eq!(rows[0]["usage_percent"], serde_json::json!(95));
        assert_eq!(rows[1]["usage_percent"], serde_json::json!(0));
    }

    #[test]
    fn parses_fstab_status() {
        assert_eq!(
            parse_fstab_check("fstab_status: problems\n\nsome warning")[0]["fstab_ok"],
            serde_json::json!(false)
        );
        assert_eq!(
            parse_fstab_check("fstab_status: ok\n")[0]["fstab_ok"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn a_full_filesystem_suggests_cleanup_arsenals() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let full = serde_json::json!({ "mount_point": "/", "usage_percent": 95 });
        let targets: Vec<String> = registry
            .evaluate("resurrection", "disk_space_critical", &full)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"defleshing".to_string()));
        assert!(targets.contains(&"ossuary".to_string()));
        assert!(targets.contains(&"obituary".to_string()));

        // A roomy filesystem suggests nothing.
        let ok = serde_json::json!({ "mount_point": "/run", "usage_percent": 0 });
        assert!(
            registry
                .evaluate("resurrection", "disk_space_critical", &ok)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn parses_failed_units_table() {
        let out = "nginx.service loaded failed failed A high performance web server\n\
                   cron.service loaded failed failed Regular background program\n";
        let rows = parse_failed_units(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].unit, "nginx.service");
        assert_eq!(rows[0].active, "failed");
        assert_eq!(rows[0].description, "A high performance web server");
        assert!(parse_failed_units("No failed units.").is_empty());
    }

    #[test]
    fn failed_units_suggest_incarnation_and_postmortem() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let hit = serde_json::json!({ "failed_unit_count": 2 });
        let targets: Vec<String> = registry
            .evaluate("resurrection", "list_failed_units", &hit)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"incarnation".to_string()));
        assert!(targets.contains(&"postmortem".to_string()));

        let clean = serde_json::json!({ "failed_unit_count": 0 });
        assert!(
            registry
                .evaluate("resurrection", "list_failed_units", &clean)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn parses_system_running_state() {
        let degraded = parse_system_running_state("degraded\n");
        assert_eq!(degraded[0]["system_state"], serde_json::json!("degraded"));
        assert_eq!(degraded[0]["is_degraded"], serde_json::json!(true));

        let ok = parse_system_running_state("running");
        assert_eq!(ok[0]["is_degraded"], serde_json::json!(false));

        assert!(parse_system_running_state("(no output)").is_empty());
    }

    #[test]
    fn counts_previous_boot_errors_skipping_markers() {
        let out =
            "-- Journal begins at ... --\nkernel: oops\nfoo.service: failed\n-- No entries --\n";
        assert_eq!(
            parse_previous_boot_errors(out)[0]["boot_error_count"],
            serde_json::json!(2)
        );
        assert_eq!(
            parse_previous_boot_errors("(no output)")[0]["boot_error_count"],
            serde_json::json!(0)
        );
    }

    #[test]
    fn degraded_state_and_boot_errors_suggest_next_steps() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();

        let degraded = serde_json::json!({ "system_state": "degraded", "is_degraded": true });
        let t: Vec<String> = registry
            .evaluate("resurrection", "system_running_state", &degraded)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(t.contains(&"postmortem".to_string()));
        assert!(t.contains(&"incarnation".to_string()));

        // A running host suggests nothing.
        let ok = serde_json::json!({ "system_state": "running", "is_degraded": false });
        assert!(
            registry
                .evaluate("resurrection", "system_running_state", &ok)
                .matches
                .is_empty()
        );

        let boot = serde_json::json!({ "boot_error_count": 3 });
        assert!(
            registry
                .evaluate("resurrection", "previous_boot_errors", &boot)
                .matches
                .iter()
                .any(|m| m.target_arsenal == "postmortem")
        );
    }

    #[test]
    fn parses_one_read_only_mount() {
        let stdout = "/mnt/data /dev/sdb1 ext4 ro,relatime\n";
        let entries = read_only_filesystem_entries(stdout);

        assert_eq!(
            entries,
            vec![serde_json::json!({
                "mount_point": "/mnt/data",
                "source": "/dev/sdb1",
                "fstype": "ext4",
            })]
        );
    }

    #[test]
    fn no_output_means_no_entries() {
        assert!(read_only_filesystem_entries("").is_empty());
    }

    #[test]
    fn read_only_mount_suggests_necropsy_and_reliquary() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({
            "mount_point": "/mnt/data",
            "source": "/dev/sdb1",
            "fstype": "ext4",
        });

        let matches = registry
            .evaluate("resurrection", "read_only_filesystems", &entry)
            .matches;
        let targets: Vec<&str> = matches.iter().map(|m| m.target_arsenal.as_str()).collect();

        assert!(targets.contains(&"necropsy"));
        assert!(targets.contains(&"reliquary"));
    }
}
