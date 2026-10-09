use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, MacroScope, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{ensure_can_edit_macro, maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, GrimoireDriftRow, GrimoireDriftTemplate, GrimoireHostRow, GrimoireHostTemplate,
    GrimoireProfileEntryView, GrimoireProfileView, GrimoireProfilesTemplate, GrimoireTemplate,
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
        return Ok(Redirect::to(&format!("/arsenals/grimoire/{host_id}")).into_response());
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
            hosts.push(GrimoireHostRow {
                is_control_plane: host.is_control_plane,
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = GrimoireTemplate { base, hosts };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Every macro visible to `ctx.user` (their own personal macros, plus
/// every role macro for a role they belong to), as `GrimoireMacroRow`s
/// ready to render -- see `repo::macros::list_visible_to_user`.
/// `can_edit` is true for the owner or anyone holding
/// `Permission::MacrosManageAll`, never for a role-mate merely using a
/// shared role macro.
async fn visible_macro_rows(
    state: &AppState,
    ctx: &AuthContext,
) -> anyhow::Result<Vec<crate::templates::GrimoireMacroRow>> {
    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let role_ids: Vec<Uuid> = user_roles.iter().map(|r| r.id).collect();
    let macros = repo::macros::list_visible_to_user(
        &state.pool,
        ctx.user.id,
        &role_ids,
        abyssal_core::MacroType::CronJob,
    )
    .await?;

    let all_roles = repo::roles::list(&state.pool).await?;
    let role_name = |id: Uuid| -> String {
        all_roles
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "unknown role".to_string())
    };

    Ok(macros
        .into_iter()
        .map(|m| {
            let can_edit = m.owner_user_id == ctx.user.id || ctx.has(Permission::MacrosManageAll);
            let scope_label = match m.scope {
                MacroScope::Personal => "Personal".to_string(),
                MacroScope::Role => format!("Role: {}", role_name(m.role_id.unwrap_or_default())),
            };
            crate::templates::GrimoireMacroRow {
                id: m.id.to_string(),
                name: m.name,
                scope_label,
                job_name: m.job_name.unwrap_or_default(),
                schedule: m.schedule.unwrap_or_default(),
                run_as_user: m.run_as_user.unwrap_or_default(),
                command: m.command.unwrap_or_default(),
                can_edit,
            }
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
async fn render_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    load_macro: Option<Uuid>,
) -> Result<Response, WebError> {
    render_host_full(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        load_macro,
        Vec::new(),
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
    mut result_error: Option<String>,
    load_macro: Option<Uuid>,
    sysctl_drift: Vec<crate::templates::SysctlDriftRow>,
    suggested_actions: Vec<crate::templates::SuggestedActionView>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

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

    let macros = visible_macro_rows(state, ctx).await?;

    let mut cron_job_name = String::new();
    let mut cron_schedule = String::new();
    let mut cron_run_as_user = String::new();
    let mut cron_command = String::new();
    if let Some(macro_id) = load_macro {
        let macro_id = macro_id.to_string();
        match macros.iter().find(|m| m.id == macro_id) {
            Some(m) => {
                cron_job_name = m.job_name.clone();
                cron_schedule = m.schedule.clone();
                cron_run_as_user = m.run_as_user.clone();
                cron_command = m.command.clone();
            }
            None => {
                result_error = Some("That macro isn't available.".to_string());
            }
        }
    }

    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let macro_roles = user_roles
        .into_iter()
        .map(|r| (r.id.to_string(), r.name))
        .collect();

    let tpl = GrimoireHostTemplate {
        can_manage: ctx.has(Permission::SystemsManage),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        macros,
        macro_roles,
        cron_job_name,
        cron_schedule,
        cron_run_as_user,
        cron_command,
        result_label,
        result_output,
        result_error,
        sysctl_drift,
        suggested_actions,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ShowHostQuery {
    #[serde(default)]
    load_macro: Option<Uuid>,
}

pub async fn show_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<ShowHostQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None, q.load_macro).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
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
                None,
            )
            .await
        }
    }
}

pub async fn view_managed_sysctl(
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
        AgentOperation::ViewManagedSysctl,
        "Managed Sysctl",
    )
    .await
}

/// Parses `SysctlManagedDrift` output (`key\tdeclared\tlive\tstatus` per line)
/// into table rows, and returns the count of drifted keys.
fn parse_sysctl_drift(stdout: &str) -> (Vec<crate::templates::SysctlDriftRow>, usize) {
    let mut rows = Vec::new();
    let mut drifted = 0;
    for line in stdout.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 {
            continue; // skips the "No managed sysctl overrides set." message
        }
        let (status_label, status_badge_class) = match f[3] {
            "in_sync" => ("in sync", "badge-success"),
            "drifted" => {
                drifted += 1;
                ("drifted", "badge-warning")
            }
            _ => ("unavailable", "badge-muted"),
        };
        rows.push(crate::templates::SysctlDriftRow {
            key: f[0].to_string(),
            declared: f[1].to_string(),
            live: f[2].to_string(),
            status_label: status_label.to_string(),
            status_badge_class: status_badge_class.to_string(),
        });
    }
    (rows, drifted)
}

pub async fn sysctl_drift(
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
    let result_label = Some(format!("Sysctl Drift -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::SysctlManagedDrift,
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
            let (rows, drifted) = parse_sysctl_drift(&output.stdout);
            let entry = serde_json::json!({ "drift_count": drifted });
            let suggested_actions = crate::common::suggested_actions_for(
                &state,
                "grimoire",
                "sysctl_drift",
                std::slice::from_ref(&entry),
                host_id,
            )
            .await;
            // When there are no parsed rows (e.g. "No managed sysctl overrides
            // set."), fall back to showing the raw message as output.
            let output_text = if rows.is_empty() {
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
                None,
                rows,
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
                None,
            )
            .await
        }
    }
}

pub async fn view_managed_cron_jobs(
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
        AgentOperation::ViewManagedCronJobs,
        "Managed Scheduled Tasks",
    )
    .await
}

// ---------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------

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
                None,
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct SetSysctlForm {
    csrf_token: String,
    key: String,
    value: String,
}

fn validate_sysctl_key(key: &str) -> Result<String, WebError> {
    let key = key.trim().to_string();
    if !abyssal_agent_protocol::is_valid_sysctl_key(&key) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid sysctl key.".into(),
        )));
    }
    Ok(key)
}

pub async fn set_persistent_sysctl(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SetSysctlForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let key = validate_sysctl_key(&form.key)?;
    if !abyssal_agent_protocol::is_valid_sysctl_value(&form.value) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid sysctl value.".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::SetPersistentSysctl {
            key: key.clone(),
            value: form.value.clone(),
        },
        &format!("Set Sysctl ({key} = {})", form.value),
    )
    .await
}

#[derive(Deserialize)]
pub struct SysctlKeyForm {
    csrf_token: String,
    key: String,
}

pub async fn remove_persistent_sysctl_key(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SysctlKeyForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let key = validate_sysctl_key(&form.key)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RemovePersistentSysctlKey { key: key.clone() },
        &format!("Remove Sysctl Key ({key})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct SetCronJobForm {
    csrf_token: String,
    job_name: String,
    schedule: String,
    run_as_user: String,
    command: String,
}

fn validate_job_name(name: &str) -> Result<String, WebError> {
    let name = name.trim().to_string();
    if !abyssal_agent_protocol::is_valid_account_name(&name) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid job name (lowercase letters, digits, - and _ only)."
                .into(),
        )));
    }
    Ok(name)
}

pub async fn set_cron_job(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SetCronJobForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let job_name = validate_job_name(&form.job_name)?;
    if !abyssal_agent_protocol::is_valid_cron_schedule(&form.schedule) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid cron schedule (e.g. \"0 3 * * *\" or \"@daily\")."
                .into(),
        )));
    }
    let run_as_user = form.run_as_user.trim().to_string();
    if !abyssal_agent_protocol::is_valid_account_name(&run_as_user) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid username.".into(),
        )));
    }
    if !abyssal_agent_protocol::is_valid_cron_command(&form.command) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid command.".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::SetCronJob {
            job_name: job_name.clone(),
            schedule: form.schedule,
            run_as_user,
            command: form.command,
        },
        &format!("Set Scheduled Task ({job_name})"),
    )
    .await
}

// ---------------------------------------------------------------------
// Scheduled-task macros -- GitHub issue #7. A macro is host-independent
// (job_name/schedule/run_as_user/command, no target host), so "save as
// macro" is a second submit button on the same Set Scheduled Task form
// (`formaction`/`formmethod`, no client-side JS) rather than a separate
// page: the browser submits the exact same field values either way.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SaveCronMacroForm {
    csrf_token: String,
    host_id: Uuid,
    job_name: String,
    schedule: String,
    run_as_user: String,
    command: String,
    macro_name: String,
    #[serde(default)]
    macro_scope: String,
    #[serde(default)]
    macro_role_id: String,
}

pub async fn save_cron_macro(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SaveCronMacroForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let job_name = validate_job_name(&form.job_name)?;
    if !abyssal_agent_protocol::is_valid_cron_schedule(&form.schedule) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid cron schedule (e.g. \"0 3 * * *\" or \"@daily\")."
                .into(),
        )));
    }
    let run_as_user = form.run_as_user.trim().to_string();
    if !abyssal_agent_protocol::is_valid_account_name(&run_as_user) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid username.".into(),
        )));
    }
    if !abyssal_agent_protocol::is_valid_cron_command(&form.command) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid command.".into(),
        )));
    }

    let macro_name = form.macro_name.trim();
    if macro_name.is_empty() || macro_name.len() > 128 {
        return Err(WebError(AppError::Validation(
            "Macro name must be 1-128 characters.".into(),
        )));
    }

    let scope: MacroScope = form
        .macro_scope
        .trim()
        .parse()
        .unwrap_or(MacroScope::Personal);
    let role_id = match scope {
        MacroScope::Personal => None,
        MacroScope::Role => {
            let role_id: Uuid = form.macro_role_id.trim().parse().map_err(|_| {
                WebError(AppError::Validation(
                    "Pick a role for a role-scoped macro.".into(),
                ))
            })?;
            let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
            if !user_roles.iter().any(|r| r.id == role_id) {
                return Err(WebError(AppError::Validation(
                    "You can only save a role macro for a role you belong to.".into(),
                )));
            }
            Some(role_id)
        }
    };

    repo::macros::create(
        &state.pool,
        repo::macros::MacroFields {
            name: macro_name,
            owner_user_id: ctx.user.id,
            scope,
            role_id,
            macro_type: abyssal_core::MacroType::CronJob,
            job_name: Some(&job_name),
            schedule: Some(&form.schedule),
            run_as_user: Some(&run_as_user),
            command: Some(&form.command),
            secret_value_encrypted: None,
        },
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::MacroCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(macro_name),
    )
    .await?;

    Ok(Redirect::to(&format!("/arsenals/grimoire/{}", form.host_id)).into_response())
}

#[allow(clippy::too_many_arguments)]
async fn render_macro_edit(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    macro_id: Uuid,
    host_id: Uuid,
    name: String,
    scope: MacroScope,
    role_id: Option<Uuid>,
    job_name: String,
    schedule: String,
    run_as_user: String,
    command: String,
    error: Option<String>,
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

    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let macro_roles = user_roles
        .into_iter()
        .map(|r| {
            let selected = scope == MacroScope::Role && role_id == Some(r.id);
            (r.id.to_string(), r.name, selected)
        })
        .collect();

    let tpl = crate::templates::GrimoireMacroEditTemplate {
        base,
        macro_id: macro_id.to_string(),
        host_id: host_id.to_string(),
        name,
        is_personal: scope == MacroScope::Personal,
        macro_roles,
        job_name,
        schedule,
        run_as_user,
        command,
        error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct MacroHostQuery {
    host_id: Uuid,
}

pub async fn macro_edit_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(macro_id): Path<Uuid>,
    Query(q): Query<MacroHostQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    let m = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &m)?;
    render_macro_edit(
        &state,
        &jar,
        &ctx,
        m.id,
        q.host_id,
        m.name,
        m.scope,
        m.role_id,
        m.job_name.unwrap_or_default(),
        m.schedule.unwrap_or_default(),
        m.run_as_user.unwrap_or_default(),
        m.command.unwrap_or_default(),
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct MacroEditForm {
    csrf_token: String,
    host_id: Uuid,
    name: String,
    job_name: String,
    schedule: String,
    run_as_user: String,
    command: String,
    #[serde(default)]
    macro_scope: String,
    #[serde(default)]
    macro_role_id: String,
}

pub async fn macro_edit(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(macro_id): Path<Uuid>,
    Form(form): Form<MacroEditForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let existing = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &existing)?;

    let render_error = |message: String| {
        let scope: MacroScope = form
            .macro_scope
            .trim()
            .parse()
            .unwrap_or(MacroScope::Personal);
        let role_id = form.macro_role_id.trim().parse::<Uuid>().ok();
        render_macro_edit(
            &state,
            &jar,
            &ctx,
            macro_id,
            form.host_id,
            form.name.clone(),
            scope,
            role_id,
            form.job_name.clone(),
            form.schedule.clone(),
            form.run_as_user.clone(),
            form.command.clone(),
            Some(message),
        )
    };

    let name = form.name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return render_error("Macro name must be 1-128 characters.".to_string()).await;
    }
    let job_name = match validate_job_name(&form.job_name) {
        Ok(v) => v,
        Err(_) => {
            return render_error(
                "That doesn't look like a valid job name (lowercase letters, digits, - and _ \
                 only)."
                    .to_string(),
            )
            .await;
        }
    };
    if !abyssal_agent_protocol::is_valid_cron_schedule(&form.schedule) {
        return render_error(
            "That doesn't look like a valid cron schedule (e.g. \"0 3 * * *\" or \"@daily\")."
                .to_string(),
        )
        .await;
    }
    let run_as_user = form.run_as_user.trim().to_string();
    if !abyssal_agent_protocol::is_valid_account_name(&run_as_user) {
        return render_error("That doesn't look like a valid username.".to_string()).await;
    }
    if !abyssal_agent_protocol::is_valid_cron_command(&form.command) {
        return render_error("That doesn't look like a valid command.".to_string()).await;
    }

    let scope: MacroScope = form
        .macro_scope
        .trim()
        .parse()
        .unwrap_or(MacroScope::Personal);
    let role_id = match scope {
        MacroScope::Personal => None,
        MacroScope::Role => {
            let Ok(role_id) = form.macro_role_id.trim().parse::<Uuid>() else {
                return render_error("Pick a role for a role-scoped macro.".to_string()).await;
            };
            let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
            if !user_roles.iter().any(|r| r.id == role_id) {
                return render_error(
                    "You can only save a role macro for a role you belong to.".to_string(),
                )
                .await;
            }
            Some(role_id)
        }
    };

    repo::macros::update(
        &state.pool,
        macro_id,
        repo::macros::MacroFields {
            name: &name,
            owner_user_id: existing.owner_user_id,
            scope,
            role_id,
            macro_type: abyssal_core::MacroType::CronJob,
            job_name: Some(&job_name),
            schedule: Some(&form.schedule),
            run_as_user: Some(&run_as_user),
            command: Some(&form.command),
            secret_value_encrypted: None,
        },
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::MacroUpdated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&name),
    )
    .await?;

    Ok(Redirect::to(&format!("/arsenals/grimoire/{}", form.host_id)).into_response())
}

pub async fn macro_remove_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(macro_id): Path<Uuid>,
    Query(q): Query<MacroHostQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    let m = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &m)?;

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

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Remove macro".to_string(),
        message: format!("This will remove the macro \"{}\".", m.name),
        action_url: format!("/arsenals/grimoire/macros/{macro_id}/remove"),
        cancel_url: format!("/arsenals/grimoire/{}", q.host_id),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "macro name".to_string(),
            expected: m.name,
        }),
        extra_hidden_fields: vec![("host_id".to_string(), q.host_id.to_string())],
        shred_option: None,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct MacroRemoveForm {
    csrf_token: String,
    host_id: Uuid,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn macro_remove(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(macro_id): Path<Uuid>,
    Form(form): Form<MacroRemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let m = repo::macros::find_by_id(&state.pool, macro_id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_macro(&ctx, &m)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &m.name)?;

    repo::macros::delete(&state.pool, macro_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::MacroDeleted, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&m.name),
    )
    .await?;

    Ok(Redirect::to(&format!("/arsenals/grimoire/{}", form.host_id)).into_response())
}

// ---------------------------------------------------------------------
// Destructive
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn destructive_confirm(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    title: &str,
    build_message: impl FnOnce(&str) -> String,
    action_url: String,
    type_to_confirm: Option<crate::templates::TypeToConfirm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;

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
        title: title.to_string(),
        message: build_message(&host.name),
        action_url,
        cancel_url: format!("/arsenals/grimoire/{host_id}"),
        escalate_host_id,
        type_to_confirm,
        extra_hidden_fields: vec![],
        shred_option: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

#[allow(clippy::too_many_arguments)]
/// `expected_confirm_text` is the type-to-confirm target: `Some(name)`
/// for ops with a single natural identifier (a job name), or `None` to
/// fall back to the host's own name (bulk "clear everything this tool
/// manages" ops with no single target) -- same reasoning Obituary's
/// journal vacuum and Defleshing's clear-tmp/clear-core-dumps document.
/// Every Destructive op here requires *some* typed confirmation; there's
/// no bare-plain-confirm case.
async fn run_destructive_op(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    expected_confirm_text: Option<&str>,
    operation: AgentOperation,
    label: &str,
    form: ConfirmForm,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(format!(
            "{label} was not confirmed."
        ))));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let expected = expected_confirm_text.unwrap_or(&host.name);
    crate::common::require_typed_confirmation(&form.confirm_text, expected)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
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
                state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                &jar,
                &ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
                None,
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct JobNameQuery {
    job_name: String,
}

pub async fn remove_cron_job_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<JobNameQuery>,
) -> Result<Response, WebError> {
    let job_name = validate_job_name(&q.job_name)?;
    let action_url = format!(
        "/arsenals/grimoire/{host_id}/remove-cron?job_name={}",
        urlencoding_encode(&job_name)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Remove scheduled task",
        move |host_name| {
            format!(
                "This will remove scheduled task \"{job_name}\" on \"{host_name}\", stopping \
                 whatever it runs on a recurring basis."
            )
        },
        action_url,
        Some(crate::templates::TypeToConfirm {
            label: "job name".to_string(),
            expected: q.job_name.clone(),
        }),
    )
    .await
}

pub async fn remove_cron_job(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<JobNameQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let job_name = validate_job_name(&q.job_name)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        Some(&job_name),
        AgentOperation::RemoveCronJob {
            job_name: job_name.clone(),
        },
        "Remove Scheduled Task",
        form,
    )
    .await
}

pub async fn clear_managed_sysctl_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    let action_url = format!("/arsenals/grimoire/{host_id}/clear-sysctl");
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let expected = host.name.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Clear managed sysctl overrides",
        move |host_name| {
            format!(
                "This will remove every persistent sysctl override this tool has set on \
                 \"{host_name}\" at once, reverting them to distro defaults."
            )
        },
        action_url,
        Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected,
        }),
    )
    .await
}

pub async fn clear_managed_sysctl(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        None,
        AgentOperation::ClearManagedSysctl,
        "Clear Managed Sysctl",
        form,
    )
    .await
}

pub async fn clear_managed_cron_jobs_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    let action_url = format!("/arsenals/grimoire/{host_id}/clear-cron");
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let expected = host.name.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Clear managed scheduled tasks",
        move |host_name| {
            format!(
                "This will remove every scheduled task this tool has set on \"{host_name}\" at \
                 once."
            )
        },
        action_url,
        Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected,
        }),
    )
    .await
}

pub async fn clear_managed_cron_jobs(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        None,
        AgentOperation::ClearManagedCronJobs,
        "Clear Managed Scheduled Tasks",
        form,
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
                None,
            )
            .await
        }
    }
}

// ---- M2: kernel module blacklist (modprobe.d) --------------------------

fn validate_module_name(module: &str) -> Result<String, WebError> {
    let module = module.trim().to_string();
    if !abyssal_agent_protocol::is_valid_kernel_module_name(&module) {
        return Err(WebError(AppError::Validation(
            "Enter a valid kernel module name (letters, digits, '_', '-', '.').".into(),
        )));
    }
    Ok(module)
}

pub async fn view_module_blacklist(
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
        AgentOperation::ViewModuleBlacklist,
        "Module Blacklist",
    )
    .await
}

#[derive(Deserialize)]
pub struct ModuleForm {
    csrf_token: String,
    module: String,
}

pub async fn blacklist_module(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ModuleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let module = validate_module_name(&form.module)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::BlacklistModule {
            module: module.clone(),
        },
        &format!("Blacklist Module ({module})"),
    )
    .await
}

pub async fn remove_module_blacklist(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ModuleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let module = validate_module_name(&form.module)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RemoveModuleBlacklist {
            module: module.clone(),
        },
        &format!("Remove Module Blacklist ({module})"),
    )
    .await
}

pub async fn clear_module_blacklist_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    let action_url = format!("/arsenals/grimoire/{host_id}/clear-module-blacklist");
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let expected = host.name.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Clear module blacklist",
        move |host_name| {
            format!(
                "This re-enables auto-loading of every kernel module this tool blacklisted on \
                 \"{host_name}\"."
            )
        },
        action_url,
        Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected,
        }),
    )
    .await
}

pub async fn clear_module_blacklist(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        None,
        AgentOperation::ClearModuleBlacklist,
        "Clear Module Blacklist",
        form,
    )
    .await
}

// ---- M2: journald retention -------------------------------------------

pub async fn view_journald_config(
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
        AgentOperation::ViewJournaldConfig,
        "Journald Config",
    )
    .await
}

#[derive(Deserialize)]
pub struct JournaldForm {
    csrf_token: String,
    setting: String,
    value: String,
}

pub async fn set_journald_retention(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<JournaldForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let setting =
        abyssal_agent_protocol::JournaldSetting::from_wire(&form.setting).ok_or_else(|| {
            WebError(AppError::Validation(
                "Choose a valid journald setting.".into(),
            ))
        })?;
    if !abyssal_agent_protocol::is_valid_journald_value(&form.value) {
        return Err(WebError(AppError::Validation(
            "Enter a valid value, e.g. 500M or 2week.".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::SetJournaldRetention {
            setting,
            value: form.value.clone(),
        },
        &format!("Journald {}={}", setting.key(), form.value),
    )
    .await
}

pub async fn clear_journald_config_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    let action_url = format!("/arsenals/grimoire/{host_id}/clear-journald");
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let expected = host.name.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Clear managed journald config",
        move |host_name| {
            format!(
                "This reverts journald on \"{host_name}\" to its own retention defaults and \
                 restarts the service."
            )
        },
        action_url,
        Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected,
        }),
    )
    .await
}

pub async fn clear_journald_config(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        None,
        AgentOperation::ClearJournaldConfig,
        "Clear Journald Config",
        form,
    )
    .await
}

// ---- M3: config profiles (config-as-code) ------------------------------

/// Maps a profile entry to the agent operation that applies it, or `None` for
/// an unknown kind. Pure and unit-tested.
fn entry_to_operation(kind: &str, key: &str, value: &str) -> Option<AgentOperation> {
    match kind {
        "sysctl" => Some(AgentOperation::SetPersistentSysctl {
            key: key.to_string(),
            value: value.to_string(),
        }),
        "module_blacklist" => Some(AgentOperation::BlacklistModule {
            module: key.to_string(),
        }),
        "journald" => abyssal_agent_protocol::JournaldSetting::from_wire(key).map(|setting| {
            AgentOperation::SetJournaldRetention {
                setting,
                value: value.to_string(),
            }
        }),
        _ => None,
    }
}

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "sysctl" => "sysctl",
        "module_blacklist" => "module blacklist",
        "journald" => "journald",
        _ => "unknown",
    }
}

/// Validates an entry's key/value for its kind, using the shared protocol
/// validators. Returns the (possibly normalized) value to store.
fn validate_entry(kind: &str, key: &str, value: &str) -> Result<String, WebError> {
    let bad = |m: &str| WebError(AppError::Validation(m.to_string()));
    match kind {
        "sysctl" => {
            if !abyssal_agent_protocol::is_valid_sysctl_key(key)
                || !abyssal_agent_protocol::is_valid_sysctl_value(value)
            {
                return Err(bad("Enter a valid sysctl key and value."));
            }
            Ok(value.to_string())
        }
        "module_blacklist" => {
            if !abyssal_agent_protocol::is_valid_kernel_module_name(key) {
                return Err(bad("Enter a valid kernel module name."));
            }
            Ok(String::new()) // module blacklist has no value
        }
        "journald" => {
            if abyssal_agent_protocol::JournaldSetting::from_wire(key).is_none()
                || !abyssal_agent_protocol::is_valid_journald_value(value)
            {
                return Err(bad("Choose a valid journald setting and value."));
            }
            Ok(value.to_string())
        }
        _ => Err(bad("Unknown config kind.")),
    }
}

/// Whether `ctx` may see a profile: their own personal one, a role one for a
/// role they're in, or anything with `MacrosManageAll`.
fn can_view_profile(
    ctx: &AuthContext,
    profile: &abyssal_database::repo::grimoire_profiles::Profile,
    user_role_ids: &[Uuid],
) -> bool {
    if ctx.has(Permission::MacrosManageAll) {
        return true;
    }
    match profile.scope {
        MacroScope::Personal => profile.owner_user_id == ctx.user.id,
        MacroScope::Role => profile.role_id.is_some_and(|r| user_role_ids.contains(&r)),
    }
}

fn ensure_can_edit_profile(
    ctx: &AuthContext,
    profile: &abyssal_database::repo::grimoire_profiles::Profile,
) -> Result<(), WebError> {
    if profile.owner_user_id == ctx.user.id || ctx.has(Permission::MacrosManageAll) {
        Ok(())
    } else {
        Err(WebError(AppError::Forbidden))
    }
}

async fn render_profiles(
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

    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let role_ids: Vec<Uuid> = user_roles.iter().map(|r| r.id).collect();
    let macro_roles = user_roles
        .iter()
        .map(|r| (r.id.to_string(), r.name.clone()))
        .collect();

    let mut profiles = Vec::new();
    for p in
        repo::grimoire_profiles::list_visible_to_user(&state.pool, ctx.user.id, &role_ids).await?
    {
        let entries = repo::grimoire_profiles::list_entries(&state.pool, p.id)
            .await?
            .into_iter()
            .map(|e| GrimoireProfileEntryView {
                id: e.id.to_string(),
                kind_label: kind_label(&e.kind).to_string(),
                key: e.key,
                value: e.value,
            })
            .collect();
        let scope_label = match p.scope {
            MacroScope::Personal => "Personal".to_string(),
            MacroScope::Role => "Role".to_string(),
        };
        let can_edit = p.owner_user_id == ctx.user.id || ctx.has(Permission::MacrosManageAll);
        profiles.push(GrimoireProfileView {
            id: p.id.to_string(),
            name: p.name,
            scope_label,
            can_edit,
            entries,
        });
    }

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(GrimoireHostRow {
                is_control_plane: host.is_control_plane,
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = GrimoireProfilesTemplate {
        can_manage: ctx.has(Permission::SystemsManage),
        base,
        profiles,
        macro_roles,
        hosts,
        result_message,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn profiles_page(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    render_profiles(&state, &jar, &ctx, None).await
}

#[derive(Deserialize)]
pub struct CreateProfileForm {
    csrf_token: String,
    name: String,
    scope: String,
    #[serde(default)]
    role_id: Option<String>,
}

pub async fn create_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<CreateProfileForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let name = form.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(WebError(AppError::Validation(
            "Enter a profile name.".into(),
        )));
    }
    let scope = if form.scope == "role" {
        MacroScope::Role
    } else {
        MacroScope::Personal
    };
    let role_id = if scope == MacroScope::Role {
        let rid = form
            .role_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                WebError(AppError::Validation(
                    "Pick a role for a role-scoped profile.".into(),
                ))
            })?;
        let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
        if !user_roles.iter().any(|r| r.id == rid) {
            return Err(WebError(AppError::Forbidden));
        }
        Some(rid)
    } else {
        None
    };
    repo::grimoire_profiles::create_profile(&state.pool, name, ctx.user.id, scope, role_id).await?;
    render_profiles(
        &state,
        &jar,
        &ctx,
        Some(format!("Created profile \"{name}\".")),
    )
    .await
}

pub async fn delete_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let profile = repo::grimoire_profiles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_profile(&ctx, &profile)?;
    repo::grimoire_profiles::delete_profile(&state.pool, id).await?;
    render_profiles(&state, &jar, &ctx, Some("Deleted profile.".to_string())).await
}

#[derive(Deserialize)]
pub struct AddEntryForm {
    csrf_token: String,
    kind: String,
    key: String,
    #[serde(default)]
    value: String,
}

pub async fn add_profile_entry(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<AddEntryForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let profile = repo::grimoire_profiles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_profile(&ctx, &profile)?;
    let key = form.key.trim();
    let value = validate_entry(&form.kind, key, form.value.trim())?;
    repo::grimoire_profiles::add_entry(&state.pool, id, &form.kind, key, &value).await?;
    render_profiles(
        &state,
        &jar,
        &ctx,
        Some("Added setting to profile.".to_string()),
    )
    .await
}

pub async fn remove_profile_entry(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((id, entry_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let profile = repo::grimoire_profiles::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    ensure_can_edit_profile(&ctx, &profile)?;
    repo::grimoire_profiles::remove_entry(&state.pool, id, entry_id).await?;
    render_profiles(
        &state,
        &jar,
        &ctx,
        Some("Removed setting from profile.".to_string()),
    )
    .await
}

#[derive(Deserialize)]
pub struct ApplyProfileForm {
    csrf_token: String,
    profile_id: Uuid,
    host_id: Uuid,
}

/// Applies every entry of a profile to one host, returning a per-entry result
/// line. Shared by single-host and fleet apply. A failure de-escalates and
/// continues so one bad setting doesn't abort the rest.
async fn apply_entries_to_host(
    state: &AppState,
    ctx: &AuthContext,
    host_id: Uuid,
    host_name: &str,
    entries: &[abyssal_database::repo::grimoire_profiles::ProfileEntry],
) -> Vec<String> {
    let mut results = Vec::new();
    for entry in entries {
        let Some(op) = entry_to_operation(&entry.kind, &entry.key, &entry.value) else {
            results.push(format!(
                "{} {}: skipped (unknown kind)",
                entry.kind, entry.key
            ));
            continue;
        };
        let elevated = state.elevation.is_elevated(host_id);
        match state
            .executor
            .execute_on_host(
                ctx,
                &state.hosts,
                host_id,
                host_name,
                op,
                Permission::SystemsManage,
                OperationKind::Write,
                false,
                Duration::from_secs(30),
                None,
                elevated,
            )
            .await
        {
            Ok(_) => results.push(format!("{} {}: applied", entry.kind, entry.key)),
            Err(e) => {
                state.elevation.mark_deescalated(host_id);
                results.push(format!("{} {}: failed ({e})", entry.kind, entry.key));
            }
        }
    }
    results
}

pub async fn apply_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ApplyProfileForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let profile = repo::grimoire_profiles::find_by_id(&state.pool, form.profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let role_ids: Vec<Uuid> = user_roles.iter().map(|r| r.id).collect();
    if !can_view_profile(&ctx, &profile, &role_ids) {
        return Err(WebError(AppError::Forbidden));
    }

    let host = repo::hosts::find_by_id(&state.pool, form.host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let entries = repo::grimoire_profiles::list_entries(&state.pool, profile.id).await?;
    let results = apply_entries_to_host(&state, &ctx, form.host_id, &host.name, &entries).await;

    let message = if results.is_empty() {
        format!("Profile \"{}\" has no settings to apply.", profile.name)
    } else {
        format!(
            "Applied profile \"{}\" to {}:\n{}",
            profile.name,
            host.name,
            results.join("\n")
        )
    };
    render_profiles(&state, &jar, &ctx, Some(message)).await
}

// ---- M5: fleet config-drift hub ----------------------------------------

/// Rolls a host's drift check up to a status label, badge, and rank (2 =
/// drifted/worst, 1 = unavailable/no-managed-config, 0 = in sync). Pure.
fn drift_status(op_ok: bool, total: usize, drifted: usize) -> (&'static str, &'static str, u8) {
    if !op_ok {
        ("unavailable", "badge-muted", 1)
    } else if total == 0 {
        ("no managed config", "badge-muted", 1)
    } else if drifted == 0 {
        ("in sync", "badge-success", 0)
    } else {
        ("drifted", "badge-warning", 2)
    }
}

pub async fn drift_hub(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    let (mut in_sync, mut drifted_hosts, mut other) = (0usize, 0usize, 0usize);
    let mut rows: Vec<(u8, GrimoireDriftRow)> = Vec::new();
    let mut suggested_actions = Vec::new();
    let mut seen = std::collections::HashSet::new();

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
                AgentOperation::SysctlManagedDrift,
                Permission::SystemsView,
                OperationKind::Read,
                false,
                Duration::from_secs(15),
                None,
                elevated,
            )
            .await;

        let (op_ok, total, drift_count, detail) = match &res {
            Ok(output) => {
                let (drows, drifted) = parse_sysctl_drift(&output.stdout);
                let total = drows.len();
                let detail = if total == 0 {
                    "No managed sysctl overrides".to_string()
                } else if drifted == 0 {
                    format!("{total} key(s) in sync")
                } else {
                    format!("{drifted} of {total} key(s) drifted")
                };
                (true, total, drifted, detail)
            }
            Err(e) => (false, 0, 0, e.to_string()),
        };

        let (status_label, status_badge_class, rank) = drift_status(op_ok, total, drift_count);
        match rank {
            2 => drifted_hosts += 1,
            0 => in_sync += 1,
            _ => other += 1,
        }

        // Aggregate the drift → Postmortem suggestion for hosts that drifted.
        if rank == 2 {
            let entry = serde_json::json!({ "drift_count": drift_count });
            for a in crate::common::suggested_actions_for(
                &state,
                "grimoire",
                "sysctl_drift",
                std::slice::from_ref(&entry),
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
            GrimoireDriftRow {
                host_id: host.id.to_string(),
                host_name: host.name,
                status_label: status_label.to_string(),
                status_badge_class: status_badge_class.to_string(),
                detail,
            },
        ));
    }

    rows.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.host_name.cmp(&b.1.host_name))
    });
    let rows: Vec<GrimoireDriftRow> = rows.into_iter().map(|(_, r)| r).collect();
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
    let tpl = GrimoireDriftTemplate {
        base,
        rows,
        total,
        in_sync,
        drifted: drifted_hosts,
        other,
        suggested_actions,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

// ---- M4: apply a profile across the fleet ------------------------------

#[derive(Deserialize)]
pub struct FleetProfileQuery {
    profile_id: Uuid,
}

/// Loads a profile and checks the caller may see it, returning the caller's
/// role ids too (both fleet handlers need the same preamble).
async fn load_visible_profile(
    state: &AppState,
    ctx: &AuthContext,
    profile_id: Uuid,
) -> Result<abyssal_database::repo::grimoire_profiles::Profile, WebError> {
    let profile = repo::grimoire_profiles::find_by_id(&state.pool, profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let user_roles = repo::roles::roles_for_user(&state.pool, ctx.user.id).await?;
    let role_ids: Vec<Uuid> = user_roles.iter().map(|r| r.id).collect();
    if !can_view_profile(ctx, &profile, &role_ids) {
        return Err(WebError(AppError::Forbidden));
    }
    Ok(profile)
}

async fn connected_hosts(state: &AppState) -> anyhow::Result<Vec<(Uuid, String)>> {
    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push((host.id, host.name));
        }
    }
    Ok(hosts)
}

pub async fn apply_profile_fleet_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<FleetProfileQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    let profile = load_visible_profile(&state, &ctx, q.profile_id).await?;
    let hosts = connected_hosts(&state).await?;
    if hosts.is_empty() {
        return render_profiles(
            &state,
            &jar,
            &ctx,
            Some("No connected hosts to apply to.".to_string()),
        )
        .await;
    }
    let entries = repo::grimoire_profiles::list_entries(&state.pool, profile.id).await?;
    let host_names: Vec<&str> = hosts.iter().map(|(_, n)| n.as_str()).collect();

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
    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: format!("Apply \u{201c}{}\u{201d} to the fleet", profile.name),
        message: format!(
            "This applies profile \"{}\" ({} setting(s)) to all {} connected host(s):\n\n{}",
            profile.name,
            entries.len(),
            hosts.len(),
            host_names.join(", ")
        ),
        action_url: format!(
            "/arsenals/grimoire/apply-profile-fleet?profile_id={}",
            profile.id
        ),
        cancel_url: "/arsenals/grimoire/profiles".to_string(),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "profile name".to_string(),
            expected: profile.name.clone(),
        }),
        extra_hidden_fields: vec![],
        shred_option: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn apply_profile_fleet(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(q): Query<FleetProfileQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Fleet apply was not confirmed.".into(),
        )));
    }
    let profile = load_visible_profile(&state, &ctx, q.profile_id).await?;
    crate::common::require_typed_confirmation(&form.confirm_text, &profile.name)?;

    let entries = repo::grimoire_profiles::list_entries(&state.pool, profile.id).await?;
    let hosts = connected_hosts(&state).await?;

    let mut summary = Vec::new();
    for (host_id, host_name) in &hosts {
        let results = apply_entries_to_host(&state, &ctx, *host_id, host_name, &entries).await;
        let failed = results.iter().filter(|r| r.contains(": failed")).count();
        let applied = results.iter().filter(|r| r.contains(": applied")).count();
        summary.push(format!("{host_name}: {applied} applied, {failed} failed"));
    }

    let message = if hosts.is_empty() {
        "No connected hosts to apply to.".to_string()
    } else {
        format!(
            "Applied profile \"{}\" to {} connected host(s):\n{}",
            profile.name,
            hosts.len(),
            summary.join("\n")
        )
    };
    render_profiles(&state, &jar, &ctx, Some(message)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_status_ranks_hosts() {
        assert_eq!(drift_status(true, 5, 0), ("in sync", "badge-success", 0));
        assert_eq!(drift_status(true, 5, 2), ("drifted", "badge-warning", 2));
        assert_eq!(drift_status(true, 0, 0).2, 1); // no managed config
        assert_eq!(drift_status(false, 0, 0).0, "unavailable");
    }

    #[test]
    fn profile_entries_map_to_the_right_operation() {
        assert!(matches!(
            entry_to_operation("sysctl", "vm.swappiness", "10"),
            Some(AgentOperation::SetPersistentSysctl { .. })
        ));
        assert!(matches!(
            entry_to_operation("module_blacklist", "usb-storage", ""),
            Some(AgentOperation::BlacklistModule { .. })
        ));
        assert!(matches!(
            entry_to_operation("journald", "system_max_use", "500M"),
            Some(AgentOperation::SetJournaldRetention { .. })
        ));
        // Unknown kind, and an invalid journald key, both map to nothing.
        assert!(entry_to_operation("nonsense", "x", "y").is_none());
        assert!(entry_to_operation("journald", "not_a_setting", "1").is_none());
    }

    #[test]
    fn profile_entry_validation_enforces_per_kind_rules() {
        assert!(validate_entry("sysctl", "vm.swappiness", "10").is_ok());
        assert!(validate_entry("sysctl", "bad key", "10").is_err());
        // module_blacklist stores no value regardless of what was passed.
        assert_eq!(
            validate_entry("module_blacklist", "usb-storage", "x").ok(),
            Some(String::new())
        );
        assert!(validate_entry("module_blacklist", "-rf", "").is_err());
        assert!(validate_entry("journald", "system_max_use", "500M").is_ok());
        assert!(validate_entry("journald", "system_max_use", "500 M").is_err());
        assert!(validate_entry("what", "k", "v").is_err());
    }

    #[test]
    fn parses_sysctl_drift_rows_and_counts_drift() {
        let stdout = "net.ipv4.ip_forward\t1\t1\tin_sync\n\
                      kernel.randomize_va_space\t2\t0\tdrifted\n\
                      net.ipv6.conf.all.forwarding\t0\tunavailable\tunavailable";
        let (rows, drifted) = parse_sysctl_drift(stdout);
        assert_eq!(rows.len(), 3);
        assert_eq!(drifted, 1);
        assert_eq!(rows[0].status_label, "in sync");
        assert_eq!(rows[1].status_label, "drifted");
        assert_eq!(rows[1].status_badge_class, "badge-warning");
        assert_eq!(rows[2].status_label, "unavailable");
    }

    #[test]
    fn no_managed_message_yields_no_rows() {
        let (rows, drifted) = parse_sysctl_drift("No managed sysctl overrides set.");
        assert!(rows.is_empty());
        assert_eq!(drifted, 0);
    }

    #[test]
    fn sysctl_drift_suggests_postmortem() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let hit = serde_json::json!({ "drift_count": 1 });
        let targets: Vec<String> = registry
            .evaluate("grimoire", "sysctl_drift", &hit)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"postmortem".to_string()));

        let clean = serde_json::json!({ "drift_count": 0 });
        assert!(
            registry
                .evaluate("grimoire", "sysctl_drift", &clean)
                .matches
                .is_empty()
        );
    }
}
