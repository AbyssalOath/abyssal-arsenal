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
use crate::templates::{BaseCtx, GrimoireHostRow, GrimoireHostTemplate, GrimoireTemplate};
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
    mut result_error: Option<String>,
    load_macro: Option<Uuid>,
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
