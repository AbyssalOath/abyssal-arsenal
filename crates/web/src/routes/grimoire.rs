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

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
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

    if let Some(host_id) = host_context::current(&jar) {
        if state.hosts.is_connected(host_id) {
            return Ok(Redirect::to(&format!("/arsenals/grimoire/{host_id}")).into_response());
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

async fn render_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
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

    let tpl = GrimoireHostTemplate {
        can_manage: ctx.has(Permission::SystemsManage),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
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

pub async fn show_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
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
