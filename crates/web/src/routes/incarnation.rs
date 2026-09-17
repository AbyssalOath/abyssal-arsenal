use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::state::AppState;
use crate::templates::{BaseCtx, IncarnationHostRow, IncarnationHostTemplate, IncarnationTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(IncarnationHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = IncarnationTemplate { base, hosts };
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
    let base = BaseCtx::build(ctx, &theme::current(jar), &csrf_token, &state.elevation);

    let tpl = IncarnationHostTemplate {
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
    #[serde(default)]
    sudo_password: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    sudo_password: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let tls_warning = match maybe_elevate(state, ctx, host_id, &host.name, sudo_password).await {
        Ok(warning) => warning.unwrap_or(""),
        Err(e) => return render_host(state, jar, ctx, host_id, result_label, None, Some(e)).await,
    };

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
                Some(format!("{tls_warning}{}", output.stdout)),
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

pub async fn list_services(
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
        AgentOperation::ListServices,
        "Services",
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct UnitForm {
    csrf_token: String,
    unit: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

fn validate_unit(unit: &str) -> Result<String, WebError> {
    let unit = unit.trim().to_string();
    if !abyssal_agent_protocol::is_valid_unit_name(&unit) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid systemd unit name.".into(),
        )));
    }
    Ok(unit)
}

pub async fn service_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UnitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let unit = validate_unit(&form.unit)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ServiceStatus { unit: unit.clone() },
        &format!("Service Status ({unit})"),
        form.sudo_password,
    )
    .await
}

pub async fn service_logs(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UnitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let unit = validate_unit(&form.unit)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ServiceLogs { unit: unit.clone() },
        &format!("Service Logs ({unit})"),
        form.sudo_password,
    )
    .await
}

/// Shared by Start/Enable/Disable: `Write`, no confirmation required.
#[allow(clippy::too_many_arguments)]
async fn run_write_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    sudo_password: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let tls_warning = match maybe_elevate(state, ctx, host_id, &host.name, sudo_password).await {
        Ok(warning) => warning.unwrap_or(""),
        Err(e) => return render_host(state, jar, ctx, host_id, result_label, None, Some(e)).await,
    };

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
                Some(format!("{tls_warning}{}", output.stdout)),
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

pub async fn start_service(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UnitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let unit = validate_unit(&form.unit)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::StartService { unit: unit.clone() },
        &format!("Start Service ({unit})"),
        form.sudo_password,
    )
    .await
}

pub async fn enable_service(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UnitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let unit = validate_unit(&form.unit)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::EnableService { unit: unit.clone() },
        &format!("Enable Service ({unit})"),
        form.sudo_password,
    )
    .await
}

pub async fn disable_service(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UnitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let unit = validate_unit(&form.unit)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::DisableService { unit: unit.clone() },
        &format!("Disable Service ({unit})"),
        form.sudo_password,
    )
    .await
}

#[derive(Deserialize)]
pub struct UnitQuery {
    unit: String,
}

/// Shared confirm-page renderer for Stop/Restart -- identical shape apart
/// from the verb, title, and target route.
#[allow(clippy::too_many_arguments)]
async fn lifecycle_confirm(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    unit: String,
    verb: &str,
    route_segment: &str,
    warning: &str,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;

    let unit = validate_unit(&unit)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let (csrf_token, new_cookie) = csrf::ensure_token(&jar);
    let base = BaseCtx::build(&ctx, &theme::current(&jar), &csrf_token, &state.elevation);

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: format!("{verb} service"),
        message: format!(
            "This will {} \"{unit}\" on \"{}\". {warning}",
            verb.to_lowercase(),
            host.name
        ),
        action_url: format!(
            "/arsenals/incarnation/{host_id}/{route_segment}?unit={}",
            urlencoding_encode(&unit)
        ),
        cancel_url: format!("/arsenals/incarnation/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "unit name".to_string(),
            expected: unit.clone(),
        }),
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn stop_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<UnitQuery>,
) -> Result<Response, WebError> {
    lifecycle_confirm(
        &state,
        jar,
        ctx,
        host_id,
        q.unit,
        "Stop",
        "stop",
        "Whatever this unit provides becomes unavailable immediately.",
    )
    .await
}

pub async fn restart_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<UnitQuery>,
) -> Result<Response, WebError> {
    lifecycle_confirm(
        &state,
        jar,
        ctx,
        host_id,
        q.unit,
        "Restart",
        "restart",
        "A brief outage is guaranteed -- if this is what's carrying your connection to this host (e.g. sshd), restarting it can cut you off.",
    )
    .await
}

#[derive(Deserialize)]
pub struct LifecycleForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
    #[serde(default)]
    sudo_password: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_lifecycle_op(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    unit: String,
    operation: AgentOperation,
    label: &str,
    form: LifecycleForm,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(format!(
            "{label} was not confirmed."
        ))));
    }

    let unit = validate_unit(&unit)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &unit)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} ({unit}) -- {}", host.name));

    let tls_warning =
        match maybe_elevate(state, &ctx, host_id, &host.name, form.sudo_password).await {
            Ok(warning) => warning.unwrap_or(""),
            Err(e) => {
                return render_host(state, &jar, &ctx, host_id, result_label, None, Some(e)).await
            }
        };

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
                Some(format!("{tls_warning}{}", output.stdout)),
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

pub async fn stop_service(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<UnitQuery>,
    Form(form): Form<LifecycleForm>,
) -> Result<Response, WebError> {
    let unit = q.unit;
    run_lifecycle_op(
        &state,
        jar,
        ctx,
        host_id,
        unit.clone(),
        AgentOperation::StopService { unit },
        "Stop Service",
        form,
    )
    .await
}

pub async fn restart_service(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<UnitQuery>,
    Form(form): Form<LifecycleForm>,
) -> Result<Response, WebError> {
    let unit = q.unit;
    run_lifecycle_op(
        &state,
        jar,
        ctx,
        host_id,
        unit.clone(),
        AgentOperation::RestartService { unit },
        "Restart Service",
        form,
    )
    .await
}
