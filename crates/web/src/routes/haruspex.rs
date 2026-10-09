//! Haruspex: Windows Active Directory / directory-services health diagnostics.
//! A per-host arsenal that runs the read-only `AdDnsReport` / `AdHealthReport`
//! agent operations against a domain controller and shows the returned
//! sectioned report. The domain FQDN is validated here (a clean error) and
//! again on the agent (the real execution boundary). Read-only throughout, so
//! no typed-confirmation gate.

use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, HaruspexHostRow, HaruspexHostTemplate, HaruspexTemplate};
use crate::theme;

/// `dcdiag /v` + replication + discovery can take a while on a real forest, so
/// the health report gets a generous ceiling; the DNS report is quicker.
const DNS_TIMEOUT: Duration = Duration::from_secs(60);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(180);

/// Landing page: a host picker, same shape as the other per-host arsenals.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SystemsView)?;

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/haruspex/{host_id}")).into_response());
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
            hosts.push(HaruspexHostRow {
                is_control_plane: host.is_control_plane,
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = HaruspexTemplate { base, hosts };
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
    render_host(&state, &jar, &ctx, host_id, String::new(), None, None, None).await
}

#[derive(Deserialize)]
pub struct ReportForm {
    csrf_token: String,
    #[serde(default)]
    domain: String,
}

pub async fn dns_report(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ReportForm>,
) -> Result<Response, WebError> {
    run_report(
        &state,
        &jar,
        &ctx,
        host_id,
        form,
        "AD DNS check",
        DNS_TIMEOUT,
        |domain| AgentOperation::AdDnsReport { domain },
    )
    .await
}

pub async fn health_report(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ReportForm>,
) -> Result<Response, WebError> {
    run_report(
        &state,
        &jar,
        &ctx,
        host_id,
        form,
        "AD health check",
        HEALTH_TIMEOUT,
        |domain| AgentOperation::AdHealthReport { domain },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_report(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    form: ReportForm,
    label: &str,
    timeout: Duration,
    build_op: impl Fn(String) -> AgentOperation,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(ctx, Permission::SystemsView)?;
    require_csrf(jar, &form.csrf_token)?;

    let domain = form.domain.trim().to_string();
    // Clean validation error here; the agent re-validates before any argv use.
    if !abyssal_agent_protocol::is_valid_hostname(&domain) {
        return render_host(
            state,
            jar,
            ctx,
            host_id,
            domain,
            Some(label.to_string()),
            None,
            Some("Enter a valid Active Directory domain FQDN (e.g. corp.example.com).".to_string()),
        )
        .await;
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = format!("{label} -- {} ({domain})", host.name);
    let elevated = state.elevation.is_elevated(host_id);

    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            build_op(domain.clone()),
            Permission::SystemsView,
            OperationKind::Read,
            false,
            timeout,
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
                domain,
                Some(result_label),
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            render_host(
                state,
                jar,
                ctx,
                host_id,
                domain,
                Some(result_label),
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn render_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    domain: String,
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

    let tpl = HaruspexHostTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        control_plane: crate::control_plane::page_note(&state.hosts, host_id),
        domain,
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
