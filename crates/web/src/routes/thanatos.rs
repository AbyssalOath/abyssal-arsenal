use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission, Severity};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    AlertRow, BaseCtx, SecurityEventRow, SeverityCountRow, SuggestedActionView, ThanatosHostRow,
    ThanatosHostTemplate, ThanatosTemplate,
};
use crate::theme;

const RECENT_EVENTS_LIMIT: i64 = 200;
const RECENT_ALERTS_LIMIT: i64 = 50;
const SUMMARY_WINDOW_HOURS: i64 = 24;

fn severity_view(severity: Severity) -> (&'static str, &'static str) {
    match severity {
        Severity::Low => ("Low", "badge-muted"),
        Severity::Medium => ("Medium", "badge-warning"),
        Severity::High => ("High", "badge-danger"),
        Severity::Critical => ("CRITICAL", "badge-danger"),
    }
}

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;

    if let Some(host_id) = host_context::current(&jar) {
        if state.hosts.is_connected(host_id) {
            return Ok(Redirect::to(&format!("/arsenals/thanatos/{host_id}")).into_response());
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
            hosts.push(ThanatosHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let severity_summary = crate::thanatos_ops::severity_summary(&state.pool, SUMMARY_WINDOW_HOURS)
        .await?
        .into_iter()
        .map(|(severity, count)| {
            let (label, badge_class) = severity_view(severity);
            SeverityCountRow {
                label,
                badge_class,
                count,
            }
        })
        .collect();

    let mut recent_alerts = Vec::new();
    for event in repo::security_events::list_recent_alerts(&state.pool, RECENT_ALERTS_LIMIT).await?
    {
        let host_name = repo::hosts::find_by_id(&state.pool, event.host_id)
            .await?
            .map(|h| h.name)
            .unwrap_or_else(|| "(removed host)".to_string());
        recent_alerts.push(AlertRow {
            host_name,
            label: event.label,
            raw_line: event.raw_line,
            occurred_at: crate::common::format_in_tz(event.occurred_at, &ctx.user.timezone),
        });
    }

    let tpl = ThanatosTemplate {
        base,
        hosts,
        severity_summary,
        recent_alerts,
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
    render_host_with_suggestions(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        Vec::new(),
    )
    .await
}

/// Same as `render_host`, but also renders a "Suggested Next Steps" section
/// from the workflow registry's matches against this result -- see `scan`
/// below, the one action that currently produces any.
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

    let mut events = Vec::new();
    for event in
        repo::security_events::list_recent_for_host(&state.pool, host_id, RECENT_EVENTS_LIMIT)
            .await?
    {
        let (severity_label, badge_class) = severity_view(event.severity);
        events.push(SecurityEventRow {
            severity_label,
            badge_class,
            label: event.label,
            source: event.source,
            raw_line: event.raw_line,
            occurred_at: crate::common::format_in_tz(event.occurred_at, &ctx.user.timezone),
        });
    }

    let tpl = ThanatosHostTemplate {
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        events,
        result_label,
        result_output,
        result_error,
        suggested_actions,
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
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

#[derive(Deserialize)]
pub struct ScanForm {
    csrf_token: String,
}

pub async fn scan(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ScanForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("Security Event Scan -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ScanSecurityEvents,
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(30),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let recipients_raw = repo::settings::get_string(
                &state.pool,
                abyssal_core::settings::THANATOS_ALERT_RECIPIENTS,
                "",
            )
            .await?;
            let recipients = crate::thanatos_ops::parse_recipients(&recipients_raw);

            let ingest = crate::thanatos_ops::ingest_scan(
                &state.pool,
                &state.notifications,
                &recipients,
                host_id,
                &host.name,
                &output.stdout,
            )
            .await;

            let mut suggested_actions = Vec::new();
            let summary = match ingest {
                Ok((persisted, informational, alerted)) => {
                    let mut lines = Vec::new();
                    if let Some(message) = informational {
                        lines.push(message);
                    } else {
                        lines.push(format!(
                            "{persisted} new event(s) persisted (already-seen lines from this \
                             scan window were skipped)."
                        ));
                    }
                    if alerted {
                        lines.push(
                            "A correlation alert was raised for this host -- see the Thanatos \
                             dashboard."
                                .to_string(),
                        );
                    }

                    let entry = serde_json::json!({
                        "persisted_count": persisted,
                        "alerted": alerted,
                    });
                    suggested_actions = crate::common::suggested_actions_for(
                        &state,
                        "thanatos",
                        "scan_security_events",
                        std::slice::from_ref(&entry),
                        host_id,
                    )
                    .await;

                    lines.join("\n")
                }
                Err(e) => format!("Scan completed, but failed to persist results: {e}"),
            };

            render_host_with_suggestions(
                &state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(summary),
                None,
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
    fn alerted_scan_suggests_inquest_and_postmortem() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "persisted_count": 5, "alerted": true });

        let matches = registry.evaluate("thanatos", "scan_security_events", &entry).matches;
        let targets: Vec<&str> = matches.iter().map(|m| m.target_arsenal.as_str()).collect();

        assert!(targets.contains(&"inquest"));
        assert!(targets.contains(&"postmortem"));
    }

    #[test]
    fn non_alerted_scan_suggests_nothing() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "persisted_count": 3, "alerted": false });

        assert!(registry
            .evaluate("thanatos", "scan_security_events", &entry)
            .matches
            .is_empty());
    }
}
