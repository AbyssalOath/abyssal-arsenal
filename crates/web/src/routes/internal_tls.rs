//! `/admin/health/tls`: managing the control plane's internal CA and server
//! certificate from the browser -- renew, reload Caddy, keep agents' trusted
//! CA current, and rotate the CA / change the addresses it covers. The
//! mechanics live in `crate::internal_tls`; this is the UI and the audit
//! trail. Gated by `SettingsManage`, like the rest of `/admin/health`.

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_internal_ca::{self as ca, CertInfo};
use axum::Form;
use axum::extract::State;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::internal_tls;
use crate::state::AppState;
use crate::templates::{BaseCtx, InternalTlsTemplate, TlsCertView, TlsHostRow, TlsSummary};
use crate::theme;

fn cert_view(info: &CertInfo, names: &[String], tz: &str) -> TlsCertView {
    let now = Utc::now().timestamp();
    TlsCertView {
        subject: info.subject.clone(),
        fingerprint: internal_tls::grouped(&info.fingerprint),
        expires: DateTime::<Utc>::from_timestamp(info.not_after, 0)
            .map(|t| crate::common::format_in_tz(t, tz))
            .unwrap_or_default(),
        days_left: info.days_left(now),
        names: names.join(", "),
    }
}

/// Also used by `/admin/health`'s summary card.
pub fn summary(tz: &str) -> TlsSummary {
    let status = internal_tls::status();
    let ca_names = |info: &CertInfo| {
        info.permitted_addresses()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };
    TlsSummary {
        managed: status.managed,
        ca: status.ca.as_ref().map(|c| cert_view(c, &ca_names(c), tz)),
        pending: status
            .pending
            .as_ref()
            .map(|c| cert_view(c, &ca_names(c), tz)),
        server: status.server.as_ref().map(|c| cert_view(c, &c.sans, tz)),
        healthy: status.renewal_due.is_none() && status.problems.is_empty(),
        renewal_due: status.renewal_due,
        problems: status.problems,
    }
}

async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    message: Option<String>,
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

    let tz = &ctx.user.timezone;
    let status = internal_tls::status();
    let active_fp = status.ca.as_ref().map(|c| c.fingerprint.clone());
    let pending_fp = status.pending.as_ref().map(|c| c.fingerprint.clone());

    let mut hosts = Vec::new();
    let mut not_ready = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.revoked_at.is_some() {
            continue;
        }
        let push = internal_tls::host_push(host.id);
        let trusts = |fp: &Option<String>| match (&push, fp) {
            (Some(p), Some(fp)) => p.trusts(fp),
            _ => false,
        };
        let row = TlsHostRow {
            name: host.name.clone(),
            online: state.hosts.is_connected(host.id),
            status: push.as_ref().map(|p| p.status.clone()),
            detail: push.as_ref().map(|p| p.detail.clone()).unwrap_or_default(),
            trusts_active: trusts(&active_fp),
            trusts_pending: trusts(&pending_fp),
            when: push
                .as_ref()
                .map(|p| crate::common::format_in_tz(p.at, tz))
                .unwrap_or_default(),
        };
        let os_store = row.status.as_deref() == Some("unmanaged");
        if pending_fp.is_some() && !row.trusts_pending && !os_store {
            not_ready.push(host.name);
        }
        hosts.push(row);
    }

    let tpl = InternalTlsTemplate {
        base,
        tls: summary(tz),
        addresses: ca::format_addresses(&status.addresses),
        hosts,
        not_ready_for_activation: not_ready,
        message,
        error,
    };
    let jar = match new_cookie {
        Some(c) => jar.clone().add(c),
        None => jar.clone(),
    };
    Ok((jar, tpl).into_response())
}

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    render(&state, &jar, &ctx, None, None).await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct RotateForm {
    csrf_token: String,
    #[serde(default)]
    addresses: String,
}

#[derive(Deserialize)]
pub struct ActivateForm {
    csrf_token: String,
    #[serde(default)]
    confirm: String,
}

async fn audit(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
    outcome: AuditOutcome,
    metadata: serde_json::Value,
) -> Result<(), WebError> {
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, outcome)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("control_plane.tls")
            .metadata(metadata),
    )
    .await?;
    Ok(())
}

/// Renders the result of an action: success message, or the error -- after
/// auditing either way.
async fn finish(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    action: &str,
    result: anyhow::Result<String>,
) -> Result<Response, WebError> {
    match result {
        Ok(message) => {
            audit(
                state,
                ctx,
                AuditOutcome::Success,
                serde_json::json!({ "action": action }),
            )
            .await?;
            render(state, jar, ctx, Some(message), None).await
        }
        Err(e) => {
            let error = format!("{e:#}");
            audit(
                state,
                ctx,
                AuditOutcome::Failure,
                serde_json::json!({ "action": action, "error": error }),
            )
            .await?;
            render(state, jar, ctx, None, Some(error)).await
        }
    }
}

fn require_managed() -> Result<(), WebError> {
    if internal_tls::active_ca_pem().is_none() {
        return Err(AppError::Validation(
            "this control plane's TLS isn't managed here (no internal CA)".to_string(),
        )
        .into());
    }
    Ok(())
}

/// Sums up a push to every connected agent.
fn push_summary(results: &[(uuid::Uuid, internal_tls::HostPush)]) -> String {
    let count = |s: &str| results.iter().filter(|(_, p)| p.status == s).count();
    let ok = count("updated") + count("unchanged");
    let mut parts = vec![format!(
        "{ok} of {} connected agent(s) now trust it",
        results.len()
    )];
    if count("unmanaged") > 0 {
        parts.push(format!(
            "{} trust the OS store instead (update it via GPO)",
            count("unmanaged")
        ));
    }
    if count("too-old") > 0 {
        parts.push(format!("{} need 'Update agent' first", count("too-old")));
    }
    if count("failed") > 0 {
        parts.push(format!("{} failed", count("failed")));
    }
    parts.join("; ")
}

pub async fn renew(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    require_managed()?;
    let result = internal_tls::renew_server_cert(true).await.map(|info| {
        format!(
            "Issued a new server certificate (SHA-256 {}) and Caddy is serving it. Nothing \
             needs to be re-trusted.",
            internal_tls::grouped(&info.fingerprint)
        )
    });
    finish(&state, &jar, &ctx, "renew", result).await
}

pub async fn reload(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    require_managed()?;
    let result = internal_tls::reload_caddy()
        .await
        .map(|()| "Caddy reloaded the certificate files.".to_string());
    finish(&state, &jar, &ctx, "reload_caddy", result).await
}

pub async fn push(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    require_managed()?;
    let results = internal_tls::push_to_all(&state.hosts).await;
    let message = format!("Pushed the CA bundle: {}.", push_summary(&results));
    finish(&state, &jar, &ctx, "push_trust", Ok(message)).await
}

pub async fn rotate(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<RotateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    require_managed()?;
    let addresses = match ca::parse_addresses(&form.addresses) {
        Ok(a) => a,
        Err(e) => return render(&state, &jar, &ctx, None, Some(format!("{e:#}"))).await,
    };
    let result = match internal_tls::begin_rotation(&addresses).await {
        Ok(info) => {
            let results = internal_tls::push_to_all(&state.hosts).await;
            Ok(format!(
                "Created a new CA for {} (SHA-256 {}). It's pending: the server still uses the \
                 current CA. Pushed both to agents: {}. Distribute the new CA to anything else \
                 that trusts the old one (GPO, admin browsers), then activate it.",
                ca::format_addresses(&addresses),
                internal_tls::grouped(&info.fingerprint),
                push_summary(&results)
            ))
        }
        Err(e) => Err(e),
    };
    finish(&state, &jar, &ctx, "begin_rotation", result).await
}

pub async fn cancel_rotation(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    require_managed()?;
    let result = match internal_tls::cancel_rotation().await {
        Ok(()) => {
            let results = internal_tls::push_to_all(&state.hosts).await;
            Ok(format!(
                "Rotation cancelled; the pending CA is deleted. Agents were sent the current CA \
                 alone: {}.",
                push_summary(&results)
            ))
        }
        Err(e) => Err(e),
    };
    finish(&state, &jar, &ctx, "cancel_rotation", result).await
}

pub async fn activate_rotation(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ActivateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    require_managed()?;
    if form.confirm.trim() != "activate" {
        return render(
            &state,
            &jar,
            &ctx,
            None,
            Some("Type \"activate\" to confirm switching to the new CA.".to_string()),
        )
        .await;
    }
    let result = match internal_tls::activate_rotation().await {
        Ok(info) => {
            // Agents reconnect through the new CA (they already trust it);
            // now drop the old one from their bundle.
            let results = internal_tls::push_to_all(&state.hosts).await;
            Ok(format!(
                "The new CA (SHA-256 {}) is active and Caddy is serving a certificate from it. \
                 Agents were sent the new CA alone: {}. New install commands on /admin/hosts \
                 carry the new fingerprint.",
                internal_tls::grouped(&info.fingerprint),
                push_summary(&results)
            ))
        }
        Err(e) => Err(e),
    };
    finish(&state, &jar, &ctx, "activate_rotation", result).await
}

/// The pending CA, for distributing (GPO, browsers) before activation.
/// Authenticated, unlike `/ca.crt`: it isn't what the server presents yet.
pub async fn pending_ca(CurrentUser(ctx): CurrentUser) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    let pem = internal_tls::pending_ca_pem().ok_or(AppError::NotFound)?;
    Ok((
        [
            (CONTENT_TYPE, "application/x-pem-file"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"abyssal-arsenal-ca-next.pem\"",
            ),
        ],
        pem,
    )
        .into_response())
}
