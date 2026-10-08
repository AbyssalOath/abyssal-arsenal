//! The control-plane diagnostics page (`/admin/health`): readiness components
//! and background-task liveness in one pane, for operators. Gated by
//! `SettingsManage`. Reads only in-memory/aggregate state -- the same cheap
//! checks `/readyz` runs, plus the heartbeat registry.

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::Permission;
use abyssal_core::settings::{
    CONTROL_PLANE_ALERT_RECIPIENTS, CONTROL_PLANE_BACKUP_OVERDUE_HOURS,
    CONTROL_PLANE_BACKUP_OVERDUE_HOURS_DEFAULT, CONTROL_PLANE_CPU_THRESHOLD,
    CONTROL_PLANE_CPU_THRESHOLD_DEFAULT, CONTROL_PLANE_DISK_THRESHOLD,
    CONTROL_PLANE_DISK_THRESHOLD_DEFAULT, CONTROL_PLANE_MEM_THRESHOLD,
    CONTROL_PLANE_MEM_THRESHOLD_DEFAULT, CONTROL_PLANE_MONITORING_ENABLED,
};
use abyssal_database::repo;
use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::task_health::TaskBeat;
use crate::templates::{BaseCtx, HealthComponentRow, SystemHealthTemplate, TaskRow};
use crate::theme;

/// How many intervals late a task may be before it's flagged stale.
const STALE_GRACE: u32 = 3;
/// Percent thresholds are clamped into a sane range before storing.
const MIN_THRESHOLD: u32 = 1;
const MAX_THRESHOLD: u32 = 100;

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    render(&state, jar, &ctx, None).await
}

async fn render(
    state: &AppState,
    jar: CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    email_test: Option<crate::templates::EmailTestResult>,
) -> Result<Response, WebError> {
    let state = state.clone();
    let ctx = ctx.clone();
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

    let readiness = crate::health::readiness(&state).await;
    let ready = readiness.ok();
    let components = readiness
        .components
        .into_iter()
        .map(|c| HealthComponentRow {
            name: prettify(c.name),
            ok: c.ok,
            detail: c.detail,
        })
        .collect();

    let now = Utc::now();
    let snapshot = state.task_health.snapshot().await;
    let mut any_task_stale = false;
    let tasks: Vec<TaskRow> = snapshot
        .into_iter()
        .map(|(name, beat)| {
            let stale = beat.is_stale(now, STALE_GRACE);
            any_task_stale |= stale;
            task_row(name, &beat, now, stale)
        })
        .collect();

    let preflight = build_preflight(&state).await;

    let tls = crate::routes::internal_tls::summary(&ctx.user.timezone);

    let tpl = SystemHealthTemplate {
        base,
        tls,
        ready,
        components,
        tasks,
        any_task_stale,
        preflight,
        monitoring_enabled: repo::settings::get_bool(
            &state.pool,
            CONTROL_PLANE_MONITORING_ENABLED,
            false,
        )
        .await?,
        cpu_threshold: repo::settings::get_u32(
            &state.pool,
            CONTROL_PLANE_CPU_THRESHOLD,
            CONTROL_PLANE_CPU_THRESHOLD_DEFAULT,
        )
        .await?,
        mem_threshold: repo::settings::get_u32(
            &state.pool,
            CONTROL_PLANE_MEM_THRESHOLD,
            CONTROL_PLANE_MEM_THRESHOLD_DEFAULT,
        )
        .await?,
        disk_threshold: repo::settings::get_u32(
            &state.pool,
            CONTROL_PLANE_DISK_THRESHOLD,
            CONTROL_PLANE_DISK_THRESHOLD_DEFAULT,
        )
        .await?,
        backup_overdue_hours: repo::settings::get_u32(
            &state.pool,
            CONTROL_PLANE_BACKUP_OVERDUE_HOURS,
            CONTROL_PLANE_BACKUP_OVERDUE_HOURS_DEFAULT,
        )
        .await?,
        alert_recipients: repo::settings::get_string(
            &state.pool,
            CONTROL_PLANE_ALERT_RECIPIENTS,
            "",
        )
        .await?,
        email_configured: state.notifications.has_email(),
        email_test_default_to: ctx.user.email.clone(),
        email_test,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Preflight / DR-readiness advisories: configuration that's easy to leave
/// wrong and only bites later. Everything here reads cheap in-memory config or
/// does one small probe -- no secrets are exposed (only present/absent).
async fn build_preflight(state: &AppState) -> Vec<crate::templates::PreflightRow> {
    use crate::templates::PreflightRow;
    let row = |label: &str, ok: bool, detail: &str| PreflightRow {
        label: label.to_string(),
        ok,
        detail: detail.to_string(),
    };

    let mut rows = Vec::new();

    rows.push(row(
        "Encryption key",
        state.encryption_key.is_some(),
        if state.encryption_key.is_some() {
            "configured (ENCRYPTION_KEY set)"
        } else {
            "not set -- managed-switch credentials can't be stored"
        },
    ));

    let public_url_set = state
        .config
        .public_url
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty());
    rows.push(row(
        "Public URL",
        public_url_set,
        if public_url_set {
            "set -- outgoing email links resolve"
        } else {
            "unset -- password-reset emails fall back to a raw token"
        },
    ));

    rows.push(row(
        "Session cookie Secure",
        state.config.cookie_secure,
        if state.config.cookie_secure {
            "on -- cookies require HTTPS"
        } else {
            "off -- only safe for local plain-HTTP development"
        },
    ));

    let providers = state.notifications.provider_count();
    rows.push(row(
        "Notification providers",
        providers > 0,
        &format!(
            "{providers} configured; email (SMTP) {}",
            if state.notifications.has_email() {
                "on -- send a test below"
            } else {
                "off -- password resets and new-account emails won't be sent"
            }
        ),
    ));

    // Backup destination writability -- a real probe write, then cleaned up.
    let (writable, wdetail) = probe_backup_writable(state).await;
    rows.push(row("Backup destination", writable, &wdetail));

    // DR readiness: is there a recent successful backup?
    let last = repo::reliquary_backups::most_recent_backup_time(&state.pool)
        .await
        .ok()
        .flatten();
    let (dr_ok, dr_detail) = match last {
        Some(ts) => {
            let hours = (Utc::now() - ts).num_hours().max(0);
            (true, format!("last successful backup {hours} h ago"))
        }
        None => (false, "no successful backup recorded yet".to_string()),
    };
    rows.push(row("Backup recency", dr_ok, &dr_detail));

    rows
}

/// Probes whether the backup destination can be written to, by creating and
/// deleting a tiny marker file. Best-effort and self-cleaning.
async fn probe_backup_writable(state: &AppState) -> (bool, String) {
    const PROBE: &str = ".abyssal_healthcheck";
    match state.reliquary_backup_storage.open_write(PROBE).await {
        Ok(writer) => {
            drop(writer);
            let _ = state.reliquary_backup_storage.delete(PROBE).await;
            (true, "writable".to_string())
        }
        Err(_) => (false, "not writable -- backups will fail".to_string()),
    }
}

#[derive(Deserialize)]
pub struct EmailTestForm {
    csrf_token: String,
    to: String,
}

/// Sends a test email and shows the outcome -- with the SMTP server's own
/// error when it fails, which is otherwise only in the server log.
pub async fn send_test_email(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<EmailTestForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let to = form.to.trim().to_string();
    let result = if to.is_empty() {
        crate::templates::EmailTestResult {
            ok: false,
            detail: "Enter an address to send the test to.".to_string(),
        }
    } else {
        match state.notifications.send_test("smtp", &to).await {
            Ok(()) => crate::templates::EmailTestResult {
                ok: true,
                detail: format!(
                    "Sent to {to}. If it doesn't arrive, check that mailbox's junk folder \
                     and the sending mailbox's Sent Items."
                ),
            },
            Err(abyssal_notifications::NotificationError::NotConfigured) => {
                crate::templates::EmailTestResult {
                    ok: false,
                    detail: "Email isn't configured: set SMTP_HOST and SMTP_FROM (and \
                             SMTP_USERNAME/SMTP_PASSWORD) in .env, then restart the app. The \
                             app's startup log says why if they're set but rejected."
                        .to_string(),
                }
            }
            Err(e) => crate::templates::EmailTestResult {
                ok: false,
                detail: e.to_string(),
            },
        }
    };
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(
            AuditAction::ConfigurationChanged,
            if result.ok {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
        )
        .actor(Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource("notifications.smtp")
        .metadata(serde_json::json!({ "action": "test_email", "to": to })),
    )
    .await?;
    render(&state, jar, &ctx, Some(result)).await
}

#[derive(Deserialize)]
pub struct MonitoringForm {
    csrf_token: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    cpu_threshold: u32,
    #[serde(default)]
    mem_threshold: u32,
    #[serde(default)]
    disk_threshold: u32,
    #[serde(default)]
    backup_overdue_hours: u32,
    #[serde(default)]
    alert_recipients: String,
}

/// Saves the control-plane self-monitoring configuration. Thresholds are
/// clamped to `1..=100`; the sweep re-reads these settings each tick, so
/// changes take effect without a restart.
pub async fn set_monitoring(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<MonitoringForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let clamp = |v: u32| v.clamp(MIN_THRESHOLD, MAX_THRESHOLD);
    let pairs: [(&str, serde_json::Value); 6] = [
        (CONTROL_PLANE_MONITORING_ENABLED, form.enabled.into()),
        (
            CONTROL_PLANE_CPU_THRESHOLD,
            clamp(form.cpu_threshold).into(),
        ),
        (
            CONTROL_PLANE_MEM_THRESHOLD,
            clamp(form.mem_threshold).into(),
        ),
        (
            CONTROL_PLANE_DISK_THRESHOLD,
            clamp(form.disk_threshold).into(),
        ),
        (
            CONTROL_PLANE_BACKUP_OVERDUE_HOURS,
            form.backup_overdue_hours.into(),
        ),
        (
            CONTROL_PLANE_ALERT_RECIPIENTS,
            form.alert_recipients.trim().into(),
        ),
    ];
    for (key, value) in pairs {
        repo::settings::set(&state.pool, key, value, Some(ctx.user.id)).await?;
    }

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("control_plane.monitoring")
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/health").into_response())
}

fn task_row(name: &str, beat: &TaskBeat, now: DateTime<Utc>, stale: bool) -> TaskRow {
    TaskRow {
        label: prettify(name),
        last_run: match beat.last_run {
            Some(ts) => ago(now, ts),
            None => "never".to_string(),
        },
        last_ok: match beat.last_ok {
            Some(ts) => ago(now, ts),
            None => "never".to_string(),
        },
        stale,
        never_ran: beat.last_run.is_none(),
        runs: beat.run_count,
        last_error: beat.last_error.clone(),
    }
}

/// `"mortiscope_metrics_sweep"` -> `"Mortiscope metrics sweep"`.
fn prettify(key: impl AsRef<str>) -> String {
    let key = key.as_ref().replace('_', " ");
    let mut chars = key.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Compact relative age (`"12s ago"` / `"4m ago"` / `"2h ago"` / `"3d ago"`).
fn ago(now: DateTime<Utc>, then: DateTime<Utc>) -> String {
    let secs = (now - then).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3_600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3_600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prettify_humanizes_task_keys() {
        assert_eq!(prettify("health_sweep"), "Health sweep");
        assert_eq!(
            prettify("mortiscope_metrics_sweep"),
            "Mortiscope metrics sweep"
        );
        assert_eq!(prettify(""), "");
    }

    #[test]
    fn ago_scales_by_magnitude() {
        let now = Utc::now();
        assert_eq!(ago(now, now), "0s ago");
        assert_eq!(ago(now, now - chrono::Duration::seconds(90)), "1m ago");
        assert_eq!(ago(now, now - chrono::Duration::seconds(7200)), "2h ago");
        assert_eq!(ago(now, now - chrono::Duration::seconds(180_000)), "2d ago");
    }
}
