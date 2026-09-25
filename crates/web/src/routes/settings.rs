use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES, APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
    AUDIT_SYSLOG_EXPORT_ENABLED, HIGH_RISK_STORAGE_OPS_ENABLED, HOST_ISOLATION_ENABLED,
    PANOPTICON_ARP_ENABLED, PANOPTICON_ARP_INTERFACE, PANOPTICON_MDNS_ENABLED,
    PANOPTICON_SWEEP_ENABLED, PANOPTICON_SWEEP_TARGET, PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS,
    PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS, PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS,
    PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS, PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS,
    PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS, PUBLIC_REGISTRATION_ENABLED,
    THANATOS_ALERT_RECIPIENTS, THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED,
    THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED, THANATOS_CORRELATION_THRESHOLD,
    THANATOS_CORRELATION_THRESHOLD_DEFAULT, THANATOS_CORRELATION_WINDOW_MINUTES,
    THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT, THANATOS_EXTRA_FIM_PATHS,
    THANATOS_MONITORING_ENABLED, THANATOS_SWEEP_INTERVAL_SECONDS,
    THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT,
};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, SettingsTemplate};
use crate::theme;

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;

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
    let public_registration_enabled =
        repo::settings::get_bool(&state.pool, PUBLIC_REGISTRATION_ENABLED, false).await?;
    let apotheosis_elevation_window_minutes = repo::settings::get_u32(
        &state.pool,
        APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
        APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES,
    )
    .await?;
    let high_risk_storage_ops_enabled =
        repo::settings::get_bool(&state.pool, HIGH_RISK_STORAGE_OPS_ENABLED, false).await?;
    let host_isolation_enabled =
        repo::settings::get_bool(&state.pool, HOST_ISOLATION_ENABLED, false).await?;
    let thanatos_monitoring_enabled =
        repo::settings::get_bool(&state.pool, THANATOS_MONITORING_ENABLED, false).await?;
    let thanatos_alert_recipients =
        repo::settings::get_string(&state.pool, THANATOS_ALERT_RECIPIENTS, "").await?;
    let thanatos_extra_fim_paths =
        repo::settings::get_string(&state.pool, THANATOS_EXTRA_FIM_PATHS, "").await?;
    let thanatos_auto_quarantine_ssh_keys_enabled = repo::settings::get_bool(
        &state.pool,
        THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED,
        false,
    )
    .await?;
    let thanatos_auto_disable_account_enabled =
        repo::settings::get_bool(&state.pool, THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED, false).await?;
    let thanatos_correlation_threshold = repo::settings::get_u32(
        &state.pool,
        THANATOS_CORRELATION_THRESHOLD,
        THANATOS_CORRELATION_THRESHOLD_DEFAULT,
    )
    .await?;
    let thanatos_correlation_window_minutes = repo::settings::get_u32(
        &state.pool,
        THANATOS_CORRELATION_WINDOW_MINUTES,
        THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT,
    )
    .await?;
    let thanatos_sweep_interval_seconds = repo::settings::get_u32(
        &state.pool,
        THANATOS_SWEEP_INTERVAL_SECONDS,
        THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT,
    )
    .await?;
    let panopticon_sweep_enabled =
        repo::settings::get_bool(&state.pool, PANOPTICON_SWEEP_ENABLED, false).await?;
    let panopticon_sweep_target =
        repo::settings::get_string(&state.pool, PANOPTICON_SWEEP_TARGET, "").await?;
    let panopticon_mdns_enabled =
        repo::settings::get_bool(&state.pool, PANOPTICON_MDNS_ENABLED, false).await?;
    let panopticon_arp_enabled =
        repo::settings::get_bool(&state.pool, PANOPTICON_ARP_ENABLED, false).await?;
    let panopticon_arp_interface =
        repo::settings::get_string(&state.pool, PANOPTICON_ARP_INTERFACE, "").await?;
    let panopticon_traffic_raw_retention_days = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS,
    )
    .await?;
    let panopticon_traffic_hourly_retention_days = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS,
    )
    .await?;
    let panopticon_traffic_daily_retention_days = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS,
    )
    .await?;
    let audit_syslog_export_enabled =
        repo::settings::get_bool(&state.pool, AUDIT_SYSLOG_EXPORT_ENABLED, false).await?;

    let tpl = SettingsTemplate {
        base,
        public_registration_enabled,
        apotheosis_elevation_window_minutes,
        high_risk_storage_ops_enabled,
        host_isolation_enabled,
        thanatos_monitoring_enabled,
        thanatos_alert_recipients,
        thanatos_extra_fim_paths,
        thanatos_auto_quarantine_ssh_keys_enabled,
        thanatos_auto_disable_account_enabled,
        thanatos_correlation_threshold,
        thanatos_correlation_window_minutes,
        thanatos_sweep_interval_seconds,
        panopticon_sweep_enabled,
        panopticon_sweep_target,
        panopticon_mdns_enabled,
        panopticon_arp_enabled,
        panopticon_arp_interface,
        panopticon_traffic_raw_retention_days,
        panopticon_traffic_hourly_retention_days,
        panopticon_traffic_daily_retention_days,
        audit_syslog_export_enabled,
        message: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RegistrationForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_registration(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<RegistrationForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        PUBLIC_REGISTRATION_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(PUBLIC_REGISTRATION_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct HighRiskStorageOpsForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_high_risk_storage_ops(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<HighRiskStorageOpsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        HIGH_RISK_STORAGE_OPS_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(HIGH_RISK_STORAGE_OPS_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct HostIsolationForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_host_isolation(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<HostIsolationForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        HOST_ISOLATION_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(HOST_ISOLATION_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ThanatosMonitoringForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_thanatos_monitoring(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosMonitoringForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        THANATOS_MONITORING_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(THANATOS_MONITORING_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ThanatosAutoQuarantineSshKeysForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_thanatos_auto_quarantine_ssh_keys(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosAutoQuarantineSshKeysForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ThanatosAutoDisableAccountForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_thanatos_auto_disable_account(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosAutoDisableAccountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct AuditSyslogExportForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_audit_syslog_export(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<AuditSyslogExportForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        AUDIT_SYSLOG_EXPORT_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(AUDIT_SYSLOG_EXPORT_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

fn validate_recipients(raw: &str) -> Result<String, WebError> {
    let cleaned: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for r in &cleaned {
        if r.len() > 254
            || !r.contains('@')
            || r.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(WebError(AppError::Validation(format!(
                "\"{r}\" doesn't look like a valid email address."
            ))));
        }
    }
    Ok(cleaned.join(","))
}

#[derive(Deserialize)]
pub struct ThanatosAlertRecipientsForm {
    csrf_token: String,
    #[serde(default)]
    recipients: String,
}

pub async fn set_thanatos_alert_recipients(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosAlertRecipientsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let recipients = validate_recipients(&form.recipients)?;

    repo::settings::set(
        &state.pool,
        THANATOS_ALERT_RECIPIENTS,
        serde_json::json!(recipients),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(THANATOS_ALERT_RECIPIENTS),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

/// Each non-empty entry must be a syntactically valid absolute path for
/// *at least one* platform (Unix or Windows) -- a mixed fleet's admin
/// can legitimately want both kinds of path in one list, so this
/// doesn't reject a Windows-shaped path just because it fails the Unix
/// validator or vice versa. `thanatos_ops::extra_fim_paths_for` is what
/// actually decides which entries apply to which host at scan time --
/// this is just a save-time sanity check against obvious typos/garbage.
fn validate_extra_fim_paths(raw: &str) -> Result<String, WebError> {
    let cleaned = crate::thanatos_ops::parse_extra_fim_paths(raw);
    for path in &cleaned {
        if !abyssal_agent_protocol::is_valid_absolute_path(path)
            && !abyssal_agent_protocol::is_valid_windows_absolute_path(path)
        {
            return Err(WebError(AppError::Validation(format!(
                "\"{path}\" doesn't look like a valid absolute path on either Linux or Windows."
            ))));
        }
    }
    // Newline-joined (not comma-joined, unlike `validate_recipients`'s
    // single-line input) so it round-trips cleanly through the
    // multi-line textarea this setting is edited in -- `parse_extra_fim_
    // paths` accepts either separator on the way back in either way.
    Ok(cleaned.join("\n"))
}

#[derive(Deserialize)]
pub struct ThanatosExtraFimPathsForm {
    csrf_token: String,
    #[serde(default)]
    paths: String,
}

pub async fn set_thanatos_extra_fim_paths(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosExtraFimPathsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let paths = validate_extra_fim_paths(&form.paths)?;

    repo::settings::set(
        &state.pool,
        THANATOS_EXTRA_FIM_PATHS,
        serde_json::json!(paths),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(THANATOS_EXTRA_FIM_PATHS),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ThanatosCorrelationForm {
    csrf_token: String,
    threshold: u32,
    window_minutes: u32,
    sweep_interval_seconds: u32,
}

/// One form, three related tunables -- the correlation threshold/window
/// (`thanatos_ops::check_and_raise_alert`) and the unattended sweep's own
/// poll interval (`spawn_thanatos_sweep`). Grouped together since they're
/// all "how sensitive/how often" knobs for the same detection pipeline,
/// same reasoning as `set_panopticon_traffic_retention`'s single form for
/// three retention settings.
pub async fn set_thanatos_correlation(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosCorrelationForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.threshold == 0 || form.threshold > 1000 {
        return Err(WebError(AppError::Validation(
            "Correlation threshold must be between 1 and 1000 events.".into(),
        )));
    }
    if form.window_minutes == 0 || form.window_minutes > 1440 {
        return Err(WebError(AppError::Validation(
            "Correlation window must be between 1 and 1440 minutes (24 hours).".into(),
        )));
    }
    if form.sweep_interval_seconds < 10 || form.sweep_interval_seconds > 3600 {
        return Err(WebError(AppError::Validation(
            "Sweep interval must be between 10 and 3600 seconds.".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        THANATOS_CORRELATION_THRESHOLD,
        serde_json::json!(form.threshold),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        THANATOS_CORRELATION_WINDOW_MINUTES,
        serde_json::json!(form.window_minutes),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        THANATOS_SWEEP_INTERVAL_SECONDS,
        serde_json::json!(form.sweep_interval_seconds),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("thanatos.correlation")
            .metadata(serde_json::json!({
                "threshold": form.threshold,
                "window_minutes": form.window_minutes,
                "sweep_interval_seconds": form.sweep_interval_seconds,
            })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct PanopticonSweepEnabledForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_panopticon_sweep_enabled(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonSweepEnabledForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        PANOPTICON_SWEEP_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(PANOPTICON_SWEEP_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct PanopticonSweepTargetForm {
    csrf_token: String,
    #[serde(default)]
    target: String,
}

pub async fn set_panopticon_sweep_target(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonSweepTargetForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let target = form.target.trim();
    if !target.is_empty() && !abyssal_agent_protocol::is_valid_network_target(target) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid IP address, CIDR range, or hostname.".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        PANOPTICON_SWEEP_TARGET,
        serde_json::json!(target),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(PANOPTICON_SWEEP_TARGET),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ElevationWindowForm {
    csrf_token: String,
    minutes: u32,
}

pub async fn set_elevation_window(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ElevationWindowForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !(1..=1440).contains(&form.minutes) {
        return Err(WebError(AppError::Validation(
            "Elevation window must be between 1 and 1440 minutes.".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
        serde_json::json!(form.minutes),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(APOTHEOSIS_ELEVATION_WINDOW_MINUTES)
            .metadata(serde_json::json!({ "minutes": form.minutes })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct PanopticonMdnsEnabledForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_panopticon_mdns_enabled(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonMdnsEnabledForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        PANOPTICON_MDNS_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(PANOPTICON_MDNS_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct PanopticonArpEnabledForm {
    csrf_token: String,
    enabled: bool,
}

pub async fn set_panopticon_arp_enabled(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonArpEnabledForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        PANOPTICON_ARP_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(PANOPTICON_ARP_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct PanopticonArpInterfaceForm {
    csrf_token: String,
    #[serde(default)]
    interface: String,
}

pub async fn set_panopticon_arp_interface(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonArpInterfaceForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let interface = form.interface.trim();
    if interface.len() > 64 || interface.chars().any(char::is_whitespace) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid interface name.".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        PANOPTICON_ARP_INTERFACE,
        serde_json::json!(interface),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(PANOPTICON_ARP_INTERFACE),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct PanopticonTrafficRetentionForm {
    csrf_token: String,
    raw_days: u32,
    hourly_days: u32,
    daily_days: u32,
}

/// One form, three retention settings -- they're conceptually a single
/// "how much bandwidth history to keep" decision (see
/// `abyssal_core::settings::PANOPTICON_TRAFFIC_*_RETENTION_DAYS`'s own
/// doc comments for what `0` means for the hourly/daily tiers), so
/// there's no reason to split them across separate forms/handlers the
/// way the enabled-toggle settings above are.
pub async fn set_panopticon_traffic_retention(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonTrafficRetentionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SettingsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.raw_days < crate::panopticon_traffic::MIN_RAW_RETENTION_DAYS || form.raw_days > 3650 {
        return Err(WebError(AppError::Validation(format!(
            "Raw retention must be between {} and 3650 days -- the daily rollup needs at \
             least a full day of raw data still on hand when it runs.",
            crate::panopticon_traffic::MIN_RAW_RETENTION_DAYS
        ))));
    }
    if form.hourly_days > 3650 || form.daily_days > 3650 {
        return Err(WebError(AppError::Validation(
            "Retention can't exceed 3650 days.".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS,
        serde_json::json!(form.raw_days),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS,
        serde_json::json!(form.hourly_days),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS,
        serde_json::json!(form.daily_days),
        Some(ctx.user.id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource("panopticon.traffic_retention")
            .metadata(serde_json::json!({
                "raw_days": form.raw_days,
                "hourly_days": form.hourly_days,
                "daily_days": form.daily_days,
            })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}
