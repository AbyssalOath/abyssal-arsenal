use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::{
    APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES, APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
    AUDIT_SYSLOG_EXPORT_ENABLED, HIGH_RISK_STORAGE_OPS_ENABLED, HOST_ISOLATION_ENABLED,
    PANOPTICON_ARP_ENABLED, PANOPTICON_ARP_INTERFACE, PANOPTICON_ENFORCEMENT_ENABLED,
    PANOPTICON_ENFORCEMENT_REVERT_MINUTES, PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT,
    PANOPTICON_MDNS_ENABLED, PANOPTICON_QUARANTINE_VLAN, PANOPTICON_QUARANTINE_VLAN_DEFAULT,
    PANOPTICON_ROGUE_ALERT_ENABLED, PANOPTICON_ROGUE_ALERT_RECIPIENTS, PANOPTICON_SWEEP_ENABLED,
    PANOPTICON_SWEEP_TARGET, PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS,
    PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS, PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS,
    PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS, PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS,
    PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS, PUBLIC_REGISTRATION_ENABLED,
    SCOURGE_CAPTURE_ENABLED, SCOURGE_CONFIG_CHANGES_ENABLED, SCOURGE_EVENT_RETENTION_DAYS,
    SCOURGE_EVENT_RETENTION_DAYS_DEFAULT, SCOURGE_IPS_ENABLED, SCOURGE_MIN_FORWARD_SEVERITY,
    SCOURGE_MIN_FORWARD_SEVERITY_DEFAULT, SCOURGE_MONITORING_ENABLED, SCOURGE_PCAP_MAX_TOTAL_MB,
    SCOURGE_PCAP_MAX_TOTAL_MB_DEFAULT, SCOURGE_PCAP_RETENTION_DAYS,
    SCOURGE_PCAP_RETENTION_DAYS_DEFAULT, SCOURGE_SWEEP_SECONDS, SCOURGE_SWEEP_SECONDS_DEFAULT,
    THANATOS_ALERT_RECIPIENTS, THANATOS_AUTO_DISABLE_ACCOUNT_ENABLED,
    THANATOS_AUTO_QUARANTINE_SSH_KEYS_ENABLED, THANATOS_C2_PORTS, THANATOS_C2_PORTS_DEFAULT,
    THANATOS_CORRELATION_THRESHOLD, THANATOS_CORRELATION_THRESHOLD_DEFAULT,
    THANATOS_CORRELATION_WINDOW_MINUTES, THANATOS_CORRELATION_WINDOW_MINUTES_DEFAULT,
    THANATOS_EVENT_RETENTION_DAYS, THANATOS_EVENT_RETENTION_DAYS_DEFAULT, THANATOS_EXTRA_FIM_PATHS,
    THANATOS_FAST_SWEEP_SECONDS, THANATOS_FAST_SWEEP_SECONDS_DEFAULT, THANATOS_MONITORING_ENABLED,
    THANATOS_SWEEP_INTERVAL_SECONDS, THANATOS_SWEEP_INTERVAL_SECONDS_DEFAULT,
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

/// Which parts of `/admin/settings` a user may see and change -- each
/// setting is owned by the role that runs what it controls, gated by that
/// domain's permission (the same one its POST handler checks), so Network
/// Admin manages Panopticon's, Security Admin Thanatos's, and so on. The page
/// itself is open to anyone who can see at least one part.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SettingsAccess {
    /// Public registration: who can get an account on this control plane.
    pub registration: bool,
    /// Email (SMTP) test: sends real mail from the organization's mailbox
    /// to any address, so `settings.manage` only.
    pub email_test: bool,
    /// Apotheosis elevation window.
    pub elevation: bool,
    /// Ossuary's high-risk storage operations.
    pub storage_ops: bool,
    /// Inquest's host network isolation.
    pub host_isolation: bool,
    /// Data sanitization policy (witness sign-off for shreds).
    pub sanitization: bool,
    pub thanatos: bool,
    /// Panopticon's sweep, alerts, passive discovery and bandwidth history.
    pub panopticon: bool,
    /// Panopticon's NAC enforcement kill-switch.
    pub nac: bool,
    /// Audit trail syslog export: `audit.export` only (Security Admin) --
    /// whoever is audited mustn't be able to stop their actions reaching
    /// the SIEM.
    pub audit_export: bool,
    /// Scourge (IDS/IPS): sweep, config/ruleset-change and capture gates.
    pub scourge: bool,
}

impl SettingsAccess {
    pub fn for_ctx(ctx: &abyssal_rbac::AuthContext) -> Self {
        Self {
            registration: ctx.has(Permission::SettingsManage),
            email_test: ctx.has(Permission::SettingsManage),
            elevation: ctx.has(Permission::HostsManage),
            storage_ops: ctx.has(Permission::StorageManage),
            host_isolation: ctx.has(Permission::IncidentsRespond),
            sanitization: ctx.has(Permission::SecurityManage),
            thanatos: ctx.has(Permission::SecurityManage),
            panopticon: ctx.has(Permission::NetworkManage),
            nac: ctx.has(Permission::NetworkNac),
            audit_export: ctx.has(Permission::AuditExport),
            scourge: ctx.has(Permission::ScourgeManage),
        }
    }

    pub fn any(&self) -> bool {
        *self != Self::default()
    }

    /// The "Elevation & Risk Controls" section has something to show.
    pub fn risk_controls(&self) -> bool {
        self.elevation || self.storage_ops || self.host_isolation
    }

    /// The Panopticon section has something to show.
    pub fn network(&self) -> bool {
        self.panopticon || self.nac
    }
}

pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    render(&state, jar, &ctx, None).await
}

async fn render(
    state: &AppState,
    jar: CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    email_test: Option<crate::templates::EmailTestResult>,
) -> Result<Response, WebError> {
    let (state, ctx) = (state.clone(), ctx.clone());
    let access = SettingsAccess::for_ctx(&ctx);
    if !access.any() {
        return Err(WebError(AppError::Forbidden));
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
    let sanitization_require_witness = repo::settings::get_bool(
        &state.pool,
        crate::common::SANITIZATION_REQUIRE_WITNESS,
        false,
    )
    .await?;
    let host_isolation_enabled =
        repo::settings::get_bool(&state.pool, HOST_ISOLATION_ENABLED, false).await?;
    let thanatos_monitoring_enabled =
        repo::settings::get_bool(&state.pool, THANATOS_MONITORING_ENABLED, false).await?;
    let thanatos_alert_recipients =
        repo::settings::get_string(&state.pool, THANATOS_ALERT_RECIPIENTS, "").await?;
    let thanatos_extra_fim_paths =
        repo::settings::get_string(&state.pool, THANATOS_EXTRA_FIM_PATHS, "").await?;
    let thanatos_c2_ports =
        repo::settings::get_string(&state.pool, THANATOS_C2_PORTS, THANATOS_C2_PORTS_DEFAULT)
            .await?;
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
    let thanatos_event_retention_days = repo::settings::get_u32(
        &state.pool,
        THANATOS_EVENT_RETENTION_DAYS,
        THANATOS_EVENT_RETENTION_DAYS_DEFAULT,
    )
    .await?;
    let thanatos_fast_sweep_seconds = repo::settings::get_u32(
        &state.pool,
        THANATOS_FAST_SWEEP_SECONDS,
        THANATOS_FAST_SWEEP_SECONDS_DEFAULT,
    )
    .await?;
    let panopticon_sweep_enabled =
        repo::settings::get_bool(&state.pool, PANOPTICON_SWEEP_ENABLED, false).await?;
    let panopticon_rogue_alert_enabled =
        repo::settings::get_bool(&state.pool, PANOPTICON_ROGUE_ALERT_ENABLED, false).await?;
    let panopticon_rogue_alert_recipients =
        repo::settings::get_string(&state.pool, PANOPTICON_ROGUE_ALERT_RECIPIENTS, "").await?;
    let panopticon_enforcement_enabled =
        repo::settings::get_bool(&state.pool, PANOPTICON_ENFORCEMENT_ENABLED, false).await?;
    let panopticon_quarantine_vlan = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_QUARANTINE_VLAN,
        PANOPTICON_QUARANTINE_VLAN_DEFAULT,
    )
    .await?;
    let panopticon_enforcement_revert_minutes = repo::settings::get_u32(
        &state.pool,
        PANOPTICON_ENFORCEMENT_REVERT_MINUTES,
        PANOPTICON_ENFORCEMENT_REVERT_MINUTES_DEFAULT,
    )
    .await?;
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
    let scourge_monitoring_enabled =
        repo::settings::get_bool(&state.pool, SCOURGE_MONITORING_ENABLED, false).await?;
    let scourge_sweep_seconds = repo::settings::get_u32(
        &state.pool,
        SCOURGE_SWEEP_SECONDS,
        SCOURGE_SWEEP_SECONDS_DEFAULT,
    )
    .await?;
    let scourge_event_retention_days = repo::settings::get_u32(
        &state.pool,
        SCOURGE_EVENT_RETENTION_DAYS,
        SCOURGE_EVENT_RETENTION_DAYS_DEFAULT,
    )
    .await?;
    let scourge_min_forward_severity = repo::settings::get_string(
        &state.pool,
        SCOURGE_MIN_FORWARD_SEVERITY,
        SCOURGE_MIN_FORWARD_SEVERITY_DEFAULT,
    )
    .await?;
    let scourge_config_changes_enabled =
        repo::settings::get_bool(&state.pool, SCOURGE_CONFIG_CHANGES_ENABLED, false).await?;
    let scourge_capture_enabled =
        repo::settings::get_bool(&state.pool, SCOURGE_CAPTURE_ENABLED, false).await?;
    let scourge_ips_enabled =
        repo::settings::get_bool(&state.pool, SCOURGE_IPS_ENABLED, false).await?;
    let scourge_pcap_retention_days = repo::settings::get_u32(
        &state.pool,
        SCOURGE_PCAP_RETENTION_DAYS,
        SCOURGE_PCAP_RETENTION_DAYS_DEFAULT,
    )
    .await?;
    let scourge_pcap_max_total_mb = repo::settings::get_u32(
        &state.pool,
        SCOURGE_PCAP_MAX_TOTAL_MB,
        SCOURGE_PCAP_MAX_TOTAL_MB_DEFAULT,
    )
    .await?;

    let tpl = SettingsTemplate {
        base,
        access,
        public_registration_enabled,
        apotheosis_elevation_window_minutes,
        high_risk_storage_ops_enabled,
        host_isolation_enabled,
        sanitization_require_witness,
        thanatos_monitoring_enabled,
        thanatos_alert_recipients,
        thanatos_extra_fim_paths,
        thanatos_c2_ports,
        thanatos_auto_quarantine_ssh_keys_enabled,
        thanatos_auto_disable_account_enabled,
        thanatos_correlation_threshold,
        thanatos_correlation_window_minutes,
        thanatos_sweep_interval_seconds,
        thanatos_fast_sweep_seconds,
        thanatos_event_retention_days,
        panopticon_sweep_enabled,
        panopticon_rogue_alert_enabled,
        panopticon_rogue_alert_recipients,
        panopticon_enforcement_enabled,
        panopticon_quarantine_vlan,
        panopticon_enforcement_revert_minutes,
        panopticon_sweep_target,
        panopticon_mdns_enabled,
        panopticon_arp_enabled,
        panopticon_arp_interface,
        panopticon_traffic_raw_retention_days,
        panopticon_traffic_hourly_retention_days,
        panopticon_traffic_daily_retention_days,
        audit_syslog_export_enabled,
        scourge_monitoring_enabled,
        scourge_sweep_seconds,
        scourge_event_retention_days,
        scourge_min_forward_severity,
        scourge_config_changes_enabled,
        scourge_capture_enabled,
        scourge_ips_enabled,
        scourge_pcap_retention_days,
        scourge_pcap_max_total_mb,
        message: None,
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
    abyssal_rbac::ensure(&ctx, Permission::StorageManage)?;
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
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
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
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
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
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
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
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
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

#[derive(Deserialize)]
pub struct ScourgeMonitoringForm {
    csrf_token: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    sweep_seconds: u32,
    #[serde(default)]
    event_retention_days: u32,
    #[serde(default)]
    min_forward_severity: String,
}

/// Scourge collection sweep settings: the monitoring toggle, sweep cadence,
/// cache retention, and the min severity forwarded into Thanatos.
pub async fn set_scourge_monitoring(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ScourgeMonitoringForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let min_forward = match form.min_forward_severity.as_str() {
        "low" | "medium" | "high" | "critical" => form.min_forward_severity.as_str(),
        _ => SCOURGE_MIN_FORWARD_SEVERITY_DEFAULT,
    };
    // Clamp the sweep interval to the agent-accepted range; 0 keeps the default.
    let sweep = if form.sweep_seconds == 0 {
        SCOURGE_SWEEP_SECONDS_DEFAULT
    } else {
        form.sweep_seconds.clamp(5, 60)
    };
    let uid = Some(ctx.user.id);
    repo::settings::set(
        &state.pool,
        SCOURGE_MONITORING_ENABLED,
        serde_json::json!(form.enabled),
        uid,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        SCOURGE_SWEEP_SECONDS,
        serde_json::json!(sweep),
        uid,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        SCOURGE_EVENT_RETENTION_DAYS,
        serde_json::json!(form.event_retention_days),
        uid,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        SCOURGE_MIN_FORWARD_SEVERITY,
        serde_json::json!(min_forward),
        uid,
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(SCOURGE_MONITORING_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled, "sweep_seconds": sweep })),
    )
    .await?;
    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ScourgeConfigChangesForm {
    csrf_token: String,
    #[serde(default)]
    enabled: bool,
}

/// The second gate allowing Scourge to change sensor config/rulesets.
pub async fn set_scourge_config_changes(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ScourgeConfigChangesForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    repo::settings::set(
        &state.pool,
        SCOURGE_CONFIG_CHANGES_ENABLED,
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
            .resource(SCOURGE_CONFIG_CHANGES_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;
    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ScourgeCaptureForm {
    csrf_token: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    pcap_retention_days: u32,
    #[serde(default)]
    pcap_max_total_mb: u32,
}

/// The packet-capture second gate + host-side pcap retention/size caps.
pub async fn set_scourge_capture(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ScourgeCaptureForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let uid = Some(ctx.user.id);
    repo::settings::set(
        &state.pool,
        SCOURGE_CAPTURE_ENABLED,
        serde_json::json!(form.enabled),
        uid,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        SCOURGE_PCAP_RETENTION_DAYS,
        serde_json::json!(form.pcap_retention_days),
        uid,
    )
    .await?;
    repo::settings::set(
        &state.pool,
        SCOURGE_PCAP_MAX_TOTAL_MB,
        serde_json::json!(form.pcap_max_total_mb),
        uid,
    )
    .await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(SCOURGE_CAPTURE_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;
    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ScourgeIpsForm {
    csrf_token: String,
    #[serde(default)]
    enabled: bool,
}

/// The inline-IPS second gate -- the highest-risk Scourge control. Off by
/// default; an admin must deliberately allow Scourge to switch a sensor inline
/// and promote signatures to drop/reject.
pub async fn set_scourge_ips(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ScourgeIpsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::ScourgeManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    repo::settings::set(
        &state.pool,
        SCOURGE_IPS_ENABLED,
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
            .resource(SCOURGE_IPS_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;
    Ok(Redirect::to("/admin/settings").into_response())
}

pub async fn set_audit_syslog_export(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<AuditSyslogExportForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::AuditExport)?;
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
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
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
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
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
pub struct ThanatosC2PortsForm {
    csrf_token: String,
    #[serde(default)]
    ports: String,
}

/// Saves `THANATOS_C2_PORTS` (the outbound-flagging port set). An all-blank
/// value is accepted and stored as empty -- that deliberately disables
/// port-based outbound flagging. A non-blank value that yields no valid port
/// is rejected (a typo shouldn't silently turn the feature off); otherwise the
/// value is normalized to a sorted, de-duplicated, comma-separated canonical
/// form so it round-trips cleanly.
pub async fn set_thanatos_c2_ports(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosC2PortsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let parsed = crate::thanatos_ops::parse_c2_ports(&form.ports);
    if parsed.is_empty() && !form.ports.trim().is_empty() {
        return Err(WebError(AppError::Validation(
            "No valid ports found. Enter comma-separated TCP port numbers (1-65535), or leave blank to disable outbound port flagging.".into(),
        )));
    }
    if parsed.len() > 256 {
        return Err(WebError(AppError::Validation(
            "Too many ports (max 256).".into(),
        )));
    }
    let canonical = parsed
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");

    repo::settings::set(
        &state.pool,
        THANATOS_C2_PORTS,
        serde_json::json!(canonical),
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
            .resource(THANATOS_C2_PORTS),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct ThanatosRetentionForm {
    csrf_token: String,
    retention_days: u32,
}

/// Saves `THANATOS_EVENT_RETENTION_DAYS` -- the SIEM event store's
/// data-lifecycle window. `0` disables pruning (keep everything); otherwise
/// bounded to a sane range so a typo can't silently keep one day or an absurd
/// span.
pub async fn set_thanatos_retention(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ThanatosRetentionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.retention_days > 3650 {
        return Err(WebError(AppError::Validation(
            "Retention must be between 0 (keep everything) and 3650 days.".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        THANATOS_EVENT_RETENTION_DAYS,
        serde_json::json!(form.retention_days),
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
            .resource(THANATOS_EVENT_RETENTION_DAYS),
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
    #[serde(default)]
    fast_sweep_seconds: u32,
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
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
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
    // Fast "act-now" sweep: 0 disables; otherwise 5-60s (clamped agent-side too).
    if form.fast_sweep_seconds != 0 && (form.fast_sweep_seconds < 5 || form.fast_sweep_seconds > 60)
    {
        return Err(WebError(AppError::Validation(
            "Fast sweep interval must be 0 (off) or between 5 and 60 seconds.".into(),
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
        THANATOS_FAST_SWEEP_SECONDS,
        serde_json::json!(form.fast_sweep_seconds),
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
                "fast_sweep_seconds": form.fast_sweep_seconds,
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
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
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
pub struct PanopticonRogueAlertForm {
    csrf_token: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    recipients: String,
}

/// NAC M1: the rogue-device alert toggle + recipient list in one form.
pub async fn set_panopticon_rogue_alerts(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonRogueAlertForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        PANOPTICON_ROGUE_ALERT_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        PANOPTICON_ROGUE_ALERT_RECIPIENTS,
        serde_json::json!(form.recipients.trim()),
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
            .resource(PANOPTICON_ROGUE_ALERT_ENABLED)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings").into_response())
}

#[derive(Deserialize)]
pub struct PanopticonEnforcementForm {
    csrf_token: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    quarantine_vlan: u32,
    #[serde(default)]
    revert_minutes: u32,
}

/// NAC M3: the global enforcement kill-switch, quarantine VLAN, and default
/// auto-revert timeout in one form. The VLAN is validated to a sane 802.1Q
/// range; `0` is accepted as "unset" (quarantine stays disabled).
pub async fn set_panopticon_enforcement(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<PanopticonEnforcementForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::NetworkNac)?;
    require_csrf(&jar, &form.csrf_token)?;

    // 802.1Q VLAN ids run 1..=4094; 0 means "unset". 4095 is reserved.
    if form.quarantine_vlan > 4094 {
        return Err(WebError(AppError::Validation(
            "Quarantine VLAN must be between 1 and 4094 (or 0 for unset).".into(),
        )));
    }

    repo::settings::set(
        &state.pool,
        PANOPTICON_ENFORCEMENT_ENABLED,
        serde_json::json!(form.enabled),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        PANOPTICON_QUARANTINE_VLAN,
        serde_json::json!(form.quarantine_vlan),
        Some(ctx.user.id),
    )
    .await?;
    repo::settings::set(
        &state.pool,
        PANOPTICON_ENFORCEMENT_REVERT_MINUTES,
        serde_json::json!(form.revert_minutes),
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
            .resource(PANOPTICON_ENFORCEMENT_ENABLED)
            .metadata(serde_json::json!({
                "enabled": form.enabled,
                "quarantine_vlan": form.quarantine_vlan,
                "revert_minutes": form.revert_minutes,
            })),
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
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    // Comma-separated IPs, CIDR ranges and/or hostnames; each one checked,
    // stored normalized ("a, b, c").
    let targets = crate::panopticon_ops::split_list(&form.target);
    if let Some(bad) = targets
        .iter()
        .find(|t| !abyssal_agent_protocol::is_valid_network_target(t))
    {
        return Err(WebError(AppError::Validation(format!(
            "\"{bad}\" doesn't look like a valid IP address, CIDR range, or hostname."
        ))));
    }
    let target = targets.join(", ");
    let target = target.as_str();

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
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
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
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
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
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
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
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    // Comma-separated: the listener captures on each one.
    let interfaces = crate::panopticon_ops::split_list(&form.interface);
    if let Some(bad) = interfaces
        .iter()
        .find(|i| i.len() > 64 || i.chars().any(char::is_whitespace))
    {
        return Err(WebError(AppError::Validation(format!(
            "\"{bad}\" doesn't look like a valid interface name."
        ))));
    }
    let interface = interfaces.join(", ");
    let interface = interface.as_str();

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
    abyssal_rbac::ensure(&ctx, Permission::NetworkManage)?;
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

#[derive(Deserialize)]
pub struct EmailTestForm {
    csrf_token: String,
    to: String,
}

/// Settings > Email: sends the test email (a Nietzsche quote, see
/// `NotificationMessage::test`) and shows the outcome -- with the SMTP server's own
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
                    "The test went to {to}. If it doesn't arrive, check that mailbox's junk \
                     folder and the sending mailbox's Sent Items."
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
            Err(abyssal_notifications::NotificationError::SendFailed(reason)) => {
                crate::templates::EmailTestResult {
                    ok: false,
                    detail: reason,
                }
            }
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
pub struct SanitizationWitnessForm {
    csrf_token: String,
    enabled: bool,
}

/// Settings > Data Sanitization: whether every shred deletion needs a
/// verified witness (`common::sanitization_sign_off`).
pub async fn set_sanitization_require_witness(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SanitizationWitnessForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::settings::set(
        &state.pool,
        crate::common::SANITIZATION_REQUIRE_WITNESS,
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
            .resource(crate::common::SANITIZATION_REQUIRE_WITNESS)
            .metadata(serde_json::json!({ "enabled": form.enabled })),
    )
    .await?;

    Ok(Redirect::to("/admin/settings#sanitization").into_response())
}
