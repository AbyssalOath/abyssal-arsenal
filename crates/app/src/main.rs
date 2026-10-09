mod arsenals;
mod cli;
mod config;

use std::net::SocketAddr;
use std::sync::Arc;

use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_auth::LoginLimiter;
use abyssal_core::settings::{
    PANOPTICON_ARP_ENABLED, PANOPTICON_ARP_INTERFACE, PANOPTICON_MDNS_ENABLED,
};
use abyssal_database::DbPool;
use abyssal_database::repo;
use abyssal_execution::Executor;
use abyssal_hosts::{ElevationTracker, HostConnectionRegistry};
use abyssal_modules::ModuleRegistry;
use abyssal_notifications::{
    NotificationDispatcher, Severity as NotificationSeverity, SmtpProvider, SmtpSecurity,
    SyslogProvider, WebhookFlavor, WebhookProvider,
};
use abyssal_web::reliquary_backup::provider::NativeProvider;
use abyssal_web::reliquary_backup::restore::MaintenanceMode;
use abyssal_web::reliquary_backup::storage::LocalFs;
use abyssal_web::{AppState, WebConfig};
use abyssal_workflows::WorkflowRegistry;
use clap::{Parser, Subcommand};
use config::Config;
use std::time::Duration;

/// Disaster-recovery CLI lives on this same binary -- GitHub issue #9 --
/// so `docker compose run --rm app reliquary backup restore <path> ...`
/// works with nothing else to install. No subcommand (the default, and
/// everything before this feature) still just runs the server.
#[derive(Parser)]
#[command(name = "abyssal-arsenal")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Reliquary {
        #[command(subcommand)]
        action: cli::ReliquaryCommand,
    },
    /// Internal TLS (private CA) -- the same operations as
    /// /admin/health/tls, for when the web UI itself is unreachable:
    /// `docker compose exec app /app/abyssal-arsenal tls status`.
    Tls {
        #[command(subcommand)]
        action: cli::TlsCommand,
    },
    /// The agent install token (AAT) -- what install.sh prints at the end:
    /// `docker compose exec app /app/abyssal-arsenal aat show`.
    Aat {
        #[command(subcommand)]
        action: cli::AatCommand,
    },
    /// Enrolling an agent on this server itself -- what install.sh runs.
    ControlPlane {
        #[command(subcommand)]
        action: cli::ControlPlaneCommand,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Cli::parse().command {
        Some(Command::Reliquary { action }) => return cli::run(action).await,
        Some(Command::Tls { action }) => return cli::run_tls(action).await,
        Some(Command::Aat { action }) => return cli::run_aat(action).await,
        Some(Command::ControlPlane { action }) => return cli::run_control_plane(action).await,
        None => {}
    }

    let mut config = Config::from_env()?;

    let pool = abyssal_database::connect(&config.database_url).await?;
    abyssal_database::run_migrations(&pool).await?;
    abyssal_database::seed::seed_core_defaults(&pool).await?;
    // The agent install token (AAT) exists from the first start, so
    // install.sh can print it and /admin/hosts always has one to show.
    // Not fatal: one that can't be decrypted (ENCRYPTION_KEY changed) only
    // stops AAT enrollment until it's rotated on /admin/hosts.
    if let Err(e) = abyssal_web::aat::ensure(&pool, config.encryption_key.as_ref()).await {
        tracing::error!(error = %format!("{e:#}"), "agent install token (AAT) unavailable");
    }

    // GitHub issue #10: backfills `network` for any device row that
    // predates the column, or was somehow left `NULL` -- idempotent,
    // cheap when there's nothing to do (the common case after the first
    // startup post-upgrade).
    match abyssal_database::repo::network_devices::backfill_network(&pool).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "panopticon: backfilled device subnet groupings"),
        Err(e) => {
            tracing::error!(error = %e, "panopticon: failed to backfill device subnet groupings")
        }
    }

    let registry = ModuleRegistry::new(arsenals::all());
    registry.ensure_seeded(&pool).await?;

    // 30 minutes -- this is `Executor::execute`'s one shared timeout across
    // every in-process `Operation` it runs, which today means Panopticon's
    // two control-plane operations: the nmap discovery scan and the SNMP
    // switch poll (`execute_on_host`, used by every other arsenal's
    // host-agent dispatches, takes its own per-call timeout instead and
    // isn't affected by this). A short default was fine for a quick SNMP
    // poll but cut off a real nmap scan of anything larger than a small
    // subnet; the SNMP poll's own per-request timeouts
    // (`panopticon_snmp.rs::REQUEST_TIMEOUT`) still bound it far tighter
    // than this in practice, so raising this shared ceiling only helps the
    // scan, not harms the poll.
    let executor = Executor::new(pool.clone(), Duration::from_secs(30 * 60));
    let encryption_key = config.encryption_key.take().map(Arc::new);

    let backup_destination = std::env::var("RELIQUARY_BACKUP_DESTINATION_PATH")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            abyssal_core::settings::RELIQUARY_BACKUP_DEFAULT_DESTINATION_PATH.to_string()
        });
    let local_fs = LocalFs::new(&backup_destination);
    local_fs.ensure_root_exists().await?;
    let backup_storage: Arc<dyn abyssal_web::reliquary_backup::storage::StorageDestination> =
        Arc::new(local_fs);
    let backup_provider: Arc<dyn abyssal_web::reliquary_backup::provider::BackupProvider> =
        Arc::new(NativeProvider {
            pool: pool.clone(),
            database_url: config.database_url.clone(),
            work_dir: std::env::temp_dir(),
            arsenal_version: abyssal_web::update_check::CURRENT_VERSION
                .trim()
                .to_string(),
        });

    let interrupted = abyssal_web::reliquary_backup::orchestrator::recover_interrupted_jobs(&pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to sweep interrupted reliquary backup jobs");
            0
        });
    if interrupted > 0 {
        tracing::warn!(
            count = interrupted,
            "reliquary: marked backup job(s) left running by a previous crash/restart as failed"
        );
    }

    // Internal TLS (no public domain): create the CA / renew the server
    // certificate before serving, so Caddy -- which waits for this app to be
    // healthy -- always has a certificate to load. Failing here is fatal on
    // purpose: an internal install without a certificate serves nothing.
    match abyssal_web::internal_tls::ensure_at_startup().await {
        Ok(Some(message)) => tracing::info!("internal TLS: {message}"),
        Ok(None) => {}
        Err(e) => return Err(e.context("internal TLS setup failed")),
    }

    let state = AppState {
        pool,
        modules: Arc::new(registry),
        workflows: Arc::new(WorkflowRegistry::load_builtin()),
        config: Arc::new(WebConfig {
            session_cookie_name: config.session_cookie_name.clone(),
            session_ttl: chrono::Duration::hours(config.session_ttl_hours),
            cookie_secure: config.cookie_secure,
            public_url: config.public_url.clone(),
        }),
        login_limiter: Arc::new(LoginLimiter::default()),
        notifications: Arc::new(build_notifications(&config).await),
        hosts: Arc::new(HostConnectionRegistry::new()),
        executor: Arc::new(executor),
        elevation: Arc::new(ElevationTracker::new()),
        update_status: Arc::new(tokio::sync::RwLock::new(
            abyssal_web::update_check::UpdateStatus::current(),
        )),
        encryption_key: encryption_key.clone(),
        deploy_jobs: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        scan_jobs: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        scourge_capture_jobs: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        reliquary_backup_provider: backup_provider.clone(),
        reliquary_backup_storage: backup_storage.clone(),
        maintenance_mode: MaintenanceMode::default(),
        self_metrics: Arc::new(tokio::sync::RwLock::new(None)),
        task_health: abyssal_web::task_health::TaskHeartbeats::new(),
    };

    if let Err(e) = abyssal_web::control_plane::load(&state.pool, &state.hosts).await {
        // Fatal: starting without knowing which host is this server would
        // leave its agent unguarded.
        return Err(e.context("failed to load the control plane's own host"));
    }

    abyssal_web::reliquary_backup::orchestrator::spawn_scheduled_backup_loop(
        state.clone(),
        backup_provider,
    );

    spawn_elevation_expiry_sweep(
        state.pool.clone(),
        state.elevation.clone(),
        state.task_health.clone(),
    );
    abyssal_web::spawn_thanatos_sweep(state.clone());
    abyssal_web::spawn_thanatos_fast_sweep(state.clone());
    abyssal_web::spawn_thanatos_retention(state.clone());
    abyssal_web::spawn_scourge_sweep(state.clone());
    abyssal_web::spawn_scourge_retention(state.clone());
    abyssal_web::spawn_health_sweep(state.clone());
    abyssal_web::spawn_mortiscope_metrics_sweep(state.clone());
    abyssal_web::spawn_self_metrics_sampler(
        state.self_metrics.clone(),
        state.task_health.clone(),
        state.pool.clone(),
    );
    abyssal_web::spawn_update_check_sweep(state.clone());
    abyssal_web::spawn_self_monitor_sweep(state.clone());
    abyssal_web::spawn_internal_tls_sweep(state.clone());
    abyssal_web::spawn_panopticon_sweep(
        state.pool.clone(),
        state.task_health.clone(),
        state.notifications.clone(),
    );
    abyssal_web::spawn_panopticon_snmp_sweep(
        state.pool.clone(),
        encryption_key.clone(),
        state.task_health.clone(),
    );
    abyssal_web::spawn_panopticon_enforcement_revert(
        state.pool.clone(),
        encryption_key.clone(),
        state.task_health.clone(),
    );
    abyssal_web::spawn_panopticon_policy_sweep(
        state.pool.clone(),
        encryption_key.clone(),
        state.task_health.clone(),
    );
    abyssal_web::spawn_panopticon_radius(state.pool.clone(), encryption_key).await;
    abyssal_web::spawn_panopticon_traffic_rollup(state.pool.clone(), state.task_health.clone());
    spawn_panopticon_listeners(state.pool.clone(), state.notifications.clone()).await;
    abyssal_web::spawn_audit_syslog_sweep(
        state.pool.clone(),
        state.notifications.clone(),
        state.task_health.clone(),
    );

    let app = abyssal_web::build(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", config.port).parse()?;
    tracing::info!(%addr, "Abyssal Arsenal starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// The first background task in this codebase: everything else here is
/// request-driven. `ElevationTracker`'s own `is_elevated`/`snapshot` already
/// evict lapsed entries lazily (only when something happens to look), which
/// is fine for UI correctness but means a natural expiry with nothing else
/// touching that host would otherwise never get an audit record at all.
/// This loop is the one active, unconditional check, on a fixed interval
/// regardless of what else is happening.
fn spawn_elevation_expiry_sweep(
    pool: DbPool,
    elevation: Arc<ElevationTracker>,
    heartbeats: abyssal_web::task_health::TaskHeartbeats,
) {
    use abyssal_web::task_health::names;
    const INTERVAL_SECS: u64 = 60;
    tokio::spawn(async move {
        heartbeats
            .register(names::ELEVATION_EXPIRY_SWEEP, INTERVAL_SECS)
            .await;
        let mut interval = tokio::time::interval(Duration::from_secs(INTERVAL_SECS));
        loop {
            interval.tick().await;
            for (host_id, host_name) in elevation.sweep_expired() {
                let event =
                    AuditEvent::new(AuditAction::HostElevationExpired, AuditOutcome::Success)
                        .resource(&host_name)
                        .metadata(serde_json::json!({ "host_id": host_id.to_string() }));
                if let Err(e) = abyssal_audit::record(&pool, event).await {
                    tracing::error!(error = %e, "failed to write audit record for elevation expiry");
                }
            }
            heartbeats
                .ok(names::ELEVATION_EXPIRY_SWEEP, INTERVAL_SECS)
                .await;
        }
    });
}

/// Starts Panopticon's mDNS/ARP listeners if their settings say to --
/// checked once, here, at startup rather than on every tick the way the
/// sweep toggles are, since binding a socket (mDNS) or opening a raw
/// capture (ARP) is a real resource acquisition, not a soft setting.
/// Toggling either setting, or changing the ARP interface, therefore
/// takes a server restart to take effect, same as the syslog receiver
/// pattern this mirrors. A DB error reading either setting is treated as
/// "off" -- these are both opt-in features, so failing safe means not
/// starting them, not starting them unconditionally.
async fn spawn_panopticon_listeners(
    pool: DbPool,
    notifications: std::sync::Arc<NotificationDispatcher>,
) {
    let mdns_enabled = repo::settings::get_bool(&pool, PANOPTICON_MDNS_ENABLED, false)
        .await
        .unwrap_or(false);
    if mdns_enabled {
        abyssal_web::spawn_panopticon_mdns_listener(pool.clone(), notifications.clone());
    }

    let arp_enabled = repo::settings::get_bool(&pool, PANOPTICON_ARP_ENABLED, false)
        .await
        .unwrap_or(false);
    let arp_interface = repo::settings::get_string(&pool, PANOPTICON_ARP_INTERFACE, "")
        .await
        .unwrap_or_default();
    if arp_enabled {
        // Comma-separated: one listener per interface.
        for interface in abyssal_web::split_settings_list(&arp_interface) {
            abyssal_web::spawn_panopticon_arp_listener(
                pool.clone(),
                interface,
                notifications.clone(),
            );
        }
    }
}

async fn build_notifications(config: &Config) -> NotificationDispatcher {
    let mut dispatcher = NotificationDispatcher::new();

    match (&config.smtp_host, &config.smtp_from) {
        (Some(host), Some(from)) => {
            let username = config.smtp_username.as_deref().unwrap_or("");
            let password = config.smtp_password.as_deref().unwrap_or("");
            let provider = SmtpSecurity::from_setting(config.smtp_tls.as_deref(), config.smtp_port)
                .and_then(|security| {
                    SmtpProvider::new(host, config.smtp_port, security, username, password, from)
                        .map(|p| (p, security))
                });
            match provider {
                Ok((provider, security)) => {
                    tracing::info!(
                        host = %host,
                        port = config.smtp_port,
                        tls = security.as_str(),
                        authenticated = !username.is_empty(),
                        "SMTP email configured -- send a test from /admin/health"
                    );
                    dispatcher.register(Box::new(provider));
                }
                Err(e) => tracing::error!(error = %format!("{e:#}"), "SMTP email not configured"),
            }
        }
        (Some(_), None) => tracing::warn!(
            "SMTP_HOST is set but SMTP_FROM isn't -- email is disabled until both are set"
        ),
        (None, Some(_)) => tracing::warn!(
            "SMTP_FROM is set but SMTP_HOST isn't -- email is disabled until both are set"
        ),
        (None, None) => {}
    }

    if let Some(host) = &config.syslog_host {
        match SyslogProvider::new(host, config.syslog_port, &config.syslog_app_name).await {
            Ok(provider) => dispatcher.register(Box::new(provider)),
            Err(e) => tracing::warn!(error = %e, "syslog notification provider not configured"),
        }
    }

    // Chat / webhook providers (M5). Each registers only if its URL is set.
    // `min_severity` defaults to `warning` so the per-finding firehose doesn't
    // flood a chat channel -- raise it to `critical` for alerts only.
    for (url, flavor, raw_min, what) in [
        (
            &config.slack_webhook_url,
            WebhookFlavor::Slack,
            &config.slack_min_severity,
            "Slack",
        ),
        (
            &config.teams_webhook_url,
            WebhookFlavor::Teams,
            &config.teams_min_severity,
            "Teams",
        ),
        (
            &config.webhook_url,
            WebhookFlavor::Generic,
            &config.webhook_min_severity,
            "webhook",
        ),
    ] {
        if let Some(url) = url {
            let min_severity = raw_min
                .as_deref()
                .and_then(NotificationSeverity::parse)
                .unwrap_or(NotificationSeverity::Warning);
            match WebhookProvider::new(url, flavor, min_severity) {
                Ok(provider) => dispatcher.register(Box::new(provider)),
                Err(e) => {
                    tracing::warn!(error = %e, "{what} notification provider not configured")
                }
            }
        }
    }

    dispatcher
}
