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
use abyssal_notifications::{NotificationDispatcher, SmtpProvider};
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Some(Command::Reliquary { action }) = Cli::parse().command {
        return cli::run(action).await;
    }

    let mut config = Config::from_env()?;

    let pool = abyssal_database::connect(&config.database_url).await?;
    abyssal_database::run_migrations(&pool).await?;
    abyssal_database::seed::seed_core_defaults(&pool).await?;

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
        notifications: Arc::new(build_notifications(&config)),
        hosts: Arc::new(HostConnectionRegistry::new()),
        executor: Arc::new(executor),
        elevation: Arc::new(ElevationTracker::new()),
        update_status: Arc::new(tokio::sync::RwLock::new(
            abyssal_web::update_check::UpdateStatus::current(),
        )),
        encryption_key: encryption_key.clone(),
        deploy_jobs: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        scan_jobs: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        reliquary_backup_provider: backup_provider.clone(),
        reliquary_backup_storage: backup_storage.clone(),
        maintenance_mode: MaintenanceMode::default(),
    };

    abyssal_web::reliquary_backup::orchestrator::spawn_scheduled_backup_loop(
        state.clone(),
        backup_provider,
    );

    spawn_elevation_expiry_sweep(state.pool.clone(), state.elevation.clone());
    abyssal_web::spawn_thanatos_sweep(state.clone());
    abyssal_web::spawn_health_sweep(state.clone());
    abyssal_web::spawn_update_check_sweep(state.clone());
    abyssal_web::spawn_panopticon_sweep(state.pool.clone());
    abyssal_web::spawn_panopticon_snmp_sweep(state.pool.clone(), encryption_key);
    abyssal_web::spawn_panopticon_traffic_rollup(state.pool.clone());
    spawn_panopticon_listeners(state.pool.clone()).await;

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
fn spawn_elevation_expiry_sweep(pool: DbPool, elevation: Arc<ElevationTracker>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
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
async fn spawn_panopticon_listeners(pool: DbPool) {
    let mdns_enabled = repo::settings::get_bool(&pool, PANOPTICON_MDNS_ENABLED, false)
        .await
        .unwrap_or(false);
    if mdns_enabled {
        abyssal_web::spawn_panopticon_mdns_listener(pool.clone());
    }

    let arp_enabled = repo::settings::get_bool(&pool, PANOPTICON_ARP_ENABLED, false)
        .await
        .unwrap_or(false);
    let arp_interface = repo::settings::get_string(&pool, PANOPTICON_ARP_INTERFACE, "")
        .await
        .unwrap_or_default();
    if arp_enabled && !arp_interface.trim().is_empty() {
        abyssal_web::spawn_panopticon_arp_listener(pool, arp_interface.trim().to_string());
    }
}

fn build_notifications(config: &Config) -> NotificationDispatcher {
    let mut dispatcher = NotificationDispatcher::new();

    if let (Some(host), Some(from)) = (&config.smtp_host, &config.smtp_from) {
        let username = config.smtp_username.as_deref().unwrap_or("");
        let password = config.smtp_password.as_deref().unwrap_or("");
        match SmtpProvider::new(host, config.smtp_port, username, password, from) {
            Ok(provider) => dispatcher.register(Box::new(provider)),
            Err(e) => tracing::warn!(error = %e, "SMTP notification provider not configured"),
        }
    }

    dispatcher
}
