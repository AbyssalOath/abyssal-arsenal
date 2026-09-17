mod arsenals;
mod config;

use std::net::SocketAddr;
use std::sync::Arc;

use abyssal_auth::LoginLimiter;
use abyssal_execution::Executor;
use abyssal_hosts::HostConnectionRegistry;
use abyssal_modules::ModuleRegistry;
use abyssal_notifications::{NotificationDispatcher, SmtpProvider};
use abyssal_web::{AppState, WebConfig};
use config::Config;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;

    let pool = abyssal_database::connect(&config.database_url).await?;
    abyssal_database::run_migrations(&pool).await?;
    abyssal_database::seed::seed_core_defaults(&pool).await?;

    let registry = ModuleRegistry::new(arsenals::all());
    registry.ensure_seeded(&pool).await?;

    let executor = Executor::new(pool.clone(), Duration::from_secs(30));

    let state = AppState {
        pool,
        modules: Arc::new(registry),
        config: Arc::new(WebConfig {
            session_cookie_name: config.session_cookie_name.clone(),
            session_ttl: chrono::Duration::hours(config.session_ttl_hours),
            cookie_secure: config.cookie_secure,
        }),
        login_limiter: Arc::new(LoginLimiter::default()),
        notifications: Arc::new(build_notifications(&config)),
        hosts: Arc::new(HostConnectionRegistry::new()),
        executor: Arc::new(executor),
    };

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
