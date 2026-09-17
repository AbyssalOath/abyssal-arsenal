use std::sync::Arc;

use abyssal_auth::LoginLimiter;
use abyssal_database::DbPool;
use abyssal_execution::Executor;
use abyssal_hosts::{ElevationTracker, HostConnectionRegistry};
use abyssal_modules::ModuleRegistry;
use abyssal_notifications::NotificationDispatcher;
use chrono::Duration;

pub struct WebConfig {
    pub session_cookie_name: String,
    pub session_ttl: Duration,
    /// Whether the session cookie should be marked `Secure`. Only disabled for
    /// local plain-HTTP development; production deployments must run behind
    /// TLS and keep this on.
    pub cookie_secure: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub modules: Arc<ModuleRegistry>,
    pub config: Arc<WebConfig>,
    pub login_limiter: Arc<LoginLimiter>,
    pub notifications: Arc<NotificationDispatcher>,
    pub hosts: Arc<HostConnectionRegistry>,
    pub executor: Arc<Executor>,
    /// Best-effort, control-plane-local mirror of which hosts are believed
    /// elevated -- see `abyssal_hosts::ElevationTracker` for why this isn't
    /// itself a security boundary.
    pub elevation: Arc<ElevationTracker>,
}
