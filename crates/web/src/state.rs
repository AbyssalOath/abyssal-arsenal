use std::sync::Arc;

use abyssal_auth::LoginLimiter;
use abyssal_core::EncryptionKey;
use abyssal_database::DbPool;
use abyssal_execution::Executor;
use abyssal_hosts::{ElevationTracker, HostConnectionRegistry};
use abyssal_modules::ModuleRegistry;
use abyssal_notifications::NotificationDispatcher;
use abyssal_workflows::WorkflowRegistry;
use chrono::Duration;
use tokio::sync::RwLock;

use crate::update_check::UpdateStatus;

pub struct WebConfig {
    pub session_cookie_name: String,
    pub session_ttl: Duration,
    /// Whether the session cookie should be marked `Secure`. Only disabled for
    /// local plain-HTTP development; production deployments must run behind
    /// TLS and keep this on.
    pub cookie_secure: bool,
    /// Base URL for links in outgoing emails -- see `Config::public_url` in
    /// `crates/app/src/config.rs` for why this isn't inferred from a
    /// request instead.
    pub public_url: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub modules: Arc<ModuleRegistry>,
    /// The Contextual Arsenal Workflow Navigation registry -- which
    /// "investigate/act on this elsewhere" buttons a source arsenal's
    /// structured result can suggest. See `abyssal_workflows` for the
    /// registry schema and evaluator.
    pub workflows: Arc<WorkflowRegistry>,
    pub config: Arc<WebConfig>,
    pub login_limiter: Arc<LoginLimiter>,
    pub notifications: Arc<NotificationDispatcher>,
    pub hosts: Arc<HostConnectionRegistry>,
    pub executor: Arc<Executor>,
    /// Best-effort, control-plane-local mirror of which hosts are believed
    /// elevated -- see `abyssal_hosts::ElevationTracker` for why this isn't
    /// itself a security boundary.
    pub elevation: Arc<ElevationTracker>,
    /// This build's version and, once the periodic check has run at least
    /// once, the latest tagged release GitHub reports -- see
    /// `crate::update_check`.
    pub update_status: Arc<RwLock<UpdateStatus>>,
    /// AES-256-GCM master key for encrypting Panopticon switches' SNMP
    /// community strings at rest -- `None` when `ENCRYPTION_KEY` isn't
    /// set, in which case the switch-add route refuses cleanly rather
    /// than storing a credential unencrypted. See
    /// `abyssal_core::crypto::EncryptionKey`.
    pub encryption_key: Option<Arc<EncryptionKey>>,
}
