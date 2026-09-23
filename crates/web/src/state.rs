use std::collections::HashMap;
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
use uuid::Uuid;

use crate::panopticon_ops::ScanJob;
use crate::reliquary_backup::provider::BackupProvider;
use crate::reliquary_backup::restore::MaintenanceMode;
use crate::reliquary_backup::storage::StorageDestination;
use crate::ssh_deploy::DeployJob;
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
    /// In-memory only, by design -- see `crate::ssh_deploy`'s module
    /// comment. Never durable: a job's meaningful outcomes are recorded
    /// via the audit log instead, and losing this map on restart (a
    /// deploy job outliving the process) isn't a requirement worth a
    /// database table for what's otherwise a few minutes of progress
    /// tracking. Each job's own `RwLock` is separate from this map's so
    /// polling one job's status page never contends with starting or
    /// looking up another.
    pub deploy_jobs: Arc<RwLock<HashMap<Uuid, Arc<RwLock<DeployJob>>>>>,
    /// Same in-memory-only shape and reasoning as `deploy_jobs`, for
    /// discovery scans -- see `panopticon_ops::ScanJob`.
    pub scan_jobs: Arc<RwLock<HashMap<Uuid, Arc<RwLock<ScanJob>>>>>,
    /// Native (control-plane) backups -- GitHub issue #9. Job *records*
    /// live durably in `reliquary_backups` (unlike `deploy_jobs`/
    /// `scan_jobs` above); what's here is just the engine + destination
    /// needed to run one, shared across every request the same way
    /// `executor`/`hosts` already are.
    pub reliquary_backup_provider: Arc<dyn BackupProvider>,
    pub reliquary_backup_storage: Arc<dyn StorageDestination>,
    /// Set for the duration of a restore -- see
    /// `reliquary_backup::restore::MaintenanceMode`.
    pub maintenance_mode: MaintenanceMode,
}
