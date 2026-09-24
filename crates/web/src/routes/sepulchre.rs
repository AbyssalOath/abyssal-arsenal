//! Sepulchre: storage & file-sharing connectivity -- see
//! `crate::sepulchre` for the engine and `docs/sepulchre.md` for the
//! full design. Connections are the control-plane-wide resource
//! (`/arsenals/sepulchre/connections/...`); host-side shares/mounts are
//! reached per-host (`/arsenals/sepulchre/hosts/:host_id`), the same
//! split Parish/Cryptkeeper use for host-scoped vs. control-plane-wide
//! pages.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{
    AccessMethod, AppError, Capability, ConnectionOrigin, ConnectionRole, ExecutionContext,
    LocalConfig, Permission, Protocol, ProtocolConfig, SftpAuthMethod, SftpConfig, SmbConfig,
    SmbEncryption, SmbMinProtocol, ValidationMode,
};
use abyssal_database::repo;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{require_csrf, suggested_actions_for, workflow_context_rows};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::sepulchre::backend;
use crate::sepulchre::provisioning::{self, HostDispatch};
use crate::state::AppState;
use crate::templates::{
    AccessMethodRow, BaseCtx, CapabilityRow, ConnectionRow, ConsumerRow, MountRow,
    MountableConnectionOption, SepulchreConnectionDetailTemplate, SepulchreHostTemplate,
    SepulchreNewConnectionTemplate, SepulchreNewMountTemplate, SepulchreNewShareTemplate,
    SepulchreProbeHostKeyTemplate, SepulchreTemplate, ShareRow, ValidationCheckRow,
    ValidationRunRow,
};
use crate::theme;

fn protocol_label(p: Protocol) -> &'static str {
    p.label()
}

fn origin_label(o: ConnectionOrigin) -> &'static str {
    match o {
        ConnectionOrigin::ControlPlane => "Control plane",
        ConnectionOrigin::HostSideManaged => "Host-side managed",
    }
}

fn role_label(r: ConnectionRole) -> &'static str {
    r.label()
}

fn capability_label(c: Capability) -> &'static str {
    match c {
        Capability::Read => "Read",
        Capability::List => "List",
        Capability::Write => "Write",
        Capability::Delete => "Delete",
    }
}

fn access_method_label(m: AccessMethod) -> &'static str {
    m.label()
}

fn context_label(c: ExecutionContext) -> &'static str {
    match c {
        ExecutionContext::ControlPlane => "Control plane",
        ExecutionContext::ManagedHost => "Managed host",
    }
}

/// Both `storage_connections.manage` (Sepulchre's own gate) AND
/// `security.manage` (Cryptkeeper's) are required to generate or
/// replace key material -- the amendment's explicit cross-cutting rule,
/// since a connection's private key is exactly the kind of secret
/// Cryptkeeper's permission model already exists to gate.
fn ensure_can_manage_key_material(ctx: &abyssal_rbac::AuthContext) -> Result<(), WebError> {
    if !ctx.has(Permission::StorageConnectionsManage) || !ctx.has(Permission::SecurityManage) {
        return Err(WebError(AppError::Forbidden));
    }
    Ok(())
}

async fn connection_row(
    state: &AppState,
    connection: &abyssal_core::StorageConnection,
) -> anyhow::Result<ConnectionRow> {
    let roles = repo::storage_connections::roles_for_connection(&state.pool, connection.id).await?;
    let mut role_names: Vec<&'static str> = roles.iter().map(|r| role_label(*r)).collect();
    role_names.sort_unstable();
    let host_name = match connection.managed_host_id {
        Some(host_id) => repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .map(|h| h.name),
        None => None,
    };
    let validation_label = match connection.last_validation_status {
        Some(abyssal_core::ValidationStatus::Ok) => "Verified".to_string(),
        Some(abyssal_core::ValidationStatus::Failed) => "Failed".to_string(),
        Some(abyssal_core::ValidationStatus::Skipped) => "Incomplete".to_string(),
        None => "Never validated".to_string(),
    };
    Ok(ConnectionRow {
        id: connection.id.to_string(),
        name: connection.name.clone(),
        protocol_label: protocol_label(connection.protocol),
        origin_label: origin_label(connection.origin),
        enabled: connection.enabled,
        roles: if role_names.is_empty() {
            "none".to_string()
        } else {
            role_names.join(", ")
        },
        validation_passed: matches!(
            connection.last_validation_status,
            Some(abyssal_core::ValidationStatus::Ok)
        ),
        validation_label,
        host_name,
    })
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    protocol: Option<String>,
    role: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(query): Query<ListQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsView)?;
    render_list(&state, &jar, &ctx, &query, None, None).await
}

async fn render_list(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    query: &ListQuery,
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

    let filter = repo::storage_connections::ConnectionFilter {
        protocol: query
            .protocol
            .as_deref()
            .and_then(|p| Protocol::from_str(p).ok()),
        role: query
            .role
            .as_deref()
            .and_then(|r| ConnectionRole::from_str(r).ok()),
    };
    let connections = repo::storage_connections::list(&state.pool, &filter, 0, 500).await?;
    let mut rows = Vec::with_capacity(connections.len());
    for connection in &connections {
        rows.push(connection_row(state, connection).await?);
    }

    let tpl = SepulchreTemplate {
        base,
        connections: rows,
        can_manage: ctx.has(Permission::StorageConnectionsManage),
        protocol_filter: query.protocol.clone().unwrap_or_default(),
        role_filter: query.role.clone().unwrap_or_default(),
        message,
        error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct NewConnectionQuery {
    protocol: String,
}

pub async fn new_connection_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(query): Query<NewConnectionQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    let protocol = Protocol::from_str(&query.protocol)
        .map_err(|_| WebError(AppError::Validation("Not a recognized protocol.".into())))?;

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
    let tpl = SepulchreNewConnectionTemplate {
        base,
        protocol: protocol.as_str().to_string(),
        protocol_label: protocol_label(protocol),
        error: None,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize, Default)]
pub struct CreateConnectionForm {
    csrf_token: String,
    protocol: String,
    name: String,
    // SFTP + SMB
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    // SFTP-only
    #[serde(default)]
    base_path: String,
    #[serde(default)]
    auth_method: String,
    // SMB-only
    #[serde(default)]
    share_name: String,
    #[serde(default)]
    subpath: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    encryption: String,
    // Local-only
    #[serde(default)]
    path: String,
    // Roles (checkbox group -- axum::Form handles repeated bool-ish
    // checkboxes fine here since each is a distinct field name, unlike
    // the repeated-key `permissions`/`modules` groups elsewhere in this
    // app that need manual `form_urlencoded` parsing).
    #[serde(default)]
    role_backup_destination: bool,
    #[serde(default)]
    role_file_transfer: bool,
    #[serde(default)]
    role_remote_storage: bool,
    #[serde(default)]
    role_other: bool,
}

fn parse_port(raw: &str, default: u16) -> Result<u16, WebError> {
    if raw.trim().is_empty() {
        return Ok(default);
    }
    raw.trim()
        .parse()
        .map_err(|_| WebError(AppError::Validation("Port must be 1-65535.".into())))
}

pub async fn create_connection(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<CreateConnectionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let protocol = Protocol::from_str(&form.protocol)
        .map_err(|_| WebError(AppError::Validation("Not a recognized protocol.".into())))?;
    let name = form.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(WebError(AppError::Validation(
            "Connection name must be 1-100 characters.".into(),
        )));
    }
    if repo::storage_connections::find_by_name(&state.pool, name)
        .await?
        .is_some()
    {
        return Err(WebError(AppError::Validation(
            "A connection named that already exists.".into(),
        )));
    }

    let (protocol_config, secret): (ProtocolConfig, Option<String>) = match protocol {
        Protocol::Local => {
            let path = form.path.trim();
            if path.is_empty() {
                return Err(WebError(AppError::Validation("Path is required.".into())));
            }
            (
                ProtocolConfig::Local(LocalConfig {
                    path: path.to_string(),
                    create_if_missing: true,
                    expected_mode: None,
                }),
                None,
            )
        }
        Protocol::Sftp => {
            let host = form.host.trim();
            if host.is_empty() {
                return Err(WebError(AppError::Validation("Host is required.".into())));
            }
            let username = form.username.trim();
            if username.is_empty() {
                return Err(WebError(AppError::Validation(
                    "Username is required.".into(),
                )));
            }
            let base_path = if form.base_path.trim().is_empty() {
                "/".to_string()
            } else {
                form.base_path.trim().to_string()
            };
            let auth_method = match form.auth_method.as_str() {
                "ssh_key" => SftpAuthMethod::SshKey,
                _ => SftpAuthMethod::Password,
            };
            let secret = if auth_method == SftpAuthMethod::Password {
                if form.password.is_empty() {
                    return Err(WebError(AppError::Validation(
                        "Password is required.".into(),
                    )));
                }
                Some(form.password.clone())
            } else {
                None // an SSH key is generated/imported as a separate step after creation
            };
            (
                ProtocolConfig::Sftp(SftpConfig {
                    host: host.to_string(),
                    port: parse_port(&form.port, 22)?,
                    base_path,
                    auth_method,
                    username: username.to_string(),
                    pinned_host_key_fingerprint: None,
                    connect_timeout_secs: 10,
                    read_timeout_secs: 30,
                }),
                secret,
            )
        }
        Protocol::Smb => {
            let host = form.host.trim();
            if host.is_empty() {
                return Err(WebError(AppError::Validation("Host is required.".into())));
            }
            let username = form.username.trim();
            if username.is_empty() {
                return Err(WebError(AppError::Validation(
                    "Username is required.".into(),
                )));
            }
            let share_name = form.share_name.trim();
            if share_name.is_empty() {
                return Err(WebError(AppError::Validation(
                    "Share name is required.".into(),
                )));
            }
            let subpath = form.subpath.trim();
            // Both end up interpolated into `smbclient`'s own `-c "..."`
            // command string at connection-use time (see
            // `sepulchre::backend::smb::SmbBackend::resolve`'s doc
            // comment) -- reject an unsafe value here too, rather than
            // only discovering it the first time the connection is used.
            crate::sepulchre::backend::smb::reject_unsafe_smb_component(share_name)?;
            crate::sepulchre::backend::smb::reject_unsafe_smb_component(subpath)?;
            if form.password.is_empty() {
                return Err(WebError(AppError::Validation(
                    "Password is required.".into(),
                )));
            }
            let encryption = match form.encryption.as_str() {
                "required" => SmbEncryption::Required,
                "off" => SmbEncryption::Off,
                _ => SmbEncryption::IfSupported,
            };
            (
                ProtocolConfig::Smb(SmbConfig {
                    host: host.to_string(),
                    port: parse_port(&form.port, 445)?,
                    share_name: share_name.to_string(),
                    subpath: subpath.to_string(),
                    username: username.to_string(),
                    domain: (!form.domain.trim().is_empty())
                        .then(|| form.domain.trim().to_string()),
                    min_protocol: SmbMinProtocol::Smb3,
                    signing_required: true,
                    encryption,
                }),
                Some(form.password.clone()),
            )
        }
        // `Protocol` is `#[non_exhaustive]` (crates/core/src/storage.rs)
        // specifically so a future NFS/WebDAV/S3 variant forces this
        // match to be revisited -- reached only once such a variant
        // exists and this form hasn't been taught about it yet.
        _ => {
            return Err(WebError(AppError::Validation(
                "This protocol isn't supported for control-plane connections yet.".into(),
            )));
        }
    };

    let connection = repo::storage_connections::create(
        &state.pool,
        repo::storage_connections::NewConnection {
            name,
            origin: ConnectionOrigin::ControlPlane,
            managed_host_id: None,
            protocol_config: &protocol_config,
            created_by: Some(ctx.user.id),
        },
    )
    .await?;

    if let Some(secret) = secret {
        crate::sepulchre::secrets::replace_password(
            &state,
            connection.id,
            &secret,
            Some(ctx.user.id),
        )
        .await?;
    }

    let mut roles = HashSet::new();
    if form.role_backup_destination {
        roles.insert(ConnectionRole::BackupDestination);
    }
    if form.role_file_transfer {
        roles.insert(ConnectionRole::FileTransfer);
    }
    if form.role_remote_storage {
        roles.insert(ConnectionRole::RemoteStorage);
    }
    if form.role_other {
        roles.insert(ConnectionRole::Other);
    }
    repo::storage_connections::set_roles(&state.pool, connection.id, &roles).await?;

    // Every control-plane connection always has `native_client` enabled
    // in the control-plane context -- that's what "control-plane
    // connection" means; other methods (mount, rsync) are opted into
    // separately, host-side.
    repo::storage_connections::add_access_method(
        &state.pool,
        connection.id,
        AccessMethod::NativeClient,
        ExecutionContext::ControlPlane,
        None,
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::StorageConnectionCreated, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(name)
            .metadata(serde_json::json!({ "protocol": protocol.as_str() })),
    )
    .await?;

    Ok(Redirect::to(&format!(
        "/arsenals/sepulchre/connections/{}",
        connection.id
    ))
    .into_response())
}

async fn render_detail(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    connection: &abyssal_core::StorageConnection,
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

    let held_roles =
        repo::storage_connections::roles_for_connection(&state.pool, connection.id).await?;
    let roles: Vec<(&'static str, &'static str, bool)> = ConnectionRole::ALL
        .iter()
        .map(|r| (r.as_str(), role_label(*r), held_roles.contains(r)))
        .collect();

    let held_caps =
        repo::storage_connections::capabilities_for_connection(&state.pool, connection.id).await?;
    let capabilities: Vec<CapabilityRow> = Capability::ALL
        .iter()
        .map(|c| {
            let held = held_caps.iter().find(|h| h.capability == *c);
            CapabilityRow {
                key: c.as_str().to_string(),
                label: capability_label(*c).to_string(),
                declared: held.is_some_and(|h| h.declared),
                verified: held.is_some_and(|h| h.is_verified()),
            }
        })
        .collect();

    let access_methods_raw =
        repo::storage_connections::access_methods_for_connection(&state.pool, connection.id)
            .await?;
    let mut access_methods = Vec::with_capacity(access_methods_raw.len());
    for am in &access_methods_raw {
        let host_name = match am.managed_host_id {
            Some(host_id) => repo::hosts::find_by_id(&state.pool, host_id)
                .await?
                .map(|h| h.name),
            None => None,
        };
        access_methods.push(AccessMethodRow {
            method_label: access_method_label(am.method),
            context_label: context_label(am.context),
            host_name,
        });
    }

    let consumers_raw =
        repo::connection_consumers::for_connection(&state.pool, connection.id).await?;
    let consumers: Vec<ConsumerRow> = consumers_raw
        .into_iter()
        .map(|c| ConsumerRow {
            arsenal: c.arsenal,
            purpose: c.purpose,
            role_label: role_label(c.role),
        })
        .collect();

    let history_raw =
        repo::validation_runs::history_for_connection(&state.pool, connection.id, 10).await?;
    let history: Vec<ValidationRunRow> = history_raw.into_iter().map(validation_run_row).collect();
    let latest_run = history.first().cloned();

    let host_name = match connection.managed_host_id {
        Some(host_id) => repo::hosts::find_by_id(&state.pool, host_id)
            .await?
            .map(|h| h.name),
        None => None,
    };

    let secret = repo::storage_connections::find_secret(&state.pool, connection.id).await?;

    let (config_summary, needs_host_key_pin, pinned_fingerprint) = match &connection.protocol_config
    {
        ProtocolConfig::Local(c) => (
            vec![
                ("Path".to_string(), c.path.clone()),
                (
                    "Create if missing".to_string(),
                    c.create_if_missing.to_string(),
                ),
            ],
            false,
            None,
        ),
        ProtocolConfig::Sftp(c) => (
            vec![
                ("Host".to_string(), format!("{}:{}", c.host, c.port)),
                ("Base path".to_string(), c.base_path.clone()),
                ("Username".to_string(), c.username.clone()),
                (
                    "Auth method".to_string(),
                    match c.auth_method {
                        SftpAuthMethod::Password => "Password".to_string(),
                        SftpAuthMethod::SshKey => "SSH key".to_string(),
                    },
                ),
            ],
            c.pinned_host_key_fingerprint.is_none(),
            c.pinned_host_key_fingerprint.clone(),
        ),
        ProtocolConfig::Smb(c) => (
            vec![
                ("Host".to_string(), format!("{}:{}", c.host, c.port)),
                ("Share".to_string(), c.share_name.clone()),
                ("Subpath".to_string(), c.subpath.clone()),
                ("Username".to_string(), c.username.clone()),
                ("Signing".to_string(), "Required".to_string()),
            ],
            false,
            None,
        ),
    };

    // Suggested next steps: evaluated from the latest run's first failed
    // check, if any. `host_id` for the workflow evaluation call is a
    // real host only for a `HostSideManaged` connection -- the entries
    // themselves are all gated on `origin == "host_side_managed"`, so a
    // match can never occur without one; `Uuid::nil()` for a
    // control-plane connection is therefore never actually followed,
    // just a placeholder the API requires either way.
    let suggested_actions = if let Some(run) = &latest_run
        && let Some(failed) = run
            .checks
            .iter()
            .find(|c| !c.status_passed && !c.status_skipped)
    {
        let result = serde_json::json!({
            "error_kind": failed.error_kind.clone().unwrap_or_default(),
            "origin": connection.origin.as_str(),
        });
        suggested_actions_for(
            state,
            "sepulchre",
            "connection_validation",
            &[result],
            connection.managed_host_id.unwrap_or_else(Uuid::nil),
        )
        .await
    } else {
        Vec::new()
    };

    let tpl = SepulchreConnectionDetailTemplate {
        base,
        id: connection.id.to_string(),
        name: connection.name.clone(),
        protocol: connection.protocol.as_str().to_string(),
        protocol_label: protocol_label(connection.protocol),
        origin_label: origin_label(connection.origin),
        enabled: connection.enabled,
        host_id: connection.managed_host_id.map(|h| h.to_string()),
        host_name,
        config_summary,
        roles,
        capabilities,
        access_methods,
        consumers,
        latest_run,
        run_history: history,
        needs_host_key_pin,
        pinned_fingerprint,
        public_key: secret.as_ref().and_then(|s| s.public_key.clone()),
        secret_updated_at: secret
            .map(|s| crate::common::format_in_tz(s.updated_at, &ctx.user.timezone)),
        can_manage: ctx.has(Permission::StorageConnectionsManage),
        can_manage_secrets: ctx.has(Permission::StorageConnectionsManage)
            && ctx.has(Permission::SecurityManage),
        suggested_actions,
        message,
        error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

fn validation_run_row(run: abyssal_core::ValidationRun) -> ValidationRunRow {
    let checks = run
        .checks
        .into_iter()
        .map(|c| ValidationCheckRow {
            check: c.check,
            status_label: match c.status {
                abyssal_core::ValidationStatus::Ok => "Passed",
                abyssal_core::ValidationStatus::Failed => "Failed",
                abyssal_core::ValidationStatus::Skipped => "Skipped",
            },
            status_passed: matches!(c.status, abyssal_core::ValidationStatus::Ok),
            status_skipped: matches!(c.status, abyssal_core::ValidationStatus::Skipped),
            error_kind: c.error_kind.map(|k| k.as_str().to_string()),
            message: c.message,
            duration_ms: c.duration_ms,
        })
        .collect();
    ValidationRunRow {
        id: run.id.to_string(),
        mode_label: match run.mode {
            ValidationMode::ReadOnly => "Read-only",
            ValidationMode::ReadWrite => "Read/write",
        },
        overall_label: match run.overall_status {
            abyssal_core::ValidationStatus::Ok => "Passed",
            abyssal_core::ValidationStatus::Failed => "Failed",
            abyssal_core::ValidationStatus::Skipped => "Incomplete",
        },
        overall_passed: matches!(run.overall_status, abyssal_core::ValidationStatus::Ok),
        started_at: run.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        checks,
    }
}

pub async fn connection_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsView)?;
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    render_detail(&state, &jar, &ctx, &connection, None, None).await
}

#[derive(Deserialize)]
pub struct ValidateForm {
    csrf_token: String,
    #[serde(default)]
    mode: String,
}

pub async fn validate_connection(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ValidateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mode = if form.mode == "read_write" {
        ValidationMode::ReadWrite
    } else {
        ValidationMode::ReadOnly
    };
    let result =
        crate::sepulchre::validation::validate(&state, &connection, mode, Some(ctx.user.id)).await;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(
            AuditAction::StorageConnectionValidated,
            if result.is_ok() {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
        )
        .actor(Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource(&connection.name),
    )
    .await?;

    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    match result {
        Ok(_) => {
            render_detail(
                &state,
                &jar,
                &ctx,
                &connection,
                Some("Validation complete.".to_string()),
                None,
            )
            .await
        }
        Err(e) => {
            render_detail(
                &state,
                &jar,
                &ctx,
                &connection,
                None,
                Some(format!("Validation could not run: {e}")),
            )
            .await
        }
    }
}

pub async fn probe_host_key_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ProtocolConfig::Sftp(config) = &connection.protocol_config else {
        return Err(WebError(AppError::Validation(
            "Host key pinning only applies to SFTP connections.".into(),
        )));
    };

    let fingerprint = backend::sftp::probe_host_key(
        &config.host,
        config.port,
        std::time::Duration::from_secs(10),
    )
    .await
    .ok();

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
    let tpl = SepulchreProbeHostKeyTemplate {
        base,
        id: connection.id.to_string(),
        name: connection.name.clone(),
        error: if fingerprint.is_none() {
            Some("Could not reach the server to read its host key.".to_string())
        } else {
            None
        },
        fingerprint,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ConfirmHostKeyForm {
    csrf_token: String,
    fingerprint: String,
}

pub async fn confirm_host_key(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ConfirmHostKeyForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ProtocolConfig::Sftp(mut config) = connection.protocol_config.clone() else {
        return Err(WebError(AppError::Validation(
            "Host key pinning only applies to SFTP connections.".into(),
        )));
    };
    config.pinned_host_key_fingerprint = Some(form.fingerprint.trim().to_string());
    repo::storage_connections::update_protocol_config(
        &state.pool,
        id,
        &ProtocolConfig::Sftp(config),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::StorageConnectionChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&connection.name)
            .metadata(serde_json::json!({ "action": "host_key_pinned" })),
    )
    .await?;

    Ok(Redirect::to(&format!("/arsenals/sepulchre/connections/{id}")).into_response())
}

#[derive(Deserialize, Default)]
pub struct ReplaceSecretForm {
    csrf_token: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    passphrase: String,
}

pub async fn replace_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ReplaceSecretForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    match form.action.as_str() {
        "generate_key" => {
            ensure_can_manage_key_material(&ctx)?;
            let keypair =
                crate::sepulchre::secrets::generate_control_plane_keypair(&connection.name)
                    .map_err(|e| WebError(AppError::Validation(e.to_string())))?;
            crate::sepulchre::secrets::replace_control_plane_key(
                &state,
                id,
                &keypair,
                Some(ctx.user.id),
            )
            .await?;
            abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::StorageKeypairGenerated, AuditOutcome::Success)
                    .actor(Actor {
                        user_id: ctx.user.id,
                        username: &ctx.user.username,
                    })
                    .resource(&connection.name),
            )
            .await?;
        }
        "import_key" => {
            ensure_can_manage_key_material(&ctx)?;
            let passphrase = (!form.passphrase.is_empty()).then_some(form.passphrase.as_str());
            let keypair =
                crate::sepulchre::secrets::import_private_key(&form.private_key, passphrase)
                    .map_err(|e| WebError(AppError::Validation(e.to_string())))?;
            crate::sepulchre::secrets::replace_control_plane_key(
                &state,
                id,
                &keypair,
                Some(ctx.user.id),
            )
            .await?;
            abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::StorageKeypairImported, AuditOutcome::Success)
                    .actor(Actor {
                        user_id: ctx.user.id,
                        username: &ctx.user.username,
                    })
                    .resource(&connection.name),
            )
            .await?;
        }
        _ => {
            if form.password.is_empty() {
                return Err(WebError(AppError::Validation(
                    "Password is required.".into(),
                )));
            }
            crate::sepulchre::secrets::replace_password(
                &state,
                id,
                &form.password,
                Some(ctx.user.id),
            )
            .await?;
            abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::StorageSecretReplaced, AuditOutcome::Success)
                    .actor(Actor {
                        user_id: ctx.user.id,
                        username: &ctx.user.username,
                    })
                    .resource(&connection.name),
            )
            .await?;
        }
    }

    Ok(Redirect::to(&format!("/arsenals/sepulchre/connections/{id}")).into_response())
}

#[derive(Deserialize, Default)]
pub struct UpdateRolesForm {
    csrf_token: String,
    #[serde(default)]
    role_backup_destination: bool,
    #[serde(default)]
    role_file_transfer: bool,
    #[serde(default)]
    role_remote_storage: bool,
    #[serde(default)]
    role_other: bool,
}

pub async fn update_roles(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdateRolesForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut roles = HashSet::new();
    if form.role_backup_destination {
        roles.insert(ConnectionRole::BackupDestination);
    }
    if form.role_file_transfer {
        roles.insert(ConnectionRole::FileTransfer);
    }
    if form.role_remote_storage {
        roles.insert(ConnectionRole::RemoteStorage);
    }
    if form.role_other {
        roles.insert(ConnectionRole::Other);
    }
    repo::storage_connections::set_roles(&state.pool, id, &roles).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::StorageConnectionChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&connection.name)
            .metadata(serde_json::json!({ "action": "roles_updated" })),
    )
    .await?;

    Ok(Redirect::to(&format!("/arsenals/sepulchre/connections/{id}")).into_response())
}

pub async fn delete_connection_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let consumer_count = repo::connection_consumers::count_for_connection(&state.pool, id).await?;

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
    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Delete storage connection".to_string(),
        message: if consumer_count > 0 {
            format!(
                "\"{}\" is currently used by {consumer_count} consumer(s). Deleting it will break \
                 whatever relies on it.",
                connection.name
            )
        } else {
            format!(
                "This will permanently delete the connection \"{}\".",
                connection.name
            )
        },
        action_url: format!("/arsenals/sepulchre/connections/{id}/delete"),
        cancel_url: format!("/arsenals/sepulchre/connections/{id}"),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "connection name".to_string(),
            expected: connection.name,
        }),
        extra_hidden_fields: vec![],
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct DeleteConnectionForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn delete_connection(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<DeleteConnectionForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }
    let connection = repo::storage_connections::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &connection.name)?;

    repo::storage_connections::delete(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::StorageConnectionDeleted, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&connection.name),
    )
    .await?;

    Ok(Redirect::to("/arsenals/sepulchre").into_response())
}

// ---------------------------------------------------------------------
// Host-side view -- the workflow-registry target `sepulchre::show_host`.
// ---------------------------------------------------------------------

pub async fn show_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsView)?;
    render_show_host(&state, &jar, &ctx, host_id, &query, None, None, None).await
}

#[allow(clippy::too_many_arguments)]
async fn render_show_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    host_id: Uuid,
    query: &HashMap<String, String>,
    package_backend: Option<String>,
    message: Option<String>,
    error: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let shares_raw = repo::managed_shares::for_host(&state.pool, host_id).await?;
    let mut shares = Vec::with_capacity(shares_raw.len());
    for share in &shares_raw {
        let connection_name = match share.connection_id {
            Some(cid) => repo::storage_connections::find_by_id(&state.pool, cid)
                .await?
                .map(|c| c.name),
            None => None,
        };
        shares.push(ShareRow {
            id: share.id.to_string(),
            protocol_label: protocol_label(share.protocol),
            local_path: share.local_path.clone(),
            label: share
                .share_name
                .clone()
                .or_else(|| share.chroot_user.clone())
                .unwrap_or_default(),
            connection_name,
        });
    }

    let mounts_raw = repo::mount_definitions::for_host(&state.pool, host_id).await?;
    let mut mounts = Vec::with_capacity(mounts_raw.len());
    for mount in &mounts_raw {
        let connection_name =
            repo::storage_connections::find_by_id(&state.pool, mount.connection_id)
                .await?
                .map(|c| c.name)
                .unwrap_or_else(|| "(deleted connection)".to_string());
        mounts.push(MountRow {
            id: mount.id.to_string(),
            mount_point: mount.mount_point.clone(),
            state_label: match mount.state {
                repo::mount_definitions::MountState::Planned => "Planned",
                repo::mount_definitions::MountState::Applied => "Applied",
                repo::mount_definitions::MountState::Failed => "Failed",
                repo::mount_definitions::MountState::Removed => "Removed",
            },
            connection_name,
        });
    }

    let context = workflow_context_rows(query);
    let suggested_actions =
        suggested_actions_for(state, "sepulchre", "show_host", &[], host_id).await;

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
    let tpl = SepulchreHostTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        package_backend,
        shares,
        mounts,
        can_manage: ctx.has(Permission::StorageConnectionsManage),
        can_manage_keys: ctx.has(Permission::StorageConnectionsManage)
            && ctx.has(Permission::SecurityManage),
        message,
        error,
        context,
        suggested_actions,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct DetectBackendForm {
    csrf_token: String,
}

pub async fn detect_host_backend(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(query): Query<HashMap<String, String>>,
    Form(form): Form<DetectBackendForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let dispatch = HostDispatch {
        executor: &state.executor,
        hosts: &state.hosts,
        ctx: &ctx,
        host_id,
        host_name: &host.name,
    };
    match dispatch.detect_package_backend().await {
        Ok(backend) => {
            render_show_host(
                &state,
                &jar,
                &ctx,
                host_id,
                &query,
                Some(backend),
                Some("Detected this host's package manager.".to_string()),
                None,
            )
            .await
        }
        Err(e) => {
            render_show_host(
                &state,
                &jar,
                &ctx,
                host_id,
                &query,
                None,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------
// Host-side share provisioning wizard: plan (form) -> apply (provision +
// create the matching connection) in one step. There is no separate
// preview page -- the warning banner on the form itself is the
// "preview," matching the amendment's own allowance for a simplified
// flow; every step is still reported back clearly, and a failure at any
// point rolls back whatever host-side state was already created rather
// than leaving a half-provisioned account behind.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NewShareQuery {
    protocol: String,
}

pub async fn new_share_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(query): Query<NewShareQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    let protocol = match query.protocol.as_str() {
        "sftp" => Protocol::Sftp,
        "smb" => Protocol::Smb,
        _ => {
            return Err(WebError(AppError::Validation(
                "Share protocol must be sftp or smb.".into(),
            )));
        }
    };
    if protocol == Protocol::Sftp {
        ensure_can_manage_key_material(&ctx)?;
    }
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

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
    let tpl = SepulchreNewShareTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        protocol: protocol.as_str().to_string(),
        protocol_label: protocol_label(protocol),
        reachable_host_default: host.last_seen_ip.unwrap_or_default(),
        error: None,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize, Default)]
pub struct CreateShareForm {
    csrf_token: String,
    protocol: String,
    connection_name: String,
    reachable_host: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    chroot_dir: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    share_name: String,
    #[serde(default)]
    local_path: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    role_backup_destination: bool,
    #[serde(default)]
    role_file_transfer: bool,
    #[serde(default)]
    role_remote_storage: bool,
    #[serde(default)]
    role_other: bool,
}

fn roles_from_share_form(form: &CreateShareForm) -> HashSet<ConnectionRole> {
    let mut roles = HashSet::new();
    if form.role_backup_destination {
        roles.insert(ConnectionRole::BackupDestination);
    }
    if form.role_file_transfer {
        roles.insert(ConnectionRole::FileTransfer);
    }
    if form.role_remote_storage {
        roles.insert(ConnectionRole::RemoteStorage);
    }
    if form.role_other {
        roles.insert(ConnectionRole::Other);
    }
    roles
}

pub async fn create_share(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<CreateShareForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let connection_name = form.connection_name.trim();
    if connection_name.is_empty() || connection_name.len() > 100 {
        return Err(WebError(AppError::Validation(
            "Connection name must be 1-100 characters.".into(),
        )));
    }
    if repo::storage_connections::find_by_name(&state.pool, connection_name)
        .await?
        .is_some()
    {
        return Err(WebError(AppError::Validation(
            "A connection named that already exists.".into(),
        )));
    }
    let reachable_host = form.reachable_host.trim();
    if reachable_host.is_empty() {
        return Err(WebError(AppError::Validation(
            "A reachable address is required.".into(),
        )));
    }

    let dispatch = HostDispatch {
        executor: &state.executor,
        hosts: &state.hosts,
        ctx: &ctx,
        host_id,
        host_name: &host.name,
    };
    let roles = roles_from_share_form(&form);
    let empty_query = HashMap::new();

    match form.protocol.as_str() {
        "sftp" => {
            // Provisioning an SFTP share always generates a fresh
            // control-plane keypair -- a key-material action, gated the
            // same as the explicit "Generate a new SSH keypair" button on
            // a connection's own page (both `storage_connections.manage`
            // and `security.manage`).
            ensure_can_manage_key_material(&ctx)?;
            let username = form.username.trim();
            if !abyssal_agent_protocol::is_valid_account_name(username) {
                return Err(WebError(AppError::Validation(
                    "Not a valid account username.".into(),
                )));
            }
            let chroot_dir = if form.chroot_dir.trim().is_empty() {
                format!("/srv/sftp/{username}")
            } else {
                form.chroot_dir.trim().to_string()
            };
            if !abyssal_agent_protocol::is_valid_absolute_path(&chroot_dir) {
                return Err(WebError(AppError::Validation(
                    "Chroot directory must be an absolute path.".into(),
                )));
            }
            if repo::managed_shares::for_host(&state.pool, host_id)
                .await?
                .iter()
                .any(|s| s.chroot_user.as_deref() == Some(username))
            {
                return Err(WebError(AppError::Validation(
                    "This host already has a share for that username.".into(),
                )));
            }

            if let Err(e) = dispatch
                .create_sftp_chroot_account(username.to_string(), chroot_dir.clone())
                .await
            {
                return render_show_host(
                    &state,
                    &jar,
                    &ctx,
                    host_id,
                    &empty_query,
                    None,
                    None,
                    Some(format!("could not create the chroot account: {e}")),
                )
                .await;
            }

            let keypair =
                match crate::sepulchre::secrets::generate_control_plane_keypair(connection_name) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = dispatch
                            .remove_sftp_chroot_account(username.to_string())
                            .await;
                        return render_show_host(
                            &state,
                            &jar,
                            &ctx,
                            host_id,
                            &empty_query,
                            None,
                            None,
                            Some(format!(
                                "could not generate a keypair; rolled back the host account: {e}"
                            )),
                        )
                        .await;
                    }
                };

            if let Err(e) = dispatch
                .install_authorized_key(username.to_string(), keypair.public_key_openssh.clone())
                .await
            {
                let _ = dispatch
                    .remove_sftp_chroot_account(username.to_string())
                    .await;
                return render_show_host(
                    &state,
                    &jar,
                    &ctx,
                    host_id,
                    &empty_query,
                    None,
                    None,
                    Some(format!(
                        "could not install the authorized key; rolled back the host account: {e}"
                    )),
                )
                .await;
            }

            let mut blocks = Vec::new();
            for share in repo::managed_shares::for_host(&state.pool, host_id)
                .await?
                .into_iter()
                .filter(|s| s.protocol == Protocol::Sftp)
            {
                if let Some(user) = &share.chroot_user
                    && let Ok(block) =
                        provisioning::render_sftp_match_block(user, &share.local_path)
                {
                    blocks.push(block);
                }
            }
            match provisioning::render_sftp_match_block(username, &chroot_dir) {
                Ok(block) => blocks.push(block),
                Err(e) => {
                    let _ = dispatch
                        .remove_sftp_chroot_account(username.to_string())
                        .await;
                    return render_show_host(
                        &state,
                        &jar,
                        &ctx,
                        host_id,
                        &empty_query,
                        None,
                        None,
                        Some(format!("invalid chroot configuration: {e}")),
                    )
                    .await;
                }
            }
            let content = provisioning::render_full_sshd_dropin(&blocks);
            if let Err(e) = dispatch
                .render_config(
                    abyssal_agent_protocol::SepulchreConfigTarget::SshdDropIn,
                    content,
                )
                .await
            {
                let _ = dispatch
                    .remove_sftp_chroot_account(username.to_string())
                    .await;
                return render_show_host(
                    &state,
                    &jar,
                    &ctx,
                    host_id,
                    &empty_query,
                    None,
                    None,
                    Some(format!(
                        "could not apply the sshd config; rolled back the host account: {e}"
                    )),
                )
                .await;
            }

            let mut warning = None;
            match dispatch
                .check_include_directive(abyssal_agent_protocol::SepulchreConfigTarget::SshdDropIn)
                .await
            {
                Ok(false) => {
                    warning = Some(
                        "the config was applied, but this host's main sshd_config doesn't \
                         Include Sepulchre's drop-in directory yet -- add an `Include \
                         /etc/ssh/sshd_config.d/*.conf` line (or similar) yourself before this \
                         share will actually take effect."
                            .to_string(),
                    );
                }
                Ok(true) => {}
                Err(e) => {
                    warning = Some(format!("could not check the Include directive: {e}"));
                }
            }

            let connection = match repo::storage_connections::create(
                &state.pool,
                repo::storage_connections::NewConnection {
                    name: connection_name,
                    origin: ConnectionOrigin::HostSideManaged,
                    managed_host_id: Some(host_id),
                    protocol_config: &ProtocolConfig::Sftp(SftpConfig {
                        host: reachable_host.to_string(),
                        port: 22,
                        // The chroot root itself is intentionally
                        // root-owned and not writable by the chroot
                        // account (OpenSSH refuses `ChrootDirectory`
                        // otherwise) -- `upload`, created alongside the
                        // account by `create_sftp_chroot_account`, is the
                        // one directory this account can actually write
                        // to. Caught live: pointing this at `/` passed
                        // read-only checks but failed the read/write
                        // validation test with `permission_denied`.
                        base_path: "/upload".to_string(),
                        auth_method: SftpAuthMethod::SshKey,
                        username: username.to_string(),
                        pinned_host_key_fingerprint: None,
                        connect_timeout_secs: 10,
                        read_timeout_secs: 30,
                    }),
                    created_by: Some(ctx.user.id),
                },
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = dispatch
                        .remove_sftp_chroot_account(username.to_string())
                        .await;
                    return render_show_host(
                        &state,
                        &jar,
                        &ctx,
                        host_id,
                        &empty_query,
                        None,
                        None,
                        Some(format!(
                            "the host account was created but the connection record could not \
                             be saved; rolled back the host account: {e}"
                        )),
                    )
                    .await;
                }
            };

            crate::sepulchre::secrets::replace_control_plane_key(
                &state,
                connection.id,
                &keypair,
                Some(ctx.user.id),
            )
            .await?;
            repo::storage_connections::set_roles(&state.pool, connection.id, &roles).await?;
            repo::storage_connections::add_access_method(
                &state.pool,
                connection.id,
                AccessMethod::NativeClient,
                ExecutionContext::ControlPlane,
                None,
            )
            .await?;

            // Host-side-managed SFTP servers pin their host key
            // automatically rather than via the externally-hosted TOFU
            // flow's explicit human confirmation step -- Sepulchre itself
            // just stood up this exact sshd config on this exact host a
            // moment ago over the already-authenticated executor channel,
            // so there's nothing for a human to newly verify here. If the
            // probe itself fails (e.g. reachable_host isn't actually
            // reachable), the connection is left unpinned and the
            // existing manual probe/confirm flow on its detail page still
            // works as a fallback.
            match backend::sftp::probe_host_key(
                reachable_host,
                22,
                std::time::Duration::from_secs(10),
            )
            .await
            {
                Ok(fingerprint) => {
                    let config = SftpConfig {
                        host: reachable_host.to_string(),
                        port: 22,
                        base_path: "/upload".to_string(),
                        auth_method: SftpAuthMethod::SshKey,
                        username: username.to_string(),
                        pinned_host_key_fingerprint: Some(fingerprint),
                        connect_timeout_secs: 10,
                        read_timeout_secs: 30,
                    };
                    repo::storage_connections::update_protocol_config(
                        &state.pool,
                        connection.id,
                        &ProtocolConfig::Sftp(config),
                    )
                    .await?;
                }
                Err(_) => {
                    warning = Some(format!(
                        "{}couldn't automatically read the new server's host key -- pin it \
                         manually from the connection's own page before using it.",
                        warning.map(|w| format!("{w} Also, ")).unwrap_or_default()
                    ));
                }
            }

            repo::managed_shares::create(
                &state.pool,
                host_id,
                Protocol::Sftp,
                &chroot_dir,
                None,
                Some(username),
                &serde_json::json!([username]),
                &serde_json::json!({ "chroot_dir": chroot_dir }),
                Some(connection.id),
                Some(ctx.user.id),
            )
            .await?;

            abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::StorageShareProvisioned, AuditOutcome::Success)
                    .actor(Actor {
                        user_id: ctx.user.id,
                        username: &ctx.user.username,
                    })
                    .resource(connection_name)
                    .metadata(serde_json::json!({ "protocol": "sftp", "host_id": host_id })),
            )
            .await?;

            render_show_host(
                &state,
                &jar,
                &ctx,
                host_id,
                &empty_query,
                None,
                Some("SFTP share provisioned.".to_string()),
                warning,
            )
            .await
        }
        "smb" => {
            let username = form.username.trim();
            if !abyssal_agent_protocol::is_valid_account_name(username) {
                return Err(WebError(AppError::Validation(
                    "Not a valid account username.".into(),
                )));
            }
            let share_name = form.share_name.trim();
            provisioning::validate_share_name(share_name)?;
            let local_path = if form.local_path.trim().is_empty() {
                format!("/srv/smb/{share_name}")
            } else {
                form.local_path.trim().to_string()
            };
            if !abyssal_agent_protocol::is_valid_absolute_path(&local_path) {
                return Err(WebError(AppError::Validation(
                    "Directory must be an absolute path.".into(),
                )));
            }
            if form.password.is_empty() {
                return Err(WebError(AppError::Validation(
                    "Password is required.".into(),
                )));
            }
            if repo::managed_shares::for_host(&state.pool, host_id)
                .await?
                .iter()
                .any(|s| s.share_name.as_deref() == Some(share_name))
            {
                return Err(WebError(AppError::Validation(
                    "This host already has a share by that name.".into(),
                )));
            }

            // The service user has to exist before the share directory
            // can be created *owned by it* -- a plain root-owned
            // directory would make every write fail with
            // `NT_STATUS_ACCESS_DENIED` regardless of what the share
            // stanza allows (caught live against a real Samba server).
            if let Err(e) = dispatch
                .create_samba_service_user(username.to_string(), form.password.clone())
                .await
            {
                return render_show_host(
                    &state,
                    &jar,
                    &ctx,
                    host_id,
                    &empty_query,
                    None,
                    None,
                    Some(format!("could not create the Samba service user: {e}")),
                )
                .await;
            }
            if let Err(e) = dispatch
                .create_share_directory(local_path.clone(), username.to_string())
                .await
            {
                let _ = dispatch
                    .remove_samba_service_user(username.to_string())
                    .await;
                return render_show_host(
                    &state,
                    &jar,
                    &ctx,
                    host_id,
                    &empty_query,
                    None,
                    None,
                    Some(format!(
                        "could not create the share directory; rolled back the service user: {e}"
                    )),
                )
                .await;
            }

            let mut stanzas = Vec::new();
            for share in repo::managed_shares::for_host(&state.pool, host_id)
                .await?
                .into_iter()
                .filter(|s| s.protocol == Protocol::Smb)
            {
                if let (Some(name), Some(user)) = (&share.share_name, &share.chroot_user)
                    && let Ok(stanza) = provisioning::render_samba_share_stanza(
                        name,
                        &share.local_path,
                        std::slice::from_ref(user),
                        false,
                    )
                {
                    stanzas.push(stanza);
                }
            }
            match provisioning::render_samba_share_stanza(
                share_name,
                &local_path,
                &[username.to_string()],
                form.read_only,
            ) {
                Ok(stanza) => stanzas.push(stanza),
                Err(e) => {
                    let _ = dispatch
                        .remove_samba_service_user(username.to_string())
                        .await;
                    return render_show_host(
                        &state,
                        &jar,
                        &ctx,
                        host_id,
                        &empty_query,
                        None,
                        None,
                        Some(format!("invalid share configuration: {e}")),
                    )
                    .await;
                }
            }
            let content = provisioning::render_full_samba_include(true, &stanzas);
            if let Err(e) = dispatch
                .render_config(
                    abyssal_agent_protocol::SepulchreConfigTarget::SambaInclude,
                    content,
                )
                .await
            {
                let _ = dispatch
                    .remove_samba_service_user(username.to_string())
                    .await;
                return render_show_host(
                    &state,
                    &jar,
                    &ctx,
                    host_id,
                    &empty_query,
                    None,
                    None,
                    Some(format!(
                        "could not apply the samba config; rolled back the service user: {e}"
                    )),
                )
                .await;
            }

            let mut warning = None;
            match dispatch
                .check_include_directive(
                    abyssal_agent_protocol::SepulchreConfigTarget::SambaInclude,
                )
                .await
            {
                Ok(false) => {
                    warning = Some(
                        "the config was applied, but this host's main smb.conf doesn't include \
                         Sepulchre's config file yet -- add an `include = \
                         /etc/samba/sepulchre.conf` line to its `[global]` section yourself \
                         before this share will actually take effect."
                            .to_string(),
                    );
                }
                Ok(true) => {}
                Err(e) => {
                    warning = Some(format!("could not check the include directive: {e}"));
                }
            }

            let connection = match repo::storage_connections::create(
                &state.pool,
                repo::storage_connections::NewConnection {
                    name: connection_name,
                    origin: ConnectionOrigin::HostSideManaged,
                    managed_host_id: Some(host_id),
                    protocol_config: &ProtocolConfig::Smb(SmbConfig {
                        host: reachable_host.to_string(),
                        port: 445,
                        share_name: share_name.to_string(),
                        subpath: String::new(),
                        username: username.to_string(),
                        domain: None,
                        min_protocol: SmbMinProtocol::Smb3,
                        signing_required: true,
                        encryption: SmbEncryption::Required,
                    }),
                    created_by: Some(ctx.user.id),
                },
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = dispatch
                        .remove_samba_service_user(username.to_string())
                        .await;
                    return render_show_host(
                        &state,
                        &jar,
                        &ctx,
                        host_id,
                        &empty_query,
                        None,
                        None,
                        Some(format!(
                            "the service user was created but the connection record could not \
                             be saved; rolled back the service user: {e}"
                        )),
                    )
                    .await;
                }
            };

            crate::sepulchre::secrets::replace_password(
                &state,
                connection.id,
                &form.password,
                Some(ctx.user.id),
            )
            .await?;
            repo::storage_connections::set_roles(&state.pool, connection.id, &roles).await?;
            repo::storage_connections::add_access_method(
                &state.pool,
                connection.id,
                AccessMethod::NativeClient,
                ExecutionContext::ControlPlane,
                None,
            )
            .await?;

            repo::managed_shares::create(
                &state.pool,
                host_id,
                Protocol::Smb,
                &local_path,
                Some(share_name),
                Some(username),
                &serde_json::json!([username]),
                &serde_json::json!({ "read_only": form.read_only }),
                Some(connection.id),
                Some(ctx.user.id),
            )
            .await?;

            abyssal_audit::record(
                &state.pool,
                AuditEvent::new(AuditAction::StorageShareProvisioned, AuditOutcome::Success)
                    .actor(Actor {
                        user_id: ctx.user.id,
                        username: &ctx.user.username,
                    })
                    .resource(connection_name)
                    .metadata(serde_json::json!({ "protocol": "smb", "host_id": host_id })),
            )
            .await?;

            render_show_host(
                &state,
                &jar,
                &ctx,
                host_id,
                &empty_query,
                None,
                Some("SMB share provisioned.".to_string()),
                warning,
            )
            .await
        }
        _ => Err(WebError(AppError::Validation(
            "Share protocol must be sftp or smb.".into(),
        ))),
    }
}

pub async fn delete_share_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((host_id, share_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let share = repo::managed_shares::find_by_id(&state.pool, share_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if share.host_id != host_id {
        return Err(WebError(AppError::NotFound));
    }
    let label = share
        .share_name
        .clone()
        .or_else(|| share.chroot_user.clone())
        .unwrap_or_else(|| share.local_path.clone());

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
    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Remove storage share".to_string(),
        message: format!(
            "This removes the {} account/config on \"{}\" and deletes the associated \
             connection. Data already on disk under {} is left in place.",
            protocol_label(share.protocol),
            host.name,
            share.local_path
        ),
        action_url: format!("/arsenals/sepulchre/hosts/{host_id}/shares/{share_id}/delete"),
        cancel_url: format!("/arsenals/sepulchre/hosts/{host_id}"),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "share name".to_string(),
            expected: label,
        }),
        extra_hidden_fields: vec![],
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct DeleteShareForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn delete_share(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((host_id, share_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<DeleteShareForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let share = repo::managed_shares::find_by_id(&state.pool, share_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if share.host_id != host_id {
        return Err(WebError(AppError::NotFound));
    }
    let label = share
        .share_name
        .clone()
        .or_else(|| share.chroot_user.clone())
        .unwrap_or_else(|| share.local_path.clone());
    crate::common::require_typed_confirmation(&form.confirm_text, &label)?;

    let dispatch = HostDispatch {
        executor: &state.executor,
        hosts: &state.hosts,
        ctx: &ctx,
        host_id,
        host_name: &host.name,
    };

    let mut warning = None;
    match share.protocol {
        Protocol::Sftp => {
            if let Some(username) = &share.chroot_user
                && let Err(e) = dispatch.remove_sftp_chroot_account(username.clone()).await
            {
                warning = Some(format!("could not remove the host account cleanly: {e}"));
            }
            let mut blocks = Vec::new();
            for remaining in repo::managed_shares::for_host(&state.pool, host_id)
                .await?
                .into_iter()
                .filter(|s| s.id != share_id && s.protocol == Protocol::Sftp)
            {
                if let Some(user) = &remaining.chroot_user
                    && let Ok(block) =
                        provisioning::render_sftp_match_block(user, &remaining.local_path)
                {
                    blocks.push(block);
                }
            }
            let content = provisioning::render_full_sshd_dropin(&blocks);
            if let Err(e) = dispatch
                .render_config(
                    abyssal_agent_protocol::SepulchreConfigTarget::SshdDropIn,
                    content,
                )
                .await
            {
                warning = Some(format!(
                    "{}account removed, but re-rendering the sshd config failed: {e}",
                    warning.map(|w| format!("{w} Also, ")).unwrap_or_default()
                ));
            }
        }
        Protocol::Smb => {
            if let Some(username) = &share.chroot_user
                && let Err(e) = dispatch.remove_samba_service_user(username.clone()).await
            {
                warning = Some(format!(
                    "could not remove the Samba service user cleanly: {e}"
                ));
            }
            let mut stanzas = Vec::new();
            for remaining in repo::managed_shares::for_host(&state.pool, host_id)
                .await?
                .into_iter()
                .filter(|s| s.id != share_id && s.protocol == Protocol::Smb)
            {
                if let (Some(name), Some(user)) = (&remaining.share_name, &remaining.chroot_user)
                    && let Ok(stanza) = provisioning::render_samba_share_stanza(
                        name,
                        &remaining.local_path,
                        std::slice::from_ref(user),
                        false,
                    )
                {
                    stanzas.push(stanza);
                }
            }
            let content = provisioning::render_full_samba_include(true, &stanzas);
            if let Err(e) = dispatch
                .render_config(
                    abyssal_agent_protocol::SepulchreConfigTarget::SambaInclude,
                    content,
                )
                .await
            {
                warning = Some(format!(
                    "{}service user removed, but re-rendering the samba config failed: {e}",
                    warning.map(|w| format!("{w} Also, ")).unwrap_or_default()
                ));
            }
        }
        // `Protocol` is `#[non_exhaustive]` -- a `local` share never
        // exists (the wizard only offers sftp/smb), reached only once a
        // future protocol variant does.
        _ => {}
    }

    if let Some(connection_id) = share.connection_id {
        let _ = repo::storage_connections::delete(&state.pool, connection_id).await;
    }
    repo::managed_shares::delete(&state.pool, share_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::StorageShareRemoved, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&label),
    )
    .await?;

    render_show_host(
        &state,
        &jar,
        &ctx,
        host_id,
        &HashMap::new(),
        None,
        Some("Share removed.".to_string()),
        warning,
    )
    .await
}

// ---------------------------------------------------------------------
// Host-side mount creation. SMB/CIFS connections only today -- SSHFS
// mounting an SFTP connection is a documented, deferred gap (see
// docs/sepulchre.md): it would need the server's raw host-key text, not
// just the SHA256 fingerprint already stored, to build a
// `UserKnownHostsFile` sshfs can actually verify against.
// ---------------------------------------------------------------------

pub async fn new_mount_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let filter = repo::storage_connections::ConnectionFilter {
        protocol: Some(Protocol::Smb),
        role: None,
    };
    let connections = repo::storage_connections::list(&state.pool, &filter, 0, 500)
        .await?
        .into_iter()
        .filter(|c| c.enabled)
        .map(|c| MountableConnectionOption {
            id: c.id.to_string(),
            label: c.name,
        })
        .collect();

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
    let tpl = SepulchreNewMountTemplate {
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        connections,
        error: None,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize, Default)]
pub struct CreateMountForm {
    csrf_token: String,
    #[serde(default)]
    connection_id: String,
    #[serde(default)]
    mount_point: String,
    #[serde(default)]
    read_only: bool,
}

pub async fn create_mount(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<CreateMountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let connection_id = Uuid::parse_str(form.connection_id.trim())
        .map_err(|_| WebError(AppError::Validation("Not a valid connection.".into())))?;
    let connection = repo::storage_connections::find_by_id(&state.pool, connection_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ProtocolConfig::Smb(config) = &connection.protocol_config else {
        return Err(WebError(AppError::Validation(
            "Only SMB connections can be mounted from here today.".into(),
        )));
    };
    if !connection.enabled {
        return Err(WebError(AppError::Validation(
            "That connection is disabled.".into(),
        )));
    }
    let mount_point = form.mount_point.trim();
    if !abyssal_agent_protocol::is_valid_absolute_path(mount_point) {
        return Err(WebError(AppError::Validation(
            "Mount point must be an absolute path.".into(),
        )));
    }
    if repo::mount_definitions::for_host(&state.pool, host_id)
        .await?
        .iter()
        .any(|m| m.mount_point == mount_point)
    {
        return Err(WebError(AppError::Validation(
            "This host already has a mount at that path.".into(),
        )));
    }

    let password = crate::sepulchre::secrets::decrypt_secret(&state, connection_id)
        .await
        .map_err(|e| WebError(AppError::Validation(e.to_string())))?;

    let dispatch = HostDispatch {
        executor: &state.executor,
        hosts: &state.hosts,
        ctx: &ctx,
        host_id,
        host_name: &host.name,
    };
    let empty_query = HashMap::new();

    let credentials_path = format!(
        "{}/{connection_id}.cred",
        provisioning::MOUNT_CREDENTIALS_DIR
    );
    let credentials_contents = match provisioning::render_cifs_credentials_file(
        &config.username,
        password.as_str(),
        config.domain.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => return Err(WebError(AppError::Validation(e.to_string()))),
    };
    if let Err(e) = dispatch
        .write_mount_credentials(credentials_path.clone(), credentials_contents)
        .await
    {
        return render_show_host(
            &state,
            &jar,
            &ctx,
            host_id,
            &empty_query,
            None,
            None,
            Some(format!("could not write the mount credentials file: {e}")),
        )
        .await;
    }

    let what = if config.subpath.is_empty() {
        format!("//{}/{}", config.host, config.share_name)
    } else {
        format!(
            "//{}/{}/{}",
            config.host,
            config.share_name,
            config.subpath.trim_matches('/')
        )
    };
    let options = format!(
        "credentials={credentials_path},{}",
        if form.read_only { "ro" } else { "rw" }
    );
    let (unit_name, content) =
        match provisioning::render_mount_unit_content(&what, mount_point, "cifs", &options) {
            Ok(v) => v,
            Err(e) => return Err(WebError(AppError::Validation(e.to_string()))),
        };

    // Even when `render_mount_unit` reports failure, the agent's own
    // implementation writes the unit file and runs `daemon-reload`/
    // `enable` *before* the final `--now` activation step that actually
    // mounts it -- so a failure here (e.g. a missing kernel filesystem
    // driver on the host, caught live in exactly this scenario) still
    // typically leaves a real, enabled systemd unit on the host. Record
    // it as a `Failed`-state `mount_definitions` row regardless, so it's
    // visible and removable through the normal delete-mount flow instead
    // of becoming an untracked orphan the admin can't see from here.
    let apply_error = dispatch
        .render_mount_unit(unit_name.clone(), mount_point.to_string(), content)
        .await
        .err();

    let mounted = apply_error.is_none()
        && dispatch
            .check_mount_status(mount_point.to_string())
            .await
            .unwrap_or(false);

    let mount = repo::mount_definitions::create(
        &state.pool,
        host_id,
        connection_id,
        mount_point,
        &serde_json::json!({ "what": what, "fs_type": "cifs", "options": options, "unit_name": unit_name }),
        repo::mount_definitions::PersistenceMethod::SystemdUnit,
        Some(ctx.user.id),
    )
    .await?;
    repo::mount_definitions::set_state(
        &state.pool,
        mount.id,
        if mounted {
            repo::mount_definitions::MountState::Applied
        } else {
            repo::mount_definitions::MountState::Failed
        },
    )
    .await?;

    if let Some(e) = apply_error {
        return render_show_host(
            &state,
            &jar,
            &ctx,
            host_id,
            &empty_query,
            None,
            None,
            Some(format!(
                "mount unit was created but activation failed (recorded as failed -- remove it from the host page if you don't want to retry): {e}"
            )),
        )
        .await;
    }

    repo::storage_connections::add_access_method(
        &state.pool,
        connection_id,
        AccessMethod::Mount,
        ExecutionContext::ManagedHost,
        Some(host_id),
    )
    .await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::StorageMountProvisioned, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(mount_point),
    )
    .await?;

    render_show_host(
        &state,
        &jar,
        &ctx,
        host_id,
        &empty_query,
        None,
        Some(if mounted {
            "Mount created and active.".to_string()
        } else {
            "Mount unit created, but the mount doesn't appear active -- check the host.".to_string()
        }),
        None,
    )
    .await
}

pub async fn delete_mount_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((host_id, mount_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    let mount = repo::mount_definitions::find_by_id(&state.pool, mount_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if mount.host_id != host_id {
        return Err(WebError(AppError::NotFound));
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
    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Remove mount".to_string(),
        message: format!(
            "This unmounts and removes the mount unit for \"{}\". The remote data itself is \
             untouched.",
            mount.mount_point
        ),
        action_url: format!("/arsenals/sepulchre/hosts/{host_id}/mounts/{mount_id}/delete"),
        cancel_url: format!("/arsenals/sepulchre/hosts/{host_id}"),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "mount point".to_string(),
            expected: mount.mount_point,
        }),
        extra_hidden_fields: vec![],
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct DeleteMountForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn delete_mount(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((host_id, mount_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<DeleteMountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::StorageConnectionsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mount = repo::mount_definitions::find_by_id(&state.pool, mount_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if mount.host_id != host_id {
        return Err(WebError(AppError::NotFound));
    }
    crate::common::require_typed_confirmation(&form.confirm_text, &mount.mount_point)?;

    let dispatch = HostDispatch {
        executor: &state.executor,
        hosts: &state.hosts,
        ctx: &ctx,
        host_id,
        host_name: &host.name,
    };

    let unit_name = mount
        .options
        .get("unit_name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "{}.mount",
                provisioning::systemd_escape_path(&mount.mount_point)
            )
        });

    let mut warning = None;
    if let Err(e) = dispatch
        .remove_mount_unit(unit_name, mount.mount_point.clone())
        .await
    {
        warning = Some(format!("could not cleanly remove the mount unit: {e}"));
    }

    repo::mount_definitions::delete(&state.pool, mount_id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::StorageMountRemoved, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&mount.mount_point),
    )
    .await?;

    render_show_host(
        &state,
        &jar,
        &ctx,
        host_id,
        &HashMap::new(),
        None,
        Some("Mount removed.".to_string()),
        warning,
    )
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn auth_failed_on_a_host_side_managed_connection_suggests_cryptkeeper() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry =
            serde_json::json!({ "error_kind": "auth_failed", "origin": "host_side_managed" });
        let matches = registry
            .evaluate("sepulchre", "connection_validation", &entry)
            .matches;
        assert!(matches.iter().any(|m| m.target_arsenal == "cryptkeeper"));
    }

    #[test]
    fn auth_failed_on_a_control_plane_connection_suggests_nothing() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "error_kind": "auth_failed", "origin": "control_plane" });
        let matches = registry
            .evaluate("sepulchre", "connection_validation", &entry)
            .matches;
        assert!(
            matches.is_empty(),
            "a control-plane connection has no host to inspect"
        );
    }

    #[test]
    fn host_key_mismatch_suggests_cryptkeeper() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry =
            serde_json::json!({ "error_kind": "host_key_mismatch", "origin": "host_side_managed" });
        let matches = registry
            .evaluate("sepulchre", "connection_validation", &entry)
            .matches;
        assert!(matches.iter().any(|m| m.target_arsenal == "cryptkeeper"));
    }

    #[test]
    fn method_unavailable_suggests_installing_prerequisites_on_sepulchres_own_host_page() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "error_kind": "method_unavailable", "origin": "host_side_managed" });
        let matches = registry
            .evaluate("sepulchre", "connection_validation", &entry)
            .matches;
        assert!(
            matches
                .iter()
                .any(|m| m.target_arsenal == "sepulchre" && m.target_action == "show_host")
        );
    }

    #[test]
    fn a_cifs_read_only_filesystem_suggests_checking_network_storage_with_sepulchre() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({
            "mount_point": "/mnt/backups",
            "source": "//fileserver/backups",
            "fstype": "cifs",
        });
        let matches = registry
            .evaluate("resurrection", "read_only_filesystems", &entry)
            .matches;
        assert!(matches.iter().any(|m| m.target_arsenal == "sepulchre"));
    }

    #[test]
    fn a_local_ext4_read_only_filesystem_does_not_suggest_sepulchre() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({
            "mount_point": "/",
            "source": "/dev/sda1",
            "fstype": "ext4",
        });
        let matches = registry
            .evaluate("resurrection", "read_only_filesystems", &entry)
            .matches;
        assert!(!matches.iter().any(|m| m.target_arsenal == "sepulchre"));
    }
}
