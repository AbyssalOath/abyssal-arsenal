use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{maybe_elevate, require_csrf, urlencoding_encode};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{BaseCtx, CryptkeeperHostRow, CryptkeeperHostTemplate, CryptkeeperTemplate};
use crate::theme;

/// Landing page for this arsenal: just a host picker, same as every other
/// per-host arsenal.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;

    if let Some(host_id) = host_context::current(&jar) {
        if state.hosts.is_connected(host_id) {
            return Ok(Redirect::to(&format!("/arsenals/cryptkeeper/{host_id}")).into_response());
        }
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

    let mut hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            hosts.push(CryptkeeperHostRow {
                id: host.id.to_string(),
                name: host.name,
            });
        }
    }

    let tpl = CryptkeeperTemplate { base, hosts };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

async fn render_host(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

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

    let tpl = CryptkeeperHostTemplate {
        can_manage: ctx.has(Permission::SecurityManage),
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        result_label,
        result_output,
        result_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn show_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    render_host(&state, &jar, &ctx, host_id, None, None, None).await
}

fn validate_path(path: &str, label: &str) -> Result<String, WebError> {
    let path = path.trim().to_string();
    if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
        return Err(WebError(AppError::Validation(format!(
            "That doesn't look like a valid {label}."
        ))));
    }
    Ok(path)
}

fn validate_username(username: &str) -> Result<String, WebError> {
    let username = username.trim().to_string();
    if !abyssal_agent_protocol::is_valid_account_name(&username) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid username.".into(),
        )));
    }
    Ok(username)
}

// ---------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

#[allow(clippy::too_many_arguments)]
async fn run_read_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::SecurityView,
            OperationKind::Read,
            false,
            Duration::from_secs(30),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

pub async fn list_ssh_host_keys(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListSshHostKeys,
        "SSH Host Keys",
    )
    .await
}

#[derive(Deserialize)]
pub struct UsernameForm {
    csrf_token: String,
    username: String,
}

pub async fn list_ssh_authorized_keys(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<UsernameForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let username = validate_username(&form.username)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListSshAuthorizedKeys {
            username: username.clone(),
        },
        &format!("Authorized Keys ({username})"),
    )
    .await
}

pub async fn list_tls_certificates(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListTlsCertificates,
        "TLS Certificates",
    )
    .await
}

#[derive(Deserialize)]
pub struct PathForm {
    csrf_token: String,
    path: String,
}

pub async fn certificate_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PathForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let path = validate_path(&form.path, "certificate path")?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::CertificateDetail { path: path.clone() },
        &format!("Certificate Detail ({path})"),
    )
    .await
}

pub async fn scan_sensitive_file_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ScanSensitiveFilePermissions,
        "Sensitive File Permission Scan",
    )
    .await
}

pub async fn view_sensitive_file(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<PathForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityView)?;
    require_csrf(&jar, &form.csrf_token)?;
    let path = validate_path(&form.path, "file path")?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ViewSensitiveFile { path: path.clone() },
        &format!("View File ({path})"),
    )
    .await
}

// ---------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_write_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::SecurityManage,
            OperationKind::Write,
            false,
            Duration::from_secs(60),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct GenerateKeypairForm {
    csrf_token: String,
    key_type: String,
    comment: String,
    path: String,
}

pub async fn generate_ssh_keypair(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<GenerateKeypairForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !abyssal_agent_protocol::is_valid_ssh_key_type(&form.key_type) {
        return Err(WebError(AppError::Validation(
            "That isn't a supported SSH key type.".into(),
        )));
    }
    if !abyssal_agent_protocol::is_valid_gecos_comment(&form.comment) {
        return Err(WebError(AppError::Validation(
            "That comment isn't valid.".into(),
        )));
    }
    let path = validate_path(&form.path, "output path")?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::GenerateSshKeypair {
            key_type: form.key_type.clone(),
            comment: form.comment.clone(),
            path: path.clone(),
        },
        &format!("Generate SSH Keypair ({path})"),
    )
    .await
}

#[derive(Deserialize)]
pub struct FixPermissionsForm {
    csrf_token: String,
    path: String,
    mode: String,
}

pub async fn fix_file_permissions(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<FixPermissionsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let path = validate_path(&form.path, "file path")?;
    if !abyssal_agent_protocol::is_valid_tightened_permission_mode(&form.mode) {
        return Err(WebError(AppError::Validation(
            "That isn't one of the allowed modes (600, 400, 640, 700).".into(),
        )));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::FixFilePermissions {
            path: path.clone(),
            mode: form.mode.clone(),
        },
        &format!("Fix Permissions ({path} -> {})", form.mode),
    )
    .await
}

// ---------------------------------------------------------------------
// Shared Destructive confirm/dispatch machinery
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn destructive_confirm(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    title: &str,
    build_message: impl FnOnce(&str) -> String,
    action_url: String,
    type_to_confirm_label: &str,
    type_to_confirm_expected: &str,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;

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

    let escalate_host_id = if base.can_hosts_elevate && !state.elevation.is_elevated(host_id) {
        Some(host_id.to_string())
    } else {
        None
    };

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: title.to_string(),
        message: build_message(&host.name),
        action_url,
        cancel_url: format!("/arsenals/cryptkeeper/{host_id}"),
        escalate_host_id,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: type_to_confirm_label.to_string(),
            expected: type_to_confirm_expected.to_string(),
        }),
        extra_hidden_fields: vec![],
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

#[allow(clippy::too_many_arguments)]
async fn run_destructive_op(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    expected_confirm_text: &str,
    operation: AgentOperation,
    label: &str,
    form: ConfirmForm,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::SecurityManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(format!(
            "{label} was not confirmed."
        ))));
    }
    crate::common::require_typed_confirmation(&form.confirm_text, expected_confirm_text)?;

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result_label = Some(format!("{label} -- {}", host.name));

    let elevated = state.elevation.is_elevated(host_id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            operation,
            Permission::SecurityManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(60),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            render_host(
                state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
            )
            .await
        }
        Err(e) => {
            state.elevation.mark_deescalated(host_id);
            render_host(
                state,
                &jar,
                &ctx,
                host_id,
                result_label,
                None,
                Some(e.to_string()),
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------
// Destructive: remove authorized_keys entry
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RemoveAuthorizedKeyQuery {
    username: String,
    fingerprint: String,
}

pub async fn remove_authorized_key_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RemoveAuthorizedKeyQuery>,
) -> Result<Response, WebError> {
    let username = validate_username(&q.username)?;
    if !abyssal_agent_protocol::is_valid_ssh_fingerprint(&q.fingerprint) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid SSH fingerprint.".into(),
        )));
    }
    let action_url = format!(
        "/arsenals/cryptkeeper/{host_id}/remove-authorized-key?username={}&fingerprint={}",
        urlencoding_encode(&username),
        urlencoding_encode(&q.fingerprint)
    );
    let fingerprint = q.fingerprint.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Remove authorized key",
        move |host_name| {
            format!(
                "This will remove the authorized_keys entry matching \"{fingerprint}\" for \
                 \"{username}\" on \"{host_name}\", revoking whatever access that key granted. \
                 This cannot be undone."
            )
        },
        action_url,
        "fingerprint",
        &q.fingerprint,
    )
    .await
}

pub async fn remove_authorized_key(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<RemoveAuthorizedKeyQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let username = validate_username(&q.username)?;
    if !abyssal_agent_protocol::is_valid_ssh_fingerprint(&q.fingerprint) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid SSH fingerprint.".into(),
        )));
    }
    let expected = q.fingerprint.clone();
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &expected,
        AgentOperation::RemoveAuthorizedKey {
            username,
            fingerprint: q.fingerprint,
        },
        "Remove Authorized Key",
        form,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive: delete SSH keypair
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SingleFieldQuery {
    value: String,
}

pub async fn delete_ssh_keypair_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    let path = validate_path(&q.value, "keypair path")?;
    let action_url = format!(
        "/arsenals/cryptkeeper/{host_id}/delete-ssh-keypair?value={}",
        urlencoding_encode(&path)
    );
    let message_path = path.clone();
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Delete SSH keypair",
        move |host_name| {
            format!(
                "This will permanently delete the private key at \"{message_path}\" (and its \
                 .pub counterpart, if present) on \"{host_name}\". If this is a host key or a \
                 key still in use anywhere, removing it can break SSH access or authentication \
                 for whatever depends on it. This cannot be undone."
            )
        },
        action_url,
        "keypair path",
        &path,
    )
    .await
}

pub async fn delete_ssh_keypair(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let path = validate_path(&q.value, "keypair path")?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &path,
        AgentOperation::DeleteSshKeypair { path: path.clone() },
        "Delete SSH Keypair",
        form,
    )
    .await
}

#[derive(Deserialize)]
pub struct ElevateForm {
    csrf_token: String,
    sudo_password: String,
}

pub async fn elevate(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ElevateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsElevate)?;
    require_csrf(&jar, &form.csrf_token)?;

    if form.sudo_password.trim().is_empty() {
        return Err(WebError(AppError::Validation(
            "Enter a sudo password to elevate.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    match maybe_elevate(&state, &ctx, host_id, &host.name, Some(form.sudo_password)).await {
        Ok(warning) => {
            let message = format!("{}Elevated.", warning.unwrap_or(""));
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                Some(message),
                None,
            )
            .await
        }
        Err(e) => {
            render_host(
                &state,
                &jar,
                &ctx,
                host_id,
                Some("Elevate".to_string()),
                None,
                Some(e),
            )
            .await
        }
    }
}
