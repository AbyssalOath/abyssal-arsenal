//! "Quick Add Host From Network Scan" (GitHub issue #5): picker -> SSH
//! credentials -> host-key review -> deploy status. All four steps are
//! plain server-rendered pages -- no client-side JS anywhere in this app,
//! so "select all"/"none" on the picker and "confirm and deploy" on the
//! host-key review page work by resubmitting a normal HTML form back to
//! this crate rather than by DOM manipulation.
//!
//! Nothing here ever writes a password, private key, passphrase, or sudo
//! password to the database or a log line. Between steps they exist only
//! as hidden form fields in the rendered HTML and the next request's body
//! -- the same mechanism `confirm.html`'s existing `sudo_password` field
//! already uses for the single-step Apotheosis elevation confirm, just
//! spanning a couple of extra hops here. See `crate::ssh_deploy`'s module
//! comment for the in-memory-only guarantee once a deploy actually starts.

use std::sync::Arc;

use abyssal_agent_protocol::is_valid_ip_address;
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::Duration as ChronoDuration;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::ssh_deploy::{
    DeployJob, DeployTarget, HostDeployState, HostDeployStatus, RusshClient, SshAuthMethod,
    SshClient, SshCredentials, run_deploy_job,
};
use crate::state::AppState;
use crate::templates::{
    BaseCtx, DeployCredentialHostRow, DeployHostKeyRow, DeployStatusHostRow,
    PanopticonDeployCredentialsTemplate, PanopticonDeployHostKeysTemplate,
    PanopticonDeployStatusTemplate, PanopticonScanPickerTemplate, ScanPickerHostRow,
};
use crate::theme;

fn control_plane_base_url(state: &AppState, headers: &HeaderMap) -> String {
    let scheme = if state.config.cookie_secure {
        "https"
    } else {
        "http"
    };
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    format!("{scheme}://{host}")
}

/// Every `ip: Vec<String>` field crossing this flow's request boundaries
/// gets checked here before it's used for anything -- these values round-
/// trip through the browser as hidden form fields between steps, so a
/// tampered or hand-crafted request is the threat model, not just a typo.
fn validate_ips(ips: &[String]) -> Result<(), WebError> {
    if ips.is_empty() {
        return Err(WebError(AppError::Validation("No hosts selected.".into())));
    }
    if ips.iter().any(|ip| !is_valid_ip_address(ip)) {
        return Err(WebError(AppError::Validation(
            "One of the selected hosts is not a valid IP address.".into(),
        )));
    }
    Ok(())
}

/// A device's inventory `hostname` came from the scan's own reverse-DNS
/// lookup -- effectively attacker-influenced data (a device on the network
/// controls its own PTR record). `shell_quote` already makes it safe to
/// interpolate into a remote command, but this is defense in depth on top
/// of that: anything that doesn't look like a real RFC 1123 hostname is
/// dropped rather than trusted as the `--name` the agent registers under
/// (`deploy_one_host` falls back to the IP address either way).
fn sanitize_hostname(hostname: Option<String>) -> Option<String> {
    hostname.filter(|h| abyssal_agent_protocol::is_valid_hostname(h))
}

// ---------------------------------------------------------------------
// Step 1: picker (rendered from `routes/panopticon.rs::scan` on success,
// and re-rendered by `scan_picker_refresh` for "select all"/"none").
// ---------------------------------------------------------------------

/// Called right after a scan completes, straight from its own structured
/// results (`DiscoveredHost`, still fresh from the sink populated during
/// this same request) -- no extra database round trip needed.
pub(crate) async fn render_scan_picker_from_discovered(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    discovered: Vec<crate::panopticon_ops::DiscoveredHost>,
) -> Result<Response, WebError> {
    let hosts = discovered
        .into_iter()
        .map(|d| ScanPickerHostRow {
            ip: d.ip,
            hostname: d.hostname.unwrap_or_else(|| "-".to_string()),
            mac: d.mac.unwrap_or_else(|| "-".to_string()),
            checked: true,
        })
        .collect();
    render_picker_response(state, jar, ctx, hosts).await
}

/// Called by "select all"/"none" (`scan_picker_refresh`), which only has
/// the IP list surviving as hidden fields -- re-derives hostname/MAC from
/// the inventory (already upserted by the scan) rather than round-
/// tripping them through the form too.
pub(crate) async fn render_scan_picker(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    ips: Vec<String>,
    all_checked: bool,
) -> Result<Response, WebError> {
    let mut hosts = Vec::with_capacity(ips.len());
    for ip in ips {
        let device = repo::network_devices::find_by_ip(&state.pool, &ip).await?;
        hosts.push(ScanPickerHostRow {
            ip,
            hostname: device
                .as_ref()
                .and_then(|d| d.hostname.clone())
                .unwrap_or_else(|| "-".to_string()),
            mac: device
                .as_ref()
                .and_then(|d| d.mac_address.clone())
                .unwrap_or_else(|| "-".to_string()),
            checked: all_checked,
        });
    }
    render_picker_response(state, jar, ctx, hosts).await
}

async fn render_picker_response(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    hosts: Vec<ScanPickerHostRow>,
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

    let tpl = PanopticonScanPickerTemplate { base, hosts };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct ScanPickerRefreshForm {
    csrf_token: String,
    #[serde(default)]
    all_ips: Vec<String>,
    select: String,
}

pub async fn scan_picker_refresh(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ScanPickerRefreshForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    render_scan_picker(&state, &jar, &ctx, form.all_ips, form.select == "all").await
}

// ---------------------------------------------------------------------
// Step 2: credentials
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ScanPickerSubmitForm {
    csrf_token: String,
    #[serde(default)]
    selected_ips: Vec<String>,
}

pub async fn credentials_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<ScanPickerSubmitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    validate_ips(&form.selected_ips)?;

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

    let mut hosts = Vec::with_capacity(form.selected_ips.len());
    for ip in form.selected_ips {
        let device = repo::network_devices::find_by_ip(&state.pool, &ip).await?;
        hosts.push(DeployCredentialHostRow {
            ip,
            hostname: device
                .and_then(|d| d.hostname)
                .unwrap_or_else(|| "-".to_string()),
        });
    }

    let tpl = PanopticonDeployCredentialsTemplate {
        base,
        hosts,
        error: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

// ---------------------------------------------------------------------
// Shared credential-resolution: a per-host override (identified by a
// non-empty override username) replaces the shared set entirely for that
// host rather than merging field-by-field -- a half-shared, half-
// overridden credential would be confusing to reason about and easy to
// get wrong (e.g. a shared password paired with an overridden username
// that doesn't use it).
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn resolve_credentials(
    shared_username: &str,
    shared_auth_method: &str,
    shared_password: &str,
    shared_pem: &str,
    shared_passphrase: &str,
    shared_sudo_password: &str,
    override_username: &str,
    override_auth_method: &str,
    override_password: &str,
    override_pem: &str,
    override_passphrase: &str,
    override_sudo_password: &str,
) -> Result<SshCredentials, WebError> {
    let use_override = !override_username.trim().is_empty();
    let (username, auth_method, password, pem, passphrase, sudo_password) = if use_override {
        (
            override_username,
            override_auth_method,
            override_password,
            override_pem,
            override_passphrase,
            override_sudo_password,
        )
    } else {
        (
            shared_username,
            shared_auth_method,
            shared_password,
            shared_pem,
            shared_passphrase,
            shared_sudo_password,
        )
    };

    if username.trim().is_empty() {
        return Err(WebError(AppError::Validation(
            "An SSH username is required (shared, or per-host).".into(),
        )));
    }

    let auth = match auth_method {
        "private_key" => {
            if pem.trim().is_empty() {
                return Err(WebError(AppError::Validation(
                    "A private key is required when the auth method is \"private key\".".into(),
                )));
            }
            SshAuthMethod::PrivateKey {
                pem: Zeroizing::new(pem.to_string()),
                passphrase: if passphrase.is_empty() {
                    None
                } else {
                    Some(Zeroizing::new(passphrase.to_string()))
                },
            }
        }
        _ => {
            if password.is_empty() {
                return Err(WebError(AppError::Validation(
                    "A password is required when the auth method is \"password\".".into(),
                )));
            }
            SshAuthMethod::Password(Zeroizing::new(password.to_string()))
        }
    };

    Ok(SshCredentials {
        username: username.to_string(),
        auth,
        sudo_password: Zeroizing::new(sudo_password.to_string()),
    })
}

// ---------------------------------------------------------------------
// Step 3: host-key probe + review
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeployCredentialsSubmitForm {
    csrf_token: String,
    ip: Vec<String>,
    shared_username: String,
    #[serde(default)]
    shared_auth_method: String,
    #[serde(default)]
    shared_password: String,
    #[serde(default)]
    shared_pem: String,
    #[serde(default)]
    shared_passphrase: String,
    #[serde(default)]
    shared_sudo_password: String,
    #[serde(default)]
    shared_ssh_port: String,
    #[serde(default)]
    override_username: Vec<String>,
    #[serde(default)]
    override_auth_method: Vec<String>,
    #[serde(default)]
    override_password: Vec<String>,
    #[serde(default)]
    override_pem: Vec<String>,
    #[serde(default)]
    override_passphrase: Vec<String>,
    #[serde(default)]
    override_sudo_password: Vec<String>,
    #[serde(default)]
    override_ssh_port: Vec<String>,
}

/// Blank (not overridden) falls back to `shared`; blank in both falls back
/// to the standard SSH port. Never fails -- an unparseable value is just
/// treated as blank, since this is a convenience default, not an input a
/// bad value should hard-error the whole flow over.
fn resolve_ssh_port(shared: &str, host_override: &str) -> u16 {
    let value = if host_override.trim().is_empty() {
        shared.trim()
    } else {
        host_override.trim()
    };
    if value.is_empty() {
        22
    } else {
        value.parse::<u16>().ok().filter(|p| *p != 0).unwrap_or(22)
    }
}

/// One selected host, resolved and ready to deploy to -- used by both
/// `deploy_hostkeys`'s "every host already trusted" fast path and
/// `deploy_confirm`'s normal path.
struct ResolvedTarget {
    ip: String,
    hostname: Option<String>,
    fingerprint: String,
    ssh_port: u16,
    credentials: SshCredentials,
}

pub async fn deploy_hostkeys(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    headers: HeaderMap,
    Form(form): Form<DeployCredentialsSubmitForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    validate_ips(&form.ip)?;

    let client = RusshClient;
    let mut rows = Vec::with_capacity(form.ip.len());
    let mut resolved = Vec::with_capacity(form.ip.len());
    let mut any_deployable = false;

    for (i, ip) in form.ip.iter().enumerate() {
        let get = |v: &Vec<String>| v.get(i).cloned().unwrap_or_default();
        let override_username = get(&form.override_username);
        let override_auth_method = get(&form.override_auth_method);
        let override_password = get(&form.override_password);
        let override_pem = get(&form.override_pem);
        let override_passphrase = get(&form.override_passphrase);
        let override_sudo_password = get(&form.override_sudo_password);
        let override_ssh_port = get(&form.override_ssh_port);
        let ssh_port = resolve_ssh_port(&form.shared_ssh_port, &override_ssh_port);

        let device = repo::network_devices::find_by_ip(&state.pool, ip).await?;
        let hostname = device.and_then(|d| d.hostname);

        let probe = client.probe_host_key(ip, ssh_port).await;
        let (fingerprint, status_label, status_class, blocked) = match probe {
            Err(reason) => (
                String::new(),
                format!("Unreachable: {}", reason.message()),
                "badge-danger".to_string(),
                true,
            ),
            Ok(fingerprint) => {
                let trusted = repo::ssh_trusted_host_keys::trusted_fingerprint(&state.pool, ip)
                    .await
                    .unwrap_or(None);
                match trusted {
                    None => (
                        fingerprint,
                        "New -- review and confirm".to_string(),
                        "badge-warning".to_string(),
                        false,
                    ),
                    Some(known) if known == fingerprint => (
                        fingerprint,
                        "Already trusted".to_string(),
                        "badge-success".to_string(),
                        false,
                    ),
                    Some(known) => (
                        fingerprint.clone(),
                        format!(
                            "Host key CHANGED since it was last trusted (was {known}) -- \
                             not proceeding for this host"
                        ),
                        "badge-danger".to_string(),
                        true,
                    ),
                }
            }
        };

        if !blocked {
            any_deployable = true;
            if let Ok(credentials) = resolve_credentials(
                &form.shared_username,
                &form.shared_auth_method,
                &form.shared_password,
                &form.shared_pem,
                &form.shared_passphrase,
                &form.shared_sudo_password,
                &override_username,
                &override_auth_method,
                &override_password,
                &override_pem,
                &override_passphrase,
                &override_sudo_password,
            ) {
                resolved.push(ResolvedTarget {
                    ip: ip.clone(),
                    hostname: sanitize_hostname(hostname.clone()),
                    fingerprint: fingerprint.clone(),
                    ssh_port,
                    credentials,
                });
            }
        }

        rows.push(DeployHostKeyRow {
            ip: ip.clone(),
            hostname: hostname.unwrap_or_else(|| "-".to_string()),
            fingerprint,
            status_label,
            status_class,
            blocked,
            ssh_port,
            override_username,
            override_auth_method,
            override_password,
            override_pem,
            override_passphrase,
            override_sudo_password,
        });
    }

    // Every deployable host already has a matching trusted key -- nothing
    // new to show the admin, so skip straight to deploying instead of
    // rendering a review page with nothing to review (also means the
    // credentials spend one fewer hop as a hidden form field).
    let all_pre_trusted = any_deployable
        && rows
            .iter()
            .filter(|r| !r.blocked)
            .all(|r| r.status_label == "Already trusted");
    if all_pre_trusted && resolved.len() == form.ip.len() {
        return start_deploy_job(&state, &ctx, &headers, resolved).await;
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

    let tpl = PanopticonDeployHostKeysTemplate {
        base,
        rows,
        any_deployable,
        shared_username: form.shared_username,
        shared_auth_method: form.shared_auth_method,
        shared_password: form.shared_password,
        shared_pem: form.shared_pem,
        shared_passphrase: form.shared_passphrase,
        shared_sudo_password: form.shared_sudo_password,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

// ---------------------------------------------------------------------
// Step 4: deploy confirm -- trusts each new fingerprint, generates one
// enrollment token per host, starts the job.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeployConfirmForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    ip: Vec<String>,
    #[serde(default)]
    expected_fingerprint: Vec<String>,
    #[serde(default)]
    ssh_port: Vec<String>,
    shared_username: String,
    #[serde(default)]
    shared_auth_method: String,
    #[serde(default)]
    shared_password: String,
    #[serde(default)]
    shared_pem: String,
    #[serde(default)]
    shared_passphrase: String,
    #[serde(default)]
    shared_sudo_password: String,
    #[serde(default)]
    override_username: Vec<String>,
    #[serde(default)]
    override_auth_method: Vec<String>,
    #[serde(default)]
    override_password: Vec<String>,
    #[serde(default)]
    override_pem: Vec<String>,
    #[serde(default)]
    override_passphrase: Vec<String>,
    #[serde(default)]
    override_sudo_password: Vec<String>,
}

pub async fn deploy_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    headers: HeaderMap,
    Form(form): Form<DeployConfirmForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "The deploy was not confirmed.".into(),
        )));
    }
    validate_ips(&form.ip)?;
    if form.expected_fingerprint.len() != form.ip.len() {
        return Err(WebError(AppError::Validation(
            "Malformed deploy request (host/fingerprint count mismatch).".into(),
        )));
    }

    let mut resolved = Vec::with_capacity(form.ip.len());
    for (i, ip) in form.ip.iter().enumerate() {
        let get = |v: &Vec<String>| v.get(i).cloned().unwrap_or_default();
        let device = repo::network_devices::find_by_ip(&state.pool, ip).await?;
        let credentials = resolve_credentials(
            &form.shared_username,
            &form.shared_auth_method,
            &form.shared_password,
            &form.shared_pem,
            &form.shared_passphrase,
            &form.shared_sudo_password,
            &get(&form.override_username),
            &get(&form.override_auth_method),
            &get(&form.override_password),
            &get(&form.override_pem),
            &get(&form.override_passphrase),
            &get(&form.override_sudo_password),
        )?;
        resolved.push(ResolvedTarget {
            ip: ip.clone(),
            hostname: sanitize_hostname(device.and_then(|d| d.hostname)),
            fingerprint: form.expected_fingerprint[i].clone(),
            ssh_port: form
                .ssh_port
                .get(i)
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|p| *p != 0)
                .unwrap_or(22),
            credentials,
        });
    }

    start_deploy_job(&state, &ctx, &headers, resolved).await
}

async fn start_deploy_job(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
    headers: &HeaderMap,
    resolved: Vec<ResolvedTarget>,
) -> Result<Response, WebError> {
    // A changed/unconfirmed host key never reaches this point (excluded
    // upstream in `deploy_hostkeys`/`deploy_confirm`), so trusting here is
    // always either a first sighting or an unremarkable re-confirmation.
    for target in &resolved {
        let _ =
            repo::ssh_trusted_host_keys::trust(&state.pool, &target.ip, &target.fingerprint).await;
    }

    let base_url = control_plane_base_url(state, headers);
    let mut ssh_targets = Vec::with_capacity(resolved.len());
    let mut job_hosts = Vec::with_capacity(resolved.len());
    for target in resolved {
        let token = generate_token();
        let hash = hash_token(&token);
        repo::host_enrollment_tokens::create(
            &state.pool,
            &hash,
            Some(ctx.user.id),
            ChronoDuration::minutes(15),
        )
        .await?;

        job_hosts.push(HostDeployStatus {
            ip_address: target.ip.clone(),
            hostname: target.hostname.clone(),
            state: HostDeployState::Pending,
            output: String::new(),
        });
        ssh_targets.push((
            DeployTarget {
                ip_address: target.ip,
                hostname: target.hostname,
                ssh_port: target.ssh_port,
                credentials: target.credentials,
            },
            target.fingerprint,
            Zeroizing::new(token),
        ));
    }

    let job_id = Uuid::new_v4();
    let job = Arc::new(tokio::sync::RwLock::new(DeployJob {
        id: job_id,
        hosts: job_hosts,
    }));
    state.deploy_jobs.write().await.insert(job_id, job.clone());

    tokio::spawn(run_deploy_job(
        Arc::new(RusshClient),
        state.pool.clone(),
        state.hosts.clone(),
        job,
        ssh_targets,
        base_url,
        crate::update_check::CURRENT_VERSION.trim().to_string(),
        crate::ssh_deploy::DEFAULT_CONCURRENCY,
        ctx.user.id,
        ctx.user.username.clone(),
    ));

    Ok(Redirect::to(&format!("/arsenals/panopticon/deploy/status/{job_id}")).into_response())
}

// ---------------------------------------------------------------------
// Step 5: status page (auto-refreshes until every host is terminal)
// ---------------------------------------------------------------------

pub async fn deploy_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(job_id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;

    let job = state
        .deploy_jobs
        .read()
        .await
        .get(&job_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let job = job.read().await;

    let hosts = job
        .hosts
        .iter()
        .map(|h| {
            let failure_detail = match &h.state {
                HostDeployState::Failed(reason) => Some(reason.message()),
                _ => None,
            };
            DeployStatusHostRow {
                ip_address: h.ip_address.clone(),
                hostname: h.hostname.clone(),
                state_label: h.state.label().to_string(),
                state_class: state_badge_class(&h.state),
                is_terminal: h.state.is_terminal(),
                failure_detail,
                output: h.output.clone(),
            }
        })
        .collect();
    let complete = job.is_complete();

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

    let tpl = PanopticonDeployStatusTemplate {
        base,
        job_id: job_id.to_string(),
        hosts,
        complete,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

fn state_badge_class(state: &HostDeployState) -> String {
    match state {
        HostDeployState::Succeeded => "badge-success",
        HostDeployState::Failed(_) => "badge-danger",
        HostDeployState::Pending => "badge-muted",
        _ => "badge-warning",
    }
    .to_string()
}
