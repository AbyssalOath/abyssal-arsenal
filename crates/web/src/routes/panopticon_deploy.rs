//! "Quick Add Host From Network Scan" (GitHub issue #5): picker -> SSH
//! credentials -> host-key review -> deploy status. The picker, credentials,
//! and host-key review steps are plain server-rendered pages with no
//! client-side JS at all, so "select all"/"none" on the picker and "confirm
//! and deploy" on the host-key review page work by resubmitting a normal
//! HTML form back to this crate rather than by DOM manipulation. The final
//! deploy status page (`deploy_status`) is one of only two pages in this
//! whole app with any client-side JS -- a small, scoped polling script that
//! updates a progress bar and each host's row in place (`deploy_status_json`
//! is what it polls), added deliberately as an exception to the
//! server-rendered-only house style everywhere else; it still degrades to a
//! `<meta http-equiv="refresh">` reload if JS never runs at all.
//!
//! Nothing here ever writes a password, private key, passphrase, or sudo
//! password to the database or a log line. Between steps they exist only
//! as hidden form fields in the rendered HTML and the next request's body
//! -- the same mechanism `confirm.html`'s existing `sudo_password` field
//! already uses for the single-step Apotheosis elevation confirm, just
//! spanning a couple of extra hops here. See `crate::ssh_deploy`'s module
//! comment for the in-memory-only guarantee once a deploy actually starts.

use std::collections::HashMap;
use std::sync::Arc;

use abyssal_agent_protocol::is_valid_ip_address;
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::Duration as ChronoDuration;
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

/// Manually parses a form body into a multi-map, one entry per distinct
/// key. `axum::Form<T>` (backed by `serde_urlencoded`) cannot deserialize a
/// `Vec<String>` field from repeated `key=a&key=b` occurrences the way a
/// checkbox group or a repeated hidden field actually submits -- it treats
/// a single occurrence as a bare scalar and fails with "invalid type:
/// string ..., expected a sequence" the moment there's more than one
/// selected host. `routes/roles.rs::update_permissions` hit and fixed this
/// exact error first; every handler below with a repeated-key field
/// follows the same fix (parse the raw body by hand) instead.
struct FormFields(HashMap<String, Vec<String>>);

impl FormFields {
    fn parse(body: &[u8]) -> Self {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (key, value) in form_urlencoded::parse(body) {
            map.entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        Self(map)
    }

    /// The first value submitted under `key`, or an empty string if it
    /// wasn't present at all -- mirrors a plain `String` field with
    /// `#[serde(default)]`.
    fn one(&self, key: &str) -> String {
        self.0
            .get(key)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    }

    /// Every value submitted under `key`, in submission order -- mirrors a
    /// `Vec<String>` field, without the limitation above.
    fn many(&self, key: &str) -> Vec<String> {
        self.0.get(key).cloned().unwrap_or_default()
    }
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
    rescan_notice: Option<String>,
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
    render_picker_response(state, jar, ctx, hosts, rescan_notice).await
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
    rescan_notice: Option<String>,
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
    render_picker_response(state, jar, ctx, hosts, rescan_notice).await
}

async fn render_picker_response(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    hosts: Vec<ScanPickerHostRow>,
    rescan_notice: Option<String>,
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

    let tpl = PanopticonScanPickerTemplate {
        base,
        hosts,
        rescan_notice,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn scan_picker_refresh(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    body: Bytes,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    let fields = FormFields::parse(&body);
    require_csrf(&jar, &fields.one("csrf_token"))?;
    let all_ips = fields.many("all_ips");
    let rescan_notice = {
        let n = fields.one("rescan_notice");
        if n.is_empty() { None } else { Some(n) }
    };
    let all_checked = fields.one("select") == "all";
    render_scan_picker(&state, &jar, &ctx, all_ips, all_checked, rescan_notice).await
}

// ---------------------------------------------------------------------
// Step 2: credentials
// ---------------------------------------------------------------------

pub async fn credentials_form(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    body: Bytes,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    let fields = FormFields::parse(&body);
    require_csrf(&jar, &fields.one("csrf_token"))?;
    let selected_ips = fields.many("selected_ips");
    validate_ips(&selected_ips)?;

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

    let mut hosts = Vec::with_capacity(selected_ips.len());
    for ip in selected_ips {
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
    shared_sudo_same_as_password: bool,
    override_username: &str,
    override_auth_method: &str,
    override_password: &str,
    override_pem: &str,
    override_passphrase: &str,
    override_sudo_password: &str,
    override_sudo_same_as_password: bool,
) -> Result<SshCredentials, WebError> {
    let use_override = !override_username.trim().is_empty();
    let (username, auth_method, password, pem, passphrase, sudo_password, sudo_same_as_password) =
        if use_override {
            (
                override_username,
                override_auth_method,
                override_password,
                override_pem,
                override_passphrase,
                override_sudo_password,
                override_sudo_same_as_password,
            )
        } else {
            (
                shared_username,
                shared_auth_method,
                shared_password,
                shared_pem,
                shared_passphrase,
                shared_sudo_password,
                shared_sudo_same_as_password,
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

    // "Same as SSH password" only makes sense in Password auth mode --
    // there's no SSH password to reuse when logging in with a key, so the
    // checkbox is a no-op there and the dedicated sudo password field
    // (possibly empty, for NOPASSWD sudo) still applies.
    let resolved_sudo_password = if sudo_same_as_password && auth_method != "private_key" {
        password
    } else {
        sudo_password
    };

    Ok(SshCredentials {
        username: username.to_string(),
        auth,
        sudo_password: Zeroizing::new(resolved_sudo_password.to_string()),
    })
}

// ---------------------------------------------------------------------
// Step 3: host-key probe + review
// ---------------------------------------------------------------------

pub struct DeployCredentialsSubmitForm {
    csrf_token: String,
    ip: Vec<String>,
    shared_username: String,
    shared_auth_method: String,
    shared_password: String,
    shared_pem: String,
    shared_passphrase: String,
    shared_sudo_password: String,
    shared_sudo_same_as_password: bool,
    shared_ssh_port: String,
    override_username: Vec<String>,
    override_auth_method: Vec<String>,
    override_password: Vec<String>,
    override_pem: Vec<String>,
    override_passphrase: Vec<String>,
    override_sudo_password: Vec<String>,
    override_sudo_same_as_password: Vec<bool>,
    override_ssh_port: Vec<String>,
}

impl DeployCredentialsSubmitForm {
    fn from_fields(fields: &FormFields) -> Self {
        let ip = fields.many("ip");
        // Auth method and "same as SSH password" are radios/checkboxes,
        // not text fields -- an unchecked control simply doesn't submit
        // at all, so a same-named field repeated across host rows can't
        // be positionally aligned back to `ip` the way the plain text
        // override_* fields below are (see `FormFields`'s own doc
        // comment). Each row's markup instead gives these two an
        // index-suffixed name (`override_auth_method_0`, `_1`, ...), read
        // back here by that same index.
        let override_auth_method = (0..ip.len())
            .map(|i| {
                let value = fields.one(&format!("override_auth_method_{i}"));
                if value.is_empty() {
                    "password".to_string()
                } else {
                    value
                }
            })
            .collect();
        let override_sudo_same_as_password = (0..ip.len())
            .map(|i| fields.one(&format!("override_sudo_same_as_password_{i}")) == "true")
            .collect();
        Self {
            csrf_token: fields.one("csrf_token"),
            shared_username: fields.one("shared_username"),
            shared_auth_method: fields.one("shared_auth_method"),
            shared_password: fields.one("shared_password"),
            shared_pem: fields.one("shared_pem"),
            shared_passphrase: fields.one("shared_passphrase"),
            shared_sudo_password: fields.one("shared_sudo_password"),
            shared_sudo_same_as_password: fields.one("shared_sudo_same_as_password") == "true",
            shared_ssh_port: fields.one("shared_ssh_port"),
            override_username: fields.many("override_username"),
            override_auth_method,
            override_password: fields.many("override_password"),
            override_pem: fields.many("override_pem"),
            override_passphrase: fields.many("override_passphrase"),
            override_sudo_password: fields.many("override_sudo_password"),
            override_sudo_same_as_password,
            override_ssh_port: fields.many("override_ssh_port"),
            ip,
        }
    }
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
    body: Bytes,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    let form = DeployCredentialsSubmitForm::from_fields(&FormFields::parse(&body));
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
        let override_sudo_same_as_password = form
            .override_sudo_same_as_password
            .get(i)
            .copied()
            .unwrap_or(false);
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
                form.shared_sudo_same_as_password,
                &override_username,
                &override_auth_method,
                &override_password,
                &override_pem,
                &override_passphrase,
                &override_sudo_password,
                override_sudo_same_as_password,
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
            override_sudo_same_as_password,
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
        shared_sudo_same_as_password: form.shared_sudo_same_as_password,
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

pub struct DeployConfirmForm {
    csrf_token: String,
    confirm: bool,
    ip: Vec<String>,
    expected_fingerprint: Vec<String>,
    ssh_port: Vec<String>,
    shared_username: String,
    shared_auth_method: String,
    shared_password: String,
    shared_pem: String,
    shared_passphrase: String,
    shared_sudo_password: String,
    shared_sudo_same_as_password: bool,
    override_username: Vec<String>,
    override_auth_method: Vec<String>,
    override_password: Vec<String>,
    override_pem: Vec<String>,
    override_passphrase: Vec<String>,
    override_sudo_password: Vec<String>,
    override_sudo_same_as_password: Vec<bool>,
}

impl DeployConfirmForm {
    fn from_fields(fields: &FormFields) -> Self {
        Self {
            csrf_token: fields.one("csrf_token"),
            confirm: fields.one("confirm") == "true",
            ip: fields.many("ip"),
            expected_fingerprint: fields.many("expected_fingerprint"),
            ssh_port: fields.many("ssh_port"),
            shared_username: fields.one("shared_username"),
            shared_auth_method: fields.one("shared_auth_method"),
            shared_password: fields.one("shared_password"),
            shared_pem: fields.one("shared_pem"),
            shared_passphrase: fields.one("shared_passphrase"),
            shared_sudo_password: fields.one("shared_sudo_password"),
            shared_sudo_same_as_password: fields.one("shared_sudo_same_as_password") == "true",
            override_username: fields.many("override_username"),
            override_auth_method: fields.many("override_auth_method"),
            override_password: fields.many("override_password"),
            override_pem: fields.many("override_pem"),
            override_passphrase: fields.many("override_passphrase"),
            override_sudo_password: fields.many("override_sudo_password"),
            override_sudo_same_as_password: fields
                .many("override_sudo_same_as_password")
                .iter()
                .map(|v| v == "true")
                .collect(),
        }
    }
}

pub async fn deploy_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    let form = DeployConfirmForm::from_fields(&FormFields::parse(&body));
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
        let override_sudo_same_as_password = form
            .override_sudo_same_as_password
            .get(i)
            .copied()
            .unwrap_or(false);
        let credentials = resolve_credentials(
            &form.shared_username,
            &form.shared_auth_method,
            &form.shared_password,
            &form.shared_pem,
            &form.shared_passphrase,
            &form.shared_sudo_password,
            form.shared_sudo_same_as_password,
            &get(&form.override_username),
            &get(&form.override_auth_method),
            &get(&form.override_password),
            &get(&form.override_pem),
            &get(&form.override_passphrase),
            &get(&form.override_sudo_password),
            override_sudo_same_as_password,
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
            // Provisional -- whatever the inventory had pre-deploy, or the
            // IP if nothing. `deploy_one_host` replaces this the moment
            // the host answers its own `hostname` command.
            hostname_is_fallback: target.hostname.is_none(),
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
// Step 5: status page (progress bar + live per-host updates via
// deploy_status_json, until every host is terminal)
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
                hostname_is_fallback: h.hostname_is_fallback,
                state_label: h.state.label().to_string(),
                state_class: state_badge_class(&h.state),
                is_terminal: h.state.is_terminal(),
                failure_detail,
                output: h.output.clone(),
            }
        })
        .collect();
    let complete = job.is_complete();
    let (hosts_terminal, percent) = deploy_job_progress(&job.hosts);

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
        hosts_terminal,
        percent,
        complete,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

/// Polled by the status page's own `<script>` -- the second (after
/// Panopticon's scan progress) and, per this app's house style, last JSON
/// endpoint anywhere in it, both existing specifically so their pages can
/// update smoothly instead of a full-page `<meta refresh>`.
pub async fn deploy_status_json(
    State(state): State<AppState>,
    CurrentUser(ctx): CurrentUser,
    Path(job_id): Path<Uuid>,
) -> Result<axum::Json<serde_json::Value>, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;

    let job = state
        .deploy_jobs
        .read()
        .await
        .get(&job_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let job = job.read().await;

    let hosts: Vec<serde_json::Value> = job
        .hosts
        .iter()
        .map(|h| {
            let failure_detail = match &h.state {
                HostDeployState::Failed(reason) => Some(reason.message()),
                _ => None,
            };
            serde_json::json!({
                "ip_address": h.ip_address,
                "hostname": h.hostname,
                "hostname_is_fallback": h.hostname_is_fallback,
                "state_label": h.state.label(),
                "state_class": state_badge_class(&h.state),
                "is_terminal": h.state.is_terminal(),
                "failure_detail": failure_detail,
                "output": h.output,
            })
        })
        .collect();
    let (hosts_terminal, _) = deploy_job_progress(&job.hosts);

    Ok(axum::Json(serde_json::json!({
        "complete": job.is_complete(),
        "hosts_total": job.hosts.len(),
        "hosts_terminal": hosts_terminal,
        "hosts": hosts,
    })))
}

/// `(hosts that have reached a terminal state, 0-100 percent complete)`.
/// Shared between the status page's own initial render and the JSON
/// endpoint it polls, so the two never compute this differently.
fn deploy_job_progress(hosts: &[HostDeployStatus]) -> (usize, u8) {
    let total = hosts.len();
    let terminal = hosts.iter().filter(|h| h.state.is_terminal()).count();
    let percent = terminal
        .checked_mul(100)
        .and_then(|v| v.checked_div(total))
        .unwrap_or(100) as u8;
    (terminal, percent)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn shared_only(
        username: &str,
        auth_method: &str,
        password: &str,
        pem: &str,
        passphrase: &str,
        sudo_password: &str,
        sudo_same_as_password: bool,
    ) -> Result<SshCredentials, WebError> {
        resolve_credentials(
            username,
            auth_method,
            password,
            pem,
            passphrase,
            sudo_password,
            sudo_same_as_password,
            "",
            "",
            "",
            "",
            "",
            "",
            false,
        )
    }

    // -------------------------------------------------------------
    // "Same as SSH password" (Phase 3c)
    // -------------------------------------------------------------

    #[test]
    fn sudo_same_as_password_reuses_the_ssh_password() {
        let creds = shared_only(
            "admin",
            "password",
            "hunter2",
            "",
            "",
            "some-other-value-that-should-be-ignored",
            true,
        )
        .ok()
        .unwrap();
        assert_eq!(creds.sudo_password.as_str(), "hunter2");
    }

    #[test]
    fn sudo_same_as_password_false_keeps_the_dedicated_field() {
        let creds = shared_only("admin", "password", "hunter2", "", "", "realsudopw", false)
            .ok()
            .unwrap();
        assert_eq!(creds.sudo_password.as_str(), "realsudopw");
    }

    #[test]
    fn sudo_same_as_password_is_a_no_op_in_key_auth_mode() {
        // No SSH password exists to reuse when logging in with a key -- the
        // checkbox must not silently blank out sudo access in that mode.
        let creds = shared_only(
            "admin",
            "private_key",
            "",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
            "",
            "realsudopw",
            true,
        )
        .ok()
        .unwrap();
        assert_eq!(creds.sudo_password.as_str(), "realsudopw");
    }

    // -------------------------------------------------------------
    // Per-host override precedence, now with the extra sudo_same_as_password
    // field threaded alongside the rest (Phase 3d).
    // -------------------------------------------------------------

    #[test]
    fn override_uses_its_own_sudo_same_as_password_not_the_shared_one() {
        let creds = resolve_credentials(
            "shared-user",
            "password",
            "shared-pw",
            "",
            "",
            "shared-sudo",
            false,
            "override-user",
            "password",
            "override-pw",
            "",
            "",
            "ignored-because-overridden",
            true,
        )
        .ok()
        .unwrap();
        assert_eq!(creds.username, "override-user");
        assert_eq!(creds.sudo_password.as_str(), "override-pw");
    }

    #[test]
    fn no_override_username_falls_back_to_shared_sudo_same_as_password() {
        let creds = resolve_credentials(
            "shared-user",
            "password",
            "shared-pw",
            "",
            "",
            "ignored-because-same-as-password",
            true,
            "",
            "",
            "",
            "",
            "",
            "",
            false,
        )
        .ok()
        .unwrap();
        assert_eq!(creds.username, "shared-user");
        assert_eq!(creds.sudo_password.as_str(), "shared-pw");
    }

    // -------------------------------------------------------------
    // deploy_job_progress -- backs both the status page's own initial
    // render and the JSON endpoint it polls (Phase 4's deploy status
    // progress bar), so the two must always agree.
    // -------------------------------------------------------------

    fn host_status(state: HostDeployState) -> HostDeployStatus {
        HostDeployStatus {
            ip_address: "10.0.0.1".to_string(),
            hostname: None,
            state,
            output: String::new(),
            hostname_is_fallback: true,
        }
    }

    #[test]
    fn progress_is_zero_percent_with_nothing_terminal_yet() {
        let hosts = vec![
            host_status(HostDeployState::Pending),
            host_status(HostDeployState::Connecting),
        ];
        assert_eq!(deploy_job_progress(&hosts), (0, 0));
    }

    #[test]
    fn progress_counts_both_success_and_failure_as_terminal() {
        let hosts = vec![
            host_status(HostDeployState::Succeeded),
            host_status(HostDeployState::Failed(
                crate::ssh_deploy::DeployFailureReason::NeverCheckedIn,
            )),
            host_status(HostDeployState::Installing),
        ];
        assert_eq!(deploy_job_progress(&hosts), (2, 66));
    }

    #[test]
    fn progress_is_100_percent_once_every_host_is_terminal() {
        let hosts = vec![
            host_status(HostDeployState::Succeeded),
            host_status(HostDeployState::Succeeded),
        ];
        assert_eq!(deploy_job_progress(&hosts), (2, 100));
    }

    #[test]
    fn progress_is_100_percent_for_an_empty_job_rather_than_dividing_by_zero() {
        assert_eq!(deploy_job_progress(&[]), (0, 100));
    }
}
