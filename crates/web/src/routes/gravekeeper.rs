//! Gravekeeper: Active Directory management across a domain or forest. Unlike
//! the per-host arsenals, Gravekeeper is **domain-scoped** -- its landing page
//! lists the configured AD domains, and directory changes run on each domain's
//! write DC through the Haruspex DC agent under a delegated service account
//! (see `docs/roadmap/ad-management.md`).
//!
//! Milestone M2 (this file): first-run setup. An admin with
//! `directory.configure` picks a connected Windows DC, discovers the forest
//! (`DirectoryDiscoverForest`), adds the domains to manage, and for each one
//! enters a delegated service account that is validated with
//! `DirectoryTestDelegation` -- refused if it can't bind or is a member of the
//! privileged groups -- before its password is sealed and stored. Until a
//! domain has a validated service account it stays read-only. Browsing and the
//! help-desk actions arrive in M3/M4.

use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::settings::GRAVEKEEPER_SETUP_COMPLETED;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Deserializer};
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, GravekeeperDomainDetail, GravekeeperDomainRow, GravekeeperDomainTemplate,
    GravekeeperForestDomainView, GravekeeperForestView, GravekeeperSetupTemplate,
    GravekeeperTemplate,
};
use crate::theme;

const DISCOVER_TIMEOUT: Duration = Duration::from_secs(60);
const DELEGATION_TIMEOUT: Duration = Duration::from_secs(90);

// --- Agent JSON output (parsed on the control plane) -----------------------

/// Accepts a JSON field that PowerShell's `ConvertTo-Json` may emit as a single
/// value, a list, or null (a one-element array serializes as a bare object),
/// always yielding a `Vec`.
pub(crate) fn one_or_many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(d)? {
        Some(OneOrMany::Many(v)) => v,
        Some(OneOrMany::One(x)) => vec![x],
        None => Vec::new(),
    })
}

#[derive(Deserialize)]
struct ForestInfo {
    #[serde(default)]
    forest_root: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    upn_suffixes: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    domains: Vec<ForestDomainInfo>,
}

#[derive(Deserialize)]
struct ForestDomainInfo {
    dns: String,
    #[serde(default)]
    netbios: Option<String>,
    #[serde(default)]
    pdc: Option<String>,
    #[serde(default)]
    forest_root: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DelegationResult {
    #[serde(default)]
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) account_found: bool,
    #[serde(default, deserialize_with = "one_or_many")]
    pub(crate) overprivileged_groups: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub(crate) manageable_ous: Vec<String>,
}

/// One OU from `DirectoryOuTree` (`Select-Object Name, DistinguishedName`).
#[derive(Deserialize)]
struct OuEntry {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "DistinguishedName", default)]
    dn: String,
}

/// One hit from `DirectorySearch`.
#[derive(Deserialize)]
struct SearchHit {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    sam: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    dn: String,
    #[serde(default)]
    enabled: Option<bool>,
}

/// One object's full detail from `DirectoryGetObject`.
#[derive(Deserialize)]
struct ObjectInfo {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    sam: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    dn: String,
    #[serde(default)]
    display: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    locked: Option<bool>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    department: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    last_logon: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    dns: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    groups: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    members: Vec<String>,
}

/// Parses an agent JSON list that may be empty (no stdout), a single object (a
/// one-element `ConvertTo-Json` array), or a real array.
fn parse_list<T: for<'de> Deserialize<'de>>(stdout: &str) -> Result<Vec<T>, serde_json::Error> {
    let s = stdout.trim();
    if s.is_empty() || s == "null" {
        return Ok(Vec::new());
    }
    match serde_json::from_str::<Vec<T>>(s) {
        Ok(v) => Ok(v),
        Err(_) => serde_json::from_str::<T>(s).map(|one| vec![one]),
    }
}

// --- Helpers ---------------------------------------------------------------

/// Active, connected hosts that report Windows -- the candidate DC agents.
async fn connected_windows_hosts(state: &AppState) -> anyhow::Result<Vec<(String, String)>> {
    Ok(repo::hosts::list(&state.pool)
        .await?
        .into_iter()
        .filter(|h| {
            h.is_active() && state.hosts.is_connected(h.id) && h.os.as_deref() == Some("windows")
        })
        .map(|h| (h.id.to_string(), h.name))
        .collect())
}

/// The default disabled-users OU DN for a domain: `OU=Disabled Users` at the
/// domain root (`corp.example.com` -> `OU=Disabled Users,DC=corp,DC=example,DC=com`).
fn default_disabled_ou(dns_name: &str) -> String {
    let dc = dns_name
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("OU=Disabled Users,{dc}")
}

/// Dispatches a (read) directory operation to a host and returns its JSON
/// stdout, or a human error. `directory.configure` is the required permission.
async fn dispatch_directory(
    state: &AppState,
    ctx: &AuthContext,
    host_id: Uuid,
    host_name: &str,
    operation: AgentOperation,
    required_permission: Permission,
    timeout: Duration,
) -> Result<String, String> {
    state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            host_name,
            operation,
            required_permission,
            OperationKind::Read,
            false,
            timeout,
            None,
            false,
        )
        .await
        .map(|o| o.stdout)
        .map_err(|e| e.to_string())
}

async fn build_base(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
) -> Result<
    (
        BaseCtx,
        Option<axum_extra::extract::cookie::Cookie<'static>>,
    ),
    WebError,
> {
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
    Ok((base, new_cookie))
}

fn respond(
    jar: &CookieJar,
    new_cookie: Option<axum_extra::extract::cookie::Cookie<'static>>,
    tpl: impl IntoResponse,
) -> Response {
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    (jar, tpl).into_response()
}

// --- Landing ---------------------------------------------------------------

/// Landing page: the configured AD domains and their state. `directory.view`.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryView)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;

    let hosts = repo::hosts::list(&state.pool).await?;
    let host_name =
        |id: Uuid| -> Option<String> { hosts.iter().find(|h| h.id == id).map(|h| h.name.clone()) };

    let domains: Vec<GravekeeperDomainRow> = repo::directory::list(&state.pool)
        .await?
        .into_iter()
        .map(|d| {
            let delegation = delegation_label(d.has_service_account, d.last_delegation_ok);
            let writable = d.is_writable();
            GravekeeperDomainRow {
                id: d.id.to_string(),
                dns_name: d.dns_name,
                netbios_name: d.netbios_name.unwrap_or_default(),
                forest_root: d.forest_root.unwrap_or_default(),
                write_dc: d.write_dc_host_id.and_then(host_name).unwrap_or_default(),
                service_account: d.service_account_upn.unwrap_or_default(),
                writable,
                delegation,
            }
        })
        .collect();

    let setup_completed =
        repo::settings::get_bool(&state.pool, GRAVEKEEPER_SETUP_COMPLETED, false).await?;

    let tpl = GravekeeperTemplate {
        base,
        setup_completed,
        can_configure: ctx.has(Permission::DirectoryConfigure),
        can_manage: ctx.has(Permission::DirectoryManage),
        domains,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

fn delegation_label(has_account: bool, ok: Option<bool>) -> String {
    match (has_account, ok) {
        (false, _) => "No service account".to_string(),
        (true, Some(true)) => "Delegation verified".to_string(),
        (true, Some(false)) => "Delegation failed".to_string(),
        (true, None) => "Not yet checked".to_string(),
    }
}

// --- Setup: pick a DC, discover the forest ---------------------------------

/// GET the setup page: a connected-DC picker. `directory.configure`.
pub async fn setup(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let tpl = GravekeeperSetupTemplate {
        base,
        hosts: connected_windows_hosts(&state).await?,
        selected_host: String::new(),
        forest: None,
        error: None,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct DiscoverForm {
    csrf_token: String,
    host_id: String,
}

/// POST: run forest discovery on the chosen DC and render what it found.
pub async fn discover(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<DiscoverForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    require_csrf(&jar, &form.csrf_token)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;

    let hosts = connected_windows_hosts(&state).await?;
    let host_id = Uuid::parse_str(form.host_id.trim()).ok();
    let host = match host_id {
        Some(id) => repo::hosts::find_by_id(&state.pool, id).await?,
        None => None,
    };
    let Some(host) = host else {
        let tpl = GravekeeperSetupTemplate {
            base,
            hosts,
            selected_host: form.host_id,
            forest: None,
            error: Some("Pick a connected domain controller to discover from.".to_string()),
        };
        return Ok(respond(&jar, new_cookie, tpl));
    };

    let (forest, error) = match dispatch_directory(
        &state,
        &ctx,
        host.id,
        &host.name,
        AgentOperation::DirectoryDiscoverForest,
        Permission::DirectoryConfigure,
        DISCOVER_TIMEOUT,
    )
    .await
    {
        Ok(stdout) => match serde_json::from_str::<ForestInfo>(stdout.trim()) {
            Ok(info) => (Some(forest_view(&state, &info, host.id).await?), None),
            Err(e) => (
                None,
                Some(format!(
                    "The DC answered, but its forest report couldn't be read ({e}). Is the \
                     ActiveDirectory PowerShell module present on {}?",
                    host.name
                )),
            ),
        },
        Err(e) => (None, Some(e)),
    };

    let tpl = GravekeeperSetupTemplate {
        base,
        hosts,
        selected_host: host.id.to_string(),
        forest,
        error,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

async fn forest_view(
    state: &AppState,
    info: &ForestInfo,
    host_id: Uuid,
) -> anyhow::Result<GravekeeperForestView> {
    let mut domains = Vec::new();
    for d in &info.domains {
        let already = repo::directory::find_by_dns(&state.pool, &d.dns)
            .await?
            .is_some();
        domains.push(GravekeeperForestDomainView {
            dns: d.dns.clone(),
            netbios: d.netbios.clone().unwrap_or_default(),
            pdc: d.pdc.clone().unwrap_or_default(),
            already_configured: already,
        });
    }
    Ok(GravekeeperForestView {
        host_id: host_id.to_string(),
        forest_root: info.forest_root.clone().unwrap_or_default(),
        upn_suffixes: info.upn_suffixes.clone(),
        domains,
    })
}

#[derive(Deserialize)]
pub struct AddDomainsForm {
    csrf_token: String,
    host_id: String,
    /// The DNS names the admin checked. Absent when none are selected.
    #[serde(default)]
    domains: Vec<String>,
}

/// POST: add the selected discovered domains. Re-runs discovery on the DC so
/// each domain's NetBIOS/PDC/forest-root come from the DC, never the client.
pub async fn add_domains(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<AddDomainsForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host_id = Uuid::parse_str(form.host_id.trim())
        .map_err(|_| WebError(AppError::Validation("Unknown domain controller.".into())))?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // The write DC a domain is bound to must be a host we actually manage and
    // can reach -- never an arbitrary id. A stored service-account credential is
    // later shipped to this host (the daily re-check and M4 writes), so binding
    // a domain to an unconnected or non-Windows host is refused here, not just
    // at dispatch time. (`upsert` additionally clears any stored credential if a
    // domain's write DC changes, forcing re-validation on the new DC.)
    if !(host.is_active()
        && state.hosts.is_connected(host.id)
        && host.os.as_deref() == Some("windows"))
    {
        return Err(WebError(AppError::Validation(
            "That domain controller isn't a connected Windows host. Pick one from the list.".into(),
        )));
    }

    if form.domains.is_empty() {
        return Ok(Redirect::to("/arsenals/gravekeeper/setup").into_response());
    }

    let stdout = dispatch_directory(
        &state,
        &ctx,
        host.id,
        &host.name,
        AgentOperation::DirectoryDiscoverForest,
        Permission::DirectoryConfigure,
        DISCOVER_TIMEOUT,
    )
    .await
    .map_err(|e| WebError(AppError::Validation(e)))?;
    let info: ForestInfo = serde_json::from_str(stdout.trim()).map_err(|e| {
        WebError(AppError::Validation(format!(
            "Couldn't read the forest: {e}"
        )))
    })?;

    for dns in &form.domains {
        let Some(d) = info.domains.iter().find(|d| &d.dns == dns) else {
            continue; // not in what the DC actually reported -- ignore
        };
        if !abyssal_agent_protocol::is_valid_hostname(&d.dns) {
            continue;
        }
        let id = repo::directory::upsert(
            &state.pool,
            &repo::directory::NewDirectoryDomain {
                dns_name: &d.dns,
                netbios_name: d.netbios.as_deref(),
                forest_root: d.forest_root.as_deref().or(info.forest_root.as_deref()),
                write_dc_host_id: Some(host.id),
                created_by: Some(ctx.user.id),
            },
        )
        .await?;
        record_audit(
            &state,
            &ctx,
            AuditAction::DirectoryDomainConfigured,
            &d.dns,
            serde_json::json!({ "domain_id": id.to_string(), "write_dc": host.name }),
        )
        .await;
    }

    // First-run setup has now produced at least one domain.
    repo::settings::set(
        &state.pool,
        GRAVEKEEPER_SETUP_COMPLETED,
        serde_json::json!(true),
        Some(ctx.user.id),
    )
    .await?;

    Ok(Redirect::to("/arsenals/gravekeeper").into_response())
}

// --- Domain detail: service account + config -------------------------------

/// GET a configured domain's detail/config page. `directory.configure`.
pub async fn domain_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    render_domain(&state, &jar, &ctx, id, None, None).await
}

async fn render_domain(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    id: Uuid,
    result: Option<String>,
    error: Option<String>,
) -> Result<Response, WebError> {
    let (base, new_cookie) = build_base(state, jar, ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let write_dc = match domain.write_dc_host_id {
        Some(hid) => repo::hosts::find_by_id(&state.pool, hid)
            .await?
            .map(|h| h.name)
            .unwrap_or_default(),
        None => String::new(),
    };

    // Manageable OUs come from the last delegation check's detail.
    let manageable_ous = match repo::directory::delegation_detail(&state.pool, id).await? {
        Some(json) => serde_json::from_str::<DelegationResult>(&json)
            .map(|r| r.manageable_ous)
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let detail = GravekeeperDomainDetail {
        id: domain.id.to_string(),
        dns_name: domain.dns_name.clone(),
        netbios: domain.netbios_name.unwrap_or_default(),
        forest_root: domain.forest_root.unwrap_or_default(),
        write_dc,
        service_account: domain.service_account_upn.unwrap_or_default(),
        writable: domain.has_service_account && domain.last_delegation_ok == Some(true),
        delegation: delegation_label(domain.has_service_account, domain.last_delegation_ok),
        disabled_ou: domain.disabled_ou.unwrap_or_default(),
        deletion_grace_days: domain.deletion_grace_days,
    };

    let tpl = GravekeeperDomainTemplate {
        base,
        default_disabled_ou: default_disabled_ou(&domain.dns_name),
        manageable_ous,
        domain: detail,
        result,
        error,
    };
    Ok(respond(jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct ServiceAccountForm {
    csrf_token: String,
    upn: String,
    password: String,
}

/// POST: validate a delegated service account against the domain's write DC and
/// store it only if the check passes and it is not overprivileged.
pub async fn set_service_account(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ServiceAccountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    require_csrf(&jar, &form.csrf_token)?;

    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let upn = form.upn.trim().to_string();

    if !abyssal_agent_protocol::is_valid_user_principal_name(&upn) {
        return render_domain(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("Enter the service account as a full userPrincipalName (e.g. svc-ad@corp.example.com).".into()),
        )
        .await;
    }
    if form.password.is_empty() {
        return render_domain(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("Enter the service account's password to validate it.".into()),
        )
        .await;
    }
    let Some(write_dc_id) = domain.write_dc_host_id else {
        return render_domain(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("This domain has no write DC set, so the account can't be validated yet.".into()),
        )
        .await;
    };
    let Some(key) = state.encryption_key.clone() else {
        return render_domain(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("This control plane has no ENCRYPTION_KEY set, so service-account credentials can't be stored securely. Set one and restart.".into()),
        )
        .await;
    };
    let write_dc = repo::hosts::find_by_id(&state.pool, write_dc_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let dispatch = dispatch_directory(
        &state,
        &ctx,
        write_dc.id,
        &write_dc.name,
        AgentOperation::DirectoryTestDelegation {
            domain_dns: domain.dns_name.clone(),
            service_account_upn: upn.clone(),
            password: form.password.clone(),
        },
        Permission::DirectoryConfigure,
        DELEGATION_TIMEOUT,
    )
    .await;

    let stdout = match dispatch {
        Ok(s) => s,
        Err(e) => {
            // A failed bind/dispatch: record the attempt (no creds stored).
            let detail = serde_json::json!({ "error": e, "upn": upn });
            let _ =
                repo::directory::record_delegation_failure(&state.pool, id, &detail.to_string())
                    .await;
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryServiceAccountValidated,
                &domain.dns_name,
                serde_json::json!({ "upn": upn, "result": "failed", "detail": e }),
            )
            .await;
            return render_domain(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some(format!("The delegation check failed: {e}")),
            )
            .await;
        }
    };

    let result: DelegationResult = match serde_json::from_str(stdout.trim()) {
        Ok(r) => r,
        Err(e) => {
            return render_domain(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some(format!("Couldn't read the delegation check result: {e}")),
            )
            .await;
        }
    };

    // Refuse to store an account that can't bind, wasn't found, or is
    // overprivileged -- exactly what this check exists to catch.
    if !result.account_found {
        return refuse(
            &state,
            &jar,
            &ctx,
            id,
            &domain.dns_name,
            &upn,
            "The service account wasn't found by its userPrincipalName in that domain.",
        )
        .await;
    }
    if !result.overprivileged_groups.is_empty() {
        let groups = result.overprivileged_groups.join(", ");
        return refuse(
            &state,
            &jar,
            &ctx,
            id,
            &domain.dns_name,
            &upn,
            &format!(
                "Refused: this account is a member of privileged group(s) ({groups}). \
                 Gravekeeper requires a least-privilege, delegated account -- not one in Domain \
                 Admins, Enterprise/Schema Admins, Administrators, or the Operators groups."
            ),
        )
        .await;
    }
    if !result.ok {
        return refuse(
            &state,
            &jar,
            &ctx,
            id,
            &domain.dns_name,
            &upn,
            "The delegation check did not pass.",
        )
        .await;
    }

    // Passed: seal the password and store it with the result detail.
    let sealed = key.encrypt(&form.password).map_err(|e| {
        WebError(AppError::Validation(format!(
            "Couldn't seal the credential: {e}"
        )))
    })?;
    let detail = serde_json::json!({
        "manageable_ous": result.manageable_ous,
        "overprivileged_groups": result.overprivileged_groups,
    });
    repo::directory::set_validated_service_account(
        &state.pool,
        id,
        &upn,
        &sealed,
        &detail.to_string(),
    )
    .await?;
    record_audit(
        &state,
        &ctx,
        AuditAction::DirectoryServiceAccountValidated,
        &domain.dns_name,
        serde_json::json!({ "upn": upn, "result": "ok", "manageable_ou_count": result.manageable_ous.len() }),
    )
    .await;

    let ous = result.manageable_ous.len();
    render_domain(
        &state,
        &jar,
        &ctx,
        id,
        Some(format!(
            "Service account validated and stored. It can manage {ous} OU(s). The domain is now \
             writable."
        )),
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn refuse(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    id: Uuid,
    dns: &str,
    upn: &str,
    message: &str,
) -> Result<Response, WebError> {
    let detail = serde_json::json!({ "reason": message, "upn": upn });
    let _ = repo::directory::record_delegation_failure(&state.pool, id, &detail.to_string()).await;
    record_audit(
        state,
        ctx,
        AuditAction::DirectoryServiceAccountValidated,
        dns,
        serde_json::json!({ "upn": upn, "result": "refused", "reason": message }),
    )
    .await;
    render_domain(state, jar, ctx, id, None, Some(message.to_string())).await
}

#[derive(Deserialize)]
pub struct DomainConfigForm {
    csrf_token: String,
    disabled_ou: String,
    deletion_grace_days: u32,
}

/// POST: set the disabled OU and deletion grace period for a domain.
pub async fn set_domain_config(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<DomainConfigForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    require_csrf(&jar, &form.csrf_token)?;

    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let disabled_ou = form.disabled_ou.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&disabled_ou) {
        return render_domain(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("Enter the disabled OU as a distinguished name (e.g. OU=Disabled Users,DC=corp,DC=example,DC=com).".into()),
        )
        .await;
    }
    if form.deletion_grace_days > 3650 {
        return render_domain(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("The deletion grace period must be 3650 days or fewer.".into()),
        )
        .await;
    }
    repo::directory::set_config(&state.pool, id, &disabled_ou, form.deletion_grace_days).await?;
    record_audit(
        &state,
        &ctx,
        AuditAction::DirectoryDomainConfigured,
        &domain.dns_name,
        serde_json::json!({ "disabled_ou": disabled_ou, "deletion_grace_days": form.deletion_grace_days }),
    )
    .await;
    render_domain(
        &state,
        &jar,
        &ctx,
        id,
        Some("Domain settings saved.".into()),
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct RemoveForm {
    csrf_token: String,
}

/// POST: remove a configured domain (and its sealed credential).
pub async fn remove_domain(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<RemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    require_csrf(&jar, &form.csrf_token)?;
    if let Some(domain) = repo::directory::find_by_id(&state.pool, id).await? {
        repo::directory::delete(&state.pool, id).await?;
        record_audit(
            &state,
            &ctx,
            AuditAction::DirectoryDomainRemoved,
            &domain.dns_name,
            serde_json::json!({ "domain_id": id.to_string() }),
        )
        .await;
    }
    Ok(Redirect::to("/arsenals/gravekeeper").into_response())
}

// --- Browse: OU tree + search + object detail (directory.view) -------------

const BROWSE_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Deserialize)]
pub struct BrowseQuery {
    #[serde(default)]
    q: String,
}

/// GET the browse page for a domain: its OU tree and (when `q` is set) a
/// user/group/computer search. `directory.view`.
pub async fn browse(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<BrowseQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryView)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;

    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let q = query.q.trim().to_string();

    let mut error: Option<String> = None;
    let mut ou_rows: Vec<crate::templates::GravekeeperOuRow> = Vec::new();
    let mut results: Vec<crate::templates::GravekeeperSearchRow> = Vec::new();

    match domain.write_dc_host_id {
        Some(hid) if state.hosts.is_connected(hid) => {
            let host = repo::hosts::find_by_id(&state.pool, hid)
                .await?
                .ok_or(AppError::NotFound)?;
            // OU tree.
            match dispatch_directory(
                &state,
                &ctx,
                host.id,
                &host.name,
                AgentOperation::DirectoryOuTree {
                    domain_dns: domain.dns_name.clone(),
                },
                Permission::DirectoryView,
                BROWSE_TIMEOUT,
            )
            .await
            {
                Ok(stdout) => match parse_list::<OuEntry>(&stdout) {
                    Ok(ous) => ou_rows = ou_tree_rows(ous),
                    Err(e) => error = Some(format!("Couldn't read the OU list: {e}")),
                },
                Err(e) => error = Some(e),
            }
            // Search (only when a query is present).
            if error.is_none() && !q.is_empty() {
                match dispatch_directory(
                    &state,
                    &ctx,
                    host.id,
                    &host.name,
                    AgentOperation::DirectorySearch {
                        domain_dns: domain.dns_name.clone(),
                        query: q.clone(),
                    },
                    Permission::DirectoryView,
                    BROWSE_TIMEOUT,
                )
                .await
                {
                    Ok(stdout) => match parse_list::<SearchHit>(&stdout) {
                        Ok(hits) => results = hits.into_iter().map(search_row).collect(),
                        Err(e) => error = Some(format!("Couldn't read the search results: {e}")),
                    },
                    Err(e) => error = Some(e),
                }
            }
        }
        Some(_) => {
            error = Some(
                "The domain's write DC isn't connected right now, so it can't be browsed.".into(),
            );
        }
        None => {
            error = Some("This domain has no write DC set yet.".into());
        }
    }

    let tpl = crate::templates::GravekeeperBrowseTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        query: q,
        ou_rows,
        results,
        error,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

/// Builds display rows for the OU tree: a stable depth-first order (parents
/// before children, siblings grouped) with an indent depth per OU.
fn ou_tree_rows(mut ous: Vec<OuEntry>) -> Vec<crate::templates::GravekeeperOuRow> {
    // Sort key: RDNs reversed (root-first) so a parent sorts right before its
    // children and siblings cluster.
    let sort_key = |dn: &str| -> String { dn.split(',').rev().collect::<Vec<_>>().join("/") };
    ous.sort_by_cached_key(|o| sort_key(&o.dn));
    ous.into_iter()
        .map(|o| {
            let depth = o.dn.matches("OU=").count().saturating_sub(1);
            crate::templates::GravekeeperOuRow {
                name: o.name,
                dn: o.dn,
                depth,
            }
        })
        .collect()
}

fn search_row(h: SearchHit) -> crate::templates::GravekeeperSearchRow {
    let sub = h
        .upn
        .filter(|s| !s.is_empty())
        .or(h.sam)
        .unwrap_or_default();
    let state = match (h.kind.as_str(), h.enabled) {
        ("group", _) => String::new(),
        (_, Some(true)) => "Enabled".to_string(),
        (_, Some(false)) => "Disabled".to_string(),
        (_, None) => String::new(),
    };
    let dn_encoded = crate::common::urlencoding_encode(&h.dn);
    crate::templates::GravekeeperSearchRow {
        kind: h.kind,
        name: h.name,
        sub,
        dn: h.dn,
        dn_encoded,
        state,
    }
}

/// GET a single object's detail by DN. `directory.view`.
pub async fn object_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<ObjectQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryView)?;
    let dn = query.dn.trim().to_string();
    render_object(&state, &jar, &ctx, id, &dn, None, None, None).await
}

/// Renders the object-detail page: re-reads the object from the DC and shows it
/// with an optional result/new-password/error banner (reused by the GET view
/// and every help-desk write that lands back here).
#[allow(clippy::too_many_arguments)]
async fn render_object(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    id: Uuid,
    dn: &str,
    result: Option<String>,
    new_password: Option<String>,
    mut error: Option<String>,
) -> Result<Response, WebError> {
    let (base, new_cookie) = build_base(state, jar, ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !abyssal_agent_protocol::is_valid_ldap_dn(dn) {
        return Err(WebError(AppError::Validation(
            "That isn't a valid distinguished name.".into(),
        )));
    }

    let mut object: Option<crate::templates::GravekeeperObjectView> = None;
    match domain.write_dc_host_id {
        Some(hid) if state.hosts.is_connected(hid) => {
            let host = repo::hosts::find_by_id(&state.pool, hid)
                .await?
                .ok_or(AppError::NotFound)?;
            match dispatch_directory(
                state,
                ctx,
                host.id,
                &host.name,
                AgentOperation::DirectoryGetObject {
                    domain_dns: domain.dns_name.clone(),
                    dn: dn.to_string(),
                },
                Permission::DirectoryView,
                BROWSE_TIMEOUT,
            )
            .await
            {
                Ok(stdout) => match serde_json::from_str::<ObjectInfo>(stdout.trim()) {
                    Ok(info) => object = Some(object_view(info)),
                    Err(e) => {
                        error.get_or_insert(format!("Couldn't read the object: {e}"));
                    }
                },
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        Some(_) => {
            error.get_or_insert("The domain's write DC isn't connected right now.".into());
        }
        None => {
            error.get_or_insert("This domain has no write DC set yet.".into());
        }
    }

    let is_user = object.as_ref().is_some_and(|o| o.kind == "user");
    let tpl = crate::templates::GravekeeperObjectTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        target_dn: dn.to_string(),
        can_helpdesk: ctx.has(Permission::DirectoryHelpdesk) && is_user,
        writable: domain.has_service_account && domain.last_delegation_ok == Some(true),
        object,
        result,
        new_password,
        error,
    };
    Ok(respond(jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct ObjectQuery {
    #[serde(default)]
    dn: String,
}

fn object_view(info: ObjectInfo) -> crate::templates::GravekeeperObjectView {
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut push = |label: &str, value: Option<String>| {
        if let Some(v) = value.filter(|s| !s.is_empty()) {
            attrs.push((label.to_string(), v));
        }
    };
    push("Name", Some(info.name.clone()));
    push("sAMAccountName", info.sam.clone());
    push("UPN", info.upn.clone());
    push("Display name", info.display.clone());
    push("Enabled", info.enabled.map(|b| b.to_string()));
    push("Locked out", info.locked.map(|b| b.to_string()));
    push("Description", info.description.clone());
    push("Email", info.email.clone());
    push("Department", info.department.clone());
    push("Title", info.title.clone());
    push("Group scope", info.scope.clone());
    push("Group type", info.category.clone());
    push("Operating system", info.os.clone());
    push("DNS host name", info.dns.clone());
    push("Created", info.created.clone());
    push("Last logon", info.last_logon.clone());
    push("Distinguished name", Some(info.dn.clone()));

    let (list_title, list) = if !info.groups.is_empty() {
        ("Member of".to_string(), info.groups)
    } else if !info.members.is_empty() {
        ("Members".to_string(), info.members)
    } else {
        (String::new(), Vec::new())
    };

    crate::templates::GravekeeperObjectView {
        enabled: info.enabled,
        locked: info.locked,
        kind: info.kind,
        name: info.name,
        attrs,
        list_title,
        list,
    }
}

// --- Help-desk writes (directory.helpdesk) ---------------------------------

const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// What a help-desk write needs: the writable domain, its connected write DC,
/// and the delegated service account's UPN + decrypted password. Returns a
/// human error otherwise (not writable, DC offline, no key, ...).
struct HelpdeskContext {
    domain_dns: String,
    write_dc_id: Uuid,
    write_dc_name: String,
    upn: String,
    password: String,
}

async fn helpdesk_prepare(state: &AppState, id: Uuid) -> Result<HelpdeskContext, String> {
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Unknown domain.")?;
    if !(domain.has_service_account && domain.last_delegation_ok == Some(true)) {
        return Err(
            "This domain is read-only: validate a delegated service account for it first.".into(),
        );
    }
    let write_dc_id = domain
        .write_dc_host_id
        .ok_or("This domain has no write DC set.")?;
    if !state.hosts.is_connected(write_dc_id) {
        return Err("The domain's write DC isn't connected right now.".into());
    }
    let write_dc_name = repo::hosts::find_by_id(&state.pool, write_dc_id)
        .await
        .map_err(|e| e.to_string())?
        .map(|h| h.name)
        .ok_or("The domain's write DC host no longer exists.")?;
    let key = state.encryption_key.clone().ok_or(
        "This control plane has no ENCRYPTION_KEY set, so the stored credential can't be used.",
    )?;
    let (upn, sealed) = repo::directory::service_account(&state.pool, id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("This domain has no stored service account.")?;
    let password = key
        .decrypt(&sealed)
        .map_err(|e| format!("Couldn't decrypt the stored credential: {e}"))?
        .to_string();
    Ok(HelpdeskContext {
        domain_dns: domain.dns_name,
        write_dc_id,
        write_dc_name,
        upn,
        password,
    })
}

/// Dispatches a help-desk WRITE op to the write DC and returns its stdout (a
/// success line) or a human error.
async fn dispatch_write(
    state: &AppState,
    ctx: &AuthContext,
    hc: &HelpdeskContext,
    operation: AgentOperation,
) -> Result<String, String> {
    state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            hc.write_dc_id,
            &hc.write_dc_name,
            operation,
            Permission::DirectoryHelpdesk,
            OperationKind::Write,
            false,
            WRITE_TIMEOUT,
            None,
            false,
        )
        .await
        .map(|o| o.stdout.trim().to_string())
        .map_err(|e| e.to_string())
}

/// A strong temporary password: 20 chars with at least one lower, upper, digit
/// and symbol (satisfies default AD complexity and typical policies). Generated
/// with the OS CSPRNG; shown once and never stored.
fn generate_temp_password() -> String {
    use rand::seq::SliceRandom;
    use rand::{RngCore, rngs::OsRng};
    const LOWER: &[u8] = b"abcdefghijkmnpqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGIT: &[u8] = b"23456789";
    const SYMBOL: &[u8] = b"!@#$%^&*()-_=+";
    let classes = [LOWER, UPPER, DIGIT, SYMBOL];
    let mut rng = OsRng;
    let pick = |rng: &mut OsRng, set: &[u8]| set[(rng.next_u32() as usize) % set.len()];
    let mut chars: Vec<u8> = classes.iter().map(|set| pick(&mut rng, set)).collect();
    let all: Vec<u8> = classes.concat();
    while chars.len() < 20 {
        chars.push(pick(&mut rng, &all));
    }
    chars.shuffle(&mut rng);
    String::from_utf8(chars).unwrap_or_else(|_| "ChangeMe!123456789".to_string())
}

fn allow_privileged(ctx: &AuthContext) -> bool {
    ctx.has(Permission::DirectoryPrivileged)
}

#[derive(Deserialize)]
pub struct TargetForm {
    csrf_token: String,
    dn: String,
}

/// POST: unlock the target account. `directory.helpdesk`.
pub async fn unlock_account(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<TargetForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryHelpdesk)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn) {
        return Err(WebError(AppError::Validation("Invalid target DN.".into())));
    }
    let (result, error) = match helpdesk_prepare(&state, id).await {
        Ok(hc) => {
            let op = AgentOperation::DirectoryUnlockAccount {
                domain_dns: hc.domain_dns.clone(),
                service_account_upn: hc.upn.clone(),
                service_account_password: hc.password.clone(),
                target_dn: dn.clone(),
                allow_privileged: allow_privileged(&ctx),
            };
            match dispatch_write(&state, &ctx, &hc, op).await {
                Ok(msg) => {
                    record_audit(
                        &state,
                        &ctx,
                        AuditAction::DirectoryAccountUnlocked,
                        &hc.domain_dns,
                        serde_json::json!({ "target_dn": dn }),
                    )
                    .await;
                    (
                        Some(if msg.is_empty() {
                            "Account unlocked.".into()
                        } else {
                            msg
                        }),
                        None,
                    )
                }
                Err(e) => (None, Some(e)),
            }
        }
        Err(e) => (None, Some(e)),
    };
    render_object(&state, &jar, &ctx, id, &dn, result, None, error).await
}

#[derive(Deserialize)]
pub struct SetEnabledForm {
    csrf_token: String,
    dn: String,
    enabled: bool,
}

/// POST: enable or disable the target account. `directory.helpdesk`.
pub async fn set_enabled(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SetEnabledForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryHelpdesk)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn) {
        return Err(WebError(AppError::Validation("Invalid target DN.".into())));
    }
    let (result, error) = match helpdesk_prepare(&state, id).await {
        Ok(hc) => {
            let op = AgentOperation::DirectorySetEnabled {
                domain_dns: hc.domain_dns.clone(),
                service_account_upn: hc.upn.clone(),
                service_account_password: hc.password.clone(),
                target_dn: dn.clone(),
                enabled: form.enabled,
                allow_privileged: allow_privileged(&ctx),
            };
            match dispatch_write(&state, &ctx, &hc, op).await {
                Ok(msg) => {
                    record_audit(
                        &state,
                        &ctx,
                        AuditAction::DirectoryAccountEnabledChanged,
                        &hc.domain_dns,
                        serde_json::json!({ "target_dn": dn, "enabled": form.enabled }),
                    )
                    .await;
                    (
                        Some(if msg.is_empty() { "Done.".into() } else { msg }),
                        None,
                    )
                }
                Err(e) => (None, Some(e)),
            }
        }
        Err(e) => (None, Some(e)),
    };
    render_object(&state, &jar, &ctx, id, &dn, result, None, error).await
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    csrf_token: String,
    dn: String,
    /// Optional operator-chosen password; generated when empty.
    #[serde(default)]
    new_password: String,
}

/// POST: reset the target account's password (must change at next logon).
/// `directory.helpdesk`. The password is shown once and never stored/logged.
pub async fn reset_password(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ResetPasswordForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryHelpdesk)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn) {
        return Err(WebError(AppError::Validation("Invalid target DN.".into())));
    }

    // An operator-entered password must be non-trivial; otherwise generate one.
    let entered = form.new_password;
    if !entered.is_empty() && entered.len() < 8 {
        return render_object(
            &state,
            &jar,
            &ctx,
            id,
            &dn,
            None,
            None,
            Some("A chosen password must be at least 8 characters, or leave it blank to generate one.".into()),
        )
        .await;
    }
    let generated = entered.is_empty();
    let new_password = if generated {
        generate_temp_password()
    } else {
        entered
    };

    let (result, shown, error) = match helpdesk_prepare(&state, id).await {
        Ok(hc) => {
            let op = AgentOperation::DirectorySetPassword {
                domain_dns: hc.domain_dns.clone(),
                service_account_upn: hc.upn.clone(),
                service_account_password: hc.password.clone(),
                target_dn: dn.clone(),
                new_password: new_password.clone(),
                allow_privileged: allow_privileged(&ctx),
            };
            match dispatch_write(&state, &ctx, &hc, op).await {
                Ok(_) => {
                    record_audit(
                        &state,
                        &ctx,
                        AuditAction::DirectoryAccountPasswordReset,
                        &hc.domain_dns,
                        // The password is never recorded -- only that a reset happened.
                        serde_json::json!({ "target_dn": dn, "generated": generated }),
                    )
                    .await;
                    let msg = if generated {
                        "Password reset. Copy the temporary password below now -- it is shown only once. The user must change it at next logon."
                    } else {
                        "Password reset. The user must change it at next logon."
                    };
                    (
                        Some(msg.to_string()),
                        generated.then_some(new_password),
                        None,
                    )
                }
                Err(e) => (None, None, Some(e)),
            }
        }
        Err(e) => (None, None, Some(e)),
    };
    render_object(&state, &jar, &ctx, id, &dn, result, shown, error).await
}

// --- Onboarding templates (directory.manage) -------------------------------

const MAIL_MODES: &[&str] = &["none", "exchange_onprem", "exchange_hybrid", "m365"];

/// GET the template list for a domain. `directory.manage`.
pub async fn templates(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let rows = repo::directory::list_templates(&state.pool, id)
        .await?
        .into_iter()
        .map(|t| crate::templates::GravekeeperTemplateRow {
            id: t.id.to_string(),
            name: t.name,
            target_ou: t.target_ou.unwrap_or_default(),
            username_pattern: t.username_pattern,
            mail_mode: t.mail_mode,
            group_count: t.groups.len(),
            manager_required: t.manager_required,
        })
        .collect();
    let tpl = crate::templates::GravekeeperTemplatesTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        templates: rows,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

/// GET the new-template form. `directory.manage`.
pub async fn new_template(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let tpl = crate::templates::GravekeeperTemplateFormTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        template_id: None,
        form: default_template_form(),
        mail_modes: MAIL_MODES.iter().map(|s| s.to_string()).collect(),
        error: None,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

/// GET the edit form for an existing template. `directory.manage`.
pub async fn edit_template(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(tid): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let t = repo::directory::find_template(&state.pool, tid)
        .await?
        .ok_or(AppError::NotFound)?;
    let domain = repo::directory::find_by_id(&state.pool, t.domain_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let tpl = crate::templates::GravekeeperTemplateFormTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        template_id: Some(t.id.to_string()),
        form: template_to_form(&t),
        mail_modes: MAIL_MODES.iter().map(|s| s.to_string()).collect(),
        error: None,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct TemplateForm {
    csrf_token: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    target_ou: String,
    #[serde(default)]
    username_pattern: String,
    #[serde(default)]
    upn_suffix: String,
    #[serde(default)]
    email_pattern: String,
    #[serde(default)]
    groups: String,
    #[serde(default)]
    attributes: String,
    #[serde(default)]
    mail_mode: String,
    #[serde(default)]
    manager_required: bool,
}

/// A parsed, validated template form ready to persist.
struct ParsedTemplate {
    name: String,
    target_ou: Option<String>,
    username_pattern: String,
    upn_suffix: Option<String>,
    email_pattern: Option<String>,
    groups_json: String,
    attributes_json: String,
    mail_mode: String,
    manager_required: bool,
}

fn parse_template_form(form: &TemplateForm) -> Result<ParsedTemplate, String> {
    let name = form.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err("Enter a template name (up to 100 characters).".into());
    }
    let username_pattern = form.username_pattern.trim().to_string();
    if username_pattern.is_empty() || username_pattern.len() > 128 {
        return Err("Enter a username pattern, e.g. {first}.{last}.".into());
    }
    // A pattern that produces nothing for a sample name is useless.
    let sample = abyssal_agent_protocol::sanitize_sam_account_name(
        &abyssal_agent_protocol::expand_name_pattern(&username_pattern, "Jane", "Doe"),
    );
    if !abyssal_agent_protocol::is_valid_sam_account_name(&sample) {
        return Err("That username pattern doesn't produce a valid logon name for a sample user (Jane Doe).".into());
    }

    let blank_to_none = |s: &str| -> Option<String> {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };
    let target_ou = blank_to_none(&form.target_ou);
    if let Some(ou) = &target_ou
        && !abyssal_agent_protocol::is_valid_ldap_dn(ou)
    {
        return Err("The target OU must be a distinguished name, or left blank.".into());
    }
    let upn_suffix = blank_to_none(&form.upn_suffix);
    if let Some(s) = &upn_suffix
        && !abyssal_agent_protocol::is_valid_upn_suffix(s)
    {
        return Err(
            "The UPN suffix must look like a domain (e.g. corp.example.com), or be blank.".into(),
        );
    }
    let email_pattern = blank_to_none(&form.email_pattern);

    // Groups: one DN per line.
    let mut groups: Vec<String> = Vec::new();
    for line in form.groups.lines() {
        let g = line.trim();
        if g.is_empty() {
            continue;
        }
        if !abyssal_agent_protocol::is_valid_ldap_dn(g) {
            return Err(format!("Group \"{g}\" isn't a valid distinguished name."));
        }
        groups.push(g.to_string());
    }

    // Attributes: "name=value" per line, name allowlisted.
    let mut attrs: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for line in form.attributes.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            return Err(format!("Attribute line \"{l}\" must be name=value."));
        };
        let k = k.trim();
        let v = v.trim();
        if !abyssal_agent_protocol::is_writable_ad_user_attribute(k) {
            return Err(format!(
                "Attribute \"{k}\" isn't one Gravekeeper may set. Allowed: {}.",
                abyssal_agent_protocol::WRITABLE_AD_USER_ATTRIBUTES.join(", ")
            ));
        }
        if v.is_empty() {
            return Err(format!("Attribute \"{k}\" has no value."));
        }
        attrs.insert(k.to_string(), v.to_string());
    }

    let mail_mode = if MAIL_MODES.contains(&form.mail_mode.as_str()) {
        form.mail_mode.clone()
    } else {
        "none".to_string()
    };

    Ok(ParsedTemplate {
        name,
        target_ou,
        username_pattern,
        upn_suffix,
        email_pattern,
        groups_json: serde_json::to_string(&groups).unwrap_or_else(|_| "[]".into()),
        attributes_json: serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".into()),
        mail_mode,
        manager_required: form.manager_required,
    })
}

/// POST: create a template for a domain. `directory.manage`.
pub async fn create_template(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<TemplateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    match parse_template_form(&form) {
        Ok(p) => {
            repo::directory::create_template(
                &state.pool,
                &repo::directory::NewDirectoryTemplate {
                    domain_id: id,
                    name: &p.name,
                    target_ou: p.target_ou.as_deref(),
                    username_pattern: &p.username_pattern,
                    upn_suffix: p.upn_suffix.as_deref(),
                    email_pattern: p.email_pattern.as_deref(),
                    groups_json: &p.groups_json,
                    attributes_json: &p.attributes_json,
                    mail_mode: &p.mail_mode,
                    manager_required: p.manager_required,
                    created_by: Some(ctx.user.id),
                },
            )
            .await?;
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryDomainConfigured,
                &domain.dns_name,
                serde_json::json!({ "template": p.name, "action": "template_created" }),
            )
            .await;
            Ok(
                Redirect::to(&format!("/arsenals/gravekeeper/domains/{id}/templates"))
                    .into_response(),
            )
        }
        Err(e) => {
            let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
            let tpl = crate::templates::GravekeeperTemplateFormTemplate {
                base,
                domain_id: id.to_string(),
                dns_name: domain.dns_name,
                template_id: None,
                form: form_echo(&form),
                mail_modes: MAIL_MODES.iter().map(|s| s.to_string()).collect(),
                error: Some(e),
            };
            Ok(respond(&jar, new_cookie, tpl))
        }
    }
}

/// POST: update a template. `directory.manage`.
pub async fn update_template(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(tid): Path<Uuid>,
    Form(form): Form<TemplateForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let t = repo::directory::find_template(&state.pool, tid)
        .await?
        .ok_or(AppError::NotFound)?;
    let domain = repo::directory::find_by_id(&state.pool, t.domain_id)
        .await?
        .ok_or(AppError::NotFound)?;
    match parse_template_form(&form) {
        Ok(p) => {
            repo::directory::update_template(
                &state.pool,
                tid,
                &repo::directory::NewDirectoryTemplate {
                    domain_id: t.domain_id,
                    name: &p.name,
                    target_ou: p.target_ou.as_deref(),
                    username_pattern: &p.username_pattern,
                    upn_suffix: p.upn_suffix.as_deref(),
                    email_pattern: p.email_pattern.as_deref(),
                    groups_json: &p.groups_json,
                    attributes_json: &p.attributes_json,
                    mail_mode: &p.mail_mode,
                    manager_required: p.manager_required,
                    created_by: None,
                },
            )
            .await?;
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryDomainConfigured,
                &domain.dns_name,
                serde_json::json!({ "template": p.name, "action": "template_updated" }),
            )
            .await;
            Ok(Redirect::to(&format!(
                "/arsenals/gravekeeper/domains/{}/templates",
                t.domain_id
            ))
            .into_response())
        }
        Err(e) => {
            let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
            let tpl = crate::templates::GravekeeperTemplateFormTemplate {
                base,
                domain_id: t.domain_id.to_string(),
                dns_name: domain.dns_name,
                template_id: Some(tid.to_string()),
                form: form_echo(&form),
                mail_modes: MAIL_MODES.iter().map(|s| s.to_string()).collect(),
                error: Some(e),
            };
            Ok(respond(&jar, new_cookie, tpl))
        }
    }
}

/// POST: delete a template. `directory.manage`.
pub async fn delete_template(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(tid): Path<Uuid>,
    Form(form): Form<RemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let t = repo::directory::find_template(&state.pool, tid)
        .await?
        .ok_or(AppError::NotFound)?;
    let domain_id = t.domain_id;
    repo::directory::delete_template(&state.pool, tid).await?;
    if let Some(domain) = repo::directory::find_by_id(&state.pool, domain_id).await? {
        record_audit(
            &state,
            &ctx,
            AuditAction::DirectoryDomainConfigured,
            &domain.dns_name,
            serde_json::json!({ "template": t.name, "action": "template_deleted" }),
        )
        .await;
    }
    Ok(Redirect::to(&format!(
        "/arsenals/gravekeeper/domains/{domain_id}/templates"
    ))
    .into_response())
}

fn default_template_form() -> crate::templates::GravekeeperTemplateFormView {
    crate::templates::GravekeeperTemplateFormView {
        name: String::new(),
        target_ou: String::new(),
        username_pattern: "{first}.{last}".to_string(),
        upn_suffix: String::new(),
        email_pattern: String::new(),
        groups: String::new(),
        attributes: String::new(),
        mail_mode: "none".to_string(),
        manager_required: false,
    }
}

fn template_to_form(
    t: &repo::directory::DirectoryTemplate,
) -> crate::templates::GravekeeperTemplateFormView {
    let attributes = t
        .attributes
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    crate::templates::GravekeeperTemplateFormView {
        name: t.name.clone(),
        target_ou: t.target_ou.clone().unwrap_or_default(),
        username_pattern: t.username_pattern.clone(),
        upn_suffix: t.upn_suffix.clone().unwrap_or_default(),
        email_pattern: t.email_pattern.clone().unwrap_or_default(),
        groups: t.groups.join("\n"),
        attributes,
        mail_mode: t.mail_mode.clone(),
        manager_required: t.manager_required,
    }
}

fn form_echo(form: &TemplateForm) -> crate::templates::GravekeeperTemplateFormView {
    crate::templates::GravekeeperTemplateFormView {
        name: form.name.clone(),
        target_ou: form.target_ou.clone(),
        username_pattern: form.username_pattern.clone(),
        upn_suffix: form.upn_suffix.clone(),
        email_pattern: form.email_pattern.clone(),
        groups: form.groups.clone(),
        attributes: form.attributes.clone(),
        mail_mode: form.mail_mode.clone(),
        manager_required: form.manager_required,
    }
}

async fn record_audit(
    state: &AppState,
    ctx: &AuthContext,
    action: AuditAction,
    resource: &str,
    metadata: serde_json::Value,
) {
    let event = AuditEvent::new(action, AuditOutcome::Success)
        .actor(abyssal_audit::Actor {
            user_id: ctx.user.id,
            username: &ctx.user.username,
        })
        .resource(resource)
        .metadata(metadata);
    if let Err(e) = abyssal_audit::record(&state.pool, event).await {
        tracing::error!(error = %e, "gravekeeper: failed to record audit event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_disabled_ou_from_dns() {
        assert_eq!(
            default_disabled_ou("corp.example.com"),
            "OU=Disabled Users,DC=corp,DC=example,DC=com"
        );
        assert_eq!(
            default_disabled_ou("example"),
            "OU=Disabled Users,DC=example"
        );
    }

    #[test]
    fn delegation_labels() {
        assert_eq!(delegation_label(false, None), "No service account");
        assert_eq!(delegation_label(true, Some(true)), "Delegation verified");
        assert_eq!(delegation_label(true, Some(false)), "Delegation failed");
        assert_eq!(delegation_label(true, None), "Not yet checked");
    }

    #[test]
    fn one_or_many_accepts_scalar_list_and_null() {
        #[derive(Deserialize)]
        struct T {
            #[serde(default, deserialize_with = "one_or_many")]
            xs: Vec<String>,
        }
        let one: T = serde_json::from_str(r#"{"xs":"a"}"#).unwrap();
        assert_eq!(one.xs, vec!["a"]);
        let many: T = serde_json::from_str(r#"{"xs":["a","b"]}"#).unwrap();
        assert_eq!(many.xs, vec!["a", "b"]);
        let none: T = serde_json::from_str(r#"{"xs":null}"#).unwrap();
        assert!(none.xs.is_empty());
        let absent: T = serde_json::from_str(r#"{}"#).unwrap();
        assert!(absent.xs.is_empty());
    }

    #[test]
    fn parses_a_delegation_result_with_single_element_arrays() {
        // PowerShell emits a one-element array as a bare object/scalar.
        let json = r#"{"ok":false,"account_found":true,"overprivileged_groups":"Domain Admins","manageable_ous":"OU=Staff,DC=corp,DC=com"}"#;
        let r: DelegationResult = serde_json::from_str(json).unwrap();
        assert!(!r.ok);
        assert!(r.account_found);
        assert_eq!(r.overprivileged_groups, vec!["Domain Admins"]);
        assert_eq!(r.manageable_ous, vec!["OU=Staff,DC=corp,DC=com"]);
    }

    #[test]
    fn parse_list_handles_empty_single_and_array() {
        // Empty stdout and the literal "null" both mean "no rows".
        let empty: Vec<OuEntry> = parse_list("").unwrap();
        assert!(empty.is_empty());
        let nulled: Vec<OuEntry> = parse_list("null").unwrap();
        assert!(nulled.is_empty());
        // A one-element ConvertTo-Json result is a bare object.
        let one: Vec<OuEntry> =
            parse_list(r#"{"Name":"HR","DistinguishedName":"OU=HR,DC=corp,DC=com"}"#).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "HR");
        // A real array.
        let many: Vec<OuEntry> = parse_list(
            r#"[{"Name":"HR","DistinguishedName":"OU=HR,DC=corp,DC=com"},{"Name":"IT","DistinguishedName":"OU=IT,DC=corp,DC=com"}]"#,
        )
        .unwrap();
        assert_eq!(many.len(), 2);
    }

    #[test]
    fn ou_tree_rows_orders_parents_before_children_with_depth() {
        let ous = vec![
            OuEntry {
                name: "Staff".into(),
                dn: "OU=Staff,OU=HR,DC=corp,DC=com".into(),
            },
            OuEntry {
                name: "HR".into(),
                dn: "OU=HR,DC=corp,DC=com".into(),
            },
            OuEntry {
                name: "IT".into(),
                dn: "OU=IT,DC=corp,DC=com".into(),
            },
        ];
        let rows = ou_tree_rows(ous);
        // HR (depth 0) sorts right before its child Staff (depth 1); IT is a
        // top-level sibling.
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["HR", "Staff", "IT"]);
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[1].depth, 1);
        assert_eq!(rows[2].depth, 0);
    }

    #[test]
    fn search_row_picks_identifier_and_account_state() {
        let user = search_row(SearchHit {
            kind: "user".into(),
            name: "Jane Doe".into(),
            sam: Some("jdoe".into()),
            upn: Some("jdoe@corp.com".into()),
            dn: "CN=Jane,OU=Staff,DC=corp,DC=com".into(),
            enabled: Some(false),
        });
        assert_eq!(user.sub, "jdoe@corp.com"); // UPN preferred over sam
        assert_eq!(user.state, "Disabled");
        assert!(!user.dn_encoded.contains(' ')); // encoded for a URL

        let group = search_row(SearchHit {
            kind: "group".into(),
            name: "Staff".into(),
            sam: Some("staff".into()),
            upn: None,
            dn: "CN=Staff,OU=Groups,DC=corp,DC=com".into(),
            enabled: None,
        });
        assert_eq!(group.sub, "staff"); // falls back to sam
        assert_eq!(group.state, ""); // groups have no enabled state
    }

    #[test]
    fn generated_password_is_strong_and_unique() {
        for _ in 0..50 {
            let pw = generate_temp_password();
            assert_eq!(pw.len(), 20);
            assert!(
                pw.chars().any(|c| c.is_ascii_lowercase()),
                "has lower: {pw}"
            );
            assert!(
                pw.chars().any(|c| c.is_ascii_uppercase()),
                "has upper: {pw}"
            );
            assert!(pw.chars().any(|c| c.is_ascii_digit()), "has digit: {pw}");
            assert!(
                pw.chars().any(|c| !c.is_ascii_alphanumeric()),
                "has symbol: {pw}"
            );
        }
        // Two draws should (overwhelmingly) differ.
        assert_ne!(generate_temp_password(), generate_temp_password());
    }
}
