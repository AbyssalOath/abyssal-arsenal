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
    groups: Vec<NameDn>,
    #[serde(default, deserialize_with = "one_or_many")]
    members: Vec<NameDn>,
}

/// A directory object's name + distinguished name (group members / memberships).
#[derive(Deserialize, Clone)]
struct NameDn {
    #[serde(default)]
    name: String,
    #[serde(default)]
    dn: String,
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
        can_manage: ctx.has(Permission::DirectoryManage),
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
    // An active offboard snapshot means this account can be un-offboarded.
    let snapshot = repo::directory::active_snapshot_for_dn(&state.pool, domain.id, dn).await?;
    let can_manage = ctx.has(Permission::DirectoryManage);
    let tpl = crate::templates::GravekeeperObjectTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        target_dn: dn.to_string(),
        can_helpdesk: ctx.has(Permission::DirectoryHelpdesk) && is_user,
        writable: domain.has_service_account && domain.last_delegation_ok == Some(true),
        can_manage,
        can_delete: ctx.has(Permission::DirectoryDelete),
        offboard_available: is_user && can_manage && snapshot.is_none(),
        undo_snapshot_id: snapshot.filter(|_| can_manage).map(|s| s.id.to_string()),
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

    let (list_title, source) = if info.kind == "group" {
        ("Members".to_string(), info.members)
    } else if !info.groups.is_empty() {
        ("Member of".to_string(), info.groups)
    } else {
        (String::new(), Vec::new())
    };
    let list = source
        .into_iter()
        .map(|nd| crate::templates::GravekeeperListItem {
            name: if nd.name.is_empty() {
                nd.dn.clone()
            } else {
                nd.name
            },
            dn: nd.dn.clone(),
            dn_encoded: crate::common::urlencoding_encode(&nd.dn),
        })
        .collect();

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

/// Dispatches a directory WRITE op to the write DC and returns its stdout (a
/// success line / JSON) or a human error. `required_permission` is the floor
/// the executor checks (`directory.helpdesk` for the help-desk actions,
/// `directory.manage` for onboarding).
async fn dispatch_write(
    state: &AppState,
    ctx: &AuthContext,
    hc: &HelpdeskContext,
    operation: AgentOperation,
    required_permission: Permission,
) -> Result<String, String> {
    state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            hc.write_dc_id,
            &hc.write_dc_name,
            operation,
            required_permission,
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
            match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryHelpdesk).await {
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
            match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryHelpdesk).await {
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
            match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryHelpdesk).await {
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

// --- Groups: create / delete / membership (directory.manage / .delete) ------

const GROUP_SCOPES: &[&str] = &["global", "universal", "domainlocal"];
const GROUP_CATEGORIES: &[&str] = &["security", "distribution"];

/// GET the new-group form. `directory.manage`.
pub async fn new_group(
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
    let tpl = crate::templates::GravekeeperGroupFormTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        error: None,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct CreateGroupForm {
    csrf_token: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    target_ou: String,
}

/// POST: create a group. `directory.manage`.
pub async fn create_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<CreateGroupForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let group_form_err = |state: &AppState, jar: &CookieJar, ctx: &AuthContext, msg: String| {
        let state = state.clone();
        let jar = jar.clone();
        let ctx = ctx.clone();
        let dns = domain.dns_name.clone();
        async move {
            let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
            let tpl = crate::templates::GravekeeperGroupFormTemplate {
                base,
                domain_id: id.to_string(),
                dns_name: dns,
                error: Some(msg),
            };
            Ok::<_, WebError>(respond(&jar, new_cookie, tpl))
        }
    };

    let name = abyssal_agent_protocol::sanitize_sam_account_name(&form.name);
    if !abyssal_agent_protocol::is_valid_sam_account_name(&name) {
        return group_form_err(&state, &jar, &ctx, "Enter a valid group name.".into()).await;
    }
    if !GROUP_SCOPES.contains(&form.scope.as_str()) {
        return group_form_err(&state, &jar, &ctx, "Pick a group scope.".into()).await;
    }
    if !GROUP_CATEGORIES.contains(&form.category.as_str()) {
        return group_form_err(&state, &jar, &ctx, "Pick a group category.".into()).await;
    }
    let target_ou = form.target_ou.trim();
    if !target_ou.is_empty() && !abyssal_agent_protocol::is_valid_ldap_dn(target_ou) {
        return group_form_err(
            &state,
            &jar,
            &ctx,
            "The target OU must be a distinguished name, or blank.".into(),
        )
        .await;
    }

    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => return group_form_err(&state, &jar, &ctx, e).await,
    };
    let op = AgentOperation::DirectoryCreateGroup(Box::new(
        abyssal_agent_protocol::CreateGroupRequest {
            domain_dns: hc.domain_dns.clone(),
            service_account_upn: hc.upn.clone(),
            service_account_password: hc.password.clone(),
            name: name.clone(),
            target_ou: target_ou.to_string(),
            scope: form.scope.clone(),
            category: form.category.clone(),
            description: form.description.trim().to_string(),
        },
    ));
    match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryManage).await {
        Ok(stdout) => {
            #[derive(Deserialize)]
            struct Created {
                #[serde(default)]
                dn: String,
            }
            let created: Created =
                serde_json::from_str(stdout.trim()).unwrap_or(Created { dn: String::new() });
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryGroupCreated,
                &domain.dns_name,
                serde_json::json!({ "name": name, "dn": created.dn }),
            )
            .await;
            if created.dn.is_empty() {
                return group_form_err(
                    &state,
                    &jar,
                    &ctx,
                    "Group created, but its DN wasn't returned.".into(),
                )
                .await;
            }
            let dn_q = crate::common::urlencoding_encode(&created.dn);
            Ok(Redirect::to(&format!(
                "/arsenals/gravekeeper/domains/{id}/object?dn={dn_q}"
            ))
            .into_response())
        }
        Err(e) => {
            group_form_err(
                &state,
                &jar,
                &ctx,
                format!("Creating the group failed: {e}"),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
pub struct MemberForm {
    csrf_token: String,
    /// The group whose membership changes, and the member, both DNs.
    group_dn: String,
    member_dn: String,
}

/// POST: add a member to a group. `directory.manage`.
pub async fn add_member(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<MemberForm>,
) -> Result<Response, WebError> {
    change_member(state, jar, ctx, id, form, true).await
}

/// POST: remove a member from a group. `directory.manage`.
pub async fn remove_member(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<MemberForm>,
) -> Result<Response, WebError> {
    change_member(state, jar, ctx, id, form, false).await
}

async fn change_member(
    state: AppState,
    jar: CookieJar,
    ctx: AuthContext,
    id: Uuid,
    form: MemberForm,
    add: bool,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let group_dn = form.group_dn.trim().to_string();
    let member_dn = form.member_dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&group_dn)
        || !abyssal_agent_protocol::is_valid_ldap_dn(&member_dn)
    {
        return Err(WebError(AppError::Validation(
            "Both the group and member must be distinguished names.".into(),
        )));
    }

    let (result, error) = match helpdesk_prepare(&state, id).await {
        Ok(hc) => {
            let (upn, password) = (hc.upn.clone(), hc.password.clone());
            let op = if add {
                AgentOperation::DirectoryAddGroupMember {
                    domain_dns: hc.domain_dns.clone(),
                    service_account_upn: upn,
                    service_account_password: password,
                    group_dn: group_dn.clone(),
                    member_dn: member_dn.clone(),
                    allow_privileged: allow_privileged(&ctx),
                }
            } else {
                AgentOperation::DirectoryRemoveGroupMember {
                    domain_dns: hc.domain_dns.clone(),
                    service_account_upn: upn,
                    service_account_password: password,
                    group_dn: group_dn.clone(),
                    member_dn: member_dn.clone(),
                    allow_privileged: allow_privileged(&ctx),
                }
            };
            match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryManage).await {
                Ok(msg) => {
                    record_audit(
                        &state,
                        &ctx,
                        AuditAction::DirectoryGroupMembershipChanged,
                        &hc.domain_dns,
                        serde_json::json!({ "group": group_dn, "member": member_dn, "add": add }),
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
    render_object(&state, &jar, &ctx, id, &group_dn, result, None, error).await
}

/// POST: delete a group. `directory.delete`.
pub async fn delete_group(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<TargetForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryDelete)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn) {
        return Err(WebError(AppError::Validation("Invalid group DN.".into())));
    }
    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => return render_object(&state, &jar, &ctx, id, &dn, None, None, Some(e)).await,
    };
    let op = AgentOperation::DirectoryDeleteGroup {
        domain_dns: hc.domain_dns.clone(),
        service_account_upn: hc.upn.clone(),
        service_account_password: hc.password.clone(),
        target_dn: dn.clone(),
        allow_privileged: allow_privileged(&ctx),
    };
    match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryDelete).await {
        Ok(_) => {
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryObjectDeleted,
                &hc.domain_dns,
                serde_json::json!({ "dn": dn, "kind": "group" }),
            )
            .await;
            Ok(Redirect::to(&format!("/arsenals/gravekeeper/domains/{id}/browse")).into_response())
        }
        Err(e) => {
            render_object(
                &state,
                &jar,
                &ctx,
                id,
                &dn,
                None,
                None,
                Some(format!("Deleting the group failed: {e}")),
            )
            .await
        }
    }
}

// --- Move / delete objects (directory.manage / .delete) ---------------------

#[derive(Deserialize)]
pub struct MoveForm {
    csrf_token: String,
    dn: String,
    new_parent_ou: String,
}

/// POST: move an object to another OU. `directory.manage`.
pub async fn move_object(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<MoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    let new_parent_ou = form.new_parent_ou.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn)
        || !abyssal_agent_protocol::is_valid_ldap_dn(&new_parent_ou)
    {
        return Err(WebError(AppError::Validation(
            "The object and destination OU must be distinguished names.".into(),
        )));
    }
    let (result, error) = match helpdesk_prepare(&state, id).await {
        Ok(hc) => {
            let op = AgentOperation::DirectoryMove {
                domain_dns: hc.domain_dns.clone(),
                service_account_upn: hc.upn.clone(),
                service_account_password: hc.password.clone(),
                target_dn: dn.clone(),
                new_parent_ou: new_parent_ou.clone(),
                allow_privileged: allow_privileged(&ctx),
            };
            match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryManage).await {
                Ok(msg) => {
                    record_audit(
                        &state,
                        &ctx,
                        AuditAction::DirectoryObjectMoved,
                        &hc.domain_dns,
                        serde_json::json!({ "dn": dn, "new_parent_ou": new_parent_ou }),
                    )
                    .await;
                    (
                        Some(if msg.is_empty() {
                            "Object moved.".into()
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
    // After a move the object's DN changed; if it succeeded, re-read at the new
    // DN (leaf RDN + new parent); otherwise re-render at the old DN.
    let show_dn = if error.is_none() {
        move_new_dn(&dn, &new_parent_ou)
    } else {
        dn.clone()
    };
    render_object(&state, &jar, &ctx, id, &show_dn, result, None, error).await
}

/// The DN an object has after moving under `new_parent`: its leaf RDN + the new
/// parent.
fn move_new_dn(dn: &str, new_parent: &str) -> String {
    match dn.split_once(',') {
        Some((rdn, _)) => format!("{rdn},{new_parent}"),
        None => dn.to_string(),
    }
}

/// POST: delete a user/computer object. `directory.delete`. (Groups use
/// `delete_group`.)
pub async fn delete_object(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<TargetForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryDelete)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn) {
        return Err(WebError(AppError::Validation("Invalid object DN.".into())));
    }
    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => return render_object(&state, &jar, &ctx, id, &dn, None, None, Some(e)).await,
    };
    let op = AgentOperation::DirectoryDeleteObject {
        domain_dns: hc.domain_dns.clone(),
        service_account_upn: hc.upn.clone(),
        service_account_password: hc.password.clone(),
        target_dn: dn.clone(),
        allow_privileged: allow_privileged(&ctx),
    };
    match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryDelete).await {
        Ok(_) => {
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryObjectDeleted,
                &hc.domain_dns,
                serde_json::json!({ "dn": dn }),
            )
            .await;
            Ok(Redirect::to(&format!("/arsenals/gravekeeper/domains/{id}/browse")).into_response())
        }
        Err(e) => {
            render_object(
                &state,
                &jar,
                &ctx,
                id,
                &dn,
                None,
                None,
                Some(format!("Deleting the object failed: {e}")),
            )
            .await
        }
    }
}

// --- Offboarding + undo (directory.manage) ----------------------------------

/// Hides (and optionally converts) a departing user's mailbox per the domain's
/// mail connection. Returns `(step_status, detail)`.
async fn offboard_mailbox(
    state: &AppState,
    ctx: &AuthContext,
    domain_id: Uuid,
    upn: &str,
) -> (&'static str, String) {
    let conn = match repo::directory::find_mail_connection(&state.pool, domain_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return ("skipped", "No mail connection configured.".into()),
        Err(e) => return ("failed", format!("Couldn't read the mail connection: {e}")),
    };
    match conn.mode.as_str() {
        "none" => ("skipped", "Mail mode is none.".into()),
        "m365" => (
            "skipped",
            "Microsoft 365 mailbox offboarding (Exchange Online app-only PowerShell) is not wired yet.".into(),
        ),
        "exchange_onprem" | "exchange_hybrid" => {
            let creds = match repo::directory::exchange_credentials(&state.pool, domain_id).await {
                Ok(Some(c)) => c,
                Ok(None) => return ("failed", "Exchange account not configured.".into()),
                Err(e) => return ("failed", format!("Couldn't read the Exchange account: {e}")),
            };
            let Some(host_id) = creds.agent_host_id else {
                return ("failed", "No Exchange agent host is set.".into());
            };
            if !state.hosts.is_connected(host_id) {
                return ("failed", "The Exchange agent host isn't connected.".into());
            }
            let Some(key) = state.encryption_key.clone() else {
                return ("failed", "This control plane has no ENCRYPTION_KEY set.".into());
            };
            let password = match key.decrypt(&creds.sealed) {
                Ok(p) => p.to_string(),
                Err(e) => return ("failed", format!("Couldn't decrypt the Exchange account: {e}")),
            };
            let host = match repo::hosts::find_by_id(&state.pool, host_id).await {
                Ok(Some(h)) => h,
                _ => return ("failed", "The Exchange agent host no longer exists.".into()),
            };
            let op = AgentOperation::ExchangeSetMailboxOffboard {
                uri: creds.uri,
                account_upn: creds.account_upn,
                account_password: password,
                target_identity: upn.to_string(),
                convert_to_shared: false,
            };
            match state
                .executor
                .execute_on_host(
                    ctx,
                    &state.hosts,
                    host_id,
                    &host.name,
                    op,
                    Permission::DirectoryManage,
                    OperationKind::Write,
                    false,
                    MAIL_TIMEOUT,
                    None,
                    false,
                )
                .await
            {
                Ok(_) => ("ok", "Mailbox hidden from address lists.".into()),
                Err(e) => ("failed", format!("Mailbox offboarding failed: {e}")),
            }
        }
        other => ("failed", format!("Unknown mail mode: {other}")),
    }
}

/// POST: offboard a user (disable, strip groups, move to the disabled OU, hide
/// the mailbox), recording an undo snapshot. `directory.manage`.
pub async fn offboard(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<TargetForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn) {
        return Err(WebError(AppError::Validation("Invalid object DN.".into())));
    }
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let disabled_ou = match domain.disabled_ou.clone() {
        Some(ou) if !ou.is_empty() => ou,
        _ => {
            return render_object(&state, &jar, &ctx, id, &dn, None, None, Some(
                "Set this domain's disabled-users OU (in its configure page) before offboarding.".into(),
            ))
            .await;
        }
    };
    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => return render_object(&state, &jar, &ctx, id, &dn, None, None, Some(e)).await,
    };

    // Read the account to capture its UPN/SAM and confirm it is a user.
    let (upn, sam) = match read_object(&state, &ctx, id, &dn).await {
        Ok(Some(info)) if info.kind == "user" => (
            info.upn.clone().unwrap_or_default(),
            info.sam.clone().unwrap_or_default(),
        ),
        Ok(Some(_)) => {
            return render_object(
                &state,
                &jar,
                &ctx,
                id,
                &dn,
                None,
                None,
                Some("Offboarding applies to user accounts.".into()),
            )
            .await;
        }
        Ok(None) | Err(_) => {
            return render_object(
                &state,
                &jar,
                &ctx,
                id,
                &dn,
                None,
                None,
                Some("Couldn't read the account to offboard.".into()),
            )
            .await;
        }
    };

    let job_id = repo::directory::create_job(
        &state.pool,
        id,
        "offboard",
        &format!(
            "Offboard {}",
            if sam.is_empty() {
                dn.clone()
            } else {
                sam.clone()
            }
        ),
        None,
        Some(ctx.user.id),
    )
    .await?;

    let op = AgentOperation::DirectoryOffboard {
        domain_dns: hc.domain_dns.clone(),
        service_account_upn: hc.upn.clone(),
        service_account_password: hc.password.clone(),
        target_dn: dn.clone(),
        disabled_ou,
        allow_privileged: allow_privileged(&ctx),
    };
    let stdout = match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryManage).await {
        Ok(s) => s,
        Err(e) => {
            repo::directory::add_job_step(
                &state.pool,
                job_id,
                1,
                "Disable, strip groups, move",
                "failed",
                Some(&e),
            )
            .await?;
            repo::directory::finish_job(&state.pool, job_id, "failed", Some(&sam), Some(&upn))
                .await?;
            return render_object(
                &state,
                &jar,
                &ctx,
                id,
                &dn,
                None,
                None,
                Some(format!("Offboarding failed: {e}")),
            )
            .await;
        }
    };

    #[derive(Deserialize)]
    struct OffboardResult {
        #[serde(default)]
        original_ou: String,
        #[serde(default, deserialize_with = "one_or_many")]
        groups: Vec<String>,
        #[serde(default)]
        new_dn: String,
    }
    let r: OffboardResult = serde_json::from_str(stdout.trim()).unwrap_or(OffboardResult {
        original_ou: String::new(),
        groups: Vec::new(),
        new_dn: dn.clone(),
    });
    let new_dn = if r.new_dn.is_empty() {
        dn.clone()
    } else {
        r.new_dn.clone()
    };
    repo::directory::add_job_step(
        &state.pool,
        job_id,
        1,
        "Disable, strip groups, move",
        "ok",
        Some(&format!(
            "Moved to the disabled OU; stripped {} group(s).",
            r.groups.len()
        )),
    )
    .await?;
    // Store the undo snapshot.
    let _ = repo::directory::create_offboard_snapshot(
        &state.pool,
        id,
        Some(&sam),
        Some(&upn),
        &new_dn,
        &r.original_ou,
        &serde_json::to_string(&r.groups).unwrap_or_else(|_| "[]".into()),
        Some(ctx.user.id),
    )
    .await?;

    // Mailbox step.
    let mut final_status = "completed";
    if !upn.is_empty() {
        let (status, detail) = offboard_mailbox(&state, &ctx, id, &upn).await;
        repo::directory::add_job_step(&state.pool, job_id, 2, "Mailbox", status, Some(&detail))
            .await?;
        if status == "failed" {
            final_status = "partial";
        }
    }
    repo::directory::finish_job(&state.pool, job_id, final_status, Some(&sam), Some(&upn)).await?;
    record_audit(
        &state,
        &ctx,
        AuditAction::DirectoryAccountOffboarded,
        &domain.dns_name,
        serde_json::json!({ "dn": dn, "new_dn": new_dn, "stripped_groups": r.groups.len(), "undo": false }),
    )
    .await;

    render_object(
        &state,
        &jar,
        &ctx,
        id,
        &new_dn,
        Some("Account offboarded (disabled, groups stripped, moved to the disabled OU). Undo is available below.".into()),
        None,
        None,
    )
    .await
}

/// Reads one object's detail (helper for offboard). `None` if not found.
async fn read_object(
    state: &AppState,
    ctx: &AuthContext,
    id: Uuid,
    dn: &str,
) -> Result<Option<ObjectInfo>, String> {
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("unknown domain")?;
    let Some(hid) = domain
        .write_dc_host_id
        .filter(|h| state.hosts.is_connected(*h))
    else {
        return Err("the domain's write DC isn't connected".into());
    };
    let host = repo::hosts::find_by_id(&state.pool, hid)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("write DC host missing")?;
    let stdout = dispatch_directory(
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
    .await?;
    serde_json::from_str::<ObjectInfo>(stdout.trim())
        .map(Some)
        .map_err(|e| e.to_string())
}

/// POST: undo an offboarding from its snapshot. `directory.manage`.
pub async fn undo_offboard(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path((id, sid)): Path<(Uuid, Uuid)>,
    Form(form): Form<RemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let snapshot = repo::directory::find_snapshot(&state.pool, sid)
        .await?
        .ok_or_else(|| {
            WebError(AppError::Validation(
                "That offboarding snapshot is gone or already undone.".into(),
            ))
        })?;
    if snapshot.domain_id != id {
        return Err(WebError(AppError::NotFound));
    }
    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => {
            return render_object(
                &state,
                &jar,
                &ctx,
                id,
                &snapshot.current_dn,
                None,
                None,
                Some(e),
            )
            .await;
        }
    };
    let op = AgentOperation::DirectoryUndoOffboard(Box::new(
        abyssal_agent_protocol::UndoOffboardRequest {
            domain_dns: hc.domain_dns.clone(),
            service_account_upn: hc.upn.clone(),
            service_account_password: hc.password.clone(),
            target_dn: snapshot.current_dn.clone(),
            original_ou: snapshot.original_ou.clone(),
            groups: snapshot.groups.clone(),
            allow_privileged: allow_privileged(&ctx),
        },
    ));
    match dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryManage).await {
        Ok(_) => {
            repo::directory::mark_snapshot_undone(&state.pool, sid).await?;
            if let Some(domain) = repo::directory::find_by_id(&state.pool, id).await? {
                record_audit(
                    &state,
                    &ctx,
                    AuditAction::DirectoryAccountOffboarded,
                    &domain.dns_name,
                    serde_json::json!({ "dn": snapshot.current_dn, "undo": true }),
                )
                .await;
            }
            // The restored DN: leaf RDN + original OU.
            let restored = move_new_dn(&snapshot.current_dn, &snapshot.original_ou);
            render_object(
                &state,
                &jar,
                &ctx,
                id,
                &restored,
                Some("Offboarding undone: re-enabled, groups restored, moved back.".into()),
                None,
                None,
            )
            .await
        }
        Err(e) => {
            render_object(
                &state,
                &jar,
                &ctx,
                id,
                &snapshot.current_dn,
                None,
                None,
                Some(format!("Undo failed: {e}")),
            )
            .await
        }
    }
}

// --- Bulk (CSV) onboarding (directory.manage) -------------------------------

/// Parses pasted CSV into `(first, last)` rows: first two comma-separated
/// columns per non-empty line, skipping a `first[,last]` / `first_name` header.
fn parse_csv_rows(csv: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for (i, line) in csv.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let mut parts = l.splitn(2, ',');
        let first = parts.next().unwrap_or("").trim().to_string();
        let last = parts.next().unwrap_or("").trim().to_string();
        if i == 0
            && (first.eq_ignore_ascii_case("first")
                || first.eq_ignore_ascii_case("first_name")
                || first.eq_ignore_ascii_case("firstname"))
        {
            continue; // header row
        }
        if first.is_empty() && last.is_empty() {
            continue;
        }
        rows.push((first, last));
    }
    rows
}

/// Builds and dispatches `DirectoryCreateUser` for a computed plan + password,
/// returning the created sam/upn (used by single and bulk onboarding).
async fn create_user_from_plan(
    state: &AppState,
    ctx: &AuthContext,
    hc: &HelpdeskContext,
    plan: &OnboardPlan,
    password: &str,
) -> Result<CreatedUser, String> {
    let op =
        AgentOperation::DirectoryCreateUser(Box::new(abyssal_agent_protocol::CreateUserRequest {
            domain_dns: hc.domain_dns.clone(),
            service_account_upn: hc.upn.clone(),
            service_account_password: hc.password.clone(),
            target_ou: plan.target_ou.clone(),
            sam_base: plan.sam_base.clone(),
            upn_suffix: plan.upn_suffix.clone(),
            given_name: plan.given_name.clone(),
            surname: plan.surname.clone(),
            display_name: plan.display_name.clone(),
            email: plan.email.clone(),
            password: password.to_string(),
            attributes: plan.attributes.clone(),
            groups: plan.groups.clone(),
            allow_privileged: allow_privileged(ctx),
        }));
    let stdout = dispatch_write(state, ctx, hc, op, Permission::DirectoryManage).await?;
    Ok(
        serde_json::from_str::<CreatedUser>(stdout.trim()).unwrap_or(CreatedUser {
            sam: plan.sam_base.clone(),
            upn: plan.upn.clone(),
        }),
    )
}

async fn bulk_cap(state: &AppState) -> u32 {
    repo::settings::get_u32(
        &state.pool,
        abyssal_core::settings::GRAVEKEEPER_BULK_IMPORT_CAP,
        abyssal_core::settings::GRAVEKEEPER_BULK_IMPORT_CAP_DEFAULT,
    )
    .await
    .unwrap_or(abyssal_core::settings::GRAVEKEEPER_BULK_IMPORT_CAP_DEFAULT)
}

/// GET the bulk onboarding form. `directory.manage`.
pub async fn bulk_form(
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
    let templates = repo::directory::list_templates(&state.pool, id)
        .await?
        .into_iter()
        .map(|t| (t.id.to_string(), t.name))
        .collect();
    let tpl = crate::templates::GravekeeperBulkTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        templates,
        cap: bulk_cap(&state).await,
        error: None,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct BulkForm {
    csrf_token: String,
    #[serde(default)]
    template_id: String,
    #[serde(default)]
    csv: String,
}

async fn bulk_form_error(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    id: Uuid,
    error: String,
) -> Result<Response, WebError> {
    let (base, new_cookie) = build_base(state, jar, ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let templates = repo::directory::list_templates(&state.pool, id)
        .await?
        .into_iter()
        .map(|t| (t.id.to_string(), t.name))
        .collect();
    let tpl = crate::templates::GravekeeperBulkTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        templates,
        cap: bulk_cap(state).await,
        error: Some(error),
    };
    Ok(respond(jar, new_cookie, tpl))
}

/// POST: preview the parsed CSV against the chosen template. `directory.manage`.
pub async fn bulk_preview(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<BulkForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let template = match load_template_for_domain(&state, id, &form.template_id).await {
        Ok(t) => t,
        Err(e) => return bulk_form_error(&state, &jar, &ctx, id, e).await,
    };
    let rows = parse_csv_rows(&form.csv);
    if rows.is_empty() {
        return bulk_form_error(
            &state,
            &jar,
            &ctx,
            id,
            "No rows found. Paste one 'First,Last' per line.".into(),
        )
        .await;
    }
    let cap = bulk_cap(&state).await;
    let over_cap = rows.len() as u32 > cap;

    let mut row_views = Vec::new();
    let mut valid_count = 0usize;
    for (first, last) in &rows {
        let plan = compute_plan(&template, &domain.dns_name, first, last);
        let valid = !first.is_empty()
            && !last.is_empty()
            && abyssal_agent_protocol::is_valid_sam_account_name(&plan.sam_base);
        if valid {
            valid_count += 1;
        }
        row_views.push(crate::templates::GravekeeperBulkRowView {
            first: first.clone(),
            last: last.clone(),
            sam: plan.sam_base.clone(),
            upn: plan.upn.clone(),
            valid,
            reason: if valid {
                String::new()
            } else {
                "Needs a first and last name that yield a valid logon name".into()
            },
        });
    }

    let tpl = crate::templates::GravekeeperBulkPreviewTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        template_id: template.id.to_string(),
        template_name: template.name,
        csv: form.csv,
        rows: row_views,
        valid_count,
        cap,
        over_cap,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

/// POST: create all valid rows. `directory.manage`.
pub async fn bulk_create(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<BulkForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let template = match load_template_for_domain(&state, id, &form.template_id).await {
        Ok(t) => t,
        Err(e) => return bulk_form_error(&state, &jar, &ctx, id, e).await,
    };
    let rows = parse_csv_rows(&form.csv);
    let cap = bulk_cap(&state).await;
    if rows.is_empty() {
        return bulk_form_error(&state, &jar, &ctx, id, "No rows to create.".into()).await;
    }
    if rows.len() as u32 > cap {
        return bulk_form_error(&state, &jar, &ctx, id, format!("Too many rows ({}); the cap is {cap}. Reduce the list or raise the cap in settings.", rows.len())).await;
    }
    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => return bulk_form_error(&state, &jar, &ctx, id, e).await,
    };

    let job_id = repo::directory::create_job(
        &state.pool,
        id,
        "bulk",
        &format!("Bulk onboard ({} rows)", rows.len()),
        Some(template.id),
        Some(ctx.user.id),
    )
    .await?;
    // Store the rows so failed ones can be retried later.
    let payload = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into());
    let _ = repo::directory::set_job_payload(&state.pool, job_id, &payload).await;

    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let (mut created, mut failed) = (Vec::new(), Vec::new());
    let mut any_fail = false;
    for (idx, (first, last)) in rows.iter().enumerate() {
        let seq = (idx + 1) as i64;
        let step_name = format!("{first} {last}");
        let plan = compute_plan(&template, &domain.dns_name, first, last);
        if first.is_empty()
            || last.is_empty()
            || !abyssal_agent_protocol::is_valid_sam_account_name(&plan.sam_base)
        {
            any_fail = true;
            repo::directory::add_job_step(
                &state.pool,
                job_id,
                seq,
                &step_name,
                "failed",
                Some("invalid name/logon"),
            )
            .await?;
            failed.push(crate::templates::GravekeeperBulkFailedView {
                first: first.clone(),
                last: last.clone(),
                reason: "invalid name".into(),
            });
            continue;
        }
        let password = generate_temp_password();
        match create_user_from_plan(&state, &ctx, &hc, &plan, &password).await {
            Ok(c) => {
                repo::directory::add_job_step(
                    &state.pool,
                    job_id,
                    seq,
                    &step_name,
                    "ok",
                    Some(&format!("Created {} ({})", c.sam, c.upn)),
                )
                .await?;
                created.push(crate::templates::GravekeeperBulkCreatedView {
                    sam: c.sam,
                    upn: c.upn,
                    password,
                });
            }
            Err(e) => {
                any_fail = true;
                repo::directory::add_job_step(
                    &state.pool,
                    job_id,
                    seq,
                    &step_name,
                    "failed",
                    Some(&e),
                )
                .await?;
                failed.push(crate::templates::GravekeeperBulkFailedView {
                    first: first.clone(),
                    last: last.clone(),
                    reason: e,
                });
            }
        }
    }
    repo::directory::finish_job(
        &state.pool,
        job_id,
        if any_fail { "partial" } else { "completed" },
        None,
        None,
    )
    .await?;
    record_audit(
        &state,
        &ctx,
        AuditAction::DirectoryAccountCreated,
        &domain.dns_name,
        serde_json::json!({ "action": "bulk_onboard", "created": created.len(), "failed": failed.len() }),
    )
    .await;

    let tpl = crate::templates::GravekeeperBulkResultTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        job_id: job_id.to_string(),
        created,
        failed,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

/// POST: retry the failed rows of a bulk job. `directory.manage`.
pub async fn bulk_retry(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(jid): Path<Uuid>,
    Form(form): Form<RemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let job = repo::directory::find_job(&state.pool, jid)
        .await?
        .ok_or(AppError::NotFound)?;
    let id = job.domain_id;
    let (Some(template_id), Some(payload)) = (job.template_id, job.payload_json.clone()) else {
        return Err(WebError(AppError::Validation(
            "This job has no retry context.".into(),
        )));
    };
    let template = repo::directory::find_template(&state.pool, template_id)
        .await?
        .ok_or_else(|| {
            WebError(AppError::Validation(
                "The template this job used no longer exists.".into(),
            ))
        })?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let rows: Vec<(String, String)> = serde_json::from_str(&payload).unwrap_or_default();
    let steps = repo::directory::job_steps(&state.pool, jid).await?;
    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => return Err(WebError(AppError::Validation(e))),
    };

    let mut still_failing = false;
    for step in &steps {
        if step.status != "failed" {
            continue;
        }
        let Some((first, last)) = rows.get((step.seq - 1) as usize) else {
            continue;
        };
        let plan = compute_plan(&template, &domain.dns_name, first, last);
        if first.is_empty()
            || last.is_empty()
            || !abyssal_agent_protocol::is_valid_sam_account_name(&plan.sam_base)
        {
            still_failing = true;
            continue;
        }
        let password = generate_temp_password();
        match create_user_from_plan(&state, &ctx, &hc, &plan, &password).await {
            Ok(c) => {
                repo::directory::update_job_step_by_seq(
                    &state.pool,
                    jid,
                    step.seq,
                    "ok",
                    Some(&format!("Created {} ({}) on retry", c.sam, c.upn)),
                )
                .await?;
            }
            Err(e) => {
                still_failing = true;
                repo::directory::update_job_step_by_seq(
                    &state.pool,
                    jid,
                    step.seq,
                    "failed",
                    Some(&e),
                )
                .await?;
            }
        }
    }
    repo::directory::set_job_status(
        &state.pool,
        jid,
        if still_failing {
            "partial"
        } else {
            "completed"
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/arsenals/gravekeeper/jobs/{jid}")).into_response())
}

// --- Cross-domain find + Thanatos workflow landing (directory.view) ----------

#[derive(Deserialize)]
pub struct FindQuery {
    #[serde(default)]
    q: String,
    /// The registry/Thanatos button may pass an account name as context.
    #[serde(default)]
    account: String,
}

/// The workflow-registry button points at `/arsenals/gravekeeper/{host_id}`
/// (the Thanatos event's host, which Gravekeeper doesn't use). This landing
/// ignores it and sends the operator to the cross-domain find, pre-filling an
/// `account` if the event supplied one. `directory.view`.
pub async fn workflow_landing(
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(_host_id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<FindQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryView)?;
    let _ = &jar;
    let account = if !query.account.is_empty() {
        query.account
    } else {
        query.q
    };
    let target = if account.trim().is_empty() {
        "/arsenals/gravekeeper/find".to_string()
    } else {
        format!(
            "/arsenals/gravekeeper/find?q={}",
            crate::common::urlencoding_encode(account.trim())
        )
    };
    Ok(Redirect::to(&target).into_response())
}

/// GET the cross-domain find page: searches every configured domain whose write
/// DC is connected and merges the results. `directory.view`.
pub async fn find(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    axum::extract::Query(query): axum::extract::Query<FindQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryView)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let q = query.q.trim().to_string();

    let mut results: Vec<crate::templates::GravekeeperFindRow> = Vec::new();
    let mut error = None;
    if !q.is_empty() {
        for domain in repo::directory::list(&state.pool).await? {
            let Some(hid) = domain
                .write_dc_host_id
                .filter(|h| state.hosts.is_connected(*h))
            else {
                continue;
            };
            let host = match repo::hosts::find_by_id(&state.pool, hid).await? {
                Some(h) => h,
                None => continue,
            };
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
                Ok(stdout) => {
                    if let Ok(hits) = parse_list::<SearchHit>(&stdout) {
                        for h in hits {
                            let sub = h
                                .upn
                                .filter(|s| !s.is_empty())
                                .or(h.sam)
                                .unwrap_or_default();
                            results.push(crate::templates::GravekeeperFindRow {
                                domain_id: domain.id.to_string(),
                                domain_dns: domain.dns_name.clone(),
                                kind: h.kind,
                                name: h.name,
                                sub,
                                dn_encoded: crate::common::urlencoding_encode(&h.dn),
                            });
                        }
                    }
                }
                Err(e) => {
                    error.get_or_insert(format!("{}: {e}", domain.dns_name));
                }
            }
        }
    }

    let tpl = crate::templates::GravekeeperFindTemplate {
        base,
        query: q,
        results,
        error,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

// --- Stale-accounts report (directory.view; disable = directory.helpdesk) ----

#[derive(Deserialize)]
struct StaleAccount {
    #[serde(default)]
    name: String,
    #[serde(default)]
    sam: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    dn: String,
    #[serde(default)]
    last_logon: String,
}

#[derive(Deserialize)]
pub struct StaleQuery {
    #[serde(default)]
    days: Option<u32>,
}

/// GET the stale-accounts report. `directory.view`.
pub async fn stale_report(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<StaleQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryView)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let days = query.days.unwrap_or(90).clamp(1, 3650);

    let mut error = None;
    let mut rows: Vec<crate::templates::GravekeeperStaleRow> = Vec::new();
    match domain.write_dc_host_id {
        Some(hid) if state.hosts.is_connected(hid) => {
            let host = repo::hosts::find_by_id(&state.pool, hid)
                .await?
                .ok_or(AppError::NotFound)?;
            match dispatch_directory(
                &state,
                &ctx,
                host.id,
                &host.name,
                AgentOperation::DirectoryStaleAccounts {
                    domain_dns: domain.dns_name.clone(),
                    days,
                },
                Permission::DirectoryView,
                BROWSE_TIMEOUT,
            )
            .await
            {
                Ok(stdout) => match parse_list::<StaleAccount>(&stdout) {
                    Ok(accts) => {
                        rows = accts
                            .into_iter()
                            .map(|a| crate::templates::GravekeeperStaleRow {
                                name: a.name,
                                sam: a.sam.unwrap_or_default(),
                                upn: a.upn.unwrap_or_default(),
                                dn_encoded: crate::common::urlencoding_encode(&a.dn),
                                dn: a.dn,
                                last_logon: if a.last_logon.is_empty() {
                                    "never".into()
                                } else {
                                    a.last_logon
                                },
                            })
                            .collect()
                    }
                    Err(e) => error = Some(format!("Couldn't read the report: {e}")),
                },
                Err(e) => error = Some(e),
            }
        }
        Some(_) => error = Some("The domain's write DC isn't connected right now.".into()),
        None => error = Some("This domain has no write DC set yet.".into()),
    }

    let tpl = crate::templates::GravekeeperStaleTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        days,
        can_disable: ctx.has(Permission::DirectoryHelpdesk),
        rows,
        error,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct StaleDisableForm {
    csrf_token: String,
    dn: String,
    #[serde(default)]
    days: u32,
}

/// POST: disable a stale account and return to the report. `directory.helpdesk`.
pub async fn stale_disable(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<StaleDisableForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryHelpdesk)?;
    require_csrf(&jar, &form.csrf_token)?;
    let dn = form.dn.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ldap_dn(&dn) {
        return Err(WebError(AppError::Validation("Invalid account DN.".into())));
    }
    if let Ok(hc) = helpdesk_prepare(&state, id).await {
        let op = AgentOperation::DirectorySetEnabled {
            domain_dns: hc.domain_dns.clone(),
            service_account_upn: hc.upn.clone(),
            service_account_password: hc.password.clone(),
            target_dn: dn.clone(),
            enabled: false,
            allow_privileged: allow_privileged(&ctx),
        };
        if dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryHelpdesk)
            .await
            .is_ok()
        {
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryAccountEnabledChanged,
                &hc.domain_dns,
                serde_json::json!({ "target_dn": dn, "enabled": false, "from": "stale_report" }),
            )
            .await;
        }
    }
    let days = form.days.clamp(1, 3650);
    Ok(Redirect::to(&format!(
        "/arsenals/gravekeeper/domains/{id}/stale?days={days}"
    ))
    .into_response())
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
    m365_usage_location: String,
    #[serde(default)]
    m365_licensing_group: String,
    #[serde(default)]
    m365_license_sku: String,
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
    mail_settings_json: Option<String>,
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

    // Microsoft 365 licensing settings (stored as the template's mail_settings).
    let usage = form.m365_usage_location.trim().to_uppercase();
    if !usage.is_empty() && !(usage.len() == 2 && usage.chars().all(|c| c.is_ascii_alphabetic())) {
        return Err("Usage location must be a 2-letter country code (e.g. US), or blank.".into());
    }
    let group = form.m365_licensing_group.trim().to_string();
    let sku = form.m365_license_sku.trim().to_string();
    let mail_settings_json = if usage.is_empty() && group.is_empty() && sku.is_empty() {
        None
    } else {
        Some(
            serde_json::json!({
                "usage_location": usage,
                "licensing_group": group,
                "license_sku": sku,
            })
            .to_string(),
        )
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
        mail_settings_json,
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
                    mail_settings_json: p.mail_settings_json.as_deref(),
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
                    mail_settings_json: p.mail_settings_json.as_deref(),
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
        m365_usage_location: String::new(),
        m365_licensing_group: String::new(),
        m365_license_sku: String::new(),
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
        m365_usage_location: t.m365_usage_location.clone(),
        m365_licensing_group: t.m365_licensing_group.clone(),
        m365_license_sku: t.m365_license_sku.clone(),
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
        m365_usage_location: form.m365_usage_location.clone(),
        m365_licensing_group: form.m365_licensing_group.clone(),
        m365_license_sku: form.m365_license_sku.clone(),
        manager_required: form.manager_required,
    }
}

// --- Onboarding: create a user from a template (directory.manage) ----------

/// The computed change-set an onboarding run will apply, for the preview and
/// the create.
struct OnboardPlan {
    sam_base: String,
    upn: String,
    email: String,
    target_ou: String,
    upn_suffix: String,
    given_name: String,
    surname: String,
    display_name: String,
    attributes: Vec<(String, String)>,
    groups: Vec<String>,
    mail_mode: String,
}

/// Builds the change-set from a template and a first/last name. Pure: the DB is
/// only read by the caller to fetch the template and domain.
fn compute_plan(
    template: &repo::directory::DirectoryTemplate,
    domain_dns: &str,
    first: &str,
    last: &str,
) -> OnboardPlan {
    let first = first.trim();
    let last = last.trim();
    let sam_base = abyssal_agent_protocol::sanitize_sam_account_name(
        &abyssal_agent_protocol::expand_name_pattern(&template.username_pattern, first, last),
    );
    let upn_suffix = template
        .upn_suffix
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| domain_dns.to_string());
    let upn = format!("{sam_base}@{upn_suffix}");
    let email = template
        .email_pattern
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|p| abyssal_agent_protocol::expand_name_pattern(p, first, last).to_lowercase())
        .unwrap_or_default();
    let display_name = match (first.is_empty(), last.is_empty()) {
        (false, false) => format!("{first} {last}"),
        (false, true) => first.to_string(),
        (true, false) => last.to_string(),
        (true, true) => sam_base.clone(),
    };
    OnboardPlan {
        sam_base,
        upn,
        email,
        target_ou: template.target_ou.clone().unwrap_or_default(),
        upn_suffix,
        given_name: first.to_string(),
        surname: last.to_string(),
        display_name,
        attributes: template.attributes.clone(),
        groups: template.groups.clone(),
        mail_mode: template.mail_mode.clone(),
    }
}

/// GET the onboarding form: pick a template, enter a name. `directory.manage`.
pub async fn onboard_form(
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
    let templates = repo::directory::list_templates(&state.pool, id)
        .await?
        .into_iter()
        .map(|t| (t.id.to_string(), t.name))
        .collect();
    let tpl = crate::templates::GravekeeperOnboardTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        templates,
        error: None,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct OnboardForm {
    csrf_token: String,
    #[serde(default)]
    template_id: String,
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
}

async fn load_template_for_domain(
    state: &AppState,
    domain_id: Uuid,
    template_id: &str,
) -> Result<repo::directory::DirectoryTemplate, String> {
    let tid = Uuid::parse_str(template_id.trim()).map_err(|_| "Pick a template.".to_string())?;
    let t = repo::directory::find_template(&state.pool, tid)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Unknown template.")?;
    if t.domain_id != domain_id {
        return Err("That template belongs to a different domain.".into());
    }
    Ok(t)
}

/// POST: compute and show the change-set preview. `directory.manage`.
pub async fn onboard_preview(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<OnboardForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let first = form.first_name.trim().to_string();
    let last = form.last_name.trim().to_string();
    let template = match load_template_for_domain(&state, id, &form.template_id).await {
        Ok(t) => t,
        Err(e) => return onboard_form_error(&state, &jar, new_cookie, base, &domain, e).await,
    };
    if first.is_empty() || last.is_empty() {
        return onboard_form_error(
            &state,
            &jar,
            new_cookie,
            base,
            &domain,
            "Enter both a first and last name.".into(),
        )
        .await;
    }

    let plan = compute_plan(&template, &domain.dns_name, &first, &last);
    if !abyssal_agent_protocol::is_valid_sam_account_name(&plan.sam_base) {
        return onboard_form_error(
            &state,
            &jar,
            new_cookie,
            base,
            &domain,
            "That name doesn't produce a valid logon name with this template's pattern.".into(),
        )
        .await;
    }

    let tpl = crate::templates::GravekeeperOnboardPreviewTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        template_id: template.id.to_string(),
        template_name: template.name,
        first_name: first,
        last_name: last,
        plan: plan_view(&plan),
    };
    Ok(respond(&jar, new_cookie, tpl))
}

async fn onboard_form_error(
    state: &AppState,
    jar: &CookieJar,
    new_cookie: Option<axum_extra::extract::cookie::Cookie<'static>>,
    base: BaseCtx,
    domain: &repo::directory::DirectoryDomain,
    error: String,
) -> Result<Response, WebError> {
    let templates = repo::directory::list_templates(&state.pool, domain.id)
        .await?
        .into_iter()
        .map(|t| (t.id.to_string(), t.name))
        .collect();
    let tpl = crate::templates::GravekeeperOnboardTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name.clone(),
        templates,
        error: Some(error),
    };
    Ok(respond(jar, new_cookie, tpl))
}

fn plan_view(plan: &OnboardPlan) -> crate::templates::GravekeeperPlanView {
    crate::templates::GravekeeperPlanView {
        sam_base: plan.sam_base.clone(),
        upn: plan.upn.clone(),
        email: plan.email.clone(),
        target_ou: plan.target_ou.clone(),
        display_name: plan.display_name.clone(),
        attributes: plan.attributes.clone(),
        groups: plan.groups.clone(),
        mail_mode: plan.mail_mode.clone(),
    }
}

/// POST: create the user. Recomputes the plan from the template + name (never
/// trusting a client-submitted change-set), dispatches `DirectoryCreateUser`,
/// records a job, and shows the result (final name + temp password once).
pub async fn onboard_create(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<OnboardForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let domain = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let first = form.first_name.trim().to_string();
    let last = form.last_name.trim().to_string();

    let template = match load_template_for_domain(&state, id, &form.template_id).await {
        Ok(t) => t,
        Err(e) => return onboard_form_error(&state, &jar, new_cookie, base, &domain, e).await,
    };
    if first.is_empty() || last.is_empty() {
        return onboard_form_error(
            &state,
            &jar,
            new_cookie,
            base,
            &domain,
            "Enter both a first and last name.".into(),
        )
        .await;
    }
    let plan = compute_plan(&template, &domain.dns_name, &first, &last);
    if !abyssal_agent_protocol::is_valid_sam_account_name(&plan.sam_base) {
        return onboard_form_error(
            &state,
            &jar,
            new_cookie,
            base,
            &domain,
            "That name doesn't produce a valid logon name with this template's pattern.".into(),
        )
        .await;
    }

    let hc = match helpdesk_prepare(&state, id).await {
        Ok(hc) => hc,
        Err(e) => return onboard_form_error(&state, &jar, new_cookie, base, &domain, e).await,
    };

    let password = generate_temp_password();
    let op =
        AgentOperation::DirectoryCreateUser(Box::new(abyssal_agent_protocol::CreateUserRequest {
            domain_dns: hc.domain_dns.clone(),
            service_account_upn: hc.upn.clone(),
            service_account_password: hc.password.clone(),
            target_ou: plan.target_ou.clone(),
            sam_base: plan.sam_base.clone(),
            upn_suffix: plan.upn_suffix.clone(),
            given_name: plan.given_name.clone(),
            surname: plan.surname.clone(),
            display_name: plan.display_name.clone(),
            email: plan.email.clone(),
            password: password.clone(),
            attributes: plan.attributes.clone(),
            groups: plan.groups.clone(),
            allow_privileged: allow_privileged(&ctx),
        }));

    // Record a job up front so the attempt is visible even if it fails.
    let job_id = repo::directory::create_job(
        &state.pool,
        id,
        "onboard",
        &format!("Onboard {} {}", first, last),
        Some(template.id),
        Some(ctx.user.id),
    )
    .await?;

    let dispatch = dispatch_write(&state, &ctx, &hc, op, Permission::DirectoryManage).await;

    match dispatch {
        Ok(stdout) => {
            let created: CreatedUser = serde_json::from_str(stdout.trim()).unwrap_or(CreatedUser {
                sam: plan.sam_base.clone(),
                upn: plan.upn.clone(),
            });
            repo::directory::add_job_step(
                &state.pool,
                job_id,
                1,
                "Create AD account",
                "ok",
                Some(&format!("Created {} ({})", created.sam, created.upn)),
            )
            .await?;
            // Mail step: provision a mailbox when the template asks for one. A
            // mail failure never rolls back the AD account -- the job ends
            // "partial" and the mail step can be retried (P2-M4).
            let mut final_status = "completed";
            if plan.mail_mode != "none" {
                let (step_status, detail) =
                    provision_mailbox(&state, &ctx, id, &created.upn, &created.sam, &template)
                        .await;
                repo::directory::add_job_step(
                    &state.pool,
                    job_id,
                    2,
                    "Mailbox",
                    step_status,
                    Some(&detail),
                )
                .await?;
                if step_status == "failed" {
                    final_status = "partial";
                }
            }
            repo::directory::finish_job(
                &state.pool,
                job_id,
                final_status,
                Some(&created.sam),
                Some(&created.upn),
            )
            .await?;
            record_audit(
                &state,
                &ctx,
                AuditAction::DirectoryAccountCreated,
                &domain.dns_name,
                serde_json::json!({ "sam": created.sam, "upn": created.upn, "template": template.name }),
            )
            .await;

            let tpl = crate::templates::GravekeeperOnboardResultTemplate {
                base,
                domain_id: domain.id.to_string(),
                dns_name: domain.dns_name,
                job_id: job_id.to_string(),
                sam: created.sam,
                upn: created.upn,
                new_password: password,
            };
            Ok(respond(&jar, new_cookie, tpl))
        }
        Err(e) => {
            repo::directory::add_job_step(
                &state.pool,
                job_id,
                1,
                "Create AD account",
                "failed",
                Some(&e),
            )
            .await?;
            repo::directory::finish_job(&state.pool, job_id, "failed", None, None).await?;
            onboard_form_error(
                &state,
                &jar,
                new_cookie,
                base,
                &domain,
                format!("Onboarding failed: {e}"),
            )
            .await
        }
    }
}

#[derive(Deserialize)]
struct CreatedUser {
    #[serde(default)]
    sam: String,
    #[serde(default)]
    upn: String,
}

// --- Jobs (directory.manage) -----------------------------------------------

/// GET a domain's onboarding/offboarding jobs. `directory.manage`.
pub async fn jobs(
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
    let rows = repo::directory::list_jobs(&state.pool, id, 100)
        .await?
        .into_iter()
        .map(|j| crate::templates::GravekeeperJobRow {
            id: j.id.to_string(),
            title: j.title,
            kind: j.kind,
            target_sam: j.target_sam.unwrap_or_default(),
            status: j.status,
            created_at: crate::common::format_in_tz(j.created_at, &ctx.user.timezone),
        })
        .collect();
    let tpl = crate::templates::GravekeeperJobsTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        jobs: rows,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

/// GET one job's detail (its steps). `directory.manage`.
pub async fn job_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(jid): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    let (base, new_cookie) = build_base(&state, &jar, &ctx).await?;
    let job = repo::directory::find_job(&state.pool, jid)
        .await?
        .ok_or(AppError::NotFound)?;
    let domain = repo::directory::find_by_id(&state.pool, job.domain_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let raw_steps = repo::directory::job_steps(&state.pool, jid).await?;
    // The mail step is retryable when it exists and didn't succeed, the job
    // still knows the account's UPN, and the template is still around.
    let can_retry_mail = job.kind == "onboard"
        && job.target_upn.is_some()
        && job.template_id.is_some()
        && raw_steps
            .iter()
            .any(|s| s.name == "Mailbox" && s.status != "ok");
    let steps = raw_steps
        .into_iter()
        .map(|s| crate::templates::GravekeeperStepView {
            name: s.name,
            status: s.status,
            detail: s.detail.unwrap_or_default(),
        })
        .collect();
    let tpl = crate::templates::GravekeeperJobTemplate {
        base,
        job_id: job.id.to_string(),
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        title: job.title,
        kind: job.kind,
        target_sam: job.target_sam.unwrap_or_default(),
        status: job.status,
        created_at: crate::common::format_in_tz(job.created_at, &ctx.user.timezone),
        steps,
        can_retry_mail,
    };
    Ok(respond(&jar, new_cookie, tpl))
}

/// POST: retry a job's mail step without re-creating the AD account.
/// `directory.manage`.
pub async fn retry_mail_step(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(jid): Path<Uuid>,
    Form(form): Form<RemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryManage)?;
    require_csrf(&jar, &form.csrf_token)?;
    let job = repo::directory::find_job(&state.pool, jid)
        .await?
        .ok_or(AppError::NotFound)?;

    let (Some(upn), Some(template_id)) = (job.target_upn.clone(), job.template_id) else {
        return Err(WebError(AppError::Validation(
            "This job can't retry mail (it has no stored account UPN or template).".into(),
        )));
    };
    let template = repo::directory::find_template(&state.pool, template_id)
        .await?
        .ok_or_else(|| {
            WebError(AppError::Validation(
                "The template this job used no longer exists.".into(),
            ))
        })?;
    let sam = job.target_sam.clone().unwrap_or_default();

    let (status, detail) =
        provision_mailbox(&state, &ctx, job.domain_id, &upn, &sam, &template).await;
    repo::directory::update_job_step_by_name(&state.pool, jid, "Mailbox", status, Some(&detail))
        .await?;
    // Recompute the job's overall status from the mail outcome.
    let job_status = if status == "ok" {
        "completed"
    } else {
        "partial"
    };
    repo::directory::set_job_status(&state.pool, jid, job_status).await?;
    if let Some(domain) = repo::directory::find_by_id(&state.pool, job.domain_id).await? {
        record_audit(
            &state,
            &ctx,
            AuditAction::DirectoryAccountCreated,
            &domain.dns_name,
            serde_json::json!({ "action": "mail_step_retried", "upn": upn, "result": status }),
        )
        .await;
    }
    Ok(Redirect::to(&format!("/arsenals/gravekeeper/jobs/{jid}")).into_response())
}

// --- Mail connections (directory.configure) --------------------------------

const MAIL_TIMEOUT: Duration = Duration::from_secs(90);

/// Provisions a mailbox for a freshly created user, per the domain's mail
/// connection. Returns `(step_status, detail)` for the onboarding job. A failure
/// here is reported, never fatal to the already-created AD account.
async fn provision_mailbox(
    state: &AppState,
    ctx: &AuthContext,
    domain_id: Uuid,
    created_upn: &str,
    created_sam: &str,
    template: &repo::directory::DirectoryTemplate,
) -> (&'static str, String) {
    let conn = match repo::directory::find_mail_connection(&state.pool, domain_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                "failed",
                "The template asks for a mailbox, but this domain has no mail connection configured.".into(),
            );
        }
        Err(e) => return ("failed", format!("Couldn't read the mail connection: {e}")),
    };
    match conn.mode.as_str() {
        "none" => (
            "skipped",
            "The domain's mail connection is set to none.".into(),
        ),
        "m365" => provision_m365_mailbox(state, domain_id, created_upn, template).await,
        "exchange_onprem" | "exchange_hybrid" => {
            let hybrid = conn.mode == "exchange_hybrid";
            let creds = match repo::directory::exchange_credentials(&state.pool, domain_id).await {
                Ok(Some(c)) => c,
                Ok(None) => return ("failed", "Exchange account not configured.".into()),
                Err(e) => return ("failed", format!("Couldn't read the Exchange account: {e}")),
            };
            let (uri, account_upn, sealed, agent_host_id, remote_routing_domain) = (
                creds.uri,
                creds.account_upn,
                creds.sealed,
                creds.agent_host_id,
                creds.remote_routing_domain,
            );
            let Some(host_id) = agent_host_id else {
                return (
                    "failed",
                    "No Exchange agent host is set for this domain.".into(),
                );
            };
            if !state.hosts.is_connected(host_id) {
                return ("failed", "The Exchange agent host isn't connected.".into());
            }
            let Some(key) = state.encryption_key.clone() else {
                return (
                    "failed",
                    "This control plane has no ENCRYPTION_KEY set.".into(),
                );
            };
            let password = match key.decrypt(&sealed) {
                Ok(p) => p.to_string(),
                Err(e) => {
                    return (
                        "failed",
                        format!("Couldn't decrypt the Exchange account: {e}"),
                    );
                }
            };
            let remote_routing_address = if hybrid {
                match remote_routing_domain {
                    Some(d) if !d.is_empty() => format!("{created_sam}@{d}"),
                    _ => {
                        return (
                            "failed",
                            "Hybrid mode needs a remote routing domain.".into(),
                        );
                    }
                }
            } else {
                String::new()
            };
            let host = match repo::hosts::find_by_id(&state.pool, host_id).await {
                Ok(Some(h)) => h,
                _ => return ("failed", "The Exchange agent host no longer exists.".into()),
            };
            let op = AgentOperation::ExchangeEnableMailbox {
                uri,
                account_upn,
                account_password: password,
                target_identity: created_upn.to_string(),
                remote_routing_address,
            };
            match state
                .executor
                .execute_on_host(
                    ctx,
                    &state.hosts,
                    host_id,
                    &host.name,
                    op,
                    Permission::DirectoryManage,
                    OperationKind::Write,
                    false,
                    MAIL_TIMEOUT,
                    None,
                    false,
                )
                .await
            {
                Ok(_) => (
                    "ok",
                    if hybrid {
                        "Remote mailbox enabled (Exchange hybrid).".into()
                    } else {
                        "Mailbox enabled (on-premises Exchange).".into()
                    },
                ),
                Err(e) => ("failed", format!("Enable mailbox failed: {e}")),
            }
        }
        other => ("failed", format!("Unknown mail mode: {other}")),
    }
}

/// The Microsoft 365 branch of [`provision_mailbox`]: license the synced user
/// via Graph using the domain's app credentials and the template's licensing
/// choices.
async fn provision_m365_mailbox(
    state: &AppState,
    domain_id: Uuid,
    created_upn: &str,
    template: &repo::directory::DirectoryTemplate,
) -> (&'static str, String) {
    let creds = match repo::directory::m365_credentials(&state.pool, domain_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                "failed",
                "Microsoft 365 isn't fully configured (tenant, app and certificate).".into(),
            );
        }
        Err(e) => return ("failed", format!("Couldn't read the M365 config: {e}")),
    };
    let Some(key) = state.encryption_key.clone() else {
        return (
            "failed",
            "This control plane has no ENCRYPTION_KEY set.".into(),
        );
    };
    let cert_pem = match key.decrypt(&creds.cert_sealed) {
        Ok(p) => p.to_string(),
        Err(e) => {
            return (
                "failed",
                format!("Couldn't decrypt the M365 certificate: {e}"),
            );
        }
    };
    let cfg = crate::gravekeeper_graph::GraphConfig {
        tenant_id: creds.tenant_id,
        app_id: creds.app_id,
        cert_pem,
        licensing_method: creds.licensing_method,
    };
    let lic = crate::gravekeeper_graph::M365Licensing {
        usage_location: template.m365_usage_location.clone(),
        licensing_group: template.m365_licensing_group.clone(),
        license_sku: template.m365_license_sku.clone(),
    };
    match crate::gravekeeper_graph::provision_user(&cfg, created_upn, &lic).await {
        Ok(detail) => ("ok", detail),
        Err(e) => ("failed", e),
    }
}

/// GET the mail-connection config page for a domain. `directory.configure`.
pub async fn mail_config(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    render_mail(&state, &jar, &ctx, id, None, None).await
}

async fn render_mail(
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
    let conn = repo::directory::find_mail_connection(&state.pool, id).await?;
    let agent_hosts = connected_windows_hosts(state).await?;

    let form = match &conn {
        Some(c) => crate::templates::GravekeeperMailFormView {
            mode: c.mode.clone(),
            exchange_version: c.exchange_version.clone().unwrap_or_else(|| "2019".into()),
            exchange_uri: c.exchange_uri.clone().unwrap_or_default(),
            exchange_account_upn: c.exchange_account_upn.clone().unwrap_or_default(),
            exchange_agent_host_id: c
                .exchange_agent_host_id
                .map(|u| u.to_string())
                .unwrap_or_default(),
            remote_routing_domain: c.remote_routing_domain.clone().unwrap_or_default(),
            m365_tenant_id: c.m365_tenant_id.clone().unwrap_or_default(),
            m365_app_id: c.m365_app_id.clone().unwrap_or_default(),
            m365_licensing_method: c
                .m365_licensing_method
                .clone()
                .unwrap_or_else(|| "group".into()),
        },
        None => crate::templates::GravekeeperMailFormView {
            mode: "none".into(),
            exchange_version: "2019".into(),
            exchange_uri: String::new(),
            exchange_account_upn: String::new(),
            exchange_agent_host_id: String::new(),
            remote_routing_domain: String::new(),
            m365_tenant_id: String::new(),
            m365_app_id: String::new(),
            m365_licensing_method: "group".into(),
        },
    };
    let last_test = conn.as_ref().and_then(|c| {
        c.last_test_ok
            .map(|ok| crate::templates::GravekeeperMailTest {
                ok,
                detail: c.last_test_detail.clone().unwrap_or_default(),
                when: c
                    .last_test_at
                    .map(|t| crate::common::format_in_tz(t, &ctx.user.timezone))
                    .unwrap_or_default(),
            })
    });

    let tpl = crate::templates::GravekeeperMailTemplate {
        base,
        domain_id: domain.id.to_string(),
        dns_name: domain.dns_name,
        form,
        agent_hosts,
        has_exchange_account: conn.as_ref().is_some_and(|c| c.has_exchange_account),
        has_m365_cert: conn.as_ref().is_some_and(|c| c.has_m365_cert),
        last_test,
        result,
        error,
    };
    Ok(respond(jar, new_cookie, tpl))
}

#[derive(Deserialize)]
pub struct MailForm {
    csrf_token: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    exchange_version: String,
    #[serde(default)]
    exchange_uri: String,
    #[serde(default)]
    exchange_account_upn: String,
    #[serde(default)]
    exchange_account_password: String,
    #[serde(default)]
    exchange_agent_host_id: String,
    #[serde(default)]
    remote_routing_domain: String,
    #[serde(default)]
    m365_tenant_id: String,
    #[serde(default)]
    m365_app_id: String,
    #[serde(default)]
    m365_cert: String,
    #[serde(default)]
    m365_licensing_method: String,
}

const MAIL_MODES_ALL: &[&str] = &["none", "exchange_onprem", "exchange_hybrid", "m365"];

/// POST: save the domain's mail connection. `directory.configure`.
pub async fn save_mail_config(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<MailForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    require_csrf(&jar, &form.csrf_token)?;
    let _ = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    if !MAIL_MODES_ALL.contains(&form.mode.as_str()) {
        return render_mail(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("Pick a valid mail mode.".into()),
        )
        .await;
    }
    let existing = repo::directory::find_mail_connection(&state.pool, id).await?;

    let blank_to_none = |s: &str| -> Option<String> {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };

    // Per-mode validation.
    if form.mode == "exchange_onprem" || form.mode == "exchange_hybrid" {
        let uri = form.exchange_uri.trim();
        if !(uri.starts_with("http://") || uri.starts_with("https://")) || uri.len() > 512 {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("Enter the Exchange connection URI (http(s)://…/PowerShell/).".into()),
            )
            .await;
        }
        let acct = form.exchange_account_upn.trim();
        if !abyssal_agent_protocol::is_valid_user_principal_name(acct) {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("Enter the Recipient Management account as a UPN.".into()),
            )
            .await;
        }
        if !["2016", "2019", "se"].contains(&form.exchange_version.as_str()) {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("Pick an Exchange version.".into()),
            )
            .await;
        }
        if Uuid::parse_str(form.exchange_agent_host_id.trim()).is_err() {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("Pick the agent host that reaches Exchange.".into()),
            )
            .await;
        }
        // The agent host must be one we actually manage and can reach -- never
        // an arbitrary id. The stored Exchange credential is later shipped to
        // this host, so binding to an unconnected or non-Windows host is refused
        // here.
        let agent_hosts = connected_windows_hosts(&state).await?;
        if !agent_hosts
            .iter()
            .any(|(hid, _)| hid == form.exchange_agent_host_id.trim())
        {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some(
                    "That agent host isn't a connected Windows host. Pick one from the list."
                        .into(),
                ),
            )
            .await;
        }
        // Credential re-targeting guard: a blank password keeps the stored
        // secret, so changing a *destination* (URI, account or agent host) while
        // leaving the password blank would re-point the stored Recipient
        // Management credential at a new target. Require re-entering it.
        if form.exchange_account_password.is_empty()
            && let Some(c) = &existing
            && c.has_exchange_account
        {
            let changed = c.exchange_uri.as_deref().unwrap_or_default() != form.exchange_uri.trim()
                || c.exchange_account_upn.as_deref().unwrap_or_default()
                    != form.exchange_account_upn.trim()
                || c.exchange_agent_host_id
                    .map(|u| u.to_string())
                    .unwrap_or_default()
                    != form.exchange_agent_host_id.trim();
            if changed {
                return render_mail(
                    &state,
                    &jar,
                    &ctx,
                    id,
                    None,
                    Some("Re-enter the Recipient Management account's password when changing the Exchange URI, account or agent host.".into()),
                )
                .await;
            }
        }
        if form.mode == "exchange_hybrid"
            && !abyssal_agent_protocol::is_valid_hostname(form.remote_routing_domain.trim())
        {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some(
                    "Hybrid mode needs a remote routing domain (e.g. tenant.mail.onmicrosoft.com)."
                        .into(),
                ),
            )
            .await;
        }
        // No stored account and no entered password -> require one.
        let has_existing = existing.as_ref().is_some_and(|c| c.has_exchange_account);
        if form.exchange_account_password.is_empty() && !has_existing {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("Enter the Recipient Management account's password.".into()),
            )
            .await;
        }
    }

    // Same credential re-targeting guard for the Microsoft 365 certificate: a
    // blank cert keeps the stored one, so changing the tenant or app id while
    // leaving it blank would re-point the stored certificate at a new tenant/app.
    if form.mode == "m365"
        && form.m365_cert.trim().is_empty()
        && let Some(c) = &existing
        && c.has_m365_cert
    {
        let changed = c.m365_tenant_id.as_deref().unwrap_or_default() != form.m365_tenant_id.trim()
            || c.m365_app_id.as_deref().unwrap_or_default() != form.m365_app_id.trim();
        if changed {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("Re-upload the certificate when changing the Microsoft 365 tenant or application id.".into()),
            )
            .await;
        }
    }

    // Resolve secrets: a blank secret field keeps the stored one.
    let exchange_sealed: Option<String> = if form.exchange_account_password.is_empty() {
        // keep existing: read the raw sealed value back
        repo::directory::exchange_credentials(&state.pool, id)
            .await?
            .map(|c| c.sealed)
    } else {
        let Some(key) = state.encryption_key.clone() else {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("No ENCRYPTION_KEY is set, so secrets can't be stored.".into()),
            )
            .await;
        };
        Some(key.encrypt(&form.exchange_account_password).map_err(|e| {
            WebError(AppError::Validation(format!(
                "Couldn't seal the password: {e}"
            )))
        })?)
    };

    // A blank certificate field keeps the stored one; a filled one is sealed.
    let m365_cert_to_store: Option<String> = if form.m365_cert.trim().is_empty() {
        existing_m365_cert(&state, id).await?
    } else {
        let Some(key) = state.encryption_key.clone() else {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some("No ENCRYPTION_KEY is set, so the certificate can't be stored.".into()),
            )
            .await;
        };
        Some(key.encrypt(form.m365_cert.trim()).map_err(|e| {
            WebError(AppError::Validation(format!(
                "Couldn't seal the certificate: {e}"
            )))
        })?)
    };

    repo::directory::upsert_mail_connection(
        &state.pool,
        &repo::directory::NewMailConnection {
            domain_id: id,
            mode: &form.mode,
            exchange_version: blank_to_none(&form.exchange_version).as_deref(),
            exchange_uri: blank_to_none(&form.exchange_uri).as_deref(),
            exchange_account_upn: blank_to_none(&form.exchange_account_upn).as_deref(),
            exchange_account_sealed: exchange_sealed.as_deref(),
            exchange_agent_host_id: Uuid::parse_str(form.exchange_agent_host_id.trim()).ok(),
            remote_routing_domain: blank_to_none(&form.remote_routing_domain).as_deref(),
            m365_tenant_id: blank_to_none(&form.m365_tenant_id).as_deref(),
            m365_app_id: blank_to_none(&form.m365_app_id).as_deref(),
            m365_cert_sealed: m365_cert_to_store.as_deref(),
            m365_licensing_method: blank_to_none(&form.m365_licensing_method).as_deref(),
            created_by: Some(ctx.user.id),
        },
    )
    .await?;

    // Keep the domain's own mail_mode in step with the connection mode.
    if let Some(domain) = repo::directory::find_by_id(&state.pool, id).await? {
        record_audit(
            &state,
            &ctx,
            AuditAction::DirectoryDomainConfigured,
            &domain.dns_name,
            serde_json::json!({ "action": "mail_connection_saved", "mode": form.mode }),
        )
        .await;
    }
    render_mail(
        &state,
        &jar,
        &ctx,
        id,
        Some("Mail connection saved.".into()),
        None,
    )
    .await
}

/// Reads the stored (sealed) M365 cert so a blank form field preserves it.
async fn existing_m365_cert(state: &AppState, domain_id: Uuid) -> Result<Option<String>, WebError> {
    let sealed: Option<Option<String>> = sqlx_scalar_m365_cert(&state.pool, domain_id)
        .await
        .map_err(|e| {
            WebError(AppError::Validation(format!(
                "Couldn't read the stored certificate: {e}"
            )))
        })?;
    Ok(sealed.flatten())
}

async fn sqlx_scalar_m365_cert(
    pool: &abyssal_database::DbPool,
    domain_id: Uuid,
) -> anyhow::Result<Option<Option<String>>> {
    Ok(sqlx::query_scalar(
        "SELECT m365_cert_sealed FROM directory_mail_connections WHERE domain_id = ?",
    )
    .bind(domain_id.to_string())
    .fetch_optional(pool)
    .await?)
}

#[derive(Deserialize)]
pub struct MailTestForm {
    csrf_token: String,
}

/// POST: test the saved Exchange connection. `directory.configure`.
pub async fn test_mail_config(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<MailTestForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::DirectoryConfigure)?;
    require_csrf(&jar, &form.csrf_token)?;
    let _ = repo::directory::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let conn = repo::directory::find_mail_connection(&state.pool, id).await?;
    let Some(conn) = conn else {
        return render_mail(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("Save a mail connection first.".into()),
        )
        .await;
    };
    if conn.mode == "m365" {
        let (ok, detail) = match repo::directory::m365_credentials(&state.pool, id).await? {
            Some(c) => {
                let Some(key) = state.encryption_key.clone() else {
                    return render_mail(
                        &state,
                        &jar,
                        &ctx,
                        id,
                        None,
                        Some("No ENCRYPTION_KEY is set.".into()),
                    )
                    .await;
                };
                match key.decrypt(&c.cert_sealed) {
                    Ok(cert_pem) => {
                        let cfg = crate::gravekeeper_graph::GraphConfig {
                            tenant_id: c.tenant_id,
                            app_id: c.app_id,
                            cert_pem: cert_pem.to_string(),
                            licensing_method: c.licensing_method,
                        };
                        match crate::gravekeeper_graph::test_connection(&cfg).await {
                            Ok(d) => (true, d),
                            Err(e) => (false, e),
                        }
                    }
                    Err(e) => (false, format!("Couldn't decrypt the certificate: {e}")),
                }
            }
            None => (
                false,
                "Microsoft 365 isn't fully configured (tenant, app and certificate).".to_string(),
            ),
        };
        let _ = repo::directory::update_mail_test_result(&state.pool, id, ok, &detail).await;
        return if ok {
            render_mail(
                &state,
                &jar,
                &ctx,
                id,
                Some(format!("Test connection succeeded. {detail}")),
                None,
            )
            .await
        } else {
            render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some(format!("Test connection failed: {detail}")),
            )
            .await
        };
    }
    if conn.mode == "none" {
        return render_mail(
            &state,
            &jar,
            &ctx,
            id,
            Some("Mail mode is none -- nothing to test.".into()),
            None,
        )
        .await;
    }

    let Some(creds) = repo::directory::exchange_credentials(&state.pool, id).await? else {
        return render_mail(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("The Exchange account isn't fully configured.".into()),
        )
        .await;
    };
    let Some(host_id) = creds.agent_host_id else {
        return render_mail(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("No Exchange agent host is set.".into()),
        )
        .await;
    };
    if !state.hosts.is_connected(host_id) {
        return render_mail(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("The Exchange agent host isn't connected.".into()),
        )
        .await;
    }
    let Some(key) = state.encryption_key.clone() else {
        return render_mail(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some("No ENCRYPTION_KEY is set.".into()),
        )
        .await;
    };
    let password = match key.decrypt(&creds.sealed) {
        Ok(p) => p.to_string(),
        Err(e) => {
            return render_mail(
                &state,
                &jar,
                &ctx,
                id,
                None,
                Some(format!("Couldn't decrypt the Exchange account: {e}")),
            )
            .await;
        }
    };
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            host_id,
            &host.name,
            AgentOperation::ExchangeTestConnection {
                uri: creds.uri,
                account_upn: creds.account_upn,
                account_password: password,
            },
            Permission::DirectoryConfigure,
            OperationKind::Read,
            false,
            MAIL_TIMEOUT,
            None,
            false,
        )
        .await;

    let (ok, detail) = match result {
        Ok(out) => (true, format!("Connected. {}", out.stdout.trim())),
        Err(e) => (false, e.to_string()),
    };
    let _ = repo::directory::update_mail_test_result(&state.pool, id, ok, &detail).await;
    if ok {
        render_mail(
            &state,
            &jar,
            &ctx,
            id,
            Some(format!("Test connection succeeded. {detail}")),
            None,
        )
        .await
    } else {
        render_mail(
            &state,
            &jar,
            &ctx,
            id,
            None,
            Some(format!("Test connection failed: {detail}")),
        )
        .await
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

    #[test]
    fn compute_plan_builds_the_change_set() {
        let t = repo::directory::DirectoryTemplate {
            id: Uuid::new_v4(),
            domain_id: Uuid::new_v4(),
            name: "Sales".into(),
            target_ou: Some("OU=Sales,DC=corp,DC=example,DC=com".into()),
            username_pattern: "{f}{last}".into(),
            upn_suffix: None, // falls back to the domain DNS
            email_pattern: Some("{first}.{last}@example.com".into()),
            groups: vec!["CN=Sales,OU=Groups,DC=corp,DC=example,DC=com".into()],
            attributes: vec![("department".into(), "Sales".into())],
            mail_mode: "none".into(),
            m365_usage_location: String::new(),
            m365_licensing_group: String::new(),
            m365_license_sku: String::new(),
            manager_required: false,
        };
        let plan = compute_plan(&t, "corp.example.com", "Jane", "Doe");
        assert_eq!(plan.sam_base, "jdoe");
        assert_eq!(plan.upn, "jdoe@corp.example.com"); // suffix from domain
        assert_eq!(plan.email, "jane.doe@example.com"); // lowercased
        assert_eq!(plan.display_name, "Jane Doe");
        assert_eq!(plan.given_name, "Jane");
        assert_eq!(plan.surname, "Doe");
        assert_eq!(plan.target_ou, "OU=Sales,DC=corp,DC=example,DC=com");
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(
            plan.attributes,
            vec![("department".to_string(), "Sales".to_string())]
        );

        // An explicit UPN suffix on the template wins over the domain DNS.
        let mut t2 = t.clone();
        t2.upn_suffix = Some("mail.example.com".into());
        let plan2 = compute_plan(&t2, "corp.example.com", "Jane", "Doe");
        assert_eq!(plan2.upn, "jdoe@mail.example.com");
    }

    #[test]
    fn csv_parsing_skips_header_and_blanks() {
        let rows = parse_csv_rows("first_name,last_name\nJane,Doe\n\nJohn , Smith \nMononym\n");
        assert_eq!(
            rows,
            vec![
                ("Jane".to_string(), "Doe".to_string()),
                ("John".to_string(), "Smith".to_string()),
                ("Mononym".to_string(), String::new()),
            ]
        );
        // A non-header first line is kept.
        let rows2 = parse_csv_rows("Ada,Lovelace");
        assert_eq!(rows2, vec![("Ada".to_string(), "Lovelace".to_string())]);
    }

    #[test]
    fn thanatos_alert_suggests_gravekeeper() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let alerted = serde_json::json!({ "persisted_count": 5, "alerted": true });
        let targets: Vec<String> = registry
            .evaluate("thanatos", "scan_security_events", &alerted)
            .matches
            .iter()
            .map(|m| m.target_arsenal.clone())
            .collect();
        assert!(targets.contains(&"gravekeeper".to_string()));

        let quiet = serde_json::json!({ "persisted_count": 0, "alerted": false });
        let quiet_targets: Vec<String> = registry
            .evaluate("thanatos", "scan_security_events", &quiet)
            .matches
            .iter()
            .map(|m| m.target_arsenal.clone())
            .collect();
        assert!(!quiet_targets.contains(&"gravekeeper".to_string()));
    }
}
