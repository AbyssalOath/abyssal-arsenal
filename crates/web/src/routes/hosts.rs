use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::secret::{generate_token, hash_token};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use chrono::Duration as ChronoDuration;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::require_csrf;
use crate::csrf;
use crate::deploy_commands;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, CommandsView, EnrollmentInstructions, HostFilterTab, HostRow, HostSummary,
    HostsTemplate, InstallTokenView, LegacyTokenView,
};
use crate::theme;

fn control_plane_base_url(state: &AppState, headers: &HeaderMap) -> String {
    crate::common::request_base_url(state, headers)
}

/// Builds the per-OS enrollment guidance for a freshly generated token. Every
/// command is fully filled in (control-plane URL, agent version, the one-time
/// token, and -- with an internal CA -- the CA fingerprint to pin) so the
/// operator copies one block verbatim. See `crate::deploy_commands`.
fn build_enrollment_instructions(base_url: &str, token: &str) -> EnrollmentInstructions {
    let ca = crate::public_ca::load();
    let ca = ca.as_ref();
    EnrollmentInstructions {
        token: token.to_string(),
        ca_fingerprint: ca.map(|ca| ca.fingerprint_display()),
        linux_oneliner: deploy_commands::linux_oneliner(base_url, token, ca),
        linux_manual: deploy_commands::linux_manual(base_url, token, ca),
        windows_oneliner: deploy_commands::windows_oneliner(base_url, token, ca),
        windows_manual: deploy_commands::windows_manual(base_url, token, ca),
        windows_rmm: deploy_commands::windows_rmm(base_url, token, ca),
    }
}

/// The host list's filter, search and sort (`GET /admin/hosts?filter=..`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostListQuery {
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub sort: String,
}

/// An install token shown in clear: right after it's created, or after an
/// audited reveal. The commands on the page fill it in.
pub struct RevealedToken {
    /// "Default token", or the additional token's label.
    pub name: String,
    pub token: String,
    pub just_created: bool,
}

/// Everything a render of `/admin/hosts` can carry beyond the page itself.
#[derive(Default)]
struct PageExtras {
    enrollment: Option<EnrollmentInstructions>,
    uninstall_command: Option<String>,
    action_result: Option<String>,
    action_error: Option<String>,
    revealed: Option<RevealedToken>,
    query: HostListQuery,
}

impl PageExtras {
    fn error(message: impl Into<String>) -> Self {
        PageExtras {
            action_error: Some(message.into()),
            ..Default::default()
        }
    }

    fn result(message: impl Into<String>) -> Self {
        PageExtras {
            action_result: Some(message.into()),
            ..Default::default()
        }
    }
}

/// What enrolled a host, for its row: "Default token", the additional
/// token's label, and so on. Empty for hosts from before it was recorded.
fn enrolled_via_label(
    source: Option<&repo::hosts::EnrollmentSource>,
    tokens: &[repo::install_tokens::InstallToken],
) -> String {
    let Some(source) = source else {
        return String::new();
    };
    match source.via.as_deref() {
        Some("default_token") => "Default token".to_string(),
        Some("install_token") => source
            .token_id
            .and_then(|id| tokens.iter().find(|t| t.id == id))
            .map(|t| format!("Install token \u{201c}{}\u{201d}", t.label))
            .unwrap_or_else(|| "Install token".to_string()),
        Some("deployment_token") => "Deployment token (legacy)".to_string(),
        Some("enrollment_token") => "One-time token".to_string(),
        Some("control_plane") => "install.sh (this server)".to_string(),
        _ => String::new(),
    }
}

/// `/admin/hosts` with this filter and the query's search and sort.
fn list_href(filter: &str, query: &HostListQuery) -> String {
    let mut params = form_urlencoded::Serializer::new(String::new());
    if filter != "all" {
        params.append_pair("filter", filter);
    }
    if !query.q.trim().is_empty() {
        params.append_pair("q", query.q.trim());
    }
    if !query.sort.is_empty() {
        params.append_pair("sort", &query.sort);
    }
    let params = params.finish();
    if params.is_empty() {
        "/admin/hosts".to_string()
    } else {
        format!("/admin/hosts?{params}")
    }
}

/// Applies the list's filter, search and sort, and counts each filter.
fn filter_hosts(rows: Vec<HostRow>, query: &HostListQuery) -> (Vec<HostRow>, Vec<HostFilterTab>) {
    const FILTERS: [(&str, &str); 5] = [
        ("all", "All"),
        ("online", "Online"),
        ("offline", "Offline"),
        ("out-of-date", "Out of date"),
        ("pending", "Pending approval"),
    ];
    let active = if FILTERS.iter().any(|(k, _)| *k == query.filter) {
        query.filter.as_str()
    } else {
        "all"
    };
    let tabs = FILTERS
        .iter()
        .map(|(key, label)| HostFilterTab {
            key,
            href: list_href(key, query),
            label,
            count: rows.iter().filter(|h| h.matches_filter(key)).count(),
            active: *key == active,
        })
        .collect();
    let needle = query.q.trim().to_lowercase();
    let mut rows: Vec<HostRow> = rows
        .into_iter()
        .filter(|h| h.matches_filter(active))
        .filter(|h| needle.is_empty() || h.name.to_lowercase().contains(&needle))
        .collect();
    match query.sort.as_str() {
        "status" => rows.sort_by(|a, b| {
            a.status_rank()
                .cmp(&b.status_rank())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        }),
        // Most recently seen first; never-seen last.
        "last-seen" => rows.sort_by_key(|h| std::cmp::Reverse(h.last_seen)),
        _ => rows.sort_by_key(|h| h.name.to_lowercase()),
    }
    (rows, tabs)
}

async fn render(
    state: &AppState,
    jar: &CookieJar,
    ctx: &abyssal_rbac::AuthContext,
    extras: PageExtras,
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
    let tz = &ctx.user.timezone;
    let now = chrono::Utc::now();

    let install_tokens = repo::install_tokens::list(&state.pool).await?;
    let sources = repo::hosts::enrollment_sources(&state.pool).await?;

    let mut all_hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        let elevation_remaining = state
            .elevation
            .remaining_for(host.id)
            .map(crate::templates::format_remaining);
        all_hosts.push(HostRow {
            is_control_plane: host.is_control_plane,
            id: host.id.to_string(),
            name: host.name.clone(),
            enrolled_at: crate::common::format_in_tz(host.enrolled_at, tz),
            enrolled_via: enrolled_via_label(sources.get(&host.id), &install_tokens),
            last_seen_at: host
                .last_seen_at
                .map(|t| crate::common::format_in_tz(t, tz))
                .unwrap_or_else(|| "never".to_string()),
            last_seen: host.last_seen_at,
            online: state.hosts.is_connected(host.id),
            revoked: host.revoked_at.is_some(),
            elevation_remaining,
            protocol_mismatch: state.hosts.agent_protocol_mismatch(host.id),
            out_of_date: host.is_active()
                && !host.pending_approval
                && crate::agent_update::is_out_of_date(state, &host),
            pending_approval: host.pending_approval,
            os: host.os.clone().unwrap_or_else(|| "unknown".to_string()),
            agent_version: host
                .agent_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        });
    }
    let summary = HostSummary {
        total: all_hosts.len(),
        online: all_hosts.iter().filter(|h| h.online).count(),
        out_of_date: all_hosts.iter().filter(|h| h.out_of_date).count(),
        pending: all_hosts.iter().filter(|h| h.pending_approval).count(),
    };
    let no_hosts = all_hosts.is_empty();
    let (hosts, filter_tabs) = filter_hosts(all_hosts, &extras.query);

    let can_manage = ctx.has(Permission::HostsManage);
    let additional_tokens = install_tokens
        .iter()
        .map(|t| InstallTokenView {
            id: t.id.to_string(),
            label: t.label.clone(),
            created: crate::common::format_in_tz(t.created_at, tz),
            expires: crate::install_tokens::expiry_label(t, now, tz),
            use_count: t.use_count,
            require_approval: t.require_approval,
            active: t.is_active(now),
            revoked: t.revoked_at.is_some(),
        })
        .collect();
    let legacy_tokens = repo::host_enrollment_tokens::list_active_deployment(&state.pool)
        .await?
        .into_iter()
        .map(|t| LegacyTokenView {
            id: t.id.to_string(),
            label: t.label.unwrap_or_else(|| "(unlabeled)".to_string()),
            created: crate::common::format_in_tz(t.created_at, tz),
            expires: crate::common::format_in_tz(t.expires_at, tz),
            use_count: t.use_count,
        })
        .collect();

    // PUBLIC_URL (install.sh sets it) -- this render has no request to infer
    // the address from, and the commands are for other machines.
    let public_url = state
        .config
        .public_url
        .as_deref()
        .unwrap_or("https://<control-plane-address>")
        .trim_end_matches('/')
        .to_string();
    let revealed_token = extras.revealed.as_ref().map(|r| r.token.as_str());
    let ca = crate::public_ca::load();
    let commands = CommandsView {
        token_name: extras
            .revealed
            .as_ref()
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "Default token".to_string()),
        revealed_token: revealed_token.map(str::to_string),
        just_created: extras.revealed.as_ref().is_some_and(|r| r.just_created),
        aat: deploy_commands::aat_commands(
            &crate::update_check::agent_release_version(state).await,
            &public_url,
            revealed_token,
        ),
        // The interactive one-liners pin the CA fingerprint themselves, so
        // they need the token in clear: only shown once one is revealed.
        linux_oneliner: revealed_token
            .map(|t| deploy_commands::linux_oneliner(&public_url, t, ca.as_ref())),
        windows_oneliner: revealed_token
            .map(|t| deploy_commands::windows_oneliner(&public_url, t, ca.as_ref())),
        windows_rmm: revealed_token
            .map(|t| deploy_commands::windows_rmm(&public_url, t, ca.as_ref())),
    };

    let update_all_count = if can_manage {
        crate::agent_update::updatable_count(state).await
    } else {
        0
    };
    // Open "Add hosts" when there's something in it to look at now.
    let add_hosts_open = no_hosts || extras.revealed.is_some() || extras.enrollment.is_some();
    let tpl = HostsTemplate {
        base,
        can_enroll: ctx.has(Permission::HostsEnroll),
        can_manage,
        update_all_count,
        summary,
        hosts,
        filter_tabs,
        query: extras.query,
        add_hosts_open,
        default_token_requires_approval: crate::aat::require_approval(&state.pool).await?,
        default_token_hosts: sources
            .values()
            .filter(|s| s.via.as_deref() == Some("default_token"))
            .count(),
        additional_tokens,
        legacy_tokens,
        expiry_choices: crate::install_tokens::EXPIRY_CHOICES
            .iter()
            .map(|(days, label)| (days.map(|d| d.to_string()).unwrap_or_default(), *label))
            .collect(),
        commands,
        enrollment: extras.enrollment,
        uninstall_command: extras.uninstall_command,
        action_result: extras.action_result,
        action_error: extras.action_error,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Query(query): Query<HostListQuery>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsView)?;
    render(
        &state,
        &jar,
        &ctx,
        PageExtras {
            query,
            ..Default::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct SimpleForm {
    csrf_token: String,
}

pub async fn generate_enrollment_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    headers: HeaderMap,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsEnroll)?;
    require_csrf(&jar, &form.csrf_token)?;

    let token = generate_token();
    let hash = hash_token(&token);
    repo::host_enrollment_tokens::create(
        &state.pool,
        &hash,
        Some(ctx.user.id),
        ChronoDuration::minutes(15),
    )
    .await?;

    let base_url = control_plane_base_url(&state, &headers);
    let instructions = build_enrollment_instructions(&base_url, &token);

    render(
        &state,
        &jar,
        &ctx,
        PageExtras {
            enrollment: Some(instructions),
            ..Default::default()
        },
    )
    .await
}

fn audit_actor(ctx: &abyssal_rbac::AuthContext) -> Actor<'_> {
    Actor {
        user_id: ctx.user.id,
        username: &ctx.user.username,
    }
}

#[derive(Deserialize)]
pub struct NewInstallTokenForm {
    csrf_token: String,
    #[serde(default)]
    label: String,
    /// Days, or empty for no expiry (`install_tokens::EXPIRY_CHOICES`).
    #[serde(default)]
    expires_in_days: String,
    /// A checkbox: present when checked.
    #[serde(default)]
    require_approval: Option<String>,
}

/// "New install token": an additional token beside the default one, shown
/// with its commands right away.
pub async fn create_install_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<NewInstallTokenForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let label = form.label.trim();
    if label.is_empty() || label.chars().count() > 100 {
        return render(
            &state,
            &jar,
            &ctx,
            PageExtras::error("Give the install token a label of up to 100 characters."),
        )
        .await;
    }
    // Only the offered choices; anything else is a hand-posted value.
    let expires_in_days = match form.expires_in_days.trim() {
        "" => None,
        days => match days.parse::<u32>() {
            Ok(d)
                if crate::install_tokens::EXPIRY_CHOICES
                    .iter()
                    .any(|(c, _)| *c == Some(d)) =>
            {
                Some(d)
            }
            _ => {
                return render(
                    &state,
                    &jar,
                    &ctx,
                    PageExtras::error("Pick one of the offered expiry times."),
                )
                .await;
            }
        },
    };
    let require_approval = form.require_approval.is_some();
    let (id, token) = crate::install_tokens::create(
        &state.pool,
        state.encryption_key.as_deref(),
        label,
        expires_in_days,
        require_approval,
        Some(ctx.user.id),
    )
    .await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(audit_actor(&ctx))
            .resource("host.install_token")
            .metadata(serde_json::json!({
                "action": "create",
                "id": id,
                "label": label,
                "expires_in_days": expires_in_days,
                "require_approval": require_approval,
            })),
    )
    .await?;

    render(
        &state,
        &jar,
        &ctx,
        PageExtras {
            revealed: Some(RevealedToken {
                name: label.to_string(),
                token,
                just_created: true,
            }),
            action_result: Some(format!(
                "Created install token \u{201c}{label}\u{201d}. Its commands are filled in under \
                 Add hosts."
            )),
            ..Default::default()
        },
    )
    .await
}

/// Shows an additional install token (and its commands). Audited, like the
/// default token's reveal.
pub async fn reveal_install_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let token = repo::install_tokens::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !token.is_active(chrono::Utc::now()) {
        return render(
            &state,
            &jar,
            &ctx,
            PageExtras::error(format!(
                "Install token \u{201c}{}\u{201d} is revoked or expired, so it no longer enrolls \
                 hosts. Create a new one.",
                token.label
            )),
        )
        .await;
    }
    let secret = match crate::install_tokens::unseal(&token, state.encryption_key.as_deref()) {
        Ok(secret) => secret,
        Err(e) => return render(&state, &jar, &ctx, PageExtras::error(format!("{e:#}"))).await,
    };
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::SecretAccessed, AuditOutcome::Success)
            .actor(audit_actor(&ctx))
            .resource("host.install_token")
            .metadata(serde_json::json!({ "id": id, "label": token.label })),
    )
    .await?;
    render(
        &state,
        &jar,
        &ctx,
        PageExtras {
            revealed: Some(RevealedToken {
                name: token.label,
                token: secret,
                just_created: false,
            }),
            ..Default::default()
        },
    )
    .await
}

/// Revokes an additional install token: it stops enrolling hosts at once.
/// Hosts it enrolled keep working -- each has its own credential.
pub async fn revoke_install_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let token = repo::install_tokens::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if repo::install_tokens::revoke(&state.pool, id).await? {
        abyssal_audit::record(
            &state.pool,
            AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
                .actor(audit_actor(&ctx))
                .resource("host.install_token")
                .metadata(serde_json::json!({
                    "action": "revoke",
                    "id": id,
                    "label": token.label,
                })),
        )
        .await?;
    }
    Ok(Redirect::to("/admin/hosts").into_response())
}

/// Revokes a legacy deployment token (it stops enrolling new hosts
/// immediately; already-enrolled hosts are unaffected). New ones can't be
/// created any more: install tokens replace them.
pub async fn revoke_deployment_token(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    repo::host_enrollment_tokens::revoke(&state.pool, id).await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(audit_actor(&ctx))
            .resource("host.deployment_token")
            .metadata(serde_json::json!({ "action": "revoke", "id": id.to_string() })),
    )
    .await?;

    Ok(Redirect::to("/admin/hosts").into_response())
}

/// Shows the default install token (the AAT) in clear. A POST, not part of
/// the page, so every view of the secret is a deliberate, audit-logged
/// action.
pub async fn reveal_aat(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let aat = match crate::aat::ensure(&state.pool, state.encryption_key.as_deref()).await {
        Ok(aat) => aat,
        Err(e) => return render(&state, &jar, &ctx, PageExtras::error(format!("{e:#}"))).await,
    };
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::SecretAccessed, AuditOutcome::Success)
            .actor(audit_actor(&ctx))
            .resource("host.aat"),
    )
    .await?;
    render(
        &state,
        &jar,
        &ctx,
        PageExtras {
            revealed: Some(RevealedToken {
                name: "Default token".to_string(),
                token: aat,
                just_created: false,
            }),
            ..Default::default()
        },
    )
    .await
}

/// Replaces the default install token. The old one stops enrolling new
/// hosts immediately; enrolled hosts and additional tokens are unaffected.
/// Shows the new one, since every deploy package using it needs updating.
pub async fn rotate_aat(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let aat = crate::aat::rotate(
        &state.pool,
        state.encryption_key.as_deref(),
        Some(ctx.user.id),
    )
    .await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(audit_actor(&ctx))
            .resource("host.aat")
            .metadata(serde_json::json!({ "action": "rotate" })),
    )
    .await?;
    render(
        &state,
        &jar,
        &ctx,
        PageExtras {
            revealed: Some(RevealedToken {
                name: "Default token".to_string(),
                token: aat,
                just_created: true,
            }),
            action_result: Some(
                "Default install token rotated. The old one no longer enrolls hosts -- update \
                 your PDQ/Intune/GPO packages with the new one under Add hosts. Additional \
                 install tokens are unaffected."
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct AatApprovalForm {
    csrf_token: String,
    /// A checkbox: present ("on") when checked, absent otherwise.
    #[serde(default)]
    require_approval: Option<String>,
}

pub async fn set_aat_approval(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<AatApprovalForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let required = form.require_approval.is_some();
    crate::aat::set_require_approval(&state.pool, required, Some(ctx.user.id)).await?;
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::ConfigurationChanged, AuditOutcome::Success)
            .actor(audit_actor(&ctx))
            .resource("host.aat")
            .metadata(serde_json::json!({ "require_approval": required })),
    )
    .await?;
    Ok(Redirect::to("/admin/hosts").into_response())
}

/// Lets a host enrolled with the AAT (while approval was required) connect.
/// Its agent is already retrying, so it shows up online within a minute.
/// Rejecting one is just Remove.
pub async fn approve(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if repo::hosts::approve(&state.pool, id).await? {
        abyssal_audit::record(
            &state.pool,
            AuditEvent::new(AuditAction::HostApproved, AuditOutcome::Success)
                .actor(Actor {
                    user_id: ctx.user.id,
                    username: &ctx.user.username,
                })
                .resource(&host.name),
        )
        .await?;
    }
    Ok(Redirect::to("/admin/hosts").into_response())
}

#[derive(serde::Deserialize)]
pub struct ControlPlaneForm {
    csrf_token: String,
    is_control_plane: bool,
}

/// Flags or unflags a host as the control plane's own server, for one that
/// wasn't enrolled by `install.sh` (or was, and the control plane has since
/// moved). Flagging turns its guardrails on immediately; unflagging turns
/// them off, which the confirm prompt spells out.
pub async fn set_control_plane(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<ControlPlaneForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    repo::hosts::set_control_plane(&state.pool, id, form.is_control_plane).await?;
    state.hosts.set_control_plane(id, form.is_control_plane);
    if form.is_control_plane && state.hosts.is_connected(id) {
        let hosts = state.hosts.clone();
        tokio::spawn(async move {
            crate::control_plane::probe_docker_device(&hosts, id).await;
        });
    }
    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::HostControlPlaneChanged, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&host.name)
            .metadata(serde_json::json!({ "is_control_plane": form.is_control_plane })),
    )
    .await?;
    Ok(Redirect::to("/admin/hosts").into_response())
}

/// Pushes the currently-connected agent to update itself to this control
/// plane's own version, over the existing WebSocket -- the one-click answer
/// to the "Agent out of date" badge. An agent too old to understand
/// `AgentOperation::SelfUpdate` is never sent it (`min_protocol`); the
/// admin is pointed at a re-deploy instead.
pub async fn update_agent(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let (operation, version) = match self_update_operation(&state, &host).await {
        Ok(planned) => planned,
        Err(message) => {
            return render(&state, &jar, &ctx, PageExtras::error(message)).await;
        }
    };
    // Too old for even this: the only way forward is a re-deploy.
    if state.hosts.is_connected(id) && !state.hosts.supports(id, &operation) {
        return render(
            &state,
            &jar,
            &ctx,
            PageExtras::error(format!(
                "{}'s agent is too old to update itself over its connection. Re-deploy it to \
                 {version} with the bootstrap one-liner (under Add hosts) or the SSH \
                 quick-add from a Panopticon scan; after that, updates are one click from here.",
                host.name
            )),
        )
        .await;
    }
    let elevated = state.elevation.is_elevated(id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            id,
            &format!("Update agent -- {}", host.name),
            operation,
            Permission::HostsManage,
            OperationKind::Write,
            false,
            // Generous: the agent downloads a ~10 MB release and unpacks it
            // before replying, all ahead of the scheduled restart.
            Duration::from_secs(180),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => render(&state, &jar, &ctx, PageExtras::result(output.stdout)).await,
        Err(e) => render(&state, &jar, &ctx, PageExtras::error(e.to_string())).await,
    }
}

/// The `SelfUpdate` to send `host`, and the version it updates to; `Err` is
/// why there's nothing to send, for the admin.
///
/// A 0.2.3+ agent gets exactly what `/agent/<os>` serves -- the build in
/// this image for Linux, the release cached here (fetched once from GitHub,
/// or put in the agent folder) for Windows -- with its SHA-256, so hosts
/// without internet access can update. An older agent can only download
/// from GitHub, so it gets the newest *published* release (never an
/// unreleased version a control plane built from main is ahead of).
/// Either way, never a downgrade.
pub(crate) async fn self_update_operation(
    state: &AppState,
    host: &abyssal_core::Host,
) -> Result<(AgentOperation, String), String> {
    use crate::update_check::parse_version;

    let from_control_plane = state.hosts.supports(
        host.id,
        &AgentOperation::SelfUpdate {
            version: String::new(),
            from_control_plane: true,
            sha256: None,
        },
    );
    let (operation, version) = if from_control_plane {
        let os = match host.os.as_deref() {
            Some("linux") => "linux",
            Some("windows") => "windows",
            other => {
                return Err(format!(
                    "{} reports platform {:?}; agent builds exist only for Linux and Windows.",
                    host.name,
                    other.unwrap_or("unknown")
                ));
            }
        };
        let agent = crate::routes::bootstrap::resolve_agent(state, os)
            .await
            .map_err(|e| format!("No agent build to update {} to: {e}", host.name))?;
        let sha256: String = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&agent.bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        let version = agent
            .version
            .clone()
            .unwrap_or_else(|| crate::update_check::CURRENT_VERSION.trim().to_string());
        (
            AgentOperation::SelfUpdate {
                version: version.clone(),
                from_control_plane: true,
                sha256: Some(sha256),
            },
            // An operator-placed build's version isn't known until the agent
            // runs it, so the downgrade check below can't apply; the agent
            // makes it itself.
            agent.version.unwrap_or_default(),
        )
    } else {
        let version = crate::update_check::agent_release_version(state).await;
        (
            AgentOperation::SelfUpdate {
                version: version.clone(),
                from_control_plane: false,
                sha256: None,
            },
            version,
        )
    };

    if let (Some(running), Some(target)) = (
        host.agent_version.as_deref().and_then(parse_version),
        parse_version(&version),
    ) && target < running
    {
        let running = host.agent_version.clone().unwrap_or_default();
        return Err(if from_control_plane {
            format!(
                "{} is already on v{running}, newer than the agent this control plane has \
                 (v{version}), so there's nothing to update to.",
                host.name
            )
        } else {
            format!(
                "{} is already on v{running}, newer than the newest release this control \
                 plane knows of (v{version}), so there's nothing to update to. If v{running} \
                 has just been released, use 'Check now' on the dashboard and try again.",
                host.name
            )
        });
    }
    let shown = if version.is_empty() {
        "the build on this control plane".to_string()
    } else {
        format!("v{version}")
    };
    Ok((operation, shown))
}

/// Starts an "Update all out-of-date agents" job and shows its progress.
pub async fn update_all_agents(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let hosts = crate::agent_update::out_of_date_hosts(&state).await?;
    if !hosts
        .iter()
        .any(|h| h.state == crate::agent_update::UpdateState::Queued)
    {
        return render(
            &state,
            &jar,
            &ctx,
            PageExtras {
                action_result: Some(if hosts.is_empty() {
                    "Every agent is up to date.".to_string()
                } else {
                    format!(
                        "Nothing to update right now. {} out-of-date host(s) can't be updated from \
                     here yet: {}",
                        hosts.len(),
                        hosts
                            .iter()
                            .map(|h| format!("{} ({})", h.name, h.detail.trim_end_matches('.')))
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                }),
                ..Default::default()
            },
        )
        .await;
    }
    let id = Uuid::new_v4();
    let job = std::sync::Arc::new(tokio::sync::RwLock::new(
        crate::agent_update::AgentUpdateJob {
            id,
            started_by: ctx.user.username.clone(),
            started_at: chrono::Utc::now(),
            hosts,
        },
    ));
    state
        .agent_update_jobs
        .write()
        .await
        .insert(id, job.clone());
    tokio::spawn(crate::agent_update::run(state.clone(), ctx.clone(), job));
    Ok(Redirect::to(&format!("/admin/hosts/update-all/{id}")).into_response())
}

pub async fn update_all_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    let job = state
        .agent_update_jobs
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let job = job.read().await.clone();

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
    use crate::agent_update::UpdateState;
    let tpl = crate::templates::AgentUpdateStatusTemplate {
        base,
        started_by: job.started_by.clone(),
        started_at: crate::common::format_in_tz(job.started_at, &ctx.user.timezone),
        finished: job.finished(),
        updated: job.count(UpdateState::Updated),
        failed: job.count(UpdateState::Failed) + job.count(UpdateState::NotBackYet),
        skipped: job.count(UpdateState::Skipped),
        rows: job
            .hosts
            .iter()
            .map(|h| crate::templates::AgentUpdateRow {
                name: h.name.clone(),
                os: h.os.clone(),
                from_version: h.from_version.clone(),
                state_label: h.state.label(),
                badge_class: h.state.badge_class(),
                detail: h.detail.clone(),
            })
            .collect(),
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

pub async fn run_system_info(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let elevated = state.elevation.is_elevated(id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            id,
            &host.name,
            AgentOperation::SystemInfo,
            Permission::HostsManage,
            OperationKind::Read,
            false,
            Duration::from_secs(10),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => render(&state, &jar, &ctx, PageExtras::result(output.stdout)).await,
        Err(e) => render(&state, &jar, &ctx, PageExtras::error(e.to_string())).await,
    }
}

pub async fn deescalate(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsElevate)?;
    require_csrf(&jar, &form.csrf_token)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    let elevated = state.elevation.is_elevated(id);
    let result = state
        .executor
        .execute_on_host(
            &ctx,
            &state.hosts,
            id,
            &format!("Elevate Privileges -- {}", host.name),
            AgentOperation::Deescalate,
            Permission::HostsElevate,
            OperationKind::Write,
            false,
            Duration::from_secs(10),
            None,
            elevated,
        )
        .await;

    state.elevation.mark_deescalated(id);

    match result {
        Ok(output) => render(&state, &jar, &ctx, PageExtras::result(output.stdout)).await,
        Err(e) => render(&state, &jar, &ctx, PageExtras::error(e.to_string())).await,
    }
}

pub async fn revoke_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
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

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Revoke host".to_string(),
        message: format!(
            "This will revoke \"{}\"'s credential. Its agent will no longer be able to connect until re-enrolled.",
            host.name
        ),
        action_url: format!("/admin/hosts/{id}/revoke"),
        cancel_url: "/admin/hosts".to_string(),
        escalate_host_id: None,
        type_to_confirm: None,
        extra_hidden_fields: vec![],
        shred_option: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RevokeForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
}

pub async fn revoke(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<RevokeForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Revocation was not confirmed.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    repo::hosts::revoke(&state.pool, id).await?;

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::HostRevoked, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&host.name),
    )
    .await?;

    Ok(Redirect::to("/admin/hosts").into_response())
}

pub async fn remove_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;

    let host = repo::hosts::find_by_id(&state.pool, id)
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

    let tpl = crate::templates::ConfirmTemplate {
        base,
        title: "Remove host".to_string(),
        message: format!(
            "This will permanently delete \"{}\" and its credential from Abyssal Arsenal -- \
             this cannot be undone. Its audit history is kept. If its agent is connected (and \
             0.2.2 or later), it uninstalls itself from the machine too: service, binary and \
             credentials. Otherwise you'll be given the command to run there.",
            host.name
        ),
        action_url: format!("/admin/hosts/{id}/remove"),
        cancel_url: "/admin/hosts".to_string(),
        escalate_host_id: None,
        type_to_confirm: Some(crate::templates::TypeToConfirm {
            label: "hostname".to_string(),
            expected: host.name.clone(),
        }),
        extra_hidden_fields: vec![],
        shred_option: None,
    };
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    Ok((jar, tpl).into_response())
}

#[derive(Deserialize)]
pub struct RemoveForm {
    csrf_token: String,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    confirm_text: String,
}

pub async fn remove(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(id): Path<Uuid>,
    Form(form): Form<RemoveForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::HostsManage)?;
    require_csrf(&jar, &form.csrf_token)?;

    if !form.confirm {
        return Err(WebError(AppError::Validation(
            "Removal was not confirmed.".into(),
        )));
    }

    let host = repo::hosts::find_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::common::require_typed_confirmation(&form.confirm_text, &host.name)?;

    // Uninstall the agent while it's still connected (it replies, then
    // uninstalls itself from a detached process), then delete. Any failure
    // here still removes the host: the admin asked for that, and the
    // credential stops working either way.
    let (uninstalled, why_not) = uninstall_agent_for_removal(&state, &ctx, &host).await;

    // Delete first, then drop any live connection -- a connection that
    // outlives the DB row can no longer be dispatched to via `/admin/hosts`
    // (its row is gone), and if it ever disconnects and tries to
    // reconnect, its credential no longer resolves to a host either.
    repo::hosts::delete(&state.pool, id).await?;
    state.hosts.unregister(id);
    state.hosts.set_control_plane(id, false);

    abyssal_audit::record(
        &state.pool,
        AuditEvent::new(AuditAction::HostRemoved, AuditOutcome::Success)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(&host.name)
            .metadata(serde_json::json!({ "agent_uninstalled": uninstalled })),
    )
    .await?;

    if uninstalled {
        let mut message = format!(
            "Removed {}. Its agent is uninstalling itself (service, binary, credentials) and \
             will disconnect in a few seconds.",
            host.name
        );
        if host.is_control_plane {
            message.push_str(
                " This was the control plane's own server: set CONTROL_PLANE_AGENT=no in .env \
                 so a later ./install.sh doesn't install it again.",
            );
        }
        return render(&state, &jar, &ctx, PageExtras::result(message)).await;
    }

    render(
        &state,
        &jar,
        &ctx,
        PageExtras {
            uninstall_command: Some(manual_uninstall_command(host.os.as_deref()).to_string()),
            action_error: why_not,
            ..Default::default()
        },
    )
    .await
}

/// Asks the host's agent to uninstall itself. `(true, None)` when it
/// accepted; otherwise `(false, Some(why))` for the admin, who then gets the
/// command to run on the host.
async fn uninstall_agent_for_removal(
    state: &AppState,
    ctx: &abyssal_rbac::AuthContext,
    host: &abyssal_core::Host,
) -> (bool, Option<String>) {
    if !state.hosts.is_connected(host.id) {
        return (
            false,
            Some(format!(
                "{} is offline, so its agent couldn't be uninstalled automatically.",
                host.name
            )),
        );
    }
    let uninstall = AgentOperation::UninstallAgent { purge: true };
    if !state.hosts.supports(host.id, &uninstall) {
        return (
            false,
            Some(format!(
                "{}'s agent (v{}) is too old to uninstall itself ({} or later can).",
                host.name,
                host.agent_version.as_deref().unwrap_or("unknown"),
                abyssal_agent_protocol::agent_release_for_protocol(uninstall.min_protocol())
                    .unwrap_or("a newer agent")
            )),
        );
    }
    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host.id,
            &host.name,
            uninstall,
            Permission::HostsManage,
            OperationKind::Destructive,
            true,
            Duration::from_secs(30),
            None,
            state.elevation.is_elevated(host.id),
        )
        .await;
    match result {
        Ok(_) => (true, None),
        Err(e) => (
            false,
            Some(format!(
                "{}'s agent couldn't uninstall itself ({e}).",
                host.name
            )),
        ),
    }
}

/// What to run on a removed host whose agent couldn't uninstall itself.
fn manual_uninstall_command(os: Option<&str>) -> &'static str {
    match os {
        Some("windows") => {
            "In an elevated PowerShell or Command Prompt:\n\
             \"C:\\Program Files\\AbyssalAgent\\abyssal-agent.exe\" /uninstall /quiet PURGE=1\n\n\
             (Installed with the MSI? Uninstall \"Abyssal Arsenal Agent\" from Apps & features \
             instead.)"
        }
        _ => {
            "sudo abyssal-agent uninstall --purge\n\n\
             (Agents before 0.2.1 don't have that command: sudo systemctl disable --now \
             abyssal-agent && sudo rm -f /usr/local/bin/abyssal-agent \
             /etc/systemd/system/abyssal-agent.service && sudo rm -rf /etc/abyssal-agent)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::PrimaryAction;

    fn row(name: &str) -> HostRow {
        HostRow {
            is_control_plane: false,
            id: name.to_string(),
            name: name.to_string(),
            enrolled_at: String::new(),
            enrolled_via: String::new(),
            last_seen_at: String::new(),
            last_seen: None,
            out_of_date: false,
            online: true,
            revoked: false,
            elevation_remaining: None,
            pending_approval: false,
            protocol_mismatch: false,
            os: "linux".to_string(),
            agent_version: "0.2.4".to_string(),
        }
    }

    #[test]
    fn primary_action_follows_the_hosts_state() {
        assert_eq!(row("a").primary_action(), PrimaryAction::SystemInfo);
        let pending = HostRow {
            pending_approval: true,
            online: false,
            ..row("p")
        };
        assert_eq!(pending.primary_action(), PrimaryAction::Approve);
        let stale = HostRow {
            out_of_date: true,
            ..row("s")
        };
        assert_eq!(stale.primary_action(), PrimaryAction::UpdateAgent);
        // An out-of-date host that's offline can't be updated now.
        let stale_offline = HostRow {
            online: false,
            ..stale
        };
        assert_eq!(stale_offline.primary_action(), PrimaryAction::SystemInfo);
        let revoked = HostRow {
            revoked: true,
            online: false,
            ..row("r")
        };
        assert_eq!(revoked.primary_action(), PrimaryAction::None);
        assert!(pending.primary_is("approve") && !pending.primary_is("system-info"));
    }

    fn names(rows: &[HostRow]) -> Vec<&str> {
        rows.iter().map(|h| h.name.as_str()).collect()
    }

    fn fleet() -> Vec<HostRow> {
        let mut offline = row("bravo");
        offline.online = false;
        offline.last_seen = Some(chrono::Utc::now() - chrono::Duration::hours(3));
        let mut stale = row("Charlie");
        stale.out_of_date = true;
        stale.last_seen = Some(chrono::Utc::now());
        let mut pending = row("alpha");
        pending.pending_approval = true;
        pending.online = false;
        vec![offline, stale, pending, row("delta")]
    }

    #[test]
    fn filters_count_and_select() {
        let query = |filter: &str| HostListQuery {
            filter: filter.to_string(),
            ..Default::default()
        };
        let (all, tabs) = filter_hosts(fleet(), &query(""));
        assert_eq!(names(&all), ["alpha", "bravo", "Charlie", "delta"]);
        let count = |key: &str| tabs.iter().find(|t| t.key == key).unwrap().count;
        assert_eq!(
            (
                count("all"),
                count("online"),
                count("offline"),
                count("out-of-date"),
                count("pending")
            ),
            (4, 2, 1, 1, 1)
        );
        assert!(tabs.iter().find(|t| t.key == "all").unwrap().active);
        // A pending host isn't "offline": it can't connect until approved.
        assert_eq!(
            names(&filter_hosts(fleet(), &query("offline")).0),
            ["bravo"]
        );
        assert_eq!(
            names(&filter_hosts(fleet(), &query("pending")).0),
            ["alpha"]
        );
        // An unknown filter is All.
        assert_eq!(filter_hosts(fleet(), &query("bogus")).0.len(), 4);
    }

    #[test]
    fn search_and_sort() {
        let (found, _) = filter_hosts(
            fleet(),
            &HostListQuery {
                q: " CHAR ".to_string(),
                ..Default::default()
            },
        );
        assert_eq!(names(&found), ["Charlie"]);
        let sorted = |sort: &str| {
            names(
                &filter_hosts(
                    fleet(),
                    &HostListQuery {
                        sort: sort.to_string(),
                        ..Default::default()
                    },
                )
                .0,
            )
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        };
        // Needs attention first: pending, out of date, offline, online.
        assert_eq!(sorted("status"), ["alpha", "Charlie", "bravo", "delta"]);
        // Most recent first, never seen last.
        assert_eq!(sorted("last-seen")[..2], ["Charlie", "bravo"]);
    }

    #[test]
    fn tab_links_keep_search_and_sort() {
        let query = HostListQuery {
            filter: "online".to_string(),
            q: "web & db".to_string(),
            sort: "status".to_string(),
        };
        assert_eq!(
            list_href("offline", &query),
            "/admin/hosts?filter=offline&q=web+%26+db&sort=status"
        );
        assert_eq!(list_href("all", &HostListQuery::default()), "/admin/hosts");
    }

    #[test]
    fn enrolled_via_names_the_token() {
        let id = Uuid::new_v4();
        let token = repo::install_tokens::InstallToken {
            id,
            label: "Finance".to_string(),
            token_sealed: String::new(),
            require_approval: false,
            created_at: chrono::Utc::now(),
            expires_at: None,
            revoked_at: None,
            use_count: 1,
            last_used_at: None,
        };
        let source = |via: &str, token_id| repo::hosts::EnrollmentSource {
            via: Some(via.to_string()),
            token_id,
        };
        let tokens = [token];
        assert_eq!(
            enrolled_via_label(Some(&source("install_token", Some(id))), &tokens),
            "Install token \u{201c}Finance\u{201d}"
        );
        assert_eq!(
            enrolled_via_label(Some(&source("default_token", None)), &tokens),
            "Default token"
        );
        assert_eq!(enrolled_via_label(None, &tokens), "");
    }
}
