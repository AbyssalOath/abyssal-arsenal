use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::settings::HOST_ISOLATION_ENABLED;
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum::Form;
use axum::extract::{Path, Query, RawQuery, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::common::{
    WorkflowContextRow, maybe_elevate, require_csrf, urlencoding_encode, workflow_context_rows,
};
use crate::csrf;
use crate::error::WebError;
use crate::extract::CurrentUser;
use crate::host_context;
use crate::pagination;
use crate::state::AppState;
use crate::templates::{
    BaseCtx, InquestHostGroup, InquestHostTemplate, InquestTemplate, SuggestedActionView,
};
use crate::theme;

/// How many host groups the group list shows per page -- same constant
/// Panopticon's Device Inventory and Thanatos's dashboard use.
const GROUPS_PER_PAGE: u32 = 25;

/// What "block an IP"/"isolate this host"/"quarantine a file" actually
/// do on this host -- differs by platform (see
/// `crates/agent/src/inquest.rs`'s module doc comment), so the per-host
/// page says so explicitly rather than showing one Linux-flavored
/// sentence regardless of what's actually connected.
fn containment_note(os: Option<&str>) -> &'static str {
    match os {
        Some("windows") => {
            "Blocking/isolation go through Windows Defender Firewall (PowerShell); \
             quarantine moves files under C:\\ProgramData\\abyssal-agent\\quarantine. \
             Isolation here can't be applied as a single atomic transaction the way the \
             Linux path's nftables/iptables mechanism can -- see this host's agent-side \
             documentation before isolating a production host for the first time."
        }
        Some("macos") => "Inquest response actions aren't supported on macOS hosts yet.",
        _ => {
            "Blocking/isolation go through nftables (preferred) or iptables, whichever this \
             host has; quarantine moves files under /var/lib/abyssal-arsenal/quarantine."
        }
    }
}

/// Landing page for this arsenal: a paginated, collapsible-per-host group
/// list (GitHub issue #10's grouped-dashboard pattern) instead of a flat
/// host-link list -- each group's body is just the read-only quick-check
/// buttons (nothing per-host to paginate inside, since these are live
/// agent reads, not stored rows), collapsed by default for the same
/// reason every other dropdown in this app now defaults closed.
pub async fn show(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    RawQuery(raw): RawQuery,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;

    if let Some(host_id) = host_context::current(&jar)
        && state.hosts.is_connected(host_id)
    {
        return Ok(Redirect::to(&format!("/arsenals/inquest/{host_id}")).into_response());
    }

    let query = pagination::parse_group_list_query(raw.as_deref());

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

    let mut connected_hosts = Vec::new();
    for host in repo::hosts::list(&state.pool).await? {
        if host.is_active() && state.hosts.is_connected(host.id) {
            connected_hosts.push(host);
        }
    }

    let open_set: std::collections::HashSet<&str> = query.open.iter().map(String::as_str).collect();
    let group_total = connected_hosts.len() as u64;
    let group_page_requested = query.group_page.unwrap_or(1).max(1);
    let group_page_num = if pagination::Page::<()>::page_out_of_range(
        group_page_requested,
        GROUPS_PER_PAGE,
        group_total,
    ) {
        pagination::total_pages(group_total, GROUPS_PER_PAGE)
    } else {
        group_page_requested
    };
    let group_offset = pagination::offset(group_page_num, GROUPS_PER_PAGE) as usize;
    let group_page_meta: pagination::Page<()> =
        pagination::Page::new(vec![], group_page_num, GROUPS_PER_PAGE, group_total);
    let group_list_page = Some(pagination::numbered_page_info(&group_page_meta, |p| {
        query.with_group_page(p).href("/arsenals/inquest")
    }));

    let groups = connected_hosts
        .iter()
        .skip(group_offset)
        .take(GROUPS_PER_PAGE as usize)
        .map(|host| {
            let host_id_str = host.id.to_string();
            let is_open = open_set.contains(host_id_str.as_str());
            let open_href =
                (!is_open).then(|| query.with_open(&host_id_str).href("/arsenals/inquest"));
            InquestHostGroup {
                host_id: host_id_str,
                host_name: host.name.clone(),
                os_label: crate::common::os_label(host.os.as_deref()),
                is_open,
                open_href,
            }
        })
        .collect();

    let tpl = InquestTemplate {
        base,
        groups,
        group_list_page,
    };
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
    render_host_with_context(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        Vec::new(),
        Vec::new(),
    )
    .await
}

/// Same as `render_host`, but also renders a "Suggested Next Steps" section
/// from the workflow registry's matches against this result -- see
/// `run_write_op`'s/`run_destructive_op`'s `workflow` parameter, the
/// source of every non-empty `suggested_actions` this ever gets called
/// with.
#[allow(clippy::too_many_arguments)]
async fn render_host_with_suggestions(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    suggested_actions: Vec<SuggestedActionView>,
) -> Result<Response, WebError> {
    render_host_with_context(
        state,
        jar,
        ctx,
        host_id,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        Vec::new(),
    )
    .await
}

/// Same as `render_host`, but also shows a banner naming which
/// workflow-registry context fields (if any) arrived in the query string
/// -- Thanatos's `persisted_count` doesn't map to a field any read op
/// here takes, so the banner is all Phase 6 adds here.
#[allow(clippy::too_many_arguments)]
async fn render_host_with_context(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    result_label: Option<String>,
    result_output: Option<String>,
    result_error: Option<String>,
    suggested_actions: Vec<SuggestedActionView>,
    context: Vec<WorkflowContextRow>,
) -> Result<Response, WebError> {
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let arrived_via_suggestion = !context.is_empty();
    let selected_host_id = if arrived_via_suggestion {
        Some(host_id)
    } else {
        host_context::current(jar)
    };

    let (csrf_token, new_cookie) = csrf::ensure_token(jar);
    let base = BaseCtx::build(
        ctx,
        &theme::current(jar),
        &csrf_token,
        &state.elevation,
        &state.hosts,
        &state.pool,
        selected_host_id,
    )
    .await?;
    let host_isolation_enabled =
        repo::settings::get_bool(&state.pool, HOST_ISOLATION_ENABLED, false).await?;
    let os_label = crate::common::os_label(host.os.as_deref());
    let containment_note = containment_note(host.os.as_deref());

    let tpl = InquestHostTemplate {
        can_manage: ctx.has(Permission::IncidentsRespond),
        host_isolation_enabled,
        elevated: state.elevation.is_elevated(host_id),
        protocol_mismatch: state.hosts.agent_protocol_mismatch(host_id),
        base,
        host_id: host_id.to_string(),
        host_name: host.name,
        os_label,
        containment_note,
        result_label,
        result_output,
        result_error,
        suggested_actions,
        context,
    };
    let jar = jar.clone();
    let jar = match new_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    let jar = match host_context::carry_forward_cookie(host_id, arrived_via_suggestion) {
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
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    render_host_with_context(
        &state,
        &jar,
        &ctx,
        host_id,
        None,
        None,
        None,
        Vec::new(),
        workflow_context_rows(&query),
    )
    .await
}

/// The second gate `IsolateHost` requires, on top of the normal
/// `incidents.respond` permission and type-to-confirm: checked fresh at
/// every entry point that leads to dispatching it (both the confirm-page
/// GET and the dispatch POST), never assumed from an earlier check --
/// same discipline as Ossuary's `ensure_high_risk_enabled`.
async fn ensure_host_isolation_enabled(state: &AppState) -> Result<(), WebError> {
    let enabled = repo::settings::get_bool(&state.pool, HOST_ISOLATION_ENABLED, false).await?;
    if !enabled {
        return Err(WebError(AppError::Validation(
            "Host network isolation is disabled. An admin must enable it on the Settings page \
             first."
                .into(),
        )));
    }
    Ok(())
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
            Permission::IncidentsView,
            OperationKind::Read,
            false,
            Duration::from_secs(20),
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

pub async fn list_blocked_ips(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListBlockedIps,
        "Blocked IPs",
    )
    .await
}

pub async fn isolation_status(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::IsolationStatus,
        "Isolation Status",
    )
    .await
}

pub async fn list_quarantined_files(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsView)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_read_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::ListQuarantinedFiles,
        "Quarantined Files",
    )
    .await
}

// ---------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------

/// `workflow`, when given, feeds a `{field: true}` result into the
/// workflow registry on success (see `crates/workflows/registry.json`'s
/// Inquest-sourced entries) -- containment/remediation actions here are
/// booleans ("did it succeed"), unlike Postmortem's read ops, which feed
/// a line count instead.
#[allow(clippy::too_many_arguments)]
async fn run_write_op(
    state: &AppState,
    jar: &CookieJar,
    ctx: &AuthContext,
    host_id: Uuid,
    operation: AgentOperation,
    label: &str,
    workflow: Option<(&str, &str)>,
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
            Permission::IncidentsRespond,
            OperationKind::Write,
            false,
            Duration::from_secs(60),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let suggested_actions = if let Some((source_action, field)) = workflow {
                let entry = serde_json::json!({ field: true });
                crate::common::suggested_actions_for(
                    state,
                    "inquest",
                    source_action,
                    std::slice::from_ref(&entry),
                    host_id,
                )
                .await
            } else {
                Vec::new()
            };
            render_host_with_suggestions(
                state,
                jar,
                ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
                suggested_actions,
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
pub struct IpForm {
    csrf_token: String,
    ip: String,
}

fn validate_ip(ip: &str) -> Result<String, WebError> {
    let ip = ip.trim().to_string();
    if !abyssal_agent_protocol::is_valid_ip_address(&ip) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a valid IP address.".into(),
        )));
    }
    Ok(ip)
}

pub async fn block_remote_ip(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<IpForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let ip = validate_ip(&form.ip)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::BlockRemoteIp { ip: ip.clone() },
        &format!("Block IP ({ip})"),
        Some(("block_remote_ip", "blocked")),
    )
    .await
}

pub async fn unblock_remote_ip(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<IpForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let ip = validate_ip(&form.ip)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::UnblockRemoteIp { ip: ip.clone() },
        &format!("Unblock IP ({ip})"),
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct QuarantineForm {
    csrf_token: String,
    path: String,
}

pub async fn quarantine_file(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<QuarantineForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let path = form.path.trim().to_string();
    // OS-aware: a Windows host's quarantine (`C:\...`) needs the
    // Windows validator, not the Unix one -- validating against the
    // wrong one would reject every legitimate path for that platform.
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let valid = if host.os.as_deref() == Some("windows") {
        abyssal_agent_protocol::is_valid_windows_absolute_path(&path)
    } else {
        abyssal_agent_protocol::is_valid_absolute_path(&path)
    };
    if !valid {
        let hint = if host.os.as_deref() == Some("windows") {
            r"Enter an absolute Windows path (e.g. C:\Users\foo\bad.exe) to quarantine."
        } else {
            "Enter an absolute path (starting with /) to quarantine."
        };
        return Err(WebError(AppError::Validation(hint.into())));
    }
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::QuarantineFile { path: path.clone() },
        &format!("Quarantine File ({path})"),
        Some(("quarantine_file", "quarantined")),
    )
    .await
}

#[derive(Deserialize)]
pub struct RestoreQuarantineForm {
    csrf_token: String,
    quarantine_filename: String,
}

fn validate_quarantine_filename(filename: &str) -> Result<String, WebError> {
    let filename = filename.trim().to_string();
    if !abyssal_agent_protocol::is_valid_quarantine_filename(&filename) {
        return Err(WebError(AppError::Validation(
            "That doesn't look like a quarantine filename -- copy it exactly from \"Quarantined \
             Files\" above."
                .into(),
        )));
    }
    Ok(filename)
}

pub async fn restore_quarantined_file(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<RestoreQuarantineForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let quarantine_filename = validate_quarantine_filename(&form.quarantine_filename)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::RestoreQuarantinedFile {
            quarantine_filename: quarantine_filename.clone(),
        },
        &format!("Restore Quarantined File ({quarantine_filename})"),
        None,
    )
    .await
}

pub async fn deisolate_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<SimpleForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::DeisolateHost,
        "De-isolate Host",
        None,
    )
    .await
}

// ---------------------------------------------------------------------
// Write: disable/enable a local account -- reuses `AgentOperation::
// LockUserAccount`/`UnlockUserAccount` (already implemented, Linux via
// `parish::lock_user_account`, Windows via `Disable-LocalUser`/
// `Enable-LocalUser`) through the same `run_write_op` every other
// Inquest write action already goes through -- deliberately not routed
// through Parish's own web handlers, since the point is this action
// being dispatched (and generically audited, same as block/quarantine/
// isolate already are) from Inquest's own incident-response context,
// not Parish's account-management one. `Write` tier, not `Destructive`:
// reversible via the paired enable action, matching Parish's own
// classification for the identical underlying operation.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AccountForm {
    csrf_token: String,
    username: String,
}

fn validate_account_username(
    host: &abyssal_core::Host,
    username: &str,
) -> Result<String, WebError> {
    let username = username.trim().to_string();
    let valid = if host.os.as_deref() == Some("windows") {
        abyssal_agent_protocol::is_valid_windows_account_name(&username)
    } else {
        abyssal_agent_protocol::is_valid_account_name(&username)
    };
    if !valid {
        return Err(WebError(AppError::Validation(
            "Enter a valid account name for this host's platform.".into(),
        )));
    }
    Ok(username)
}

pub async fn disable_account(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<AccountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let username = validate_account_username(&host, &form.username)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::LockUserAccount {
            username: username.clone(),
        },
        &format!("Disable Account ({username})"),
        None,
    )
    .await
}

pub async fn enable_account(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<AccountForm>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
    require_csrf(&jar, &form.csrf_token)?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let username = validate_account_username(&host, &form.username)?;
    run_write_op(
        &state,
        &jar,
        &ctx,
        host_id,
        AgentOperation::UnlockUserAccount {
            username: username.clone(),
        },
        &format!("Enable Account ({username})"),
        None,
    )
    .await
}

// ---------------------------------------------------------------------
// Shared Destructive confirm/dispatch machinery -- used by both
// `DeleteQuarantinedFile` (conservative tier) and `IsolateHost`
// (high-risk tier). `high_risk` controls whether
// `ensure_host_isolation_enabled` also gates this; every high-risk call
// site still checks it again itself right before this too -- belt and
// suspenders on the one gate this arsenal can't afford to get wrong.
#[allow(clippy::too_many_arguments)]
async fn destructive_confirm(
    state: &AppState,
    jar: CookieJar,
    ctx: AuthContext,
    host_id: Uuid,
    title: &str,
    message: String,
    action_url: String,
    type_to_confirm_label: &str,
    type_to_confirm_expected: &str,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;

    // Fetched only to confirm the host still exists before rendering a
    // confirm page for it -- the message/expected-confirm-text are
    // already built by the caller, which fetched the host itself too.
    let _host = repo::hosts::find_by_id(&state.pool, host_id)
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
        message,
        action_url,
        cancel_url: format!("/arsenals/inquest/{host_id}"),
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
    workflow: Option<(&str, &str)>,
) -> Result<Response, WebError> {
    abyssal_rbac::ensure(&ctx, Permission::IncidentsRespond)?;
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
            Permission::IncidentsRespond,
            OperationKind::Destructive,
            true,
            Duration::from_secs(60),
            None,
            elevated,
        )
        .await;

    match result {
        Ok(output) => {
            let suggested_actions = if let Some((source_action, field)) = workflow {
                let entry = serde_json::json!({ field: true });
                crate::common::suggested_actions_for(
                    state,
                    "inquest",
                    source_action,
                    std::slice::from_ref(&entry),
                    host_id,
                )
                .await
            } else {
                Vec::new()
            };
            render_host_with_suggestions(
                state,
                &jar,
                &ctx,
                host_id,
                result_label,
                Some(output.stdout),
                None,
                suggested_actions,
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
// Destructive (conservative tier): delete quarantined file
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SingleFieldQuery {
    value: String,
}

pub async fn delete_quarantined_file_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    let filename = validate_quarantine_filename(&q.value)?;
    let action_url = format!(
        "/arsenals/inquest/{host_id}/delete-quarantined?value={}",
        urlencoding_encode(&filename)
    );
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Delete quarantined file",
        format!(
            "This will permanently delete the quarantined file \"{filename}\". It cannot be \
             restored afterward. This cannot be undone."
        ),
        action_url,
        "quarantine filename",
        &filename,
    )
    .await
}

pub async fn delete_quarantined_file(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let filename = validate_quarantine_filename(&q.value)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &filename,
        AgentOperation::DeleteQuarantinedFile {
            filename: filename.clone(),
        },
        "Delete Quarantined File",
        form,
        None,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive (conservative tier): kill a process -- reuses
// `AgentOperation::SendSignal` (already implemented, Linux via `kill
// -s`, Windows via `Stop-Process -Force`) the same way disable/enable
// account reuses `LockUserAccount`/`UnlockUserAccount` above: dispatched
// from Inquest's own incident-response context rather than Reanimation's
// process-management one, through the same shared destructive machinery
// every other Inquest destructive action already uses. Always sends
// `KILL` -- an incident-response kill is meant to stop a process right
// now, not ask it nicely to exit, and `KILL`/`TERM` are the only two
// signal names with any Windows equivalent at all (see
// `reanimation::send_signal`'s Windows doc comment).
// ---------------------------------------------------------------------

fn validate_pid_query(value: &str) -> Result<u32, WebError> {
    let pid: u32 = value
        .trim()
        .parse()
        .map_err(|_| WebError(AppError::Validation("Enter a numeric process ID.".into())))?;
    if !abyssal_agent_protocol::is_valid_pid(pid) {
        return Err(WebError(AppError::Validation(
            "Refusing to operate on that process ID.".into(),
        )));
    }
    Ok(pid)
}

pub async fn kill_process_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
) -> Result<Response, WebError> {
    let pid = validate_pid_query(&q.value)?;
    let action_url = format!("/arsenals/inquest/{host_id}/kill-process?value={pid}");
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Kill process",
        format!(
            "This will forcibly terminate process {pid} on this host right now. It cannot be \
             undone -- any unsaved work in that process is lost."
        ),
        action_url,
        "process ID",
        &pid.to_string(),
    )
    .await
}

pub async fn kill_process(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Query(q): Query<SingleFieldQuery>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    let pid = validate_pid_query(&q.value)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &pid.to_string(),
        AgentOperation::SendSignal {
            pid,
            signal: "KILL".to_string(),
        },
        "Kill Process",
        form,
        None,
    )
    .await
}

// ---------------------------------------------------------------------
// Destructive (high-risk tier): full host isolation
// ---------------------------------------------------------------------

pub async fn isolate_host_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
) -> Result<Response, WebError> {
    ensure_host_isolation_enabled(&state).await?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let action_url = format!("/arsenals/inquest/{host_id}/isolate");
    destructive_confirm(
        &state,
        jar,
        ctx,
        host_id,
        "Isolate host",
        format!(
            "This will block ALL network traffic on \"{}\" except loopback, already-established \
             connections, and the control plane's own connection back to this agent. If anything \
             about that exception is wrong for this host's network setup (NAT, a DNS-based \
             control-plane address that later re-resolves differently, a multi-homed host), this \
             can sever the agent's own connection with no remote way to undo it -- recovery would \
             then need physical or console access. Double-check this is really the host you mean \
             before confirming.",
            host.name
        ),
        action_url,
        "hostname",
        &host.name,
    )
    .await
}

pub async fn isolate_host(
    State(state): State<AppState>,
    jar: CookieJar,
    CurrentUser(ctx): CurrentUser,
    Path(host_id): Path<Uuid>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response, WebError> {
    ensure_host_isolation_enabled(&state).await?;
    let host = repo::hosts::find_by_id(&state.pool, host_id)
        .await?
        .ok_or(AppError::NotFound)?;
    run_destructive_op(
        &state,
        jar,
        ctx,
        host_id,
        &host.name,
        AgentOperation::IsolateHost,
        "Isolate Host",
        form,
        Some(("isolate_host", "isolated")),
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

#[cfg(test)]
mod tests {
    #[test]
    fn isolating_a_host_suggests_postmortem() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "isolated": true });
        let targets: Vec<String> = registry
            .evaluate("inquest", "isolate_host", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"postmortem".to_string()));
    }

    #[test]
    fn blocking_an_ip_suggests_thanatos() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "blocked": true });
        let targets: Vec<String> = registry
            .evaluate("inquest", "block_remote_ip", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"thanatos".to_string()));
    }

    #[test]
    fn quarantining_a_file_suggests_thanatos() {
        let registry = abyssal_workflows::WorkflowRegistry::load_builtin();
        let entry = serde_json::json!({ "quarantined": true });
        let targets: Vec<String> = registry
            .evaluate("inquest", "quarantine_file", &entry)
            .matches
            .into_iter()
            .map(|m| m.target_arsenal)
            .collect();
        assert!(targets.contains(&"thanatos".to_string()));
    }
}
