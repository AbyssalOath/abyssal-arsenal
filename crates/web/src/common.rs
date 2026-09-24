use std::collections::HashMap;
use std::time::Duration;

use abyssal_agent_protocol::AgentOperation;
use abyssal_core::settings::{
    APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES, APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
};
use abyssal_core::{AppError, Permission};
use abyssal_database::repo;
use abyssal_execution::OperationKind;
use abyssal_rbac::AuthContext;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::csrf;
use crate::error::WebError;
use crate::state::AppState;

/// Renders a UTC timestamp (everything is stored in UTC) in `tz_name`
/// (an IANA name, e.g. `"America/Chicago"`, as stored on `User::timezone`).
/// Falls back to UTC if `tz_name` somehow isn't a real zone -- this is
/// display-only, so a bad value here should never become a hard error for
/// an otherwise-unrelated page.
pub fn format_in_tz(dt: DateTime<Utc>, tz_name: &str) -> String {
    let tz: chrono_tz::Tz = tz_name.parse().unwrap_or(chrono_tz::UTC);
    dt.with_timezone(&tz)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

pub fn require_csrf(jar: &CookieJar, submitted: &str) -> Result<(), WebError> {
    if csrf::verify(jar, submitted) {
        Ok(())
    } else {
        Err(WebError(AppError::Validation(
            "Your session expired or this form was submitted from an untrusted origin. Please try again.".into(),
        )))
    }
}

/// Server-side type-to-confirm check for irreversible/lockout-risk actions
/// (see `crate::templates::TypeToConfirm`). There's no JS to disable the
/// submit button until the input matches, so a mismatch just re-renders
/// the normal validation error, the same as any other bad input.
pub fn require_typed_confirmation(submitted: &str, expected: &str) -> Result<(), WebError> {
    if submitted.trim() == expected {
        Ok(())
    } else {
        Err(WebError(AppError::Validation(format!(
            "Typed confirmation didn't match \"{expected}\" -- please try again."
        ))))
    }
}

/// Only the owner of a macro, or someone with `Permission::MacrosManageAll`,
/// may edit/delete it -- a role-mate can use a shared role macro but never
/// change or remove it. Shared by every macro surface (Grimoire's
/// scheduled-task macros, Panopticon's/Account's SNMP community-string
/// macros) since the rule is the same regardless of macro type. Enforced
/// here (not just by hiding the Edit/Delete links in the template), since
/// the UI check alone would be bypassable by visiting the URL directly.
pub fn ensure_can_edit_macro(ctx: &AuthContext, m: &abyssal_core::Macro) -> Result<(), WebError> {
    if m.owner_user_id == ctx.user.id || ctx.has(Permission::MacrosManageAll) {
        Ok(())
    } else {
        Err(WebError(AppError::Forbidden))
    }
}

/// Validates a `return_to` value carried through a macro edit/remove
/// step (e.g. back to `/arsenals/panopticon/switches` or `/account`,
/// depending on where the admin came from) before it's ever handed to
/// `Redirect::to`. Only a same-origin, absolute path is accepted --
/// anything else (an absolute URL, a protocol-relative `//evil.example`,
/// an empty string) falls back to `default` rather than becoming an open
/// redirect.
pub fn safe_return_to<'a>(return_to: &'a str, default: &'a str) -> &'a str {
    if return_to.starts_with('/') && !return_to.starts_with("//") {
        return_to
    } else {
        default
    }
}

// -----------------------------------------------------------------------
// Custom-role delegation (GitHub issue #8). There is deliberately no
// hard-coded "is Super Admin" flag anywhere -- `has_no_ceiling` derives
// the same idea purely from holding every known permission, matching
// this platform's existing rule that "a role is just a named collection
// of permissions, nothing more" (see ARCHITECTURE.md#authorization-rbac).
// -----------------------------------------------------------------------

/// True for a user who holds every permission the platform knows about
/// (in practice, today, only Super Admin) -- the computed stand-in for
/// "no delegation ceiling applies to this user" used throughout the rest
/// of this section, rather than a hard-coded role-name check.
pub fn has_no_ceiling(ctx: &AuthContext) -> bool {
    Permission::ALL.iter().all(|p| ctx.has(*p))
}

/// Only a user with no ceiling, or someone holding `roles.manage` whose
/// own assigned role's subtree contains `role`, may create, edit, or
/// delete it. System roles are always root roles with no parent for a
/// delegated admin's subtree to descend from, so editing one -- same as
/// today -- requires no ceiling. A user can never manage the role they
/// themselves are currently assigned (stops widening your own grants by
/// editing your own role), except a no-ceiling user, who already has
/// nothing to gain by it. Enforced here (not just by hiding the
/// create/edit/delete controls in the template), since the UI check
/// alone would be bypassable by visiting the URL directly.
pub async fn ensure_can_manage_role(
    pool: &abyssal_database::DbPool,
    ctx: &AuthContext,
    role: &abyssal_core::Role,
) -> Result<(), WebError> {
    if !ctx.has(Permission::RolesManage) {
        return Err(WebError(AppError::Forbidden));
    }
    if has_no_ceiling(ctx) {
        return Ok(());
    }
    if role.is_system {
        return Err(WebError(AppError::Forbidden));
    }

    let own_roles = repo::roles::roles_for_user(pool, ctx.user.id).await?;
    if own_roles.iter().any(|r| r.id == role.id) {
        return Err(WebError(AppError::Forbidden));
    }
    for own_role in &own_roles {
        if repo::roles::is_within_subtree(pool, role.id, own_role.id).await? {
            return Ok(());
        }
    }
    Err(WebError(AppError::Forbidden))
}

/// Depth-and-name-sorted view of `roles`, each paired with its nesting
/// depth (1 = root) -- shared shaping for every role `<select>` in the
/// app (Add/Edit User's role picker, the Roles page's "create under"
/// parent picker), so a flat dropdown still shows the hierarchy without
/// needing a true cascading pair of selects and their own JS.
pub async fn sorted_role_options(
    pool: &abyssal_database::DbPool,
    roles: Vec<abyssal_core::Role>,
) -> anyhow::Result<Vec<(Uuid, String, u8)>> {
    let mut options = Vec::with_capacity(roles.len());
    for role in roles {
        let depth = repo::roles::depth_of(pool, role.id).await?;
        options.push((role.id, role.name, depth));
    }
    options.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.1.cmp(&b.1)));
    Ok(options)
}

/// The permission ceiling `ctx` may grant to any role right now: every
/// known permission for a no-ceiling user (Super Admin can grant
/// anything), or exactly their own current effective permissions
/// otherwise -- "a creator can only grant permissions they currently
/// hold themselves." Callers building/validating a role's requested
/// permission set additionally intersect this with the chosen parent's
/// own effective set (`repo::roles::effective_permissions_for_role`),
/// since a role's grants must fit under its parent too, not just under
/// its creator's ceiling.
pub fn grantable_permissions(ctx: &AuthContext) -> std::collections::HashSet<Permission> {
    if has_no_ceiling(ctx) {
        Permission::ALL.iter().copied().collect()
    } else {
        ctx.permissions.clone()
    }
}

/// Which roles `ctx` may assign to a user right now, as either the
/// top-level role or the sub-role in the Add/Edit User picker -- a
/// no-ceiling user may assign any role; otherwise, `ctx`'s own assigned
/// role plus everything descending from it, since assigning a role is
/// itself a form of granting whatever permissions that role carries, and
/// assigning your own (unchanged) role never grants more than you
/// already have.
pub async fn assignable_roles(
    pool: &abyssal_database::DbPool,
    ctx: &AuthContext,
) -> anyhow::Result<Vec<abyssal_core::Role>> {
    if has_no_ceiling(ctx) {
        return repo::roles::list(pool).await;
    }
    let own_roles = repo::roles::roles_for_user(pool, ctx.user.id).await?;
    let mut seen = std::collections::HashSet::new();
    let mut assignable = Vec::new();
    for own_role in own_roles {
        let mut candidates = repo::roles::descendants_of(pool, own_role.id).await?;
        candidates.push(own_role);
        for role in candidates {
            if seen.insert(role.id) {
                assignable.push(role);
            }
        }
    }
    Ok(assignable)
}

/// Builds the session cookie. Deliberately left without an explicit
/// `Max-Age`/`Expires`, making it a browser "session cookie" (cleared on
/// browser close) in addition to the server-side TTL enforced on every
/// validation — belt and suspenders rather than trusting the client's clock.
pub fn build_session_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((state.config.session_cookie_name.clone(), token))
        .path("/")
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(SameSite::Lax)
        .build()
}

pub fn clear_session_cookie(state: &AppState) -> Cookie<'static> {
    Cookie::build((state.config.session_cookie_name.clone(), ""))
        .path("/")
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(-1))
        .build()
}

/// Shown right after a real Apotheosis elevation over a non-TLS connection.
/// Not an enforcement mechanism (matches the rest of this app's posture:
/// warn for local testing, hard-require TLS in production) -- see
/// SECURITY.md.
const TLS_WARNING: &str = "WARNING: this connection is not running over TLS -- the sudo password was sent in \
     plaintext over the network. Do not use Apotheosis over an untrusted network without \
     TLS.\n\n";

/// Escalates a host ("Apotheosis") if a non-empty sudo password was
/// submitted alongside an arsenal action -- a no-op (`Ok(None)`) otherwise,
/// which covers both "this host is already elevated" (no password field
/// shown) and "this action didn't need root after all" (field shown but
/// left blank). Callers should try this before dispatching the action
/// they actually wanted, and only proceed to dispatch it if this returns
/// `Ok`; on `Ok(Some(warning))`, that warning should be prepended to
/// whatever result the caller goes on to show.
///
/// Goes through `execute_on_host` like every other dispatch, so it's
/// permission-checked (`hosts.elevate`, independently of whatever
/// permission the arsenal action itself required -- Apotheosis stays
/// Super-Admin-gated no matter which page triggers it) and audited the
/// same way the original standalone Apotheosis panel was.
pub async fn maybe_elevate(
    state: &AppState,
    ctx: &AuthContext,
    host_id: Uuid,
    host_name: &str,
    sudo_password: Option<String>,
) -> Result<Option<&'static str>, String> {
    let Some(password) = sudo_password.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let password = Zeroizing::new(password);

    let window_minutes = repo::settings::get_u32(
        &state.pool,
        APOTHEOSIS_ELEVATION_WINDOW_MINUTES,
        APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES,
    )
    .await
    .unwrap_or(APOTHEOSIS_ELEVATION_WINDOW_DEFAULT_MINUTES);
    let window = Duration::from_secs(u64::from(window_minutes) * 60);

    let result = state
        .executor
        .execute_on_host(
            ctx,
            &state.hosts,
            host_id,
            &format!("Elevate Privileges -- {host_name}"),
            AgentOperation::Elevate {
                password: password.to_string(),
                idle_timeout_secs: window.as_secs(),
            },
            Permission::HostsElevate,
            OperationKind::Write,
            false,
            Duration::from_secs(10),
            None,
            false,
        )
        .await;
    drop(password);

    match result {
        Ok(_) => {
            state
                .elevation
                .mark_elevated(host_id, host_name.to_string(), window);
            Ok((!state.config.cookie_secure).then_some(TLS_WARNING))
        }
        Err(e) => Err(format!("Escalation failed: {e}")),
    }
}

/// Minimal, dependency-free percent-encoding for the handful of characters
/// that can plausibly show up in a scan target, interface name, or vacuum
/// size/duration and would otherwise break a query string -- used to carry
/// a parameterized destructive action's value from its confirm page's GET
/// query string through to the POST handler (this crate doesn't already
/// depend on a URL-encoding crate for anything else).
pub fn urlencoding_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Reconstructs a human-readable size (e.g. `"943M"`, `"1.2G"`, `"0"`) as a
/// byte count, base 1024. Returns `None` for anything that doesn't parse.
/// Shared by every arsenal that turns a `df -h`/`du -sh`/`journalctl
/// --disk-usage`-style size back into a structured, comparable number for
/// the workflow registry -- see `abyssal_workflows`.
pub fn parse_human_size(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (number_part, multiplier) = match raw.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let multiplier = match c.to_ascii_uppercase() {
                'K' => 1024u64,
                'M' => 1024u64.pow(2),
                'G' => 1024u64.pow(3),
                'T' => 1024u64.pow(4),
                'P' => 1024u64.pow(5),
                _ => return None,
            };
            (&raw[..raw.len() - c.len_utf8()], multiplier)
        }
        _ => (raw, 1),
    };
    let value: f64 = number_part.parse().ok()?;
    Some((value * multiplier as f64).round() as u64)
}

/// One piece of context a "Suggested Next Steps" link carried forward in
/// its query string, labeled for display on the destination page -- Phase
/// 6 of Contextual Arsenal Workflow Navigation: the destination page shows
/// *why* it has this context, even where there's no specific form field to
/// pre-fill with it.
#[derive(Clone)]
pub struct WorkflowContextRow {
    pub label: &'static str,
    pub value: String,
}

/// The workflow registry's known `context_fields` (see
/// `crates/workflows/registry.json`), each with a human label. Kept in one
/// place so every destination page recognizes the same set -- adding a
/// context field to a new registry entry means adding it here too, so it
/// actually renders on arrival instead of sitting unused in the query
/// string.
const KNOWN_CONTEXT_FIELDS: &[(&str, &str)] = &[
    ("mount_point", "Mount point"),
    ("device", "Device"),
    ("source", "Source device"),
    ("pid", "PID"),
    ("comm", "Process"),
    ("cpu_percent", "CPU %"),
    ("usage_percent", "Usage %"),
    ("usage_bytes", "Usage (bytes)"),
    ("persisted_count", "New events"),
    ("days_until_expiry", "Days until expiry"),
    ("path", "Path"),
    ("connection_id", "Connection"),
    ("connection_name", "Connection name"),
    ("method", "Access method"),
];

/// Picks out whichever of the workflow registry's known context fields are
/// present in a destination page's incoming query string, as labeled rows
/// ready to render in an "arrived here because..." banner. An unrecognized
/// query parameter is never shown -- this only ever surfaces fields the
/// registry itself is known to pass, never arbitrary query input.
pub fn workflow_context_rows(query: &HashMap<String, String>) -> Vec<WorkflowContextRow> {
    KNOWN_CONTEXT_FIELDS
        .iter()
        .filter_map(|(key, label)| {
            query.get(*key).map(|value| WorkflowContextRow {
                label,
                value: value.clone(),
            })
        })
        .collect()
}

fn workflow_suggested_action_view(
    matched: abyssal_workflows::MatchedAction,
    host_id: Uuid,
) -> crate::templates::SuggestedActionView {
    let mut url = format!("/arsenals/{}/{}", matched.target_arsenal, host_id);
    if !matched.context.is_empty() {
        let query = matched
            .context
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding_encode(k), urlencoding_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        url.push('?');
        url.push_str(&query);
    }
    crate::templates::SuggestedActionView {
        label: matched.label,
        url,
    }
}

/// Persists every workflow-registry evaluation failure to the audit trail
/// (Obituary's audit log), so an admin debugging why a suggestion did or
/// didn't show up can see it there instead of only in server logs -- the
/// evaluator itself (`abyssal_workflows`) stays pure and never does I/O, so
/// this is the one place that turns a returned failure into something
/// admin-visible. Best-effort: a failure to *record* a failure must never
/// block the page that's rendering.
async fn record_workflow_evaluation_failures(
    pool: &abyssal_database::DbPool,
    failures: &[abyssal_workflows::EvaluationFailure],
) {
    for failure in failures {
        let resource = format!(
            "{}:{} -> {}:{}",
            failure.source_arsenal,
            failure.source_action,
            failure.target_arsenal,
            failure.target_action
        );
        let result = abyssal_audit::record(
            pool,
            abyssal_audit::AuditEvent::new(
                abyssal_audit::AuditAction::WorkflowEvaluationFailed,
                abyssal_audit::AuditOutcome::Failure,
            )
            .resource(&resource)
            .metadata(serde_json::json!({
                "field": failure.field,
                "message": failure.message,
            })),
        )
        .await;
        if let Err(e) = result {
            tracing::error!(error = %e, "failed to record workflow evaluation failure to audit log");
        }
    }
}

/// Evaluates every entry in `results` (one structured result per filesystem,
/// process, mount, etc.) against the workflow registry for
/// `source_arsenal`/`source_action`, resolving every match to a button for
/// `host_id` and persisting any evaluation failures across all of them in
/// one batch. The one place every source arsenal's read handler goes
/// through to produce its "Suggested Next Steps" list -- see
/// `abyssal_workflows` for the registry and evaluator this wraps.
pub async fn suggested_actions_for(
    state: &AppState,
    source_arsenal: &str,
    source_action: &str,
    results: &[serde_json::Value],
    host_id: Uuid,
) -> Vec<crate::templates::SuggestedActionView> {
    let mut matches = Vec::new();
    let mut failures = Vec::new();
    for result in results {
        let mut outcome = state
            .workflows
            .evaluate(source_arsenal, source_action, result);
        matches.append(&mut outcome.matches);
        failures.append(&mut outcome.failures);
    }
    if !failures.is_empty() {
        record_workflow_evaluation_failures(&state.pool, &failures).await;
    }
    matches
        .into_iter()
        .map(|matched| workflow_suggested_action_view(matched, host_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn parses_common_suffixes() {
        assert_eq!(parse_human_size("900M"), Some(943_718_400));
        assert_eq!(parse_human_size("1.2G"), Some(1_288_490_189));
        assert_eq!(parse_human_size("0"), Some(0));
        assert_eq!(parse_human_size("116.0M"), Some(121_634_816));
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(parse_human_size(""), None);
        assert_eq!(parse_human_size("abc"), None);
        assert_eq!(parse_human_size("12X"), None);
    }

    #[test]
    fn workflow_context_rows_picks_out_known_fields_only() {
        let mut query = HashMap::new();
        query.insert("mount_point".to_string(), "/tmp".to_string());
        query.insert("usage_percent".to_string(), "97".to_string());
        query.insert(
            "unrelated_param".to_string(),
            "should not appear".to_string(),
        );

        let rows = workflow_context_rows(&query);
        let labels: Vec<&str> = rows.iter().map(|r| r.label).collect();

        assert!(labels.contains(&"Mount point"));
        assert!(labels.contains(&"Usage %"));
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn workflow_context_rows_empty_when_nothing_recognized() {
        let mut query = HashMap::new();
        query.insert("host".to_string(), "web-01".to_string());
        assert!(workflow_context_rows(&query).is_empty());
    }

    #[test]
    fn workflow_suggested_action_view_builds_url_with_context() {
        let host_id = Uuid::nil();
        let matched = abyssal_workflows::MatchedAction {
            target_arsenal: "catacomb".to_string(),
            target_action: "directory_usage_breakdown".to_string(),
            label: "Investigate /tmp with Catacomb".to_string(),
            context: vec![
                ("mount_point".to_string(), "/tmp".to_string()),
                ("usage_percent".to_string(), "97".to_string()),
            ],
        };

        let view = workflow_suggested_action_view(matched, host_id);

        assert_eq!(
            view.url,
            format!("/arsenals/catacomb/{host_id}?mount_point=%2Ftmp&usage_percent=97")
        );
    }

    #[test]
    fn workflow_suggested_action_view_with_no_context_has_no_query_string() {
        let host_id = Uuid::nil();
        let matched = abyssal_workflows::MatchedAction {
            target_arsenal: "resurrection".to_string(),
            target_action: "read_only_filesystems".to_string(),
            label: "Check Read-Only Filesystems with Resurrection".to_string(),
            context: vec![],
        };

        let view = workflow_suggested_action_view(matched, host_id);

        assert_eq!(view.url, format!("/arsenals/resurrection/{host_id}"));
    }

    fn ctx_with(user_id: Uuid, permissions: &[Permission]) -> AuthContext {
        AuthContext {
            user: abyssal_core::User {
                id: user_id,
                username: "test".into(),
                email: "test@example.com".into(),
                password_hash: None,
                auth_provider: abyssal_core::AuthProviderKind::local(),
                is_active: true,
                must_change_password: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login_at: None,
                timezone: "UTC".into(),
            },
            permissions: permissions
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>(),
        }
    }

    fn macro_owned_by(owner_user_id: Uuid) -> abyssal_core::Macro {
        abyssal_core::Macro {
            id: Uuid::new_v4(),
            name: "Nightly backup".into(),
            owner_user_id,
            scope: abyssal_core::MacroScope::Personal,
            role_id: None,
            macro_type: abyssal_core::MacroType::CronJob,
            job_name: Some("nightly-backup".into()),
            schedule: Some("@daily".into()),
            run_as_user: Some("root".into()),
            command: Some("/usr/local/bin/backup.sh".into()),
            secret_value_encrypted: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn owner_can_edit_their_own_macro() {
        let owner = Uuid::new_v4();
        let ctx = ctx_with(owner, &[]);
        assert!(ensure_can_edit_macro(&ctx, &macro_owned_by(owner)).is_ok());
    }

    #[test]
    fn non_owner_without_manage_all_cannot_edit() {
        let ctx = ctx_with(Uuid::new_v4(), &[]);
        assert!(matches!(
            ensure_can_edit_macro(&ctx, &macro_owned_by(Uuid::new_v4())),
            Err(WebError(AppError::Forbidden))
        ));
    }

    #[test]
    fn non_owner_with_manage_all_can_edit() {
        let ctx = ctx_with(Uuid::new_v4(), &[Permission::MacrosManageAll]);
        assert!(ensure_can_edit_macro(&ctx, &macro_owned_by(Uuid::new_v4())).is_ok());
    }

    #[test]
    fn safe_return_to_accepts_a_same_origin_path() {
        assert_eq!(
            safe_return_to("/arsenals/panopticon/switches", "/account"),
            "/arsenals/panopticon/switches"
        );
    }

    #[test]
    fn safe_return_to_rejects_absolute_and_protocol_relative_urls() {
        assert_eq!(
            safe_return_to("https://evil.example/", "/account"),
            "/account"
        );
        assert_eq!(safe_return_to("//evil.example/", "/account"), "/account");
        assert_eq!(safe_return_to("", "/account"), "/account");
    }

    // -- Custom-role delegation (GitHub issue #8): escalation-prevention --

    #[test]
    fn user_holding_every_permission_has_no_ceiling() {
        let ctx = ctx_with(Uuid::new_v4(), Permission::ALL);
        assert!(has_no_ceiling(&ctx));
    }

    #[test]
    fn user_missing_even_one_permission_has_a_ceiling() {
        let held: Vec<Permission> = Permission::ALL
            .iter()
            .copied()
            .filter(|p| *p != Permission::RolesManage)
            .collect();
        let ctx = ctx_with(Uuid::new_v4(), &held);
        assert!(!has_no_ceiling(&ctx));
    }

    #[test]
    fn no_ceiling_user_can_grant_every_permission() {
        let ctx = ctx_with(Uuid::new_v4(), Permission::ALL);
        assert_eq!(
            grantable_permissions(&ctx),
            Permission::ALL.iter().copied().collect::<HashSet<_>>()
        );
    }

    #[test]
    fn scoped_user_can_only_grant_permissions_they_hold() {
        // GitHub issue #8: "a creator can only grant permissions they
        // currently hold themselves." A Network Admin-shaped user must
        // never be able to grant, say, `users.delete`, which they don't
        // have -- `grantable_permissions` is exactly what every
        // permission-editing route checks the submission against.
        let held = [
            Permission::NetworkView,
            Permission::NetworkManage,
            Permission::RolesManage,
        ];
        let ctx = ctx_with(Uuid::new_v4(), &held);
        let cap = grantable_permissions(&ctx);
        assert_eq!(cap, held.iter().copied().collect::<HashSet<_>>());
        assert!(!cap.contains(&Permission::UsersDelete));

        // The actual enforcement every route performs: a requested set
        // that reaches outside the cap must fail the subset check.
        let requested: HashSet<Permission> = [Permission::NetworkManage, Permission::UsersDelete]
            .into_iter()
            .collect();
        assert!(
            !requested.is_subset(&cap),
            "a request naming a permission outside the holder's own grants must be rejected"
        );
    }
}
