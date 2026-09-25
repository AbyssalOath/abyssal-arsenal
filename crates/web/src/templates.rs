use abyssal_core::Permission;
use abyssal_database::{DbPool, repo};
use abyssal_hosts::{ElevationTracker, HostConnectionRegistry};
use abyssal_rbac::AuthContext;
use askama::Template;
use uuid::Uuid;

use crate::common::WorkflowContextRow;

/// One host the nav's Apotheosis panel shows as currently (believed)
/// elevated, with a human-readable remaining time.
#[derive(Clone)]
pub struct ElevatedHostView {
    pub id: String,
    pub name: String,
    pub remaining: String,
}

/// One IANA timezone name for the account-menu `<select>`, with the
/// comparison against the user's current choice done server-side rather
/// than in the template -- same pattern as `PermissionRow::granted`.
#[derive(Clone)]
pub struct TimezoneOption {
    pub name: &'static str,
    pub selected: bool,
}

/// One connected, active host offered by the global host switcher in the
/// top nav.
#[derive(Clone)]
pub struct HostOption {
    pub id: String,
    pub name: String,
    pub selected: bool,
}

/// Shared chrome context every authenticated page template embeds: identity,
/// theme, the CSRF token forms must echo back, and which admin nav links this
/// user is even allowed to see. The links are a convenience — every one of
/// the routes they point at re-checks the same permission server-side.
#[derive(Clone)]
pub struct BaseCtx {
    pub username: String,
    pub theme: String,
    pub csrf_token: String,
    pub can_users_view: bool,
    pub can_roles_manage: bool,
    pub can_audit_view: bool,
    pub can_modules_manage: bool,
    pub can_settings_manage: bool,
    pub can_hosts_view: bool,
    pub can_hosts_elevate: bool,
    /// True when at least one host is currently (believed) elevated --
    /// drives the nav button's red pulse.
    pub apotheosis_active: bool,
    pub elevated_hosts: Vec<ElevatedHostView>,
    /// This user's own chosen IANA timezone name, used to render every
    /// timestamp in the app from their point of view.
    pub timezone: String,
    pub available_timezones: Vec<TimezoneOption>,
    /// Name of the globally selected host (`host_context::current`), for a
    /// "Host: <name>" style label -- `None` means "All hosts".
    pub selected_host_name: Option<String>,
    /// Every connected, active host, for the top-nav switcher `<select>`.
    pub available_hosts: Vec<HostOption>,
}

impl BaseCtx {
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        ctx: &AuthContext,
        theme: &str,
        csrf_token: &str,
        elevation: &ElevationTracker,
        hosts: &HostConnectionRegistry,
        pool: &DbPool,
        selected_host_id: Option<Uuid>,
    ) -> anyhow::Result<Self> {
        let snapshot = elevation.snapshot();
        let elevated_hosts = snapshot
            .into_iter()
            .map(|h| ElevatedHostView {
                id: h.host_id.to_string(),
                name: h.host_name,
                remaining: format_remaining(h.remaining),
            })
            .collect::<Vec<_>>();

        let mut zone_names: Vec<&'static str> =
            chrono_tz::TZ_VARIANTS.iter().map(|tz| tz.name()).collect();
        zone_names.sort_unstable();
        let available_timezones = zone_names
            .into_iter()
            .map(|name| TimezoneOption {
                name,
                selected: name == ctx.user.timezone,
            })
            .collect();

        let mut selected_host_name = None;
        let mut available_hosts = Vec::new();
        for host in repo::hosts::list(pool).await? {
            if !host.is_active() || !hosts.is_connected(host.id) {
                continue;
            }
            let selected = Some(host.id) == selected_host_id;
            if selected {
                selected_host_name = Some(host.name.clone());
            }
            available_hosts.push(HostOption {
                id: host.id.to_string(),
                name: host.name,
                selected,
            });
        }

        Ok(Self {
            username: ctx.user.username.clone(),
            theme: theme.to_string(),
            csrf_token: csrf_token.to_string(),
            can_users_view: ctx.has(Permission::UsersView),
            can_roles_manage: ctx.has(Permission::RolesManage),
            can_audit_view: ctx.has(Permission::AuditView),
            can_modules_manage: ctx.has(Permission::ModulesManage),
            can_settings_manage: ctx.has(Permission::SettingsManage),
            can_hosts_view: ctx.has(Permission::HostsView),
            can_hosts_elevate: ctx.has(Permission::HostsElevate),
            apotheosis_active: !elevated_hosts.is_empty(),
            elevated_hosts,
            timezone: ctx.user.timezone.clone(),
            available_timezones,
            selected_host_name,
            available_hosts,
        })
    }
}

pub(crate) fn format_remaining(remaining: std::time::Duration) -> String {
    let minutes = remaining.as_secs() / 60;
    let seconds = remaining.as_secs() % 60;
    format!("{minutes}m{seconds:02}s left")
}

#[derive(Template)]
#[template(path = "setup.html")]
pub struct SetupTemplate {
    pub theme: String,
    pub csrf_token: String,
    pub error: Option<String>,
    pub username: String,
    pub email: String,
    pub generated_password: Option<String>,
    pub password_prefill: String,
}

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub theme: String,
    pub csrf_token: String,
    pub error: Option<String>,
    pub username: String,
    pub email: String,
    pub generated_password: Option<String>,
    pub password_prefill: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub theme: String,
    pub csrf_token: String,
    pub error: Option<String>,
    pub registration_enabled: bool,
}

#[derive(Template)]
#[template(path = "forgot_password.html")]
pub struct ForgotPasswordTemplate {
    pub theme: String,
    pub csrf_token: String,
    /// Always the same message regardless of whether the email matched an
    /// account -- set once the form has been submitted, `None` for the
    /// initial blank form.
    pub submitted: bool,
}

#[derive(Template)]
#[template(path = "reset_password.html")]
pub struct ResetPasswordTemplate {
    pub theme: String,
    pub csrf_token: String,
    /// Pre-filled from `?token=` when present, but always a plain editable
    /// field -- without `PUBLIC_URL` configured, the reset email has no
    /// link at all, just a code the recipient pastes in here directly.
    pub token: String,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct ModuleTile {
    pub key: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub category: String,
    pub pinned: bool,
}

/// One `ModuleCategory` section of the dashboard's grouped tile grid.
/// Never holds a pinned tile -- those render once, in the "Pinned" row.
pub struct ModuleGroup {
    pub category: String,
    pub tiles: Vec<ModuleTile>,
}

pub struct ActivityRow {
    pub occurred_at: String,
    pub username: String,
    /// A single human-readable phrase combining the operation and what it
    /// acted on (e.g. `"Rebooted — WEB-01"`), rather than a raw audit
    /// action key and a separate resource column.
    pub summary: String,
    pub result: String,
}

/// One host `host_health_snapshots` flags as needing attention.
pub struct HostAttentionRow {
    pub host_name: String,
    pub reason: String,
}

/// The single most recent Reliquary backup across the fleet.
pub struct LastBackupRow {
    pub host_name: String,
    pub name: String,
    pub when: String,
}

/// The dashboard's fleet-health overview -- replaces the old permanent
/// "Active tasks" placeholder with real, cheaply-queried aggregates.
pub struct FleetHealthCtx {
    pub host_count: usize,
    pub online_count: usize,
    pub open_alerts: i64,
    pub hosts_needing_attention: Vec<HostAttentionRow>,
    pub last_backup: Option<LastBackupRow>,
}

/// The dashboard's version notice: this build's own version always shown,
/// plus a newer release's version and link once `update_check` has
/// confirmed one exists.
pub struct UpdateNoticeCtx {
    pub current_version: String,
    /// Empty until `update_available` is true, at which point both this and
    /// `release_url` are guaranteed non-empty.
    pub latest_version: String,
    pub release_url: String,
    pub update_available: bool,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub base: BaseCtx,
    pub search_query: String,
    pub pinned: Vec<ModuleTile>,
    pub groups: Vec<ModuleGroup>,
    pub fleet_health: FleetHealthCtx,
    pub update_notice: UpdateNoticeCtx,
    pub recent_activity: Vec<ActivityRow>,
}

pub struct UserRow {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_active: bool,
    pub roles: String,
}

/// One role a user can be picked from a `<select>` -- `depth` (1 = root,
/// 2 = its direct child, ...) drives indentation so a flat dropdown still
/// shows the hierarchy, standing in for a true cascading "role, then
/// sub-role" pair of selects without needing client-side JS to filter
/// the second one.
pub struct RoleOption {
    pub id: String,
    pub name: String,
    pub depth: u8,
}

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersTemplate {
    pub base: BaseCtx,
    pub users: Vec<UserRow>,
    /// Only roles the viewing admin may assign -- see
    /// `common::assignable_roles`. Never the full role catalogue for a
    /// scoped (non-no-ceiling) admin.
    pub roles: Vec<RoleOption>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub new_username: String,
    pub new_email: String,
    pub generated_password: Option<String>,
    pub password_prefill: String,
}

/// One user's edit page -- profile fields (username/email, to fix a typo
/// made at creation) plus an admin-triggered password reset, which mirrors
/// the create-user page's own "generate, review, then confirm" flow: a
/// separate "Generate strong password" submit re-renders this same page
/// with `generated_password` set (a one-time preview, nothing persisted
/// yet), and only the following "Reset password" submit -- which posts
/// back whatever's currently in the password field -- actually writes it.
#[derive(Template)]
#[template(path = "user_edit.html")]
pub struct UserEditTemplate {
    pub base: BaseCtx,
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub error: Option<String>,
    pub generated_password: Option<String>,
    pub password_prefill: String,
    /// Only roles the viewing admin may assign -- see
    /// `common::assignable_roles`. If this user's *current* role isn't
    /// in that set (a scoped admin viewing someone outside their
    /// subtree), it's added anyway so the dropdown doesn't silently
    /// misrepresent their current role, but see `can_change_role`.
    pub roles: Vec<RoleOption>,
    pub current_role_id: String,
    /// False when the viewing admin isn't allowed to change this user's
    /// role at all (their current role is outside the viewer's subtree,
    /// or the target is the viewer themselves) -- the role selector
    /// renders disabled/read-only rather than letting a submit silently
    /// no-op or a raw POST attempt succeed unexpectedly.
    pub can_change_role: bool,
}

pub struct PermissionRow {
    pub key: String,
    pub granted: bool,
}

/// One arsenal's dashboard-visibility checkbox state for a role, editable
/// on `/admin/roles` independently of (and always still bounded by) its
/// permission-based access.
pub struct ModuleVisibilityRow {
    pub key: &'static str,
    pub display_name: &'static str,
    pub visible: bool,
}

/// Lightweight per-role summary -- the roles list page's cards, and a
/// role detail page's list of its own children, both just need
/// name/description/counts and a link, never the full permission/
/// visibility computation `RoleDetail` below carries. Kept separate so
/// listing every role in the system doesn't run a permissions-capping
/// and module-visibility query for each one just to render a summary
/// card that immediately links elsewhere for the real editing UI.
pub struct RoleSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    /// 1 for a root role, 2 for its direct child, 3 for a grandchild --
    /// drives the indentation in the hierarchy list.
    pub depth: u8,
    pub parent_name: Option<String>,
    pub user_count: i64,
    pub child_count: i64,
}

pub struct RoleDetail {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    /// 1 for a root role, 2 for its direct child, 3 for a grandchild --
    /// drives the indentation in the hierarchy list.
    pub depth: u8,
    pub parent_name: Option<String>,
    /// Paired with `parent_name` so the detail page can link up to the
    /// parent role's own page -- `None` exactly when `parent_name` is.
    pub parent_id: Option<String>,
    /// Only the permissions the *viewing* user is allowed to grant on
    /// this role are included -- see `common::grantable_permissions` and
    /// `RoleDetail`'s construction in `routes/roles.rs::build_role_detail`.
    /// The rest exist on the role (or not) but are neither shown nor
    /// editable by this viewer.
    pub permissions: Vec<PermissionRow>,
    /// How many of this role's actual permissions were left out of
    /// `permissions` above because the viewer isn't allowed to grant (or
    /// see) them -- shown as a one-line note so a scoped admin isn't left
    /// wondering where a permission went.
    pub hidden_permission_count: usize,
    pub module_visibility: Vec<ModuleVisibilityRow>,
    /// Whether this role has an explicit dashboard-visibility override.
    /// When false, `module_visibility` reflects today's plain
    /// permission-based visibility as a starting point for editing, not a
    /// saved customization yet.
    pub visibility_customized: bool,
    /// Whether the viewing user may edit/delete this role at all -- see
    /// `common::ensure_can_manage_role`. `false` hides every editing
    /// control for this role (view-only card) -- note this can still be
    /// `true` for a system role, since a no-ceiling (Super Admin) viewer
    /// may always adjust a system role's permissions; only rename/delete
    /// stay hard-blocked for system roles regardless of `can_manage`.
    pub can_manage: bool,
    pub user_count: i64,
    pub child_count: i64,
}

#[derive(Template)]
#[template(path = "roles.html")]
pub struct RolesTemplate {
    pub base: BaseCtx,
    pub roles: Vec<RoleSummary>,
    /// Whether the viewing user has no delegation ceiling (Super Admin)
    /// -- only they may create a brand new root role with no parent at
    /// all; shown as a small form directly on this list page, since a
    /// root role (by definition) has no parent role's own page for that
    /// form to live on instead. Every other role's "create a sub-role
    /// here" form lives on that role's own detail page
    /// (`RoleDetailPageTemplate`) -- see GitHub issue #8 follow-up.
    pub can_create_root: bool,
    pub create_error: Option<String>,
}

#[derive(Template)]
#[template(path = "role_detail.html")]
pub struct RoleDetailPageTemplate {
    pub base: BaseCtx,
    pub role: RoleDetail,
    pub children: Vec<RoleSummary>,
    /// Whether this role may serve as the parent of a new sub-role the
    /// viewing user creates -- see `common::assignable_roles` and
    /// `abyssal_core::MAX_ROLE_DEPTH`. Independent of `role.can_manage`:
    /// a user's own role is always in their `assignable_roles` (they may
    /// create a sub-role under it) even though they can never manage
    /// (edit permissions on) their own role directly -- exactly how
    /// delegation bootstraps.
    pub can_create_sub_role: bool,
    /// Every permission the viewer could grant a brand-new sub-role
    /// created directly under `role` right now -- `grantable_permissions
    /// (ctx) ∩ role`'s own effective permissions, the exact cap
    /// `routes::roles::create_role` itself enforces server-side. Always
    /// unchecked (`granted: false`) since nothing has been decided yet;
    /// left empty when `can_create_sub_role` is false.
    pub sub_role_permission_options: Vec<PermissionRow>,
    pub create_error: Option<String>,
}

pub struct AuditRow {
    pub occurred_at: String,
    pub username: String,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub source_ip: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditTemplate {
    pub base: BaseCtx,
    pub entries: Vec<AuditRow>,
    /// Keyset (cursor) pagination, not offset -- the audit log is
    /// append-heavy and unbounded in principle, so this never runs a
    /// `COUNT(*)` or an `OFFSET` scan (GitHub issue #10). `None` when
    /// there's nothing further in that direction.
    pub newer_href: Option<String>,
    pub older_href: Option<String>,
    pub action_filter: String,
}

pub struct ModuleRow {
    pub key: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub enabled: bool,
}

#[derive(Template)]
#[template(path = "modules.html")]
pub struct ModulesTemplate {
    pub base: BaseCtx,
    pub modules: Vec<ModuleRow>,
}

/// One row of the Contextual Arsenal Workflow Navigation registry admin
/// view -- a read-only rendering of `abyssal_workflows::WorkflowEntry`, for
/// debugging why a suggestion did or didn't show up without reading
/// `registry.json` directly.
pub struct WorkflowEntryRow {
    pub source_arsenal: String,
    pub source_action: String,
    pub condition: String,
    pub target_arsenal: String,
    pub target_action: String,
    pub label: String,
    pub context_fields: String,
}

#[derive(Template)]
#[template(path = "workflows.html")]
pub struct WorkflowsTemplate {
    pub base: BaseCtx,
    pub entries: Vec<WorkflowEntryRow>,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub base: BaseCtx,
    pub public_registration_enabled: bool,
    pub apotheosis_elevation_window_minutes: u32,
    pub high_risk_storage_ops_enabled: bool,
    pub host_isolation_enabled: bool,
    pub thanatos_monitoring_enabled: bool,
    pub thanatos_alert_recipients: String,
    pub thanatos_extra_fim_paths: String,
    pub thanatos_auto_quarantine_ssh_keys_enabled: bool,
    pub thanatos_auto_disable_account_enabled: bool,
    pub thanatos_correlation_threshold: u32,
    pub thanatos_correlation_window_minutes: u32,
    pub thanatos_sweep_interval_seconds: u32,
    pub panopticon_sweep_enabled: bool,
    pub panopticon_sweep_target: String,
    pub panopticon_mdns_enabled: bool,
    pub panopticon_arp_enabled: bool,
    pub panopticon_arp_interface: String,
    pub panopticon_traffic_raw_retention_days: u32,
    pub panopticon_traffic_hourly_retention_days: u32,
    pub panopticon_traffic_daily_retention_days: u32,
    pub audit_syslog_export_enabled: bool,
    pub message: Option<String>,
}

#[derive(Template)]
#[template(path = "style_guide.html")]
pub struct StyleGuideTemplate {
    pub base: BaseCtx,
}

/// One saved SNMP community-string macro, as shown either on the Account
/// page (the macros this user owns) or on Panopticon's add-switch form
/// (every macro of this type visible to them -- their own personal ones
/// plus their roles'). `can_edit` is only true for the macro's owner or
/// someone with `Permission::MacrosManageAll`. The secret value itself is
/// never rendered anywhere -- there's no plaintext to show, only
/// ciphertext is on hand.
pub struct CommunityMacroRow {
    pub id: String,
    pub name: String,
    pub scope_label: String,
    pub can_edit: bool,
}

#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountTemplate {
    pub base: BaseCtx,
    /// True while this account still has an admin-set temporary password
    /// it hasn't changed yet -- shows a banner and is why `CurrentUser`
    /// keeps redirecting here from every other page until it's resolved.
    pub must_change_password: bool,
    pub password_error: Option<String>,
    /// SNMP community-string macros this user owns -- see
    /// `routes/account.rs::add_community_macro`.
    pub community_macros: Vec<CommunityMacroRow>,
    /// (role_id, role_name) for every role this user belongs to -- the
    /// "My role: X" options on the Add Macro scope picker.
    pub macro_roles: Vec<(String, String)>,
    pub macro_error: Option<String>,
}

/// Edit form for one SNMP community-string macro -- see
/// `routes/account.rs::community_macro_edit_*`. Shared by every surface
/// that links here (the Account page's own list, Panopticon's add-switch
/// macro list) via `return_to`, since a community-string macro isn't tied
/// to any one of them. The secret value is deliberately never prefilled
/// -- leaving it blank on submit means "keep the existing one".
#[derive(Template)]
#[template(path = "account_macro_edit.html")]
pub struct AccountMacroEditTemplate {
    pub base: BaseCtx,
    pub macro_id: String,
    pub return_to: String,
    pub name: String,
    pub is_personal: bool,
    /// (role_id, role_name, is this macro's current role)
    pub macro_roles: Vec<(String, String, bool)>,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "arsenal_detail.html")]
pub struct ArsenalDetailTemplate {
    pub base: BaseCtx,
    pub display_name: String,
    pub description: String,
    pub category: String,
}

pub struct HostRow {
    pub id: String,
    pub name: String,
    pub enrolled_at: String,
    pub last_seen_at: String,
    pub online: bool,
    pub revoked: bool,
    pub elevation_remaining: Option<String>,
    /// True when this host is currently connected but its agent's reported
    /// (or missing) protocol version doesn't match this control plane's --
    /// see `abyssal_hosts::HostConnectionRegistry::agent_protocol_mismatch`.
    pub protocol_mismatch: bool,
}

#[derive(Template)]
#[template(path = "hosts.html")]
pub struct HostsTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<HostRow>,
    pub enrollment_command: Option<String>,
    pub uninstall_command: Option<String>,
    pub action_result: Option<String>,
    pub action_error: Option<String>,
}

/// Extra friction for confirming an action that's irreversible or risks
/// locking out access: the admin must type the exact resource name back,
/// not just click a button. Checked server-side in the POST handler --
/// there's no JS to disable the submit button until it matches, so a
/// mismatch just re-renders the normal validation error, same as any
/// other bad input.
pub struct TypeToConfirm {
    /// e.g. "hostname", "username" -- what the input's label calls it.
    pub label: String,
    pub expected: String,
}

#[derive(Template)]
#[template(path = "confirm.html")]
pub struct ConfirmTemplate {
    pub base: BaseCtx,
    pub title: String,
    pub message: String,
    pub action_url: String,
    pub cancel_url: String,
    /// Some(host_id) when confirming a host-dispatched operation that might
    /// need escalation and the host isn't already believed elevated --
    /// renders an optional sudo password field alongside the confirm
    /// button. `None` for confirm pages unrelated to a host operation
    /// (e.g. revoking/removing a host itself).
    pub escalate_host_id: Option<String>,
    /// Some(..) for confirms that need the admin to type the resource name
    /// back rather than just clicking Confirm (see `TypeToConfirm`).
    pub type_to_confirm: Option<TypeToConfirm>,
    /// Extra opaque (name, value) pairs carried through the confirm step as
    /// hidden fields -- e.g. a JSON-encoded payload computed on the way
    /// into the confirm page that the final POST handler needs back
    /// unchanged. Empty for confirms that need nothing beyond the standard
    /// `csrf_token`/`confirm`.
    pub extra_hidden_fields: Vec<(String, String)>,
}

pub struct CystoolboxHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "cystoolbox.html")]
pub struct CystoolboxTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<CystoolboxHostRow>,
}

/// One "Suggested Next Steps" button: a matched workflow-registry action,
/// already resolved to a concrete URL for this host. See
/// `abyssal_workflows` for how matches are produced.
#[derive(Clone)]
pub struct SuggestedActionView {
    pub label: String,
    pub url: String,
}

#[derive(Template)]
#[template(path = "cystoolbox_host.html")]
pub struct CystoolboxHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub can_manage: bool,
    /// True when this host is believed already elevated -- hides the sudo
    /// password fields on every action form when true.
    pub elevated: bool,
    /// True when connected but the agent's protocol version doesn't match.
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    /// Workflow-registry matches for this result, if any. Empty for every
    /// action that doesn't emit a structured result the registry reacts to.
    pub suggested_actions: Vec<SuggestedActionView>,
}

pub struct CadavaultHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "cadavault.html")]
pub struct CadavaultTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<CadavaultHostRow>,
}

#[derive(Template)]
#[template(path = "cadavault_host.html")]
pub struct CadavaultHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub can_manage: bool,
    pub elevated: bool,
    /// True when connected but the agent's protocol version doesn't match.
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

/// One connected host's collapsible group on the Postmortem/Inquest fleet
/// dashboard -- the group-list half of Panopticon's Device Inventory
/// pattern (GitHub issue #10), without per-group row pagination: unlike
/// Panopticon's subnet groups or Thanatos's per-host event history,
/// there's no structured per-host row data here to page through, only a
/// handful of read-only quick-check buttons that cost nothing to reveal
/// -- so a group's body is just those buttons, gated behind `<details>`
/// purely to keep a fleet of many hosts visually tidy, not for any
/// query-cost reason. Always starts closed (no render-budget setting),
/// matching this app's default posture for every collapsible section.
pub struct PostmortemHostGroup {
    pub host_id: String,
    pub host_name: String,
    pub is_open: bool,
    pub open_href: Option<String>,
}

#[derive(Template)]
#[template(path = "postmortem.html")]
pub struct PostmortemTemplate {
    pub base: BaseCtx,
    pub groups: Vec<PostmortemHostGroup>,
    pub group_list_page: Option<NumberedPageInfo>,
}

/// No `can_manage` field -- every op in this arsenal is read-only forensic
/// examination, so there's no write/destructive section to gate.
#[derive(Template)]
#[template(path = "postmortem_host.html")]
pub struct PostmortemHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub context: Vec<WorkflowContextRow>,
}

pub struct MortiscopeHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "mortiscope.html")]
pub struct MortiscopeTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<MortiscopeHostRow>,
}

/// No `can_manage` field -- every op in this arsenal is read-only
/// monitoring, so there's no write/destructive section to gate.
#[derive(Template)]
#[template(path = "mortiscope_host.html")]
pub struct MortiscopeHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub context: Vec<WorkflowContextRow>,
}

pub struct GrimoireHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "grimoire.html")]
pub struct GrimoireTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<GrimoireHostRow>,
}

/// One saved scheduled-task macro, as visible to the current user -- see
/// `routes/grimoire.rs::visible_macro_rows`. `can_edit` is only true for
/// the macro's owner or someone with `Permission::MacrosManageAll`; a
/// role-mate merely using a shared role macro sees no Edit/Delete links.
pub struct GrimoireMacroRow {
    pub id: String,
    pub name: String,
    pub scope_label: String,
    pub job_name: String,
    pub schedule: String,
    pub run_as_user: String,
    pub command: String,
    pub can_edit: bool,
}

#[derive(Template)]
#[template(path = "grimoire_host.html")]
pub struct GrimoireHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `systems.manage` -- gates the Write/Destructive section, distinct
    /// from the `systems.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    /// Every macro visible to this user (personal + their roles'),
    /// GitHub issue #7.
    pub macros: Vec<GrimoireMacroRow>,
    /// (role_id, role_name) for every role this user belongs to -- the
    /// "My role: X" options on the Save as Macro scope picker. Empty for
    /// a user in no roles, in which case only "Just me" is offered.
    pub macro_roles: Vec<(String, String)>,
    /// Prefills the Set Scheduled Task fields below -- blank unless a
    /// `?load_macro=` picked one, in which case these are that macro's
    /// stored values.
    pub cron_job_name: String,
    pub cron_schedule: String,
    pub cron_run_as_user: String,
    pub cron_command: String,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

/// Edit form for one macro -- see `routes/grimoire.rs::macro_edit_*`.
/// `host_id` is carried through purely to redirect back to the host page
/// the admin came from; a macro itself isn't tied to any one host.
#[derive(Template)]
#[template(path = "grimoire_macro_edit.html")]
pub struct GrimoireMacroEditTemplate {
    pub base: BaseCtx,
    pub macro_id: String,
    pub host_id: String,
    pub name: String,
    pub is_personal: bool,
    /// (role_id, role_name, is this macro's current role)
    pub macro_roles: Vec<(String, String, bool)>,
    pub job_name: String,
    pub schedule: String,
    pub run_as_user: String,
    pub command: String,
    pub error: Option<String>,
}

pub struct OssuaryHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "ossuary.html")]
pub struct OssuaryTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<OssuaryHostRow>,
}

#[derive(Template)]
#[template(path = "ossuary_host.html")]
pub struct OssuaryHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `storage.manage` -- gates the Write/Destructive sections,
    /// distinct from the `storage.view` the read operations use.
    pub can_manage: bool,
    /// The admin-configured "high-risk storage operations" setting
    /// (Settings page) -- distinct from `can_manage`, gates only the
    /// partition/RAID/LVM-create/mkfs section even when the caller has
    /// `storage.manage`.
    pub high_risk_ops_enabled: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub context: Vec<WorkflowContextRow>,
    /// Pre-fills Partition Table's device field when a suggestion carried
    /// a `device` (not every suggestion into this page names one).
    pub prefill_device: Option<String>,
}

/// Same shape and reasoning as `PostmortemHostGroup`.
pub struct InquestHostGroup {
    pub host_id: String,
    pub host_name: String,
    /// "Linux"/"Windows"/"macOS"/"Unknown OS", from `Host.os` -- see
    /// `common::os_label`.
    pub os_label: &'static str,
    pub is_open: bool,
    pub open_href: Option<String>,
}

#[derive(Template)]
#[template(path = "inquest.html")]
pub struct InquestTemplate {
    pub base: BaseCtx,
    pub groups: Vec<InquestHostGroup>,
    pub group_list_page: Option<NumberedPageInfo>,
}

#[derive(Template)]
#[template(path = "inquest_host.html")]
pub struct InquestHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// "Linux"/"Windows"/"macOS"/"Unknown OS", from `Host.os` -- see
    /// `common::os_label`.
    pub os_label: &'static str,
    /// What block/isolate/quarantine actually do on this host -- see
    /// `routes::inquest::containment_note`.
    pub containment_note: &'static str,
    /// `incidents.respond` -- gates the Write/Destructive sections,
    /// distinct from the `incidents.view` the read operations use.
    pub can_manage: bool,
    /// The admin-configured "host network isolation" setting (Settings
    /// page) -- distinct from `can_manage`, gates only `IsolateHost`
    /// even when the caller has `incidents.respond`. `DeisolateHost`
    /// stays ungated: undoing isolation should never be harder than
    /// applying it.
    pub host_isolation_enabled: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub context: Vec<WorkflowContextRow>,
}

pub struct NetworkDeviceRow {
    pub id: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    /// Best-effort manufacturer name from the MAC's OUI prefix
    /// (`NetworkDevice::vendor`), or `None` when there's no MAC on record
    /// or its prefix isn't in Panopticon's curated table.
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    /// Open ports joined into one display string (e.g. `"22/tcp ssh,
    /// 80/tcp http"`) -- normalized storage lives in
    /// `panopticon_device_ports`; this is just this row's rendering of it.
    pub open_ports: Option<String>,
    pub device_type_label: String,
    /// Raw `DeviceType::as_str()` key, for pre-selecting the classify
    /// form's `<select>`.
    pub device_type_value: String,
    pub trust_label: String,
    /// Raw `TrustState::as_str()` key -- also doubles as the CSS badge
    /// modifier class suffix (`badge-{trust_value}` isn't used directly,
    /// see the template's own `{% match %}` for the mapping).
    pub trust_value: String,
    pub notes: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    /// Set when `last_seen_at` is older than Panopticon's staleness
    /// threshold -- see `routes/panopticon.rs::STALE_THRESHOLD`. This is
    /// never real-time presence, only "the last scan that saw it responded
    /// this long ago".
    pub stale: bool,
    /// `Some(host.name)` when this device's IP matches a currently
    /// enrolled host's last-known connecting address (`Host::last_seen_ip`)
    /// -- a best-effort correlation, not a guarantee (a host's LAN address
    /// can change, and this is only ever as fresh as that host's last
    /// WebSocket reconnect).
    pub managed_host_name: Option<String>,
    /// `"<switch name> / <port label>"` from the most recent SNMP poll
    /// that found this device's MAC in a switch's forwarding database, or
    /// `None` if no poll ever has (no switches configured, this device's
    /// MAC unknown to any polled switch, or it hasn't been polled since
    /// this device first appeared).
    pub switch_location: Option<String>,
}

/// Generic numbered-pagination info for an Askama template: first/prev/
/// next/last plus a windowed, ellipsis-collapsed page strip and a
/// "Showing X-Y of Z" range -- built once in Rust
/// (`pagination::page_window`/`page_link`) and handed to the
/// `pagination_nav` macro (`templates/_pagination.html`), never
/// assembled in the template itself. Used by the Device Inventory
/// group-list, an ad-hoc `?subnet=` filtered view, and any other
/// offset-paginated view (GitHub issue #10).
pub struct NumberedPageInfo {
    pub current_page: u32,
    pub total_pages: u32,
    pub range_start: u64,
    pub range_end: u64,
    pub total: u64,
    pub first_href: Option<String>,
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
    pub last_href: Option<String>,
    /// `(label, href, is_current)` -- `href: None` renders as a plain
    /// ellipsis, not a link.
    pub numbered: Vec<(String, Option<String>, bool)>,
}

/// A single subnet group's own row pagination -- deliberately simpler
/// than [`NumberedPageInfo`] (no numbered strip) so a page with several
/// open groups doesn't repeat a full pager widget inside every one of
/// them.
pub struct GroupPageInfo {
    pub current_page: u32,
    pub total_pages: u32,
    pub range_start: u64,
    pub range_end: u64,
    pub total: u64,
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// One subnet group in the Device Inventory's grouped view -- a
/// `<details>` whose `<summary>` (subnet, device count, managed count)
/// always renders, but whose body (`devices`) is only populated when
/// `is_open` -- see `docs/device-inventory.md`'s render-budget/`open`-param
/// design. A device with multiple IPs would appear in each group its
/// IPs fall into, never twice within the same one -- moot today, since
/// `panopticon_devices` has exactly one IP per row (see that doc's
/// "multi-IP devices" note).
pub struct InventoryGroup {
    /// The canonical CIDR string (`"10.0.1.0/24"`), or the literal
    /// `"unassigned"` sentinel for the "Unassigned / Unknown" group --
    /// also what `?open=`/`gp[...]` keys use, so a group's own links are
    /// stable across reloads.
    pub network: String,
    /// `"10.0.1.0/24"` or `"Unassigned / Unknown"` -- what the
    /// `<summary>` actually displays.
    pub display_label: String,
    pub is_unassigned: bool,
    pub device_count: i64,
    pub managed_count: i64,
    pub is_open: bool,
    pub devices: Vec<NetworkDeviceRow>,
    /// The "Load devices" link shown in place of a body when `!is_open`.
    pub open_href: Option<String>,
    pub scroll_aria_label: String,
    pub page_info: Option<GroupPageInfo>,
    /// Existing "Rescan"/"Remove" actions, preserved from the old
    /// Topology table -- `None` for the Unassigned group, which can't be
    /// rescanned (there's no CIDR to target) though it can still be
    /// cleared via Remove.
    pub rescan_href: Option<String>,
    pub remove_href: Option<String>,
}

#[derive(Template)]
#[template(path = "panopticon.html")]
pub struct PanopticonTemplate {
    pub base: BaseCtx,
    /// `network.scan` -- gates the discovery-scan form, distinct from the
    /// `network.view` the inventory/topology views use.
    pub can_scan: bool,
    /// `network.manage` -- gates removing a device from the inventory.
    pub can_manage: bool,
    /// `hosts.manage` -- gates the "Quick add" action (Quick Add Host From
    /// Network Scan, `routes/panopticon_deploy.rs`), distinct from both
    /// `can_scan`/`can_manage` above.
    pub can_deploy: bool,
    /// The `?port=` query value echoed back into the filter input, empty
    /// when unfiltered.
    pub port_filter: String,
    pub total_device_count: i64,
    pub render_budget: u32,
    /// Empty when `filtered_devices` is `Some` (an ad-hoc `?subnet=`
    /// filter replaces the grouped view entirely, per GitHub issue #10's
    /// "filters to one group").
    pub groups: Vec<InventoryGroup>,
    pub group_list_page: Option<NumberedPageInfo>,
    pub subnet_filter_input: String,
    pub subnet_filter_error: Option<String>,
    pub filtered_subnet: Option<String>,
    /// Where the filter chip's "x" link goes -- the current query with
    /// `subnet`/`page` dropped, built in Rust
    /// (`InventoryQuery::without_subnet`) rather than hand-assembled in
    /// the template, so it stays consistent with every other pagination
    /// link on this page. `None` whenever `filtered_subnet` is `None`.
    pub clear_subnet_href: Option<String>,
    pub filtered_devices: Vec<NetworkDeviceRow>,
    pub filtered_page: Option<NumberedPageInfo>,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

/// The device classification form -- see `routes/panopticon.rs::classify_*`.
#[derive(Template)]
#[template(path = "panopticon_classify.html")]
pub struct PanopticonClassifyTemplate {
    pub base: BaseCtx,
    pub device_id: String,
    pub ip_address: String,
    /// (`DeviceType::as_str()` key, label, is this the device's current type)
    pub device_types: Vec<(&'static str, &'static str, bool)>,
    /// (`TrustState::as_str()` key, label, is this the device's current state)
    pub trust_states: Vec<(&'static str, &'static str, bool)>,
    pub notes: String,
}

pub struct PanopticonSwitchRow {
    pub id: String,
    pub name: String,
    pub ip_address: String,
    pub snmp_port: u16,
    pub snmp_version_label: &'static str,
    pub enabled: bool,
    pub last_polled_at: Option<String>,
    pub last_poll_error: Option<String>,
}

/// Managed-switch list + add form -- see `routes/panopticon.rs::switches_*`.
#[derive(Template)]
#[template(path = "panopticon_switches.html")]
pub struct PanopticonSwitchesTemplate {
    pub base: BaseCtx,
    pub can_manage: bool,
    pub can_scan: bool,
    pub switches: Vec<PanopticonSwitchRow>,
    /// `false` when no `ENCRYPTION_KEY` is configured -- the add-switch
    /// form is hidden (with an explanatory note) rather than accepting a
    /// community string it can't actually store safely.
    pub encryption_configured: bool,
    /// (`SnmpVersion::as_str()` key, label, is this the form's default)
    pub snmp_versions: Vec<(&'static str, &'static str, bool)>,
    /// (key, label, is this the form's default) for each of the three v3
    /// dropdowns -- security level, auth protocol, privacy protocol.
    pub snmp_security_levels: Vec<(&'static str, &'static str, bool)>,
    pub snmp_auth_protocols: Vec<(&'static str, &'static str, bool)>,
    pub snmp_priv_protocols: Vec<(&'static str, &'static str, bool)>,
    /// SNMP community-string macros visible to this user -- their own
    /// personal ones plus their roles' -- see
    /// `routes/panopticon.rs::visible_community_macro_rows`.
    pub macros: Vec<CommunityMacroRow>,
    /// (role_id, role_name) for every role this user belongs to -- the
    /// "My role: X" options on the add-switch form's Save as Macro scope
    /// picker.
    pub macro_roles: Vec<(String, String)>,
    /// Prefills the add-switch form's community-string field -- blank
    /// unless a `?load_macro=` picked one.
    pub prefilled_community: String,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

/// Edit form for one switch -- see `routes/panopticon.rs::switch_edit_*`.
/// Every secret field (the v1/v2c community string, the v3 auth/privacy
/// passwords) is deliberately never prefilled -- there's no plaintext to
/// show, only ciphertext is on hand, and even if it weren't, echoing a
/// live credential back into a form is bad practice. Leaving a secret
/// field blank on submit means "keep the existing one", but only when
/// `snmp_version` isn't also changing -- switching version requires full
/// new credentials for it, since the old secrets don't apply to the new
/// version at all.
#[derive(Template)]
#[template(path = "panopticon_switch_edit.html")]
pub struct PanopticonSwitchEditTemplate {
    pub base: BaseCtx,
    pub switch_id: String,
    pub name: String,
    pub ip_address: String,
    pub snmp_port: u16,
    /// (key, label, is this switch's current version)
    pub snmp_versions: Vec<(&'static str, &'static str, bool)>,
    /// Not a secret -- prefilled from the switch's current v3 config (if
    /// any) so re-saving without changing it doesn't require retyping it.
    pub snmp_v3_username: String,
    pub snmp_security_levels: Vec<(&'static str, &'static str, bool)>,
    pub snmp_auth_protocols: Vec<(&'static str, &'static str, bool)>,
    pub snmp_priv_protocols: Vec<(&'static str, &'static str, bool)>,
    pub error: Option<String>,
}

pub struct PanopticonPortRow {
    pub if_index: u32,
    pub label: String,
    pub last_seen_at: String,
    pub current_in: String,
    pub current_out: String,
}

/// One switch's port list + (optionally) a rendered chart for one
/// selected port -- see `routes/panopticon.rs::switch_traffic`.
#[derive(Template)]
#[template(path = "panopticon_switch_traffic.html")]
pub struct PanopticonSwitchTrafficTemplate {
    pub base: BaseCtx,
    pub switch_id: String,
    pub switch_name: String,
    pub ports: Vec<PanopticonPortRow>,
    pub selected_port: Option<u32>,
    pub selected_range: String,
    /// (range key, label, is this the selected one) for the duration
    /// buttons -- only ranges the current retention settings can actually
    /// serve are included (see `panopticon_traffic::available_ranges`).
    pub ranges: Vec<(String, String, bool)>,
    pub chart_svg: Option<String>,
    pub chart_port_label: Option<String>,
    pub chart_current_in: Option<String>,
    pub chart_current_out: Option<String>,
}

// -----------------------------------------------------------------------
// "Quick Add Host From Network Scan" -- picker -> credentials -> host-key
// review -> deploy status. See `routes/panopticon_deploy.rs` and
// `crate::ssh_deploy` for the handlers/orchestration behind these.
// -----------------------------------------------------------------------

pub struct ScanPickerHostRow {
    pub ip: String,
    pub hostname: String,
    pub mac: String,
    pub checked: bool,
}

/// After a discovery scan, lets the admin pick which of the just-discovered
/// devices to deploy the agent to over SSH -- see
/// `routes/panopticon_deploy.rs::render_scan_picker`. "Select all"/"none"
/// (`scan_picker_refresh`) re-renders this same template rather than using
/// client-side JS, matching this app's server-rendered-only house style.
#[derive(Template)]
#[template(path = "panopticon_scan_picker.html")]
pub struct PanopticonScanPickerTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<ScanPickerHostRow>,
    /// Set when this picker follows a one-click rescan of an already-known
    /// target (see `routes/panopticon.rs::has_scan_history`) -- shown as a
    /// small banner so skipping the old confirm dialog doesn't leave the
    /// rescan looking like nothing happened.
    pub rescan_notice: Option<String>,
}

/// A running discovery scan's progress -- see
/// `routes/panopticon_scan.rs::scan_status`. `percent`/`hosts_scanned`/
/// `hosts_total` are this page's initial (server-rendered) values; the
/// page's own `<script>` immediately starts polling
/// `scan_status_json` for live updates and only falls back to this
/// template's `<meta http-equiv="refresh">` if JS never runs at all.
#[derive(Template)]
#[template(path = "panopticon_scan_progress.html")]
pub struct PanopticonScanProgressTemplate {
    pub base: BaseCtx,
    pub job_id: String,
    pub target: String,
    pub percent: u8,
    pub hosts_scanned: usize,
    pub hosts_total: usize,
}

pub struct DeployCredentialHostRow {
    pub ip: String,
    pub hostname: String,
}

/// SSH credentials for the selected hosts: one shared set, plus an
/// optional per-host override (see `routes/panopticon_deploy.rs`'s doc
/// comment on `resolve_credentials` for the override semantics). Nothing
/// here is ever written to a database -- these fields only ever exist in
/// this rendered HTML and the next request's body.
#[derive(Template)]
#[template(path = "panopticon_deploy_credentials.html")]
pub struct PanopticonDeployCredentialsTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<DeployCredentialHostRow>,
    pub error: Option<String>,
}

/// One host's host-key probe result, plus its credential fields carried
/// forward verbatim as hidden inputs (not re-derived -- see
/// `routes/panopticon_deploy.rs::deploy_hostkeys`) so the final confirm
/// step gets exactly what the admin typed without this page needing to
/// persist anything server-side.
pub struct DeployHostKeyRow {
    pub ip: String,
    pub hostname: String,
    pub fingerprint: String,
    pub status_label: String,
    pub status_class: String,
    /// A changed (not new) host key is a hard stop -- this host is shown
    /// with an explanation but its fields aren't emitted as hidden inputs,
    /// so it can't be included in the confirm step no matter what's
    /// clicked.
    pub blocked: bool,
    /// Already resolved from shared/override at probe time (the probe
    /// itself needed the real port) -- carried forward as one final value
    /// rather than shared/override fields again.
    pub ssh_port: u16,
    pub override_username: String,
    pub override_auth_method: String,
    pub override_password: String,
    pub override_pem: String,
    pub override_passphrase: String,
    pub override_sudo_password: String,
    pub override_sudo_same_as_password: bool,
}

#[derive(Template)]
#[template(path = "panopticon_deploy_hostkeys.html")]
pub struct PanopticonDeployHostKeysTemplate {
    pub base: BaseCtx,
    pub rows: Vec<DeployHostKeyRow>,
    pub any_deployable: bool,
    pub shared_username: String,
    pub shared_auth_method: String,
    pub shared_password: String,
    pub shared_pem: String,
    pub shared_passphrase: String,
    pub shared_sudo_password: String,
    pub shared_sudo_same_as_password: bool,
}

pub struct DeployStatusHostRow {
    pub ip_address: String,
    pub hostname: Option<String>,
    /// `true` when `hostname` above is really just the IP standing in for
    /// a name the deploy never managed to resolve -- see
    /// `ssh_deploy::deploy_one_host`'s hostname resolution. Shown as a
    /// badge so it reads as "go investigate," not "this is the real name."
    pub hostname_is_fallback: bool,
    pub state_label: String,
    pub state_class: String,
    pub is_terminal: bool,
    pub failure_detail: Option<String>,
    pub output: String,
}

/// Auto-refreshes (`<meta http-equiv="refresh">`) until every host reaches
/// a terminal state -- see `routes/panopticon_deploy.rs::deploy_status`.
#[derive(Template)]
#[template(path = "panopticon_deploy_status.html")]
pub struct PanopticonDeployStatusTemplate {
    pub base: BaseCtx,
    pub job_id: String,
    pub hosts: Vec<DeployStatusHostRow>,
    pub hosts_terminal: usize,
    pub percent: u8,
    pub complete: bool,
}

pub struct CryptkeeperHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "cryptkeeper.html")]
pub struct CryptkeeperTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<CryptkeeperHostRow>,
}

#[derive(Template)]
#[template(path = "cryptkeeper_host.html")]
pub struct CryptkeeperHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `security.manage` -- gates the Write/Destructive sections,
    /// distinct from the `security.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
}

/// One connected host's collapsible group on the Thanatos fleet dashboard
/// -- the same `<details>` + independently-paginated-rows pattern
/// Panopticon's Device Inventory uses for subnet groups (GitHub issue
/// #10), keyed by host instead of by subnet. A host's `<summary>` (name,
/// event count) always renders; its event rows only render when open
/// (render-budget-vs-`open=` mechanics identical to Panopticon's).
pub struct ThanatosHostGroup {
    pub host_id: String,
    pub host_name: String,
    /// "Linux"/"Windows"/"macOS"/"Unknown OS", from `Host.os` -- see
    /// `routes::thanatos::os_label`.
    pub os_label: &'static str,
    pub event_count: i64,
    pub is_open: bool,
    pub events: Vec<SecurityEventRow>,
    /// The "Load events" link shown in place of a body when `!is_open`.
    pub open_href: Option<String>,
    pub scroll_aria_label: String,
    pub page_info: Option<GroupPageInfo>,
}

pub struct SeverityCountRow {
    pub label: &'static str,
    pub badge_class: &'static str,
    pub count: i64,
}

pub struct SecurityEventRow {
    pub id: String,
    pub severity_label: &'static str,
    pub badge_class: &'static str,
    pub label: String,
    pub source: String,
    pub raw_line: String,
    pub occurred_at: String,
    pub status_label: &'static str,
    pub status_badge_class: &'static str,
    /// Whether to show the "Acknowledge" button -- only when this event
    /// is still `Open` (acknowledging an already-acknowledged event is a
    /// no-op with nothing to confirm, so the button just doesn't appear
    /// rather than being shown disabled).
    pub can_acknowledge: bool,
    /// Whether to show the "Resolve"/"Suppress" buttons -- both stay
    /// available while the event is `Open` or `Acknowledged`; once it's
    /// `Resolved`/`Suppressed` there's no further transition in this
    /// pass (no "reopen" -- see `docs` for why).
    pub can_resolve_or_suppress: bool,
    pub resolution_note: Option<String>,
}

pub struct AlertRow {
    pub host_name: String,
    pub label: String,
    pub raw_line: String,
    pub occurred_at: String,
}

#[derive(Template)]
#[template(path = "thanatos.html")]
pub struct ThanatosTemplate {
    pub base: BaseCtx,
    /// `security.manage` -- gates the acknowledge/resolve/suppress
    /// buttons on every event row, distinct from the `security.view`
    /// every read-facing Thanatos route already requires.
    pub can_manage: bool,
    pub severity_summary: Vec<SeverityCountRow>,
    pub recent_alerts: Vec<AlertRow>,
    pub total_event_count: i64,
    pub render_budget: u32,
    pub groups: Vec<ThanatosHostGroup>,
    pub group_list_page: Option<NumberedPageInfo>,
    /// Whether resolved/suppressed events are currently included -- drives
    /// the "Show resolved"/"Hide resolved" toggle link's label.
    pub show_resolved: bool,
    pub toggle_resolved_href: String,
}

#[derive(Template)]
#[template(path = "thanatos_host.html")]
pub struct ThanatosHostTemplate {
    pub base: BaseCtx,
    pub can_manage: bool,
    pub host_id: String,
    pub host_name: String,
    /// "Linux"/"Windows"/"macOS"/"Unknown OS", from `Host.os` -- see
    /// `routes::thanatos::os_label`.
    pub os_label: &'static str,
    /// What the scan button actually reads on this host -- see
    /// `routes::thanatos::detection_sources_note`.
    pub detection_sources_note: &'static str,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub events: Vec<SecurityEventRow>,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub context: Vec<WorkflowContextRow>,
    pub show_resolved: bool,
    pub toggle_resolved_href: String,
}

pub struct ApothecaryHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "apothecary.html")]
pub struct ApothecaryTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<ApothecaryHostRow>,
}

#[derive(Template)]
#[template(path = "apothecary_host.html")]
pub struct ApothecaryHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `systems.manage` -- gates the Write/Destructive section, distinct
    /// from the `systems.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

pub struct CatacombHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "catacomb.html")]
pub struct CatacombTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<CatacombHostRow>,
}

#[derive(Template)]
#[template(path = "catacomb_host.html")]
pub struct CatacombHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `storage.manage` -- gates the Write/Destructive section, distinct
    /// from the `storage.view` the read/inspection operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    /// Which workflow-registry context fields (if any) arrived in the
    /// query string, for an "arrived here because..." banner.
    pub context: Vec<WorkflowContextRow>,
    /// Pre-fills the Directory Usage Breakdown path field when a
    /// suggestion carried a `mount_point` -- the user still has to click
    /// "run."
    pub prefill_path: Option<String>,
}

pub struct ParishHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "parish.html")]
pub struct ParishTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<ParishHostRow>,
}

#[derive(Template)]
#[template(path = "parish_host.html")]
pub struct ParishHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `host_users.manage` -- gates the Write/Destructive section,
    /// distinct from the `host_users.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

pub struct VivisectionHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "vivisection.html")]
pub struct VivisectionTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<VivisectionHostRow>,
}

#[derive(Template)]
#[template(path = "vivisection_host.html")]
pub struct VivisectionHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `systems.manage` -- gates the Write tuning section, distinct from
    /// the `systems.view` the read/profiling operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub context: Vec<WorkflowContextRow>,
}

pub struct DefleshingHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "defleshing.html")]
pub struct DefleshingTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<DefleshingHostRow>,
}

#[derive(Template)]
#[template(path = "defleshing_host.html")]
pub struct DefleshingHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `systems.manage` -- gates the Write/Destructive cleanup section,
    /// distinct from the `systems.view` the read operation uses.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub context: Vec<WorkflowContextRow>,
}

pub struct ReanimationHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "reanimation.html")]
pub struct ReanimationTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<ReanimationHostRow>,
}

#[derive(Template)]
#[template(path = "reanimation_host.html")]
pub struct ReanimationHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `systems.manage` -- gates the Write/Destructive process-control
    /// section, distinct from the `systems.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub context: Vec<WorkflowContextRow>,
    /// Pre-fills Process Detail's PID field when a suggestion carried one.
    pub prefill_pid: Option<String>,
}

pub struct NecropolisHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "necropolis.html")]
pub struct NecropolisTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<NecropolisHostRow>,
}

#[derive(Template)]
#[template(path = "necropolis_host.html")]
pub struct NecropolisHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `containers.manage` -- gates the Write/Destructive lifecycle
    /// section, distinct from the `containers.view` the read operations
    /// use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

pub struct NecropsyHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "necropsy.html")]
pub struct NecropsyTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<NecropsyHostRow>,
}

/// No `can_manage` field -- every op in this arsenal is read-only hardware
/// inspection, so there's no write/destructive section to gate.
#[derive(Template)]
#[template(path = "necropsy_host.html")]
pub struct NecropsyHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub context: Vec<WorkflowContextRow>,
    /// Pre-fills Disk Health's device field when a suggestion carried one.
    pub prefill_device: Option<String>,
}

pub struct IncarnationHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "incarnation.html")]
pub struct IncarnationTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<IncarnationHostRow>,
}

#[derive(Template)]
#[template(path = "incarnation_host.html")]
pub struct IncarnationHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `systems.manage` -- gates the Write/Destructive service-lifecycle
    /// section, distinct from the `systems.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub context: Vec<WorkflowContextRow>,
}

pub struct ResurrectionHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "resurrection.html")]
pub struct ResurrectionTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<ResurrectionHostRow>,
}

#[derive(Template)]
#[template(path = "resurrection_host.html")]
pub struct ResurrectionHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `systems.manage` -- gates the Write/Destructive recovery section,
    /// distinct from the `systems.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub context: Vec<WorkflowContextRow>,
}

pub struct ReliquaryHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "reliquary.html")]
pub struct ReliquaryTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<ReliquaryHostRow>,
}

#[derive(Template)]
#[template(path = "reliquary_host.html")]
pub struct ReliquaryHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `backups.create` -- gates the Create Backup form.
    pub can_create: bool,
    /// `backups.restore` -- gates the Restore Backup form, distinct from
    /// `backups.create` since restoring is destructive and creating isn't.
    pub can_restore: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub context: Vec<WorkflowContextRow>,
    /// Pre-fills Create Backup's source path when a suggestion carried a
    /// `mount_point`.
    pub prefill_source_path: Option<String>,
}

pub struct NecrolinkHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "necrolink.html")]
pub struct NecrolinkTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<NecrolinkHostRow>,
}

#[derive(Template)]
#[template(path = "necrolink_host.html")]
pub struct NecrolinkHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub can_manage: bool,
    /// `network.scan` specifically -- distinct from `can_manage`
    /// (`network.manage`), Super Admin only by default.
    pub can_scan: bool,
    pub elevated: bool,
    /// True when connected but the agent's protocol version doesn't match.
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}

pub struct ObituaryHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "obituary.html")]
pub struct ObituaryTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<ObituaryHostRow>,
}

#[derive(Template)]
#[template(path = "obituary_host.html")]
pub struct ObituaryHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    /// `audit.manage` -- gates the two destructive vacuum operations,
    /// distinct from the `audit.view` the read operations use.
    pub can_manage: bool,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
}

// -----------------------------------------------------------------------
// Reliquary native (control-plane) backups -- GitHub issue #9. See
// `routes/reliquary_backup.rs` and `crate::reliquary_backup`. Kept apart
// from `reliquary_host.html`/`ReliquaryHostTemplate` above (the existing
// Remote/Agent-mode UI), which this doesn't touch.
// -----------------------------------------------------------------------

pub struct BackupJobRow {
    pub id: String,
    pub status_label: &'static str,
    pub status_key: &'static str,
    pub trigger_label: &'static str,
    pub components: String,
    pub encrypted: bool,
    pub size_display: String,
    pub created_at: String,
    pub verification_label: String,
    pub verification_passed: bool,
    /// Only populated when verification failed -- `quick_verify`'s reason,
    /// shown inline so an admin doesn't have to guess or query the
    /// database directly to find out why.
    pub verification_failure_detail: Option<String>,
    pub can_download: bool,
    pub error_message: Option<String>,
    /// "Local" or "Sepulchre: &lt;connection name&gt;" (or a note that the
    /// connection has since been deleted).
    pub destination_label: String,
}

#[derive(Template)]
#[template(path = "reliquary_backup.html")]
pub struct ReliquaryBackupTemplate {
    pub base: BaseCtx,
    /// `backups.create` -- gates Backup Now, settings, verify, delete.
    pub can_manage: bool,
    /// `backups.restore` -- gates the restore flow specifically.
    pub can_restore: bool,
    pub jobs: Vec<BackupJobRow>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub schedule_enabled: bool,
    pub schedule_interval_hours: u32,
    pub retention_keep_last: u32,
    pub retention_days: u32,
    pub destination_path: String,
    /// (connection id, connection name, is the scheduled-backup default)
    /// for every connection eligible as a backup destination -- enabled,
    /// holding the `backup_destination` role. Offered in both the manual
    /// "Backup now" form (which ignores the third element) and the
    /// scheduled-backup settings' own destination picker (which uses it
    /// to preselect the current default).
    pub destination_connections: Vec<(String, String, bool)>,
    /// The scheduled-backup loop's configured destination connection id,
    /// or empty for local -- preselects the settings form's picker.
    pub default_destination_connection_id: String,
    pub encrypt_by_default: bool,
    pub encryption_key_available: bool,
    pub include_audit_logs_by_default: bool,
}

#[derive(Template)]
#[template(path = "reliquary_restore_preview.html")]
pub struct ReliquaryRestorePreviewTemplate {
    pub base: BaseCtx,
    pub job_id: String,
    pub is_encrypted: bool,
    pub is_verified: bool,
    pub schema_version_matches: bool,
    pub current_schema_version: i64,
    pub backup_schema_version: i64,
    pub mariadb_major_version_differs: bool,
    pub current_mariadb_version: String,
    pub backup_mariadb_version: String,
    pub components: Vec<String>,
}

// -----------------------------------------------------------------------
// Sepulchre: storage & file-sharing connectivity. See
// `routes/sepulchre.rs` and `crate::sepulchre`.
// -----------------------------------------------------------------------

pub struct ConnectionRow {
    pub id: String,
    pub name: String,
    pub protocol_label: &'static str,
    pub origin_label: &'static str,
    pub enabled: bool,
    pub roles: String,
    pub validation_label: String,
    pub validation_passed: bool,
    pub host_name: Option<String>,
}

#[derive(Template)]
#[template(path = "sepulchre.html")]
pub struct SepulchreTemplate {
    pub base: BaseCtx,
    pub connections: Vec<ConnectionRow>,
    pub can_manage: bool,
    pub protocol_filter: String,
    pub role_filter: String,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "sepulchre_new_connection.html")]
pub struct SepulchreNewConnectionTemplate {
    pub base: BaseCtx,
    pub protocol: String,
    pub protocol_label: &'static str,
    pub error: Option<String>,
}

pub struct CapabilityRow {
    pub key: String,
    pub label: String,
    pub declared: bool,
    pub verified: bool,
}

pub struct AccessMethodRow {
    pub method_label: &'static str,
    pub context_label: &'static str,
    pub host_name: Option<String>,
}

pub struct ConsumerRow {
    pub arsenal: String,
    pub purpose: String,
    pub role_label: &'static str,
}

#[derive(Clone)]
pub struct ValidationCheckRow {
    pub check: String,
    pub status_label: &'static str,
    pub status_passed: bool,
    pub status_skipped: bool,
    pub error_kind: Option<String>,
    pub message: String,
    pub duration_ms: u64,
}

#[derive(Clone)]
pub struct ValidationRunRow {
    pub id: String,
    pub mode_label: &'static str,
    pub overall_label: &'static str,
    pub overall_passed: bool,
    pub started_at: String,
    pub checks: Vec<ValidationCheckRow>,
}

#[derive(Template)]
#[template(path = "sepulchre_connection_detail.html")]
pub struct SepulchreConnectionDetailTemplate {
    pub base: BaseCtx,
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub protocol_label: &'static str,
    pub origin_label: &'static str,
    pub enabled: bool,
    pub host_id: Option<String>,
    pub host_name: Option<String>,
    pub config_summary: Vec<(String, String)>,
    pub roles: Vec<(&'static str, &'static str, bool)>,
    pub capabilities: Vec<CapabilityRow>,
    pub access_methods: Vec<AccessMethodRow>,
    pub consumers: Vec<ConsumerRow>,
    pub latest_run: Option<ValidationRunRow>,
    pub run_history: Vec<ValidationRunRow>,
    pub needs_host_key_pin: bool,
    pub pinned_fingerprint: Option<String>,
    pub public_key: Option<String>,
    pub secret_updated_at: Option<String>,
    pub can_manage: bool,
    pub can_manage_secrets: bool,
    pub suggested_actions: Vec<SuggestedActionView>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "sepulchre_probe_host_key.html")]
pub struct SepulchreProbeHostKeyTemplate {
    pub base: BaseCtx,
    pub id: String,
    pub name: String,
    pub fingerprint: Option<String>,
    pub error: Option<String>,
}

pub struct ShareRow {
    pub id: String,
    pub protocol_label: &'static str,
    pub local_path: String,
    pub label: String,
    pub connection_name: Option<String>,
}

pub struct MountRow {
    pub id: String,
    pub mount_point: String,
    pub state_label: &'static str,
    pub connection_name: String,
}

#[derive(Template)]
#[template(path = "sepulchre_host.html")]
pub struct SepulchreHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub package_backend: Option<String>,
    pub shares: Vec<ShareRow>,
    pub mounts: Vec<MountRow>,
    pub can_manage: bool,
    pub can_manage_keys: bool,
    pub message: Option<String>,
    pub error: Option<String>,
    pub context: Vec<WorkflowContextRow>,
    pub suggested_actions: Vec<SuggestedActionView>,
}

#[derive(Template)]
#[template(path = "sepulchre_new_share.html")]
pub struct SepulchreNewShareTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub protocol: String,
    pub protocol_label: &'static str,
    pub reachable_host_default: String,
    pub error: Option<String>,
}

pub struct MountableConnectionOption {
    pub id: String,
    pub label: String,
}

#[derive(Template)]
#[template(path = "sepulchre_new_mount.html")]
pub struct SepulchreNewMountTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub connections: Vec<MountableConnectionOption>,
    pub error: Option<String>,
}
