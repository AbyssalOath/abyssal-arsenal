use abyssal_core::Permission;
use abyssal_hosts::ElevationTracker;
use abyssal_rbac::AuthContext;
use askama::Template;

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
}

impl BaseCtx {
    pub fn build(
        ctx: &AuthContext,
        theme: &str,
        csrf_token: &str,
        elevation: &ElevationTracker,
    ) -> Self {
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

        Self {
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
        }
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

pub struct ModuleTile {
    pub key: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub category: String,
}

pub struct ActivityRow {
    pub occurred_at: String,
    pub username: String,
    pub action: String,
    pub result: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub base: BaseCtx,
    pub modules: Vec<ModuleTile>,
    pub recent_activity: Vec<ActivityRow>,
}

pub struct UserRow {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_active: bool,
    pub roles: String,
}

pub struct RoleOption {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersTemplate {
    pub base: BaseCtx,
    pub users: Vec<UserRow>,
    pub roles: Vec<RoleOption>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub new_username: String,
    pub new_email: String,
    pub generated_password: Option<String>,
    pub password_prefill: String,
}

pub struct PermissionRow {
    pub key: String,
    pub granted: bool,
}

pub struct RoleDetail {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    pub permissions: Vec<PermissionRow>,
}

#[derive(Template)]
#[template(path = "roles.html")]
pub struct RolesTemplate {
    pub base: BaseCtx,
    pub roles: Vec<RoleDetail>,
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
    pub page: i64,
    pub total_pages: i64,
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

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub base: BaseCtx,
    pub public_registration_enabled: bool,
    pub apotheosis_elevation_window_minutes: u32,
    pub message: Option<String>,
}

#[derive(Template)]
#[template(path = "style_guide.html")]
pub struct StyleGuideTemplate {
    pub base: BaseCtx,
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

pub struct PostmortemHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "postmortem.html")]
pub struct PostmortemTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<PostmortemHostRow>,
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
}
