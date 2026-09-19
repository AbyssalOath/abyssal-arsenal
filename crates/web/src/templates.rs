use abyssal_core::Permission;
use abyssal_database::{repo, DbPool};
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

/// One arsenal's dashboard-visibility checkbox state for a role, editable
/// on `/admin/roles` independently of (and always still bounded by) its
/// permission-based access.
pub struct ModuleVisibilityRow {
    pub key: &'static str,
    pub display_name: &'static str,
    pub visible: bool,
}

pub struct RoleDetail {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    pub permissions: Vec<PermissionRow>,
    pub module_visibility: Vec<ModuleVisibilityRow>,
    /// Whether this role has an explicit dashboard-visibility override.
    /// When false, `module_visibility` reflects today's plain
    /// permission-based visibility as a starting point for editing, not a
    /// saved customization yet.
    pub visibility_customized: bool,
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
    pub message: Option<String>,
}

#[derive(Template)]
#[template(path = "style_guide.html")]
pub struct StyleGuideTemplate {
    pub base: BaseCtx,
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
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
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

pub struct InquestHostRow {
    pub id: String,
    pub name: String,
}

#[derive(Template)]
#[template(path = "inquest.html")]
pub struct InquestTemplate {
    pub base: BaseCtx,
    pub hosts: Vec<InquestHostRow>,
}

#[derive(Template)]
#[template(path = "inquest_host.html")]
pub struct InquestHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
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
    pub context: Vec<WorkflowContextRow>,
}

pub struct NetworkDeviceRow {
    pub id: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub open_ports: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    /// `Some(host.name)` when this device's IP matches a currently
    /// enrolled host's last-known connecting address (`Host::last_seen_ip`)
    /// -- a best-effort correlation, not a guarantee (a host's LAN address
    /// can change, and this is only ever as fresh as that host's last
    /// WebSocket reconnect).
    pub managed_host_name: Option<String>,
}

/// One row of Panopticon's topology view -- devices grouped by inferred
/// IPv4 /24 (the common case for a LAN) or bucketed together under
/// `"other"` for anything else (IPv6, or an address this simple grouping
/// can't parse). Deliberately not real L2/switch topology -- see the
/// `arsenal-panopticon` crate's doc comment for why that's out of scope
/// without SNMP/LLDP access this platform doesn't have.
pub struct SubnetGroup {
    pub subnet: String,
    pub device_count: usize,
    pub managed_count: usize,
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
    pub devices: Vec<NetworkDeviceRow>,
    pub subnets: Vec<SubnetGroup>,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
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

pub struct ThanatosHostRow {
    pub id: String,
    pub name: String,
}

pub struct SeverityCountRow {
    pub label: &'static str,
    pub badge_class: &'static str,
    pub count: i64,
}

pub struct SecurityEventRow {
    pub severity_label: &'static str,
    pub badge_class: &'static str,
    pub label: String,
    pub source: String,
    pub raw_line: String,
    pub occurred_at: String,
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
    pub hosts: Vec<ThanatosHostRow>,
    pub severity_summary: Vec<SeverityCountRow>,
    pub recent_alerts: Vec<AlertRow>,
}

#[derive(Template)]
#[template(path = "thanatos_host.html")]
pub struct ThanatosHostTemplate {
    pub base: BaseCtx,
    pub host_id: String,
    pub host_name: String,
    pub elevated: bool,
    pub protocol_mismatch: bool,
    pub events: Vec<SecurityEventRow>,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
    pub suggested_actions: Vec<SuggestedActionView>,
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
