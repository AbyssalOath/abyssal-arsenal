use abyssal_core::Permission;
use abyssal_rbac::AuthContext;
use askama::Template;

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
}

impl BaseCtx {
    pub fn build(ctx: &AuthContext, theme: &str, csrf_token: &str) -> Self {
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
        }
    }
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
    pub message: Option<String>,
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

#[derive(Template)]
#[template(path = "confirm.html")]
pub struct ConfirmTemplate {
    pub base: BaseCtx,
    pub title: String,
    pub message: String,
    pub action_url: String,
    pub cancel_url: String,
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
    pub can_manage: bool,
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
    pub can_manage: bool,
    pub result_label: Option<String>,
    pub result_output: Option<String>,
    pub result_error: Option<String>,
}
