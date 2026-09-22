use std::fmt;

/// Every granular permission in the system. A role is just a named collection of
/// these — there is no hard-coded "admin boolean" anywhere in the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// These four gate the control plane's *own* login accounts
    /// (`/admin/users`) -- who can sign in to this application. Deliberately
    /// separate from `HostUsersView`/`HostUsersManage` below, which gate
    /// Parish's Linux account/group administration *on managed hosts*.
    /// Granting one was never meant to imply the other: someone who
    /// manages who can log into this control plane shouldn't automatically
    /// be able to create real OS accounts on the servers it manages, or
    /// vice versa.
    UsersView,
    UsersCreate,
    UsersModify,
    UsersDelete,

    SystemsView,
    SystemsManage,

    /// User, group, and account administration *on a managed host*
    /// (Parish) -- distinct from `UsersView`/`UsersCreate`/`UsersModify`/
    /// `UsersDelete` above, which gate the control plane's own login
    /// accounts. A single View/Manage pair rather than the finer
    /// View/Create/Modify/Delete split those use: Parish's Manage-gated
    /// operations don't have meaningfully different risk tiers the way
    /// the control plane's own user lifecycle does (creating a login vs.
    /// deleting one), so the extra granularity wouldn't buy anything real.
    HostUsersView,
    HostUsersManage,

    NetworkView,
    NetworkManage,
    NetworkScan,

    SecurityView,
    SecurityManage,

    ContainersView,
    ContainersManage,

    StorageView,
    StorageManage,

    BackupsView,
    BackupsCreate,
    BackupsRestore,

    IncidentsView,
    IncidentsRespond,

    AuditView,
    AuditExport,
    /// Destructive log/journal retention operations on a managed host
    /// (Obituary's vacuum-by-size/vacuum-by-time) -- distinct from
    /// `AuditExport` (reads the control plane's own audit trail) and
    /// deliberately not granted to any seeded role except Super Admin:
    /// deleting a host's historical logs can destroy the exact evidence a
    /// later investigation would need.
    AuditManage,

    RolesManage,
    ModulesManage,
    SettingsManage,
    NotificationsManage,

    HostsView,
    HostsManage,
    HostsElevate,

    /// Edit or delete a macro owned by someone else, or a role-scoped macro
    /// for a role this user isn't a member of. Never granted by any seeded
    /// role except Super Admin -- the owner of a macro (or a role member,
    /// for using/viewing a role macro) never needs it for their own.
    MacrosManageAll,
}

impl Permission {
    /// The stable string key persisted in the `permissions` table, e.g. `"users.view"`.
    pub const fn as_key(self) -> &'static str {
        match self {
            Permission::UsersView => "users.view",
            Permission::UsersCreate => "users.create",
            Permission::UsersModify => "users.modify",
            Permission::UsersDelete => "users.delete",

            Permission::SystemsView => "systems.view",
            Permission::SystemsManage => "systems.manage",

            Permission::HostUsersView => "host_users.view",
            Permission::HostUsersManage => "host_users.manage",

            Permission::NetworkView => "network.view",
            Permission::NetworkManage => "network.manage",
            Permission::NetworkScan => "network.scan",

            Permission::SecurityView => "security.view",
            Permission::SecurityManage => "security.manage",

            Permission::ContainersView => "containers.view",
            Permission::ContainersManage => "containers.manage",

            Permission::StorageView => "storage.view",
            Permission::StorageManage => "storage.manage",

            Permission::BackupsView => "backups.view",
            Permission::BackupsCreate => "backups.create",
            Permission::BackupsRestore => "backups.restore",

            Permission::IncidentsView => "incidents.view",
            Permission::IncidentsRespond => "incidents.respond",

            Permission::AuditView => "audit.view",
            Permission::AuditExport => "audit.export",
            Permission::AuditManage => "audit.manage",

            Permission::RolesManage => "roles.manage",
            Permission::ModulesManage => "modules.manage",
            Permission::SettingsManage => "settings.manage",
            Permission::NotificationsManage => "notifications.manage",

            Permission::HostsView => "hosts.view",
            Permission::HostsManage => "hosts.manage",
            Permission::HostsElevate => "hosts.elevate",

            Permission::MacrosManageAll => "macros.manage_all",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.as_key() == key)
    }

    /// Every permission the platform knows about, in a stable order used for seeding.
    pub const ALL: &'static [Permission] = &[
        Permission::UsersView,
        Permission::UsersCreate,
        Permission::UsersModify,
        Permission::UsersDelete,
        Permission::SystemsView,
        Permission::SystemsManage,
        Permission::HostUsersView,
        Permission::HostUsersManage,
        Permission::NetworkView,
        Permission::NetworkManage,
        Permission::NetworkScan,
        Permission::SecurityView,
        Permission::SecurityManage,
        Permission::ContainersView,
        Permission::ContainersManage,
        Permission::StorageView,
        Permission::StorageManage,
        Permission::BackupsView,
        Permission::BackupsCreate,
        Permission::BackupsRestore,
        Permission::IncidentsView,
        Permission::IncidentsRespond,
        Permission::AuditView,
        Permission::AuditExport,
        Permission::AuditManage,
        Permission::RolesManage,
        Permission::ModulesManage,
        Permission::SettingsManage,
        Permission::NotificationsManage,
        Permission::HostsView,
        Permission::HostsManage,
        Permission::HostsElevate,
        Permission::MacrosManageAll,
    ];
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_permission_key() {
        for perm in Permission::ALL {
            let key = perm.as_key();
            assert_eq!(Permission::from_key(key), Some(*perm));
        }
    }

    #[test]
    fn unknown_key_resolves_to_none() {
        assert_eq!(Permission::from_key("not.a.permission"), None);
    }
}
