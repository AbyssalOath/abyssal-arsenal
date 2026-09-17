use std::fmt;

/// Every granular permission in the system. A role is just a named collection of
/// these — there is no hard-coded "admin boolean" anywhere in the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    UsersView,
    UsersCreate,
    UsersModify,
    UsersDelete,

    SystemsView,
    SystemsManage,

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
