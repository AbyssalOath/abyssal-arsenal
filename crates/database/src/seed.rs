use abyssal_core::{role, Permission};

use crate::{repo, DbPool};

/// Idempotently seeds the fixed permission catalogue and the built-in roles with
/// their default permission sets. Safe to call on every startup — existing rows
/// are left as-is aside from the permission catalogue itself, which always
/// reflects `Permission::ALL` (the Rust enum is the single source of truth).
pub async fn seed_core_defaults(pool: &DbPool) -> anyhow::Result<()> {
    for perm in Permission::ALL {
        sqlx::query("INSERT IGNORE INTO permissions (`key`, description) VALUES (?, ?)")
            .bind(perm.as_key())
            .bind(perm.as_key())
            .execute(pool)
            .await?;
    }

    seed_role(
        pool,
        role::SUPER_ADMIN,
        "Full administrative control.",
        Permission::ALL.to_vec(),
    )
    .await?;

    seed_role(
        pool,
        role::SYSTEM_ADMIN,
        "General system administration: systems, storage, containers, backups.",
        vec![
            Permission::UsersView,
            Permission::SystemsView,
            Permission::SystemsManage,
            Permission::StorageView,
            Permission::StorageManage,
            Permission::ContainersView,
            Permission::ContainersManage,
            Permission::BackupsView,
            Permission::BackupsCreate,
            Permission::BackupsRestore,
            Permission::AuditView,
            Permission::HostsView,
            Permission::HostsManage,
        ],
    )
    .await?;

    seed_role(
        pool,
        role::NETWORK_ADMIN,
        "Network configuration and connectivity.",
        vec![
            Permission::SystemsView,
            Permission::NetworkView,
            Permission::NetworkManage,
            Permission::AuditView,
        ],
    )
    .await?;

    seed_role(
        pool,
        role::SECURITY_ADMIN,
        "Security hardening, incident response, and audit oversight.",
        vec![
            Permission::UsersView,
            Permission::SecurityView,
            Permission::SecurityManage,
            Permission::IncidentsView,
            Permission::IncidentsRespond,
            Permission::AuditView,
            Permission::AuditExport,
        ],
    )
    .await?;

    seed_role(
        pool,
        role::REGULAR_USER,
        "Read-only visibility across operational domains.",
        vec![
            Permission::SystemsView,
            Permission::NetworkView,
            Permission::SecurityView,
            Permission::ContainersView,
            Permission::StorageView,
            Permission::BackupsView,
            Permission::IncidentsView,
        ],
    )
    .await?;

    Ok(())
}

async fn seed_role(
    pool: &DbPool,
    name: &str,
    description: &str,
    permissions: Vec<Permission>,
) -> anyhow::Result<()> {
    let role = match repo::roles::find_by_name(pool, name).await? {
        Some(existing) => existing,
        None => repo::roles::create(pool, name, description, true).await?,
    };

    // Only set the permission set the first time it's created; an admin may have
    // since customized it and startup shouldn't clobber that.
    let current = repo::roles::permissions_for_role(pool, role.id).await?;
    if current.is_empty() {
        repo::roles::set_permissions(pool, role.id, &permissions).await?;
    }

    Ok(())
}
