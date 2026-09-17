use std::collections::HashSet;

use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::{ModuleCategory, Permission};
use abyssal_database::{repo, DbPool};

use crate::Arsenal;

#[derive(Debug, Clone)]
pub struct ModuleView {
    pub key: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub category: ModuleCategory,
    pub view_permissions: &'static [Permission],
    pub enabled: bool,
}

/// Holds every statically-known arsenal and overlays the database's
/// enabled/disabled state on top. `app`/`web` only ever go through this —
/// they never know the concrete arsenal types, which is what lets a new
/// arsenal crate be added without touching either.
pub struct ModuleRegistry {
    arsenals: Vec<Box<dyn Arsenal>>,
}

impl ModuleRegistry {
    pub fn new(arsenals: Vec<Box<dyn Arsenal>>) -> Self {
        Self { arsenals }
    }

    pub fn keys(&self) -> Vec<&'static str> {
        self.arsenals.iter().map(|a| a.key()).collect()
    }

    pub fn find(&self, key: &str) -> Option<&dyn Arsenal> {
        self.arsenals
            .iter()
            .find(|a| a.key() == key)
            .map(|b| b.as_ref())
    }

    /// Inserts any arsenal keys the database doesn't know about yet
    /// (defaulting them to enabled). Safe to call on every startup.
    pub async fn ensure_seeded(&self, pool: &DbPool) -> anyhow::Result<()> {
        let keys = self.keys();
        repo::modules::ensure_seeded(pool, &keys).await
    }

    pub async fn list(&self, pool: &DbPool) -> anyhow::Result<Vec<ModuleView>> {
        let enabled: HashSet<String> = repo::modules::enabled_keys(pool)
            .await?
            .into_iter()
            .collect();
        Ok(self
            .arsenals
            .iter()
            .map(|a| ModuleView {
                key: a.key(),
                display_name: a.display_name(),
                description: a.description(),
                category: a.category(),
                view_permissions: a.view_permissions(),
                enabled: enabled.contains(a.key()),
            })
            .collect())
    }

    pub async fn is_enabled(&self, pool: &DbPool, key: &str) -> anyhow::Result<bool> {
        repo::modules::is_enabled(pool, key).await
    }

    pub async fn set_enabled(
        &self,
        pool: &DbPool,
        key: &str,
        enabled: bool,
        actor: Actor<'_>,
    ) -> anyhow::Result<()> {
        repo::modules::set_enabled(pool, key, enabled).await?;

        let action = if enabled {
            AuditAction::ModuleEnabled
        } else {
            AuditAction::ModuleDisabled
        };
        abyssal_audit::record(
            pool,
            AuditEvent::new(action, AuditOutcome::Success)
                .actor(actor)
                .resource(key),
        )
        .await?;
        Ok(())
    }
}
