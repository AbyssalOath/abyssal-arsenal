//! The top bar's **Arsenals** menu, and the one rule for which arsenals a
//! user can see -- shared with the dashboard's tile grid, so the two can
//! never disagree.
//!
//! The module registry is set once at startup (`set_registry`) because the
//! top bar is built by `BaseCtx::build`, which every page calls without the
//! application state. Without a registry (some tests) the menu is empty.

use std::sync::{Arc, OnceLock};

use abyssal_core::ModuleCategory;
use abyssal_database::{DbPool, repo};
use abyssal_modules::ModuleRegistry;
use abyssal_rbac::AuthContext;

static REGISTRY: OnceLock<Arc<ModuleRegistry>> = OnceLock::new();

/// Called once at startup with the application's registry.
pub fn set_registry(registry: Arc<ModuleRegistry>) {
    let _ = REGISTRY.set(registry);
}

/// The order categories appear in, on the dashboard and in the menu.
pub const CATEGORY_ORDER: [ModuleCategory; 4] = [
    ModuleCategory::Operate,
    ModuleCategory::Observe,
    ModuleCategory::Defend,
    ModuleCategory::PreserveRecover,
];

/// An arsenal this user may open.
#[derive(Debug, Clone)]
pub struct VisibleModule {
    pub key: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub category: ModuleCategory,
    pub pinned: bool,
}

/// Every arsenal the user may open: enabled, one of its view permissions
/// held (or none required), and not hidden from the user's roles.
pub async fn visible_modules(
    registry: &ModuleRegistry,
    pool: &DbPool,
    ctx: &AuthContext,
) -> anyhow::Result<Vec<VisibleModule>> {
    let pinned_keys = repo::pinned_modules::list_for_user(pool, ctx.user.id).await?;
    let role_restriction =
        repo::role_module_visibility::effective_restriction_for_user(pool, ctx.user.id).await?;
    Ok(registry
        .list(pool)
        .await?
        .into_iter()
        .filter(|m| m.enabled)
        .filter(|m| m.view_permissions.is_empty() || m.view_permissions.iter().any(|p| ctx.has(*p)))
        .filter(|m| match &role_restriction {
            Some(allowed) => allowed.contains(m.key),
            None => true,
        })
        .map(|m| VisibleModule {
            key: m.key,
            display_name: m.display_name,
            description: m.description,
            category: m.category,
            pinned: pinned_keys.iter().any(|k| k == m.key),
        })
        .collect())
}

/// One section of the Arsenals menu.
#[derive(Debug, Clone)]
pub struct ArsenalMenuGroup {
    pub label: String,
    /// The Pinned group, laid out as a row across the top of the menu.
    pub pinned: bool,
    pub items: Vec<ArsenalMenuItem>,
}

#[derive(Debug, Clone)]
pub struct ArsenalMenuItem {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
}

/// The menu as the dashboard groups it: "Pinned" first (if any), then each
/// category in order, a pinned arsenal shown only under Pinned.
pub fn group_menu(modules: &[VisibleModule]) -> Vec<ArsenalMenuGroup> {
    let item = |m: &VisibleModule| ArsenalMenuItem {
        key: m.key,
        name: m.display_name,
        description: m.description,
    };
    let mut groups = Vec::new();
    let pinned: Vec<ArsenalMenuItem> = modules.iter().filter(|m| m.pinned).map(item).collect();
    if !pinned.is_empty() {
        groups.push(ArsenalMenuGroup {
            label: "Pinned".to_string(),
            pinned: true,
            items: pinned,
        });
    }
    for category in CATEGORY_ORDER {
        let items: Vec<ArsenalMenuItem> = modules
            .iter()
            .filter(|m| !m.pinned && m.category == category)
            .map(item)
            .collect();
        if !items.is_empty() {
            groups.push(ArsenalMenuGroup {
                label: category.to_string(),
                pinned: false,
                items,
            });
        }
    }
    groups
}

/// The Arsenals menu for this user. Empty (rather than an error page) if
/// it can't be built: the menu is a convenience, the dashboard still works.
pub async fn arsenal_menu(pool: &DbPool, ctx: &AuthContext) -> Vec<ArsenalMenuGroup> {
    let Some(registry) = REGISTRY.get() else {
        return Vec::new();
    };
    match visible_modules(registry, pool, ctx).await {
        Ok(modules) => group_menu(&modules),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't build the Arsenals menu");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(key: &'static str, category: ModuleCategory, pinned: bool) -> VisibleModule {
        VisibleModule {
            key,
            display_name: key,
            description: "",
            category,
            pinned,
        }
    }

    #[test]
    fn groups_like_the_dashboard_with_pinned_first() {
        let menu = group_menu(&[
            m("thanatos", ModuleCategory::Defend, false),
            m("parish", ModuleCategory::Operate, false),
            m("reliquary", ModuleCategory::PreserveRecover, true),
            m("mortiscope", ModuleCategory::Observe, false),
        ]);
        let labels: Vec<&str> = menu.iter().map(|g| g.label.as_str()).collect();
        assert_eq!(labels[0], "Pinned");
        assert_eq!(menu[0].items[0].key, "reliquary");
        assert_eq!(
            labels.len(),
            4,
            "the now-empty Preserve / Recover group is left out"
        );
        assert!(
            menu.iter()
                .skip(1)
                .all(|g| g.items.iter().all(|i| i.key != "reliquary")),
            "a pinned arsenal is listed once"
        );
        assert_eq!(
            &labels[1..],
            &[
                ModuleCategory::Operate.to_string().as_str(),
                ModuleCategory::Observe.to_string().as_str(),
                ModuleCategory::Defend.to_string().as_str(),
            ]
        );
    }

    #[test]
    fn nothing_visible_means_no_menu() {
        assert!(group_menu(&[]).is_empty());
    }
}
