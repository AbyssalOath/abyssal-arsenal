use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Disaster recovery and restoration of failed systems.
pub struct ResurrectionArsenal;

impl Arsenal for ResurrectionArsenal {
    fn key(&self) -> &'static str {
        "resurrection"
    }

    fn display_name(&self) -> &'static str {
        "Resurrection"
    }

    fn description(&self) -> &'static str {
        "Disaster recovery and restoration of failed systems."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::PreserveRecover
    }

    // systems.view, matching its routes (systems.view / systems.manage):
    // it restores failed services and units, which is systems work. Gating
    // it on backups.view showed it to roles its every page then refused.
    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
