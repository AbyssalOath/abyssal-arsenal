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

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::BackupsView]
    }
}
