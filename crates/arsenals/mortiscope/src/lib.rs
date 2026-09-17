use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// System health and resource monitoring.
pub struct MortiscopeArsenal;

impl Arsenal for MortiscopeArsenal {
    fn key(&self) -> &'static str {
        "mortiscope"
    }

    fn display_name(&self) -> &'static str {
        "Mortiscope"
    }

    fn description(&self) -> &'static str {
        "System health and resource monitoring."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Observe
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
