use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Application and service deployment and provisioning.
pub struct IncarnationArsenal;

impl Arsenal for IncarnationArsenal {
    fn key(&self) -> &'static str {
        "incarnation"
    }

    fn display_name(&self) -> &'static str {
        "Incarnation"
    }

    fn description(&self) -> &'static str {
        "Application and service deployment and provisioning."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
