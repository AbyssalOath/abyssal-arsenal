use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Process and service management.
pub struct ReanimationArsenal;

impl Arsenal for ReanimationArsenal {
    fn key(&self) -> &'static str {
        "reanimation"
    }

    fn display_name(&self) -> &'static str {
        "Reanimation"
    }

    fn description(&self) -> &'static str {
        "Process and service management."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
