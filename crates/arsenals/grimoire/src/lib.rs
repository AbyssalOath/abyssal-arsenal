use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Configuration management and repeatable system configuration.
pub struct GrimoireArsenal;

impl Arsenal for GrimoireArsenal {
    fn key(&self) -> &'static str {
        "grimoire"
    }

    fn display_name(&self) -> &'static str {
        "Grimoire"
    }

    fn description(&self) -> &'static str {
        "Configuration management and repeatable system configuration."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
