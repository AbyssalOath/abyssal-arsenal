use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Hardware inspection and diagnostics.
pub struct NecropsyArsenal;

impl Arsenal for NecropsyArsenal {
    fn key(&self) -> &'static str {
        "necropsy"
    }

    fn display_name(&self) -> &'static str {
        "Necropsy"
    }

    fn description(&self) -> &'static str {
        "Hardware inspection and diagnostics."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Observe
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
