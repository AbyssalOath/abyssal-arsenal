use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Performance analysis, profiling, and system tuning.
pub struct VivisectionArsenal;

impl Arsenal for VivisectionArsenal {
    fn key(&self) -> &'static str {
        "vivisection"
    }

    fn display_name(&self) -> &'static str {
        "Vivisection"
    }

    fn description(&self) -> &'static str {
        "Performance analysis, profiling, and system tuning."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Observe
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
