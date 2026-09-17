use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Linux package management.
pub struct ApothecaryArsenal;

impl Arsenal for ApothecaryArsenal {
    fn key(&self) -> &'static str {
        "apothecary"
    }

    fn display_name(&self) -> &'static str {
        "Apothecary"
    }

    fn description(&self) -> &'static str {
        "Linux package management."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
