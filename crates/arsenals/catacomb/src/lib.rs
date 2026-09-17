use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Filesystem inspection, maintenance, traversal, and repair utilities.
pub struct CatacombArsenal;

impl Arsenal for CatacombArsenal {
    fn key(&self) -> &'static str {
        "catacomb"
    }

    fn display_name(&self) -> &'static str {
        "Catacomb"
    }

    fn description(&self) -> &'static str {
        "Filesystem inspection, maintenance, traversal, and repair utilities."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::PreserveRecover
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::StorageView]
    }
}
