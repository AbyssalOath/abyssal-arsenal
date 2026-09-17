use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// System cleanup and routine maintenance.
pub struct DefleshingArsenal;

impl Arsenal for DefleshingArsenal {
    fn key(&self) -> &'static str {
        "defleshing"
    }

    fn display_name(&self) -> &'static str {
        "Defleshing"
    }

    fn description(&self) -> &'static str {
        "System cleanup and routine maintenance."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SystemsView]
    }
}
