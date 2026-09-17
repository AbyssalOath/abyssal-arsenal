use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Container and container-runtime administration.
pub struct NecropolisArsenal;

impl Arsenal for NecropolisArsenal {
    fn key(&self) -> &'static str {
        "necropolis"
    }

    fn display_name(&self) -> &'static str {
        "Necropolis"
    }

    fn description(&self) -> &'static str {
        "Container and container-runtime administration."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Operate
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::ContainersView]
    }
}
