use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Forensic examination of systems after failures, incidents, or suspected compromise.
pub struct PostmortemArsenal;

impl Arsenal for PostmortemArsenal {
    fn key(&self) -> &'static str {
        "postmortem"
    }

    fn display_name(&self) -> &'static str {
        "Postmortem"
    }

    fn description(&self) -> &'static str {
        "Forensic examination of systems after failures, incidents, or suspected compromise."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Defend
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SecurityView]
    }
}
