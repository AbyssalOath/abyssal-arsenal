use abyssal_core::{ModuleCategory, Permission};
use abyssal_modules::Arsenal;

/// Security telemetry collection, threat detection, event correlation, endpoint monitoring, and security alerting.
pub struct ThanatosArsenal;

impl Arsenal for ThanatosArsenal {
    fn key(&self) -> &'static str {
        "thanatos"
    }

    fn display_name(&self) -> &'static str {
        "Thanatos"
    }

    fn description(&self) -> &'static str {
        "Security telemetry collection, threat detection, event correlation, endpoint monitoring, and security alerting."
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Defend
    }

    fn view_permissions(&self) -> &'static [Permission] {
        &[Permission::SecurityView]
    }
}
