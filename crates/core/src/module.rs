use std::fmt;

/// The four functional quadrants arsenals are grouped under in the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleCategory {
    Operate,
    Observe,
    Defend,
    PreserveRecover,
}

impl fmt::Display for ModuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ModuleCategory::Operate => "Operate",
            ModuleCategory::Observe => "Observe",
            ModuleCategory::Defend => "Defend",
            ModuleCategory::PreserveRecover => "Preserve / Recover",
        };
        f.write_str(s)
    }
}
