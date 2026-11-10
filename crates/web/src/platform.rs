//! Which hosts an arsenal is for, by OS -- the UI side of
//! `AgentOperation::platforms` / `Arsenal::platforms`. Pages use this to hide
//! what a host's OS can't run; `HostConnectionRegistry::dispatch` refuses it
//! regardless, so hiding is a convenience, not the guarantee.

use abyssal_agent_protocol::{AgentOperation, HostOs, Platforms};
use abyssal_hosts::HostConnectionRegistry;
use uuid::Uuid;

use crate::state::AppState;

/// A host's OS: what its live connection reported, else what was last
/// recorded (`hosts.os`), for an offline host.
pub fn host_os(hosts: &HostConnectionRegistry, host_id: Uuid, recorded: Option<&str>) -> HostOs {
    if hosts.is_connected(host_id) {
        hosts.host_os(host_id)
    } else {
        HostOs::parse(recorded)
    }
}

/// The OSes the arsenal `key` is for; `Both` for a key the registry doesn't
/// know (nothing is hidden on a guess).
pub fn arsenal_platforms(state: &AppState, key: &str) -> Platforms {
    state
        .modules
        .find(key)
        .map(|a| a.platforms())
        .unwrap_or(Platforms::Both)
}

/// Whether the arsenal `key` is for `host_id`, by its live connection's OS --
/// for a landing page deciding whether to go straight to the selected host.
pub fn arsenal_runs_on(state: &AppState, key: &str, host_id: Uuid) -> bool {
    arsenal_platforms(state, key).allows(state.hosts.host_os(host_id))
}

/// What an individual page needs to hide actions by OS: whether this host
/// can run Linux-only and Windows-only operations. An unknown OS can run
/// both, which is how every host was treated before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPlatform {
    pub os: HostOs,
    pub linux: bool,
    pub windows: bool,
}

impl HostPlatform {
    pub fn new(os: HostOs) -> Self {
        Self {
            os,
            linux: Platforms::Linux.allows(os),
            windows: Platforms::Windows.allows(os),
        }
    }

    pub fn for_host(state: &AppState, host_id: Uuid, recorded: Option<&str>) -> Self {
        Self::new(host_os(&state.hosts, host_id, recorded))
    }

    pub fn runs(&self, operation: &AgentOperation) -> bool {
        operation.platforms().allows(self.os)
    }
}

/// "2 Windows hosts not shown: Catacomb is for Linux hosts only." for the
/// hosts a picker left out, so a short list doesn't look like a bug. `None`
/// when none were.
pub fn hidden_hosts_note(arsenal: &str, platforms: Platforms, hidden: &[HostOs]) -> Option<String> {
    if hidden.is_empty() {
        return None;
    }
    let windows = hidden.iter().filter(|os| **os == HostOs::Windows).count();
    let linux = hidden.len() - windows;
    let mut parts = Vec::new();
    for (n, label) in [(linux, "Linux"), (windows, "Windows")] {
        if n > 0 {
            parts.push(format!("{n} {label} host{}", if n == 1 { "" } else { "s" }));
        }
    }
    Some(format!(
        "{} not shown: {arsenal} is for {} hosts only.",
        parts.join(" and "),
        platforms.label()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_platform_flags() {
        let linux = HostPlatform::new(HostOs::Linux);
        assert!(linux.linux && !linux.windows);
        let windows = HostPlatform::new(HostOs::Windows);
        assert!(!windows.linux && windows.windows);
        let unknown = HostPlatform::new(HostOs::Unknown);
        assert!(unknown.linux && unknown.windows);
        assert!(!windows.runs(&AgentOperation::LoadAverage));
        assert!(windows.runs(&AgentOperation::MemoryDetail));
    }

    #[test]
    fn hidden_note_counts_by_os() {
        assert_eq!(hidden_hosts_note("Catacomb", Platforms::Linux, &[]), None);
        assert_eq!(
            hidden_hosts_note("Catacomb", Platforms::Linux, &[HostOs::Windows]).as_deref(),
            Some("1 Windows host not shown: Catacomb is for Linux hosts only.")
        );
        assert_eq!(
            hidden_hosts_note(
                "Haruspex",
                Platforms::Windows,
                &[HostOs::Linux, HostOs::Linux]
            )
            .as_deref(),
            Some("2 Linux hosts not shown: Haruspex is for Windows hosts only.")
        );
    }
}
