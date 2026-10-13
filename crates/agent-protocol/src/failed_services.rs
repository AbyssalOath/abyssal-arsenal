//! Failed services on Windows hosts (docs/roadmap/0.2.4.md, section 1): what
//! `FailedServices` and `ListFailedUnits` report there, shared by the agent
//! (which applies the built-in rules) and the control plane (which applies
//! the operator's ignore list and shows the built-in one in Settings).
//!
//! No new operation and no protocol bump: a Windows agent answers the same
//! two operations a Linux one does, in its own format.
//!
//! - `FailedServices`: a readable table, then `N failed services listed.`
//!   (the Linux answer ends in `N loaded units listed.`; the health check
//!   reads either).
//! - `ListFailedUnits`: one tab-separated line per service:
//!   `name \t state \t exit code \t display name \t why`, or `No failed
//!   services.` when there are none.

/// The trailing summary line's suffix in a Windows `FailedServices` answer.
pub const WINDOWS_SUMMARY_SUFFIX: &str = "failed services listed.";

/// Automatic-start services that are routinely stopped, so a stopped one
/// isn't a failure. A trailing `*` matches a prefix (versioned names).
/// Compared case-insensitively.
pub const BUILTIN_IGNORED_SERVICES: &[&str] = &[
    "sppsvc",
    "gupdate",
    "gupdatem",
    "GoogleUpdaterService*",
    "GoogleUpdaterInternalService*",
    "edgeupdate",
    "edgeupdatem",
    "MicrosoftEdgeElevationService",
    "MapsBroker",
    "RemoteRegistry",
    "TrustedInstaller",
    "clr_optimization_*",
    "WbioSrvc",
    "tiledatamodelsvc",
];

/// Whether `name` matches an ignore-list `pattern`: equal ignoring case, or
/// a prefix match for a pattern ending in `*`.
pub fn matches_ignore_pattern(name: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    match pattern.strip_suffix('*') {
        Some(prefix) => {
            name.len() >= prefix.len()
                && name.is_char_boundary(prefix.len())
                && name[..prefix.len()].eq_ignore_ascii_case(prefix)
        }
        None => !pattern.is_empty() && name.eq_ignore_ascii_case(pattern),
    }
}

/// Whether any pattern in `patterns` matches `name`.
pub fn is_ignored<S: AsRef<str>>(name: &str, patterns: &[S]) -> bool {
    patterns
        .iter()
        .any(|p| matches_ignore_pattern(name, p.as_ref()))
}

/// A Windows service *name* (not its display name) safe to hand to
/// `Start-Service` inside a single-quoted PowerShell literal: letters,
/// digits and `- _ . $ @ + { }` (`MSSQL$SQLEXPRESS`, `{GUID}` driver
/// services), no quotes, spaces or anything else.
pub fn is_valid_windows_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.starts_with('-')
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '$' | '@' | '+' | '{' | '}')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_patterns() {
        assert!(matches_ignore_pattern("SPPSVC", "sppsvc"));
        assert!(matches_ignore_pattern(
            "clr_optimization_v4.0.30319_64",
            "clr_optimization_*"
        ));
        assert!(!matches_ignore_pattern("sppsvc2", "sppsvc"));
        assert!(!matches_ignore_pattern("Spooler", ""));
        assert!(!matches_ignore_pattern("ab", "abc*"));
        assert!(is_ignored(
            "GoogleUpdaterService142.0",
            BUILTIN_IGNORED_SERVICES
        ));
        assert!(!is_ignored("Spooler", BUILTIN_IGNORED_SERVICES));
    }

    #[test]
    fn windows_service_names() {
        for ok in [
            "Spooler",
            "MSSQL$SQLEXPRESS",
            "{4D36E96A-E325}",
            "a.b_c-d@e+f",
        ] {
            assert!(is_valid_windows_service_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-x",
            "a b",
            "x'y",
            "x;y",
            "x`y",
            "x\"y",
            &"a".repeat(257),
        ] {
            assert!(!is_valid_windows_service_name(bad), "{bad}");
        }
    }
}
