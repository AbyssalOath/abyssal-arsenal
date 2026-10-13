//! Cadavault's posture checks (docs/roadmap/0.2.4.md, section 1): a
//! catalog of individual checks, each deciding passed, failed or not
//! applicable from the facts an agent reports (`PostureFacts`,
//! `abyssal_agent_protocol::PostureFactsReport`).
//!
//! The rules live here, on the control plane, so improving a check needs no
//! agent update. Every check has a stable ID (`AA-LNX-SSH-001`), a title, a
//! rationale, a remediation (text and a command to copy, never run), MITRE
//! ATT&CK references where one fits, and a rule.
//!
//! Remediation commands are shown for an administrator to review and run;
//! nothing here executes them. Where Cadavault already has a safe action for
//! the fix (SSH hardening, the sysctl baseline, enabling the firewall),
//! [`Fix`] names it so the page can link there.

use std::collections::BTreeMap;

use abyssal_agent_protocol::PostureFactsReport;

mod linux;
mod windows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
}

impl Platform {
    pub fn from_report(platform: &str) -> Option<Self> {
        match platform {
            "linux" => Some(Platform::Linux),
            "windows" => Some(Platform::Windows),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    Failed,
    Passed,
    NotApplicable,
}

impl Status {
    /// Stored and exported form.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Passed => "passed",
            Status::Failed => "failed",
            Status::NotApplicable => "na",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "passed" => Some(Status::Passed),
            "failed" => Some(Status::Failed),
            "na" => Some(Status::NotApplicable),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::Passed => "Passed",
            Status::Failed => "Failed",
            Status::NotApplicable => "Not applicable",
        }
    }
}

/// An existing Cadavault action that fixes a failed check through the
/// normal confirm, permission and audit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fix {
    /// `HardenSshd` with this setting (`SshHardeningSetting::as_str`).
    SshHardening(&'static str),
    /// The kernel parameter baseline, whose rows each have an Apply.
    SysctlBaseline,
    /// `FirewallEnable`.
    FirewallEnable,
}

/// What a rule decided, and what it saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: Status,
    /// What was found on the host, or why the check doesn't apply.
    pub evidence: String,
}

pub fn passed(evidence: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Passed,
        evidence: evidence.into(),
    }
}

pub fn failed(evidence: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Failed,
        evidence: evidence.into(),
    }
}

pub fn not_applicable(reason: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::NotApplicable,
        evidence: reason.into(),
    }
}

/// One check in the catalog.
pub struct Check {
    pub id: &'static str,
    pub platform: Platform,
    /// For grouping on the page: "SSH", "Kernel", "Accounts", ...
    pub category: &'static str,
    pub title: &'static str,
    pub rationale: &'static str,
    pub remediation: &'static str,
    /// A command or policy path to copy. Shown for review, never run.
    pub command: Option<&'static str>,
    pub fix: Option<Fix>,
    /// MITRE ATT&CK technique IDs.
    pub mitre: &'static [&'static str],
    pub rule: fn(&Facts) -> Outcome,
}

/// The facts a rule reads, with the agent's notes for why some are missing.
pub struct Facts<'a> {
    facts: &'a BTreeMap<String, String>,
    notes: &'a BTreeMap<String, String>,
}

impl<'a> Facts<'a> {
    pub fn new(facts: &'a BTreeMap<String, String>, notes: &'a BTreeMap<String, String>) -> Self {
        Facts { facts, notes }
    }

    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.facts.get(key).map(String::as_str)
    }

    /// Not applicable because `key` wasn't reported, with the agent's
    /// reason when it gave one for that fact or its group.
    pub fn missing(&self, key: &str) -> Outcome {
        let reason = self
            .notes
            .iter()
            .filter(|(group, _)| key == group.as_str() || key.starts_with(&format!("{group}.")))
            .max_by_key(|(group, _)| group.len())
            .map(|(_, note)| note.clone());
        not_applicable(match reason {
            Some(note) => format!("Couldn't be read on this host: {note}"),
            None => "Not reported by this host's agent.".to_string(),
        })
    }

    pub fn int(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.trim().parse().ok())
    }
}

// ---------------------------------------------------------------- helpers --
// Used by the catalogs to keep each rule one line where it can be.

/// Passes when `key`'s value is one of `ok` (case-insensitive).
pub(crate) fn one_of(f: &Facts, key: &str, label: &str, ok: &[&str]) -> Outcome {
    match f.get(key) {
        None => f.missing(key),
        Some(v) if ok.iter().any(|o| o.eq_ignore_ascii_case(v.trim())) => {
            passed(format!("{label} = {v}"))
        }
        Some(v) => failed(format!("{label} = {v}")),
    }
}

/// Passes when `key`'s integer value satisfies `ok`.
pub(crate) fn int_where(
    f: &Facts,
    key: &str,
    label: &str,
    ok: fn(i64) -> bool,
    want: &str,
) -> Outcome {
    match (f.get(key), f.int(key)) {
        (None, _) => f.missing(key),
        (Some(v), None) => failed(format!("{label} = {v} (not a number; want {want})")),
        (Some(_), Some(n)) if ok(n) => passed(format!("{label} = {n}")),
        (Some(_), Some(n)) => failed(format!("{label} = {n} (want {want})")),
    }
}

/// Passes when the comma-separated list at `key` is empty.
pub(crate) fn list_empty(f: &Facts, key: &str, what: &str) -> Outcome {
    match f.get(key) {
        None => f.missing(key),
        Some(v) if v.trim().is_empty() => passed(format!("No {what}.")),
        Some(v) => failed(format!("Found: {}", v.replace(',', ", "))),
    }
}

/// Passes when none of `banned` is in the comma-separated list at `key`.
pub(crate) fn list_excludes(f: &Facts, key: &str, label: &str, banned: &[&str]) -> Outcome {
    match f.get(key) {
        None => f.missing(key),
        Some(v) => {
            let found: Vec<&str> = v
                .split(',')
                .map(str::trim)
                .filter(|item| banned.iter().any(|b| b.eq_ignore_ascii_case(item)))
                .collect();
            if found.is_empty() {
                passed(format!("No weak {label} enabled."))
            } else {
                failed(format!("Weak {label} enabled: {}", found.join(", ")))
            }
        }
    }
}

// ------------------------------------------------------------- evaluation --

/// Every check for a platform, in catalog order.
pub fn catalog(platform: Platform) -> &'static [Check] {
    match platform {
        Platform::Linux => linux::CHECKS,
        Platform::Windows => windows::CHECKS,
    }
}

/// A check by ID, from either catalog.
pub fn find(id: &str) -> Option<&'static Check> {
    linux::CHECKS
        .iter()
        .chain(windows::CHECKS.iter())
        .find(|c| c.id == id)
}

pub struct CheckResult {
    pub check: &'static Check,
    pub outcome: Outcome,
}

/// Runs every check for the report's platform. `None` for a platform with
/// no catalog.
pub fn evaluate(report: &PostureFactsReport) -> Option<Vec<CheckResult>> {
    let platform = Platform::from_report(&report.platform)?;
    let facts = Facts::new(&report.facts, &report.notes);
    Some(
        catalog(platform)
            .iter()
            .map(|check| CheckResult {
                check,
                outcome: (check.rule)(&facts),
            })
            .collect(),
    )
}

/// Passed, failed and not-applicable counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
}

impl Tally {
    pub fn of<I: IntoIterator<Item = Status>>(statuses: I) -> Self {
        let mut t = Tally::default();
        for s in statuses {
            match s {
                Status::Passed => t.passed += 1,
                Status::Failed => t.failed += 1,
                Status::NotApplicable => t.not_applicable += 1,
            }
        }
        t
    }

    /// Passed as a percentage of the checks that applied; `None` when none
    /// did.
    pub fn score(&self) -> Option<u8> {
        let applied = self.passed + self.failed;
        (applied > 0).then(|| ((self.passed * 100 + applied / 2) / applied) as u8)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn ids_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for (platform, prefix) in [(Platform::Linux, "AA-LNX-"), (Platform::Windows, "AA-WIN-")] {
            for c in catalog(platform) {
                assert!(seen.insert(c.id), "duplicate {}", c.id);
                assert!(c.id.starts_with(prefix), "{}", c.id);
                assert_eq!(c.platform, platform, "{}", c.id);
                let n = c.id.rsplit('-').next().unwrap();
                assert!(
                    n.len() == 3 && n.chars().all(|ch| ch.is_ascii_digit()),
                    "{}",
                    c.id
                );
                assert!(
                    !c.title.is_empty() && !c.rationale.is_empty() && !c.remediation.is_empty()
                );
                for t in c.mitre {
                    assert!(t.starts_with('T') && t.len() >= 5, "{}: {t}", c.id);
                }
            }
        }
        assert!(catalog(Platform::Linux).len() >= 45);
        assert!(catalog(Platform::Windows).len() >= 35);
        assert!(find("AA-LNX-SSH-001").is_some());
    }

    #[test]
    fn every_rule_says_not_applicable_with_no_facts() {
        let empty = BTreeMap::new();
        let facts = Facts::new(&empty, &empty);
        for platform in [Platform::Linux, Platform::Windows] {
            for c in catalog(platform) {
                let out = (c.rule)(&facts);
                assert_eq!(out.status, Status::NotApplicable, "{}: {:?}", c.id, out);
                assert!(!out.evidence.is_empty(), "{}", c.id);
            }
        }
    }

    #[test]
    fn missing_facts_quote_the_agents_note() {
        let facts = BTreeMap::new();
        let notes = BTreeMap::from([("sshd".to_string(), "`sshd -T` needs root".to_string())]);
        let f = Facts::new(&facts, &notes);
        assert!(
            f.missing("sshd.permitrootlogin")
                .evidence
                .contains("needs root")
        );
        assert!(f.missing("sysctl.x").evidence.contains("Not reported"));
    }

    #[test]
    fn tally_and_score() {
        let t = Tally::of([
            Status::Passed,
            Status::Passed,
            Status::Failed,
            Status::NotApplicable,
        ]);
        assert_eq!((t.passed, t.failed, t.not_applicable), (2, 1, 1));
        assert_eq!(t.score(), Some(67));
        assert_eq!(Tally::of([Status::NotApplicable]).score(), None);
        assert_eq!(Status::parse(Status::Failed.as_str()), Some(Status::Failed));
    }

    #[test]
    fn unknown_platform_has_no_catalog() {
        let report = PostureFactsReport {
            platform: "plan9".into(),
            ..Default::default()
        };
        assert!(evaluate(&report).is_none());
    }
}
