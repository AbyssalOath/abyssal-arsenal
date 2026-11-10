//! Test-only: checks a generated Windows script with PowerShell's own parser.
//!
//! Needs `pwsh` on PATH: skipped without it locally, required in CI
//! (ubuntu-latest and windows-latest both have it).
//!
//! `pwsh` occasionally crashes while starting up ("An error has occurred
//! that was not properly handled") when several start at once. Cargo runs
//! tests in parallel, so this runs one `pwsh` at a time, and retries any run
//! that didn't get as far as printing the parser's verdict (the
//! [`VERDICT`] line). A real parse error is never retried.

use std::sync::Mutex;

/// One `pwsh` at a time across the whole test binary.
static PWSH: Mutex<()> = Mutex::new(());

/// Printed by the check once the parser has run, followed by the error
/// count. Its absence means `pwsh` died before reaching a verdict.
const VERDICT: &str = "ABYSSAL-PARSE-ERRORS:";

const ATTEMPTS: usize = 3;

const CHECK: &str = "$t = $null; $e = $null; \
     [void][System.Management.Automation.Language.Parser]::ParseFile($env:SCRIPT, [ref]$t, [ref]$e); \
     foreach ($x in $e) { \"$($x.Extent.StartLineNumber): $($x.Message)\" }; \
     \"ABYSSAL-PARSE-ERRORS:$($e.Count)\"";

/// Panics with the parser's messages if `script` doesn't parse. `name`
/// labels the failure and the temp file.
pub(crate) fn assert_parses_as_powershell(name: &str, script: &str) {
    let _guard = PWSH.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if std::process::Command::new("pwsh")
        .arg("-Version")
        .output()
        .is_err()
    {
        assert!(
            std::env::var_os("CI").is_none(),
            "pwsh is required for this test in CI"
        );
        eprintln!("skipping {name}: pwsh not on PATH");
        return;
    }
    let path = std::env::temp_dir().join(format!("{name}-{}.ps1", std::process::id()));
    std::fs::write(&path, script).unwrap();
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        let out = std::process::Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command", CHECK])
            .env("SCRIPT", &path)
            .output()
            .unwrap();
        let report = format!(
            "{name} (attempt {attempt}, {}):\n{}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(count) = stdout.lines().find_map(|l| l.trim().strip_prefix(VERDICT)) {
            let _ = std::fs::remove_file(&path);
            assert_eq!(count.trim(), "0", "{report}");
            return;
        }
        eprintln!("pwsh did not finish the check, retrying: {report}");
        last = report;
    }
    let _ = std::fs::remove_file(&path);
    panic!("pwsh failed {ATTEMPTS} times without reporting a parse result: {last}");
}

/// A real parse error fails straight away instead of being retried as a
/// crash. Without `pwsh` (locally) the helper skips, so there is nothing to
/// panic about.
#[test]
fn a_broken_script_is_reported() {
    if std::process::Command::new("pwsh")
        .arg("-Version")
        .output()
        .is_err()
    {
        return;
    }
    let result = std::panic::catch_unwind(|| {
        assert_parses_as_powershell("pwsh-parse-broken", "function f { if ($x) { }");
    });
    let message = result.expect_err("a broken script must fail");
    let text = message
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(text.contains("attempt 1"), "{text}");
}
