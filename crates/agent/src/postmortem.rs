//! Forensic examination ops ("Postmortem"): reboot/crash history, kernel and
//! system log errors, failed-login search, OOM kills, core dumps, and a
//! recently-modified-files sweep of common system paths. Every op here is
//! read-only -- forensic examination means looking, not changing anything.
//!
//! Several of the underlying tools (`coredumpctl`, `find` against a
//! partially-unreadable tree) use a non-zero exit code to mean "ran fine,
//! found nothing" rather than "something went wrong." Using
//! `ElevationState::run` (which treats any non-zero exit as a hard error)
//! for those would misreport a clean negative result -- itself a real
//! forensic finding, e.g. "no failed logins" -- as a failure. Every op here
//! goes through `run_allow_failure` and decides for itself what an empty or
//! non-zero-but-harmless result means.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::process::command_exists;

/// Runs `program`/`args` (elevation-aware) and substitutes a friendly
/// message when there's genuinely nothing to show, rather than an empty
/// output box -- used by the ops that don't need their own custom framing.
async fn run_and_present(
    elevation: &ElevationState,
    program: &str,
    args: &[&str],
) -> CommandOutcome {
    match elevation.run_allow_failure(program, args).await {
        Ok(output) => CommandOutcome::Ok(present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn present(output: OperationOutput, empty_message: &str) -> OperationOutput {
    if output.stdout.trim().is_empty() {
        let stdout = if !output.stderr.trim().is_empty() {
            output.stderr.trim().to_string()
        } else {
            empty_message.to_string()
        };
        OperationOutput { stdout, ..output }
    } else {
        output
    }
}

/// Keeps only the lines matching any of `keywords` (case-sensitive
/// substring match -- these are all fixed log phrases, not user input) and
/// substitutes `empty_message` when nothing matched, rather than an empty
/// box that reads like the fetch itself silently failed.
///
/// Empty *input* stdout is handled separately from "no keyword matched":
/// a tool like `dmesg` that fails outright (e.g. `dmesg_restrict` blocking
/// an unprivileged read) also produces empty stdout, with the actual
/// problem on stderr. Applying the keyword filter to that would silently
/// present a real failure as a clean "nothing found" result -- exactly
/// backwards for a forensic tool, where a negative result needs to mean
/// the check actually ran.
fn filter_lines(
    output: OperationOutput,
    keywords: &[&str],
    empty_message: &str,
) -> OperationOutput {
    if output.stdout.trim().is_empty() {
        return present(output, empty_message);
    }
    let matched: Vec<&str> = output
        .stdout
        .lines()
        .filter(|line| keywords.iter().any(|k| line.contains(k)))
        .collect();
    let stdout = if matched.is_empty() {
        empty_message.to_string()
    } else {
        matched.join("\n")
    };
    OperationOutput { stdout, ..output }
}

async fn first_existing_path(candidates: &[&'static str]) -> Option<&'static str> {
    for path in candidates {
        if tokio::fs::metadata(path).await.is_ok() {
            return Some(path);
        }
    }
    None
}

pub async fn boot_history() -> CommandOutcome {
    match crate::process::run_command_allow_failure("last", &["-x", "-n", "25"]).await {
        Ok(output) => CommandOutcome::Ok(present(output, "No boot/shutdown history recorded.")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn kernel_ring_buffer(elevation: &ElevationState) -> CommandOutcome {
    run_and_present(elevation, "dmesg", &["-T", "--level=err,warn"]).await
}

pub async fn system_journal_errors(elevation: &ElevationState) -> CommandOutcome {
    match init_system::detect().await {
        InitSystem::Systemd => {
            run_and_present(
                elevation,
                "journalctl",
                &["-p", "warning", "-b", "--no-pager", "-n", "200"],
            )
            .await
        }
        InitSystem::Other => match first_existing_path(&["/var/log/syslog", "/var/log/messages"])
            .await
        {
            Some(path) => run_and_present(elevation, "tail", &["-n", "200", path]).await,
            None => CommandOutcome::Err(
                "No systemd journal and no /var/log/syslog or /var/log/messages found.".to_string(),
            ),
        },
    }
}

const FAILED_LOGIN_KEYWORDS: &[&str] = &[
    "Failed password",
    "authentication failure",
    "FAILED su",
    "Invalid user",
    "PAM: Authentication failure",
];

pub async fn failed_login_attempts(elevation: &ElevationState) -> CommandOutcome {
    let raw = match init_system::detect().await {
        InitSystem::Systemd => {
            elevation
                .run_allow_failure("journalctl", &["--no-pager", "-n", "2000"])
                .await
        }
        InitSystem::Other => match first_existing_path(&["/var/log/auth.log", "/var/log/secure"])
            .await
        {
            Some(path) => {
                elevation
                    .run_allow_failure("tail", &["-n", "2000", path])
                    .await
            }
            None => Err(
                "No systemd journal and no /var/log/auth.log or /var/log/secure found.".to_string(),
            ),
        },
    };
    match raw {
        Ok(output) => CommandOutcome::Ok(filter_lines(
            output,
            FAILED_LOGIN_KEYWORDS,
            "No failed login attempts found in the recent log window.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

const OOM_KEYWORDS: &[&str] = &["Out of memory", "oom-kill", "oom_kill", "Killed process"];

pub async fn oom_kill_events(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run_allow_failure("dmesg", &["-T"]).await {
        Ok(output) => CommandOutcome::Ok(filter_lines(
            output,
            OOM_KEYWORDS,
            "No OOM-kill events found in the kernel ring buffer.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn core_dumps(elevation: &ElevationState) -> CommandOutcome {
    if command_exists("coredumpctl").await {
        return run_and_present(elevation, "coredumpctl", &["list", "--no-pager"]).await;
    }
    match elevation
        .run_allow_failure(
            "find",
            &[
                "/var/crash",
                "/var/lib/systemd/coredump",
                "-maxdepth",
                "1",
                "-type",
                "f",
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(present(
            output,
            "No core dump artifacts found under /var/crash or /var/lib/systemd/coredump.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

const SCAN_PATHS: &[&str] = &[
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

pub async fn recently_modified_files(hours: u32, elevation: &ElevationState) -> CommandOutcome {
    // Defense in depth: the control plane already validates this before
    // dispatching, but this agent is the actual execution boundary and never
    // trusts a wire value on that basis alone.
    if !abyssal_agent_protocol::is_valid_lookback_hours(hours) {
        return CommandOutcome::Err(format!(
            "refusing invalid lookback window: {hours} hours (must be 1-720)"
        ));
    }

    let newer_than = format!("-{hours} hours");
    let mut args: Vec<&str> = SCAN_PATHS.to_vec();
    args.extend(["-newermt", newer_than.as_str(), "-type", "f"]);

    match elevation.run_allow_failure("find", &args).await {
        Ok(output) => {
            let no_matches = output.stdout.trim().is_empty();
            let unreadable_paths = !output.stderr.trim().is_empty();
            let stdout = match (no_matches, unreadable_paths) {
                (true, true) => format!(
                    "No files modified in the last {hours}h among the paths this agent could read. \
                     Some paths were not readable without elevation -- supply a sudo password and \
                     try again for a complete scan:\n\n{}",
                    output.stderr.trim()
                ),
                (true, false) => format!(
                    "No files modified in the last {hours}h under {}.",
                    SCAN_PATHS.join(", ")
                ),
                (false, _) => output.stdout,
            };
            CommandOutcome::Ok(OperationOutput { stdout, ..output })
        }
        Err(e) => CommandOutcome::Err(e),
    }
}
