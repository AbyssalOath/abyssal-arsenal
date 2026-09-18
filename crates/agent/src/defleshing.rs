//! System cleanup and routine maintenance ("Defleshing"): visibility into
//! and clearing of the standard cleanup-relevant locations -- `/tmp`,
//! `/var/tmp`, and accumulated core dumps -- plus forcing an immediate
//! log rotation. Deliberately narrow: package-cache cleanup belongs to
//! Apothecary (package management) and journal retention belongs to
//! Obituary (audit/log retention); this arsenal only owns the plain
//! filesystem cleanup that doesn't fit either of those.

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::{present, truncate_lines};

/// Fixed, hardcoded cleanup targets -- never an admin-supplied path. Accepting
/// an arbitrary directory here would turn `ClearTmpFiles` into a general
/// recursive-delete primitive instead of a narrowly scoped maintenance op.
const TMP_PATHS: &[&str] = &["/tmp", "/var/tmp"];
const COREDUMP_DIR: &str = "/var/lib/systemd/coredump";

/// Header line + 200 deleted paths -- a busy `/tmp` or a coredump
/// directory that's never been cleaned could otherwise produce an
/// enormous listing.
const DELETED_FILES_LINES: usize = 201;

/// Runs a `find ... -print -delete` and reports both what `-print` found
/// *and* what `-delete` actually failed to remove -- `-print` succeeding
/// is not proof `-delete` did too. Confirmed against a real host: the
/// agent had read+execute on `/var/lib/systemd/coredump` (so every file
/// was listed) but not write on the directory itself (so every `-delete`
/// silently failed), and `find`'s own non-zero exit plus its stderr
/// explaining why both would have been dropped by a naive
/// stdout-only/only-on-empty-stdout presentation -- exactly the
/// "succeeded" a real deletion of nothing would misleadingly look like.
/// Always surfaces stderr when present, never just as an empty-stdout
/// fallback.
async fn find_and_delete(
    elevation: &ElevationState,
    args: &[&str],
    empty_message: &str,
) -> CommandOutcome {
    match elevation.run_allow_failure("find", args).await {
        Ok(output) => {
            let output = truncate_lines(output, DELETED_FILES_LINES);
            let mut stdout = if output.stdout.trim().is_empty() {
                empty_message.to_string()
            } else {
                output.stdout
            };
            if !output.stderr.trim().is_empty() {
                stdout.push_str("\n\nSome deletions may have failed:\n");
                stdout.push_str(output.stderr.trim());
            }
            CommandOutcome::Ok(OperationOutput {
                stdout,
                stderr: String::new(),
                exit_code: output.exit_code,
            })
        }
        Err(e) => CommandOutcome::Err(e),
    }
}

/// `du` reports a non-zero exit when one of several paths it was given
/// doesn't exist (e.g. no systemd-coredump on this host), while still
/// printing useful sizes to stdout for the paths that do -- a normal,
/// partial result here, not a failure.
pub async fn cleanup_targets_summary(elevation: &ElevationState) -> CommandOutcome {
    let mut args = vec!["-sh"];
    args.extend_from_slice(TMP_PATHS);
    args.push(COREDUMP_DIR);
    match elevation.run_allow_failure("du", &args).await {
        Ok(output) => CommandOutcome::Ok(present(output, "(no output)")),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn force_log_rotation(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run("logrotate", &["-f", "/etc/logrotate.conf"])
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// `find` exits non-zero the moment it can't descend into *any*
/// subdirectory -- and `/tmp` on a systemd host always has root-owned
/// `systemd-private-*` service directories an unprivileged run can't
/// enter. That's normal, expected, and doesn't mean the sweep failed:
/// `find` still processes (and `-delete`s) everything it *can* reach.
pub async fn clear_tmp_files(older_than_days: u32, elevation: &ElevationState) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_cleanup_days(older_than_days) {
        return CommandOutcome::Err(format!(
            "refusing invalid cleanup age: {older_than_days} days"
        ));
    }
    let days_arg = format!("+{older_than_days}");
    let mut args = TMP_PATHS.to_vec();
    args.extend_from_slice(&[
        "-type",
        "f",
        "-mtime",
        days_arg.as_str(),
        "-print",
        "-delete",
    ]);
    match find_and_delete(elevation, &args, "(nothing matched)").await {
        CommandOutcome::Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Deleted files under {} older than {older_than_days} days.\n{}",
                TMP_PATHS.join(", "),
                output.stdout
            ),
            ..output
        }),
        other => other,
    }
}

/// `find` exits non-zero when `COREDUMP_DIR` doesn't exist at all (hosts
/// without systemd-coredump) -- a normal "nothing to clean" result here,
/// not a failure.
pub async fn clear_core_dumps(elevation: &ElevationState) -> CommandOutcome {
    find_and_delete(
        elevation,
        &[COREDUMP_DIR, "-type", "f", "-print", "-delete"],
        "No core dumps found (or no systemd-coredump directory on this host).",
    )
    .await
}
