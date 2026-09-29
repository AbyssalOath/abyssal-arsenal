//! Process and service management ("Reanimation"): the process half of
//! that description -- listing, inspecting, renicing, and signaling
//! individual processes. The service half is already Incarnation's job
//! (systemd unit lifecycle), so nothing here duplicates that.

use std::collections::HashMap;

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::{command_exists, truncate_lines};

/// Header row + 40 processes. Sorted highest-CPU-first so the offenders an
/// operator most likely wants to act on are at the top of the (truncated) list.
const PROCESS_LIST_LINES: usize = 41;

pub async fn list_processes(elevation: &ElevationState) -> CommandOutcome {
    // A structured `-o` format (with the process STATE, so the control plane
    // can flag zombies and render a table with per-row actions) rather than the
    // old `-ef --forest` text dump. `ppid` is kept as a column so hierarchy is
    // still visible.
    match elevation
        .run(
            "ps",
            &["-eo", "pid,ppid,user,stat,pcpu,pmem,comm", "--sort=-pcpu"],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(truncate_lines(output, PROCESS_LIST_LINES)),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn validate_pid(pid: u32) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_pid(pid) {
        return Err(format!("refusing to operate on protected pid {pid}"));
    }
    if pid == std::process::id() {
        return Err("refusing to operate on the agent's own process".to_string());
    }
    Ok(())
}

pub async fn process_detail(pid: u32, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let pid_str = pid.to_string();
    match elevation
        .run(
            "ps",
            &[
                "-p",
                pid_str.as_str(),
                "-o",
                "pid,ppid,user,stat,%cpu,%mem,etime,lstart,cmd",
                "-ww",
            ],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

fn validate_priority(priority: i32) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_nice_priority(priority) {
        return Err(format!(
            "refusing invalid nice priority {priority} (must be -20 to 19)"
        ));
    }
    Ok(())
}

pub async fn renice_priority(
    pid: u32,
    priority: i32,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    if let Err(e) = validate_priority(priority) {
        return CommandOutcome::Err(e);
    }
    let pid_str = pid.to_string();
    let priority_str = priority.to_string();
    match elevation
        .run(
            "renice",
            &["-n", priority_str.as_str(), "-p", pid_str.as_str()],
        )
        .await
    {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(unix)]
pub async fn set_io_priority(
    pid: u32,
    class: u8,
    level: u8,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_ionice_class(class) {
        return CommandOutcome::Err(format!(
            "refusing invalid ionice class {class} (must be 1-3)"
        ));
    }
    if !abyssal_agent_protocol::is_valid_ionice_level(level) {
        return CommandOutcome::Err(format!(
            "refusing invalid ionice level {level} (must be 0-7)"
        ));
    }
    let pid_str = pid.to_string();
    let class_str = class.to_string();
    let level_str = level.to_string();
    // The idle class (3) has no priority levels, so `-n` is omitted there.
    let args: Vec<&str> = if class == 3 {
        vec!["-c", &class_str, "-p", &pid_str]
    } else {
        vec!["-c", &class_str, "-n", &level_str, "-p", &pid_str]
    };
    match elevation.run("ionice", &args).await {
        Ok(output) => CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
            stdout: format!(
                "Set I/O priority (class {class}, level {level}) for pid {pid}.\n{}",
                output.stdout.trim_end()
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(windows)]
pub async fn set_io_priority(
    _pid: u32,
    _class: u8,
    _level: u8,
    _elevation: &ElevationState,
) -> CommandOutcome {
    CommandOutcome::Err("I/O priority (ionice) isn't supported on Windows".to_string())
}

#[cfg(unix)]
pub async fn set_oom_score_adj(pid: u32, adj: i32, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_oom_score_adj(adj) {
        return CommandOutcome::Err(format!(
            "refusing invalid oom_score_adj {adj} (must be -1000 to 1000)"
        ));
    }
    // Write the value through `tee` (via elevation) rather than a shell
    // redirect, so no shell is involved and the elevation path is the usual one.
    let path = format!("/proc/{pid}/oom_score_adj");
    match elevation
        .run_with_stdin("tee", &[path.as_str()], &adj.to_string())
        .await
    {
        Ok(output) => CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
            stdout: format!(
                "Set oom_score_adj={adj} for pid {pid}.\n{}",
                output.stdout.trim_end()
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(windows)]
pub async fn set_oom_score_adj(
    _pid: u32,
    _adj: i32,
    _elevation: &ElevationState,
) -> CommandOutcome {
    CommandOutcome::Err("OOM score adjustment isn't supported on Windows".to_string())
}

pub async fn process_open_files(pid: u32, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let pid_str = pid.to_string();
    // Prefer lsof (types, socket peers, deleted-but-held files); fall back to
    // the fd symlinks in /proc when it isn't installed -- detect, don't assume.
    let result = if command_exists("lsof").await {
        elevation.run("lsof", &["-p", pid_str.as_str()]).await
    } else {
        elevation
            .run("ls", &["-l", &format!("/proc/{pid}/fd")])
            .await
    };
    match result {
        Ok(output) => CommandOutcome::Ok(truncate_lines(output, 100)),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn process_limits(pid: u32, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let mut out = String::new();

    let exe_path = format!("/proc/{pid}/exe");
    if let Ok(o) = elevation
        .run_allow_failure("readlink", &[exe_path.as_str()])
        .await
        && o.exit_code == Some(0)
    {
        out.push_str(&format!("exe: {}\n", o.stdout.trim()));
    }
    let cwd_path = format!("/proc/{pid}/cwd");
    if let Ok(o) = elevation
        .run_allow_failure("readlink", &[cwd_path.as_str()])
        .await
        && o.exit_code == Some(0)
    {
        out.push_str(&format!("cwd: {}\n", o.stdout.trim()));
    }
    let task_path = format!("/proc/{pid}/task");
    if let Ok(o) = elevation
        .run_allow_failure("ls", &[task_path.as_str()])
        .await
        && o.exit_code == Some(0)
    {
        out.push_str(&format!(
            "threads: {}\n",
            o.stdout.split_whitespace().count()
        ));
    }

    // The environment (/proc/<pid>/environ) is deliberately not read -- it
    // routinely holds credentials.
    let limits_path = format!("/proc/{pid}/limits");
    match elevation.run("cat", &[limits_path.as_str()]).await {
        Ok(o) => {
            out.push('\n');
            out.push_str(o.stdout.trim_end());
            CommandOutcome::Ok(OperationOutput {
                stdout: out,
                stderr: String::new(),
                exit_code: Some(0),
            })
        }
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Formats `ps -eo pid,ppid,stat,comm` output into a zombie report: every
/// `Z`-state process and the parent that hasn't reaped it. Pure, so it's
/// unit-tested without a live host.
fn build_zombie_report(ps_stdout: &str) -> String {
    struct Row {
        pid: String,
        ppid: String,
        stat: String,
        comm: String,
    }
    let rows: Vec<Row> = ps_stdout
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let pid = it.next()?.to_string();
            let ppid = it.next()?.to_string();
            let stat = it.next()?.to_string();
            let comm = it.collect::<Vec<_>>().join(" ");
            if comm.is_empty() {
                return None;
            }
            Some(Row {
                pid,
                ppid,
                stat,
                comm,
            })
        })
        .collect();

    let comm_by_pid: HashMap<&str, &str> = rows
        .iter()
        .map(|r| (r.pid.as_str(), r.comm.as_str()))
        .collect();
    let zombies: Vec<&Row> = rows.iter().filter(|r| r.stat.starts_with('Z')).collect();

    if zombies.is_empty() {
        return "No zombie/defunct processes found.".to_string();
    }

    let mut s = format!("{} zombie/defunct process(es):\n\n", zombies.len());
    for z in &zombies {
        let parent = comm_by_pid
            .get(z.ppid.as_str())
            .copied()
            .unwrap_or("(unknown)");
        s.push_str(&format!(
            "  pid {} ({})  <- parent pid {} ({})\n",
            z.pid, z.comm, z.ppid, parent
        ));
    }
    s.push_str(
        "\nA zombie is a finished child the parent hasn't reaped. Signaling the zombie won't \
         clear it -- investigate or restart the parent process.",
    );
    s
}

pub async fn zombie_report(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("ps", &["-eo", "pid,ppid,stat,comm"]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: build_zombie_report(&output.stdout),
            stderr: String::new(),
            exit_code: Some(0),
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Parses `pgrep -l` output ("pid name" per line) into eligible matches,
/// excluding pid<=1 and the agent's own process so a signal-by-name can never
/// take out the agent itself.
#[cfg(unix)]
fn eligible_matches(listing: &str) -> Vec<(u32, String)> {
    let self_pid = std::process::id();
    listing
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let pid: u32 = it.next()?.parse().ok()?;
            let name = it.collect::<Vec<_>>().join(" ");
            (pid > 1 && pid != self_pid).then_some((pid, name))
        })
        .collect()
}

#[cfg(unix)]
pub async fn signal_by_name(
    name: String,
    signal: String,
    dry_run: bool,
    elevation: &ElevationState,
) -> CommandOutcome {
    use abyssal_agent_protocol::OperationOutput;

    if !abyssal_agent_protocol::is_valid_process_name(&name) {
        return CommandOutcome::Err(format!("refusing invalid process name: {name}"));
    }
    let signal = match validate_signal(&signal) {
        Ok(s) => s,
        Err(e) => return CommandOutcome::Err(e),
    };

    let listing = match elevation
        .run_allow_failure("pgrep", &["-l", name.as_str()])
        .await
    {
        Ok(o) if o.exit_code == Some(0) => o.stdout,
        // pgrep exits 1 when nothing matched -- not an error.
        Ok(_) => {
            return CommandOutcome::Ok(OperationOutput {
                stdout: format!("No processes matched name '{name}'."),
                stderr: String::new(),
                exit_code: Some(0),
            });
        }
        Err(e) => return CommandOutcome::Err(e),
    };

    let matches = eligible_matches(&listing);
    if matches.is_empty() {
        return CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "No eligible processes matched '{name}' (after excluding the agent and pid<=1)."
            ),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    let list_str = matches
        .iter()
        .map(|(pid, comm)| format!("  {pid}  {comm}"))
        .collect::<Vec<_>>()
        .join("\n");

    if dry_run {
        return CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Would send SIG{signal} to {} process(es):\n{list_str}",
                matches.len()
            ),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    let mut results = Vec::new();
    for (pid, comm) in &matches {
        let pid_str = pid.to_string();
        match elevation
            .run_allow_failure("kill", &["-s", signal.as_str(), pid_str.as_str()])
            .await
        {
            Ok(o) if o.exit_code == Some(0) => results.push(format!("  {pid} {comm}: signaled")),
            Ok(o) => results.push(format!("  {pid} {comm}: failed ({})", o.stderr.trim())),
            Err(e) => results.push(format!("  {pid} {comm}: error ({e})")),
        }
    }
    CommandOutcome::Ok(OperationOutput {
        stdout: format!(
            "Sent SIG{signal} to matching processes:\n{}",
            results.join("\n")
        ),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

#[cfg(windows)]
pub async fn signal_by_name(
    _name: String,
    _signal: String,
    _dry_run: bool,
    _elevation: &ElevationState,
) -> CommandOutcome {
    CommandOutcome::Err(
        "signal-by-name isn't supported on Windows (no pgrep / POSIX signals)".to_string(),
    )
}

fn validate_signal(signal: &str) -> Result<String, String> {
    if !abyssal_agent_protocol::is_valid_signal_name(signal) {
        return Err(format!("refusing unrecognized signal: {signal}"));
    }
    let normalized = signal.to_ascii_uppercase();
    Ok(normalized
        .strip_prefix("SIG")
        .unwrap_or(&normalized)
        .to_string())
}

#[cfg(unix)]
pub async fn send_signal(pid: u32, signal: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let signal = match validate_signal(&signal) {
        Ok(s) => s,
        Err(e) => return CommandOutcome::Err(e),
    };
    let pid_str = pid.to_string();
    match elevation
        .run("kill", &["-s", signal.as_str(), pid_str.as_str()])
        .await
    {
        Ok(output) => CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
            stdout: format!("Sent SIG{signal} to pid {pid}.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Windows has no POSIX signal delivery at all -- `Stop-Process -Force`
/// is a forced termination, not a signal, so only the two signal names
/// that already mean "terminate this process" on Unix (`KILL`/`TERM`)
/// have any real Windows equivalent. Any other validated-but-not-
/// terminating signal (`HUP`/`USR1`/`STOP`/...) is refused with a clear
/// reason rather than silently terminating the process anyway, which
/// would be a surprising and platform-inconsistent side effect for a
/// caller that asked for something else entirely.
#[cfg(windows)]
pub async fn send_signal(pid: u32, signal: String, _elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_pid(pid) {
        return CommandOutcome::Err(e);
    }
    let signal = match validate_signal(&signal) {
        Ok(s) => s,
        Err(e) => return CommandOutcome::Err(e),
    };
    if !matches!(signal.as_str(), "KILL" | "TERM") {
        return CommandOutcome::Err(format!(
            "SIG{signal} has no Windows equivalent -- only KILL/TERM (both map to a forced \
             process termination via Stop-Process) are supported on this platform"
        ));
    }
    let script = crate::process::ps_checked(&format!("Stop-Process -Id {pid} -Force"));
    match crate::process::run_command(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    )
    .await
    {
        Ok(output) => CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
            stdout: format!("Terminated pid {pid} (SIG{signal}).\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn eligible_matches_excludes_pid_one_and_the_agent() {
        let self_pid = std::process::id();
        let listing = format!("1 systemd\n2 kthreadd\n4242 nginx\n{self_pid} abyssal-agent\n");
        let matches = eligible_matches(&listing);
        let pids: Vec<u32> = matches.iter().map(|(p, _)| *p).collect();
        assert!(pids.contains(&4242));
        assert!(!pids.contains(&1)); // pid<=1 excluded
        assert!(!pids.contains(&self_pid)); // the agent itself excluded
        // kthreadd (pid 2) is eligible by these rules (>1, not the agent).
        assert!(pids.contains(&2));
    }

    #[test]
    fn zombie_report_names_zombies_and_their_parents() {
        let ps = "  PID  PPID STAT COMMAND\n\
                    1     0 Ss   systemd\n\
                  100     1 Sl   supervisor\n\
                  200   100 Z    worker <defunct>\n";
        let report = build_zombie_report(ps);
        assert!(report.starts_with("1 zombie/defunct process(es):"));
        assert!(report.contains("pid 200"));
        assert!(report.contains("parent pid 100 (supervisor)"));
    }

    #[test]
    fn zombie_report_is_clean_when_none() {
        let ps = "  PID  PPID STAT COMMAND\n1 0 Ss systemd\n100 1 Sl nginx\n";
        assert_eq!(
            build_zombie_report(ps),
            "No zombie/defunct processes found."
        );
    }
}
