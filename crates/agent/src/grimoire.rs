//! Configuration management and repeatable system configuration
//! ("Grimoire"), deliberately narrow: every operation here reads or
//! writes exactly one of two files this tool exclusively owns --
//! `SYSCTL_FILE` (persistent sysctl overrides) and `CRON_FILE`
//! (scheduled tasks) -- never an arbitrary or pre-existing system file.
//! Editing a shared file like `/etc/hosts` in place risks corrupting it
//! through a string-manipulation bug; a dedicated drop-in file this tool
//! always fully controls and always renders from scratch can't have that
//! failure mode. Complements Vivisection's `SetSwappiness` (runtime-only)
//! with the persistent counterpart.

use abyssal_agent_protocol::{is_valid_account_name, CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::present;

const SYSCTL_FILE: &str = "/etc/sysctl.d/99-abyssal-arsenal.conf";
const CRON_FILE: &str = "/etc/cron.d/abyssal-arsenal";
const SYSCTL_HEADER: &str = "# Managed by Abyssal Arsenal (Grimoire) -- do not edit manually\n";
const CRON_HEADER: &str =
    "# Managed by Abyssal Arsenal (Grimoire) -- do not edit manually\nSHELL=/bin/sh\n\n";
const CRON_JOB_MARKER: &str = "# abyssal-arsenal-job: ";

/// Reads a managed file's current content. A missing file is a normal,
/// empty starting state here (the file is created on first write), not
/// an error -- so this goes through `run_allow_failure`.
async fn read_managed_file(path: &str, elevation: &ElevationState) -> Result<String, String> {
    match elevation.run_allow_failure("cat", &[path]).await {
        Ok(output) if output.exit_code == Some(0) => Ok(output.stdout),
        Ok(_) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

async fn write_managed_file(
    path: &str,
    content: &str,
    elevation: &ElevationState,
) -> Result<OperationOutput, String> {
    elevation.run_with_stdin("tee", &[path], content).await
}

// ---------------------------------------------------------------------
// Sysctl
// ---------------------------------------------------------------------

fn parse_sysctl(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

fn render_sysctl(entries: &[(String, String)]) -> String {
    let mut out = String::from(SYSCTL_HEADER);
    for (k, v) in entries {
        out.push_str(&format!("{k} = {v}\n"));
    }
    out
}

fn validate_sysctl_key(key: &str) -> Result<(), String> {
    if !abyssal_agent_protocol::is_valid_sysctl_key(key) {
        return Err(format!("refusing invalid sysctl key: {key}"));
    }
    Ok(())
}

pub async fn view_managed_sysctl(elevation: &ElevationState) -> CommandOutcome {
    match read_managed_file(SYSCTL_FILE, elevation).await {
        Ok(content) => CommandOutcome::Ok(present(
            OperationOutput {
                stdout: content,
                stderr: String::new(),
                exit_code: Some(0),
            },
            "No managed sysctl overrides set yet.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn set_persistent_sysctl(
    key: String,
    value: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_sysctl_key(&key) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_sysctl_value(&value) {
        return CommandOutcome::Err(format!("refusing invalid sysctl value: {value}"));
    }

    let current = match read_managed_file(SYSCTL_FILE, elevation).await {
        Ok(c) => c,
        Err(e) => return CommandOutcome::Err(e),
    };
    let mut entries = parse_sysctl(&current);
    if let Some(existing) = entries.iter_mut().find(|(k, _)| *k == key) {
        existing.1 = value.clone();
    } else {
        entries.push((key.clone(), value.clone()));
    }
    let rendered = render_sysctl(&entries);

    if let Err(e) = write_managed_file(SYSCTL_FILE, &rendered, elevation).await {
        return CommandOutcome::Err(e);
    }

    match elevation.run("sysctl", &["-p", SYSCTL_FILE]).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Set {key} = {value} and applied it.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_persistent_sysctl_key(
    key: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_sysctl_key(&key) {
        return CommandOutcome::Err(e);
    }
    let current = match read_managed_file(SYSCTL_FILE, elevation).await {
        Ok(c) => c,
        Err(e) => return CommandOutcome::Err(e),
    };
    let entries: Vec<(String, String)> = parse_sysctl(&current)
        .into_iter()
        .filter(|(k, _)| *k != key)
        .collect();
    let rendered = render_sysctl(&entries);
    match write_managed_file(SYSCTL_FILE, &rendered, elevation).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Removed {key} from the managed sysctl file.\n{}",
                output.stdout
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn clear_managed_sysctl(elevation: &ElevationState) -> CommandOutcome {
    match write_managed_file(SYSCTL_FILE, SYSCTL_HEADER, elevation).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Cleared the managed sysctl file.\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

// ---------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------

struct CronJob {
    name: String,
    schedule: String,
    user: String,
    command: String,
}

fn parse_cron(content: &str) -> Vec<CronJob> {
    let mut jobs = Vec::new();
    let mut pending_name: Option<String> = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix(CRON_JOB_MARKER) {
            pending_name = Some(name.trim().to_string());
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(name) = pending_name.take() else {
            continue;
        };
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let field_count = if tokens[0].starts_with('@') { 1 } else { 5 };
        if tokens.len() < field_count + 2 {
            continue;
        }
        jobs.push(CronJob {
            name,
            schedule: tokens[..field_count].join(" "),
            user: tokens[field_count].to_string(),
            command: tokens[field_count + 1..].join(" "),
        });
    }
    jobs
}

fn render_cron(jobs: &[CronJob]) -> String {
    let mut out = String::from(CRON_HEADER);
    for job in jobs {
        out.push_str(&format!(
            "{CRON_JOB_MARKER}{}\n{} {} {}\n\n",
            job.name, job.schedule, job.user, job.command
        ));
    }
    out
}

fn validate_job_name(name: &str) -> Result<(), String> {
    if !is_valid_account_name(name) {
        return Err(format!("refusing invalid job name: {name}"));
    }
    Ok(())
}

pub async fn view_managed_cron_jobs(elevation: &ElevationState) -> CommandOutcome {
    match read_managed_file(CRON_FILE, elevation).await {
        Ok(content) => CommandOutcome::Ok(present(
            OperationOutput {
                stdout: content,
                stderr: String::new(),
                exit_code: Some(0),
            },
            "No managed scheduled tasks set yet.",
        )),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn set_cron_job(
    job_name: String,
    schedule: String,
    run_as_user: String,
    command: String,
    elevation: &ElevationState,
) -> CommandOutcome {
    if let Err(e) = validate_job_name(&job_name) {
        return CommandOutcome::Err(e);
    }
    if !abyssal_agent_protocol::is_valid_cron_schedule(&schedule) {
        return CommandOutcome::Err(format!("refusing invalid cron schedule: {schedule}"));
    }
    if !is_valid_account_name(&run_as_user) {
        return CommandOutcome::Err(format!("refusing invalid user: {run_as_user}"));
    }
    if !abyssal_agent_protocol::is_valid_cron_command(&command) {
        return CommandOutcome::Err("refusing invalid cron command".to_string());
    }

    let current = match read_managed_file(CRON_FILE, elevation).await {
        Ok(c) => c,
        Err(e) => return CommandOutcome::Err(e),
    };
    let mut jobs = parse_cron(&current);
    let new_job = CronJob {
        name: job_name.clone(),
        schedule,
        user: run_as_user,
        command,
    };
    if let Some(existing) = jobs.iter_mut().find(|j| j.name == job_name) {
        *existing = new_job;
    } else {
        jobs.push(new_job);
    }
    let rendered = render_cron(&jobs);

    match write_managed_file(CRON_FILE, &rendered, elevation).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Set scheduled task \"{job_name}\".\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn remove_cron_job(job_name: String, elevation: &ElevationState) -> CommandOutcome {
    if let Err(e) = validate_job_name(&job_name) {
        return CommandOutcome::Err(e);
    }
    let current = match read_managed_file(CRON_FILE, elevation).await {
        Ok(c) => c,
        Err(e) => return CommandOutcome::Err(e),
    };
    let jobs: Vec<CronJob> = parse_cron(&current)
        .into_iter()
        .filter(|j| j.name != job_name)
        .collect();
    let rendered = render_cron(&jobs);
    match write_managed_file(CRON_FILE, &rendered, elevation).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!("Removed scheduled task \"{job_name}\".\n{}", output.stdout),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn clear_managed_cron_jobs(elevation: &ElevationState) -> CommandOutcome {
    match write_managed_file(CRON_FILE, CRON_HEADER, elevation).await {
        Ok(output) => CommandOutcome::Ok(OperationOutput {
            stdout: format!(
                "Cleared the managed scheduled tasks file.\n{}",
                output.stdout
            ),
            ..output
        }),
        Err(e) => CommandOutcome::Err(e),
    }
}
