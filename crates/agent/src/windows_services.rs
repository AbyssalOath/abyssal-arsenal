//! Failed services on Windows (docs/roadmap/0.2.4.md, section 1): the
//! Windows answer to `FailedServices` (the fleet health check) and
//! `ListFailedUnits` / `RecoverUnit` (Resurrection), which on Linux are
//! `systemctl --failed` and `systemctl restart`.
//!
//! A failed service is an automatic-start one that's stopped, except where
//! that's normal ([`select_failed`] has the rules). PowerShell only collects
//! the raw facts as JSON; the rules are here, so they're tested on captured
//! exports rather than only on a real Windows host. The output formats are
//! described in `abyssal_agent_protocol::failed_services`.

// Only Windows builds run it; elsewhere it's here for its tests.
#![cfg_attr(not(windows), allow(dead_code))]

use abyssal_agent_protocol::failed_services::{
    BUILTIN_IGNORED_SERVICES, WINDOWS_SUMMARY_SUFFIX, is_ignored,
};
use serde::Deserialize;

/// A delayed-start service gets this long after boot before a stopped one
/// counts (Windows starts them about two minutes in).
const DELAYED_START_GRACE_SECS: i64 = 10 * 60;

/// `ERROR_SERVICE_SPECIFIC_ERROR`: the real code is the service's own.
const SERVICE_SPECIFIC_ERROR: i64 = 1066;

/// Registry `Type` bits for per-user services (a template, or an instance
/// running for one signed-in user): they stop when that user signs out.
const USER_SERVICE_BITS: i64 = 0x40 | 0x80;

/// The System-log events that say why a service didn't start or stopped:
/// 7000 failed to start, 7009 and 7011 timeouts, 7023 terminated with an
/// error, 7031 terminated unexpectedly.
const FAILURE_EVENT_IDS: &str = "7000,7009,7011,7023,7031";

/// Collects automatic-start services that aren't running, with what the
/// rules need, plus (with `$withEvents`) the last week's failure events.
/// Prefixed with `$withEvents = $true|$false` by [`script`].
const SCRIPT_BODY: &str = r#"$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$uptime = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
$services = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | ForEach-Object {
  $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $_.Name
  $type = (Get-ItemProperty -LiteralPath $key -Name Type -ErrorAction SilentlyContinue).Type
  [pscustomobject]@{
    Name = [string]$_.Name
    DisplayName = [string]$_.DisplayName
    State = [string]$_.State
    ExitCode = [int64]$_.ExitCode
    ServiceSpecificExitCode = [int64]$_.ServiceSpecificExitCode
    DelayedAutoStart = [bool]$_.DelayedAutoStart
    HasTrigger = [bool](Test-Path -LiteralPath ($key + '\TriggerInfo'))
    ServiceType = if ($null -ne $type) { [int64]$type } else { [int64]0 }
  }
})
$events = @()
if ($withEvents -and $services.Count -gt 0) {
  $filter = @{ LogName = 'System'; Id = @(__EVENT_IDS__); StartTime = (Get-Date).AddDays(-7) }
  $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
      Id = [int]$_.Id
      Time = $_.TimeCreated.ToUniversalTime().ToString('o')
      Params = @($_.Properties | ForEach-Object { [string]$_.Value })
      Message = ([string]$_.Message -replace '\s+', ' ').Trim()
    }
  })
}
[pscustomobject]@{ UptimeSeconds = $uptime; Services = $services; Events = $events } | ConvertTo-Json -Depth 4 -Compress
"#;

/// The collection script; `with_events` also fetches the failure events
/// (Resurrection's list wants them, the 5-minute health check doesn't).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn script(with_events: bool) -> String {
    format!(
        "$withEvents = ${with_events}\n{}",
        SCRIPT_BODY.replace("__EVENT_IDS__", FAILURE_EVENT_IDS)
    )
}

/// PowerShell 5.1's `ConvertTo-Json` writes a one-element array as a bare
/// object, so accept either.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    Many(Vec<T>),
    One(T),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        OneOrMany::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::Many(v) => v,
            OneOrMany::One(t) => vec![t],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Snapshot {
    uptime_seconds: i64,
    #[serde(default)]
    services: Option<OneOrMany<ServiceRecord>>,
    #[serde(default)]
    events: Option<OneOrMany<EventRecord>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ServiceRecord {
    name: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    exit_code: i64,
    #[serde(default)]
    service_specific_exit_code: i64,
    #[serde(default)]
    delayed_auto_start: bool,
    #[serde(default)]
    has_trigger: bool,
    #[serde(default)]
    service_type: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EventRecord {
    #[serde(default)]
    time: String,
    #[serde(default)]
    params: Option<OneOrMany<String>>,
    #[serde(default)]
    message: String,
}

/// One failed service, as reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedService {
    pub name: String,
    pub display_name: String,
    pub state: String,
    /// The meaningful exit code: the service's own when Windows reports
    /// "service-specific error".
    pub exit_code: String,
    /// The latest matching System-log failure event, if any.
    pub why: String,
}

/// The rules: an automatic-start service that's stopped counts as failed,
/// except
/// - a trigger-start service (it stops by design when idle);
/// - a delayed-start one within [`DELAYED_START_GRACE_SECS`] of boot;
/// - one that exited cleanly (exit code 0), such as an updater;
/// - a per-user service (it stops when its user signs out);
/// - one on [`BUILTIN_IGNORED_SERVICES`].
///
/// Pending states (starting, stopping) aren't failures either.
fn select_failed(snapshot: Snapshot) -> Vec<FailedService> {
    let uptime = snapshot.uptime_seconds;
    let events: Vec<EventRecord> = snapshot.events.map(OneOrMany::into_vec).unwrap_or_default();
    let mut failed: Vec<FailedService> = snapshot
        .services
        .map(OneOrMany::into_vec)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.state.eq_ignore_ascii_case("Stopped"))
        .filter(|s| !s.has_trigger)
        .filter(|s| !(s.delayed_auto_start && uptime < DELAYED_START_GRACE_SECS))
        .filter(|s| s.exit_code != 0)
        .filter(|s| s.service_type & USER_SERVICE_BITS == 0)
        .filter(|s| !is_ignored(&s.name, BUILTIN_IGNORED_SERVICES))
        .map(|s| FailedService {
            why: why_failed(&s, &events),
            exit_code: if s.exit_code == SERVICE_SPECIFIC_ERROR {
                format!("{} (service-specific)", s.service_specific_exit_code)
            } else {
                s.exit_code.to_string()
            },
            name: one_line(&s.name),
            display_name: one_line(&s.display_name),
            state: one_line(&s.state),
        })
        .collect();
    failed.sort_by_key(|s| s.name.to_lowercase());
    failed
}

/// The newest failure event naming this service (events come newest
/// first), as "2026-10-12 08:01 UTC: <message>".
fn why_failed(service: &ServiceRecord, events: &[EventRecord]) -> String {
    let names_it = |e: &&EventRecord| {
        e.params.as_ref().is_some_and(|p| {
            let params: &[String] = match p {
                OneOrMany::Many(v) => v,
                OneOrMany::One(one) => std::slice::from_ref(one),
            };
            params.iter().any(|p| {
                p.eq_ignore_ascii_case(&service.name)
                    || (!service.display_name.is_empty()
                        && p.eq_ignore_ascii_case(&service.display_name))
            })
        })
    };
    let Some(event) = events.iter().find(names_it) else {
        return String::new();
    };
    let when = event
        .time
        .get(..16)
        .unwrap_or(&event.time)
        .replace('T', " ");
    let mut message = one_line(&event.message);
    if message.chars().count() > 300 {
        message = message.chars().take(300).collect::<String>() + "…";
    }
    format!("{when} UTC: {message}")
}

/// Tabs and line breaks would break the line-per-service format.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `FailedServices`: a table, then `N failed services listed.`
pub fn format_failed_services(failed: &[FailedService]) -> String {
    let mut out = String::new();
    if failed.is_empty() {
        out.push_str("No failed services.\n");
    } else {
        let width = failed
            .iter()
            .map(|s| s.name.len())
            .max()
            .unwrap_or(0)
            .max("SERVICE".len());
        out.push_str(&format!(
            "{:width$}  {:8}  {:18}  DISPLAY NAME\n",
            "SERVICE", "STATE", "EXIT CODE"
        ));
        for s in failed {
            out.push_str(&format!(
                "{:width$}  {:8}  {:18}  {}\n",
                s.name, s.state, s.exit_code, s.display_name
            ));
        }
    }
    out.push_str(&format!("\n{} {WINDOWS_SUMMARY_SUFFIX}\n", failed.len()));
    out
}

/// `ListFailedUnits`: one tab-separated line per service.
pub fn format_list(failed: &[FailedService]) -> String {
    if failed.is_empty() {
        return "No failed services.".to_string();
    }
    failed
        .iter()
        .map(|s| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                s.name, s.state, s.exit_code, s.display_name, s.why
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parses the collection script's JSON and applies the rules.
pub fn failed_from_json(json: &str) -> Result<Vec<FailedService>, String> {
    let snapshot: Snapshot = serde_json::from_str(json.trim())
        .map_err(|e| format!("couldn't read the service list from PowerShell: {e}"))?;
    Ok(select_failed(snapshot))
}

#[cfg(windows)]
mod windows {
    use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

    use super::*;
    use crate::process::{ps_checked, ps_quote, run_powershell};

    async fn collect(with_events: bool) -> Result<Vec<FailedService>, String> {
        let output = run_powershell(&script(with_events)).await?;
        failed_from_json(&output.stdout)
    }

    fn ok(stdout: String) -> CommandOutcome {
        CommandOutcome::Ok(OperationOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }

    pub async fn failed_services() -> CommandOutcome {
        match collect(false).await {
            Ok(failed) => ok(format_failed_services(&failed)),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn list_failed() -> CommandOutcome {
        match collect(true).await {
            Ok(failed) => ok(format_list(&failed)),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    /// `Start-Service`, then waits up to 30 seconds for it to be running.
    /// `Get-Service` fails first for a name that isn't a service.
    pub async fn start(name: &str) -> CommandOutcome {
        if !abyssal_agent_protocol::failed_services::is_valid_windows_service_name(name) {
            return CommandOutcome::Err(format!("refusing invalid service name: {name}"));
        }
        let quoted = ps_quote(name);
        let script = ps_checked(&format!(
            "$s = Get-Service -Name {quoted}; Start-Service -InputObject $s; \
             $s.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)); \
             'Started ' + $s.Name + ' (' + $s.DisplayName + '); it is now ' + \
             (Get-Service -Name {quoted}).Status + '.'"
        ));
        match run_powershell(&script).await {
            Ok(output) => CommandOutcome::Ok(output),
            Err(e) => CommandOutcome::Err(e),
        }
    }
}

#[cfg(windows)]
pub use windows::{failed_services, list_failed, start};

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built in the script's output shape, with real Windows service
    /// names, start types and exit codes covering each rule. (A capture
    /// from a real host can replace it; the shape is the same.)
    const CAPTURED: &str = r#"{"UptimeSeconds":86400,"Services":[
      {"Name":"Spooler","DisplayName":"Print Spooler","State":"Stopped","ExitCode":1067,"ServiceSpecificExitCode":0,"DelayedAutoStart":false,"HasTrigger":false,"ServiceType":272},
      {"Name":"MSSQL$SQLEXPRESS","DisplayName":"SQL Server (SQLEXPRESS)","State":"Stopped","ExitCode":1066,"ServiceSpecificExitCode":17058,"DelayedAutoStart":false,"HasTrigger":false,"ServiceType":16},
      {"Name":"gpsvc","DisplayName":"Group Policy Client","State":"Stopped","ExitCode":1077,"ServiceSpecificExitCode":0,"DelayedAutoStart":false,"HasTrigger":true,"ServiceType":32},
      {"Name":"edgeupdate","DisplayName":"Microsoft Edge Update Service (edgeupdate)","State":"Stopped","ExitCode":1077,"ServiceSpecificExitCode":0,"DelayedAutoStart":true,"HasTrigger":false,"ServiceType":16},
      {"Name":"sppsvc","DisplayName":"Software Protection","State":"Stopped","ExitCode":1077,"ServiceSpecificExitCode":0,"DelayedAutoStart":true,"HasTrigger":true,"ServiceType":16},
      {"Name":"BITS","DisplayName":"Background Intelligent Transfer Service","State":"Stopped","ExitCode":0,"ServiceSpecificExitCode":0,"DelayedAutoStart":true,"HasTrigger":false,"ServiceType":32},
      {"Name":"OneSyncSvc_4f2a1","DisplayName":"Sync Host_4f2a1","State":"Stopped","ExitCode":1077,"ServiceSpecificExitCode":0,"DelayedAutoStart":true,"HasTrigger":false,"ServiceType":224},
      {"Name":"CDPUserSvc","DisplayName":"Connected Devices Platform User Service","State":"Stopped","ExitCode":1077,"ServiceSpecificExitCode":0,"DelayedAutoStart":false,"HasTrigger":false,"ServiceType":96},
      {"Name":"wuauserv","DisplayName":"Windows Update","State":"Start Pending","ExitCode":0,"ServiceSpecificExitCode":0,"DelayedAutoStart":false,"HasTrigger":false,"ServiceType":32},
      {"Name":"DoSvc","DisplayName":"Delivery Optimization","State":"Stopped","ExitCode":1067,"ServiceSpecificExitCode":0,"DelayedAutoStart":true,"HasTrigger":false,"ServiceType":32}
    ],"Events":[
      {"Id":7031,"Time":"2026-10-12T08:01:13.0000000Z","Params":["Print Spooler","1","60000","1","Restart the service"],"Message":"The Print Spooler service terminated unexpectedly.  It has done this 1 time(s)."},
      {"Id":7000,"Time":"2026-10-11T07:00:00.0000000Z","Params":["Print Spooler","%%1053"],"Message":"older event"},
      {"Id":7009,"Time":"2026-10-12T07:55:00.0000000Z","Params":["30000","DoSvc"],"Message":"A timeout was reached (30000 milliseconds) while waiting for the DoSvc service to connect."}
    ]}"#;

    fn names(failed: &[FailedService]) -> Vec<&str> {
        failed.iter().map(|s| s.name.as_str()).collect()
    }

    #[test]
    fn rules_on_a_captured_export() {
        let failed = failed_from_json(CAPTURED).unwrap();
        // Out: gpsvc (trigger), edgeupdate and sppsvc (built-in list), BITS
        // (exit 0), OneSyncSvc_* and CDPUserSvc (per-user), wuauserv
        // (pending). DoSvc is delayed-start but well past the grace window.
        assert_eq!(names(&failed), ["DoSvc", "MSSQL$SQLEXPRESS", "Spooler"]);
        let sql = &failed[1];
        assert_eq!(sql.exit_code, "17058 (service-specific)");
        let spooler = &failed[2];
        assert_eq!(spooler.exit_code, "1067");
        // The newest matching event, matched on the display name.
        assert_eq!(
            spooler.why,
            "2026-10-12 08:01 UTC: The Print Spooler service terminated unexpectedly. It has \
             done this 1 time(s)."
        );
        // Matched on the service name, in a later parameter.
        assert!(failed[0].why.contains("timeout"), "{}", failed[0].why);
        assert_eq!(failed[1].why, "");
    }

    #[test]
    fn delayed_start_grace_after_boot() {
        let json = CAPTURED.replace("\"UptimeSeconds\":86400", "\"UptimeSeconds\":120");
        let failed = failed_from_json(&json).unwrap();
        assert!(!names(&failed).contains(&"DoSvc"));
        assert!(names(&failed).contains(&"Spooler"));
    }

    #[test]
    fn powershell_51_single_objects_and_nothing_at_all() {
        let one = r#"{"UptimeSeconds":5000,"Services":{"Name":"Spooler","DisplayName":"Print Spooler","State":"Stopped","ExitCode":1067},"Events":{"Id":7031,"Time":"2026-10-12T08:01:13Z","Params":"Print Spooler","Message":"x"}}"#;
        let failed = failed_from_json(one).unwrap();
        assert_eq!(names(&failed), ["Spooler"]);
        assert!(failed[0].why.ends_with(": x"));
        let none = r#"{"UptimeSeconds":5000,"Services":[],"Events":[]}"#;
        assert!(failed_from_json(none).unwrap().is_empty());
        let nulls = r#"{"UptimeSeconds":5000,"Services":null,"Events":null}"#;
        assert!(failed_from_json(nulls).unwrap().is_empty());
        assert!(failed_from_json("not json").is_err());
    }

    #[test]
    fn output_formats() {
        let failed = failed_from_json(CAPTURED).unwrap();
        let table = format_failed_services(&failed);
        assert!(table.starts_with("SERVICE"));
        assert!(table.trim_end().ends_with("3 failed services listed."));
        assert!(format_failed_services(&[]).contains("0 failed services listed."));

        let list = format_list(&failed);
        let first: Vec<&str> = list.lines().next().unwrap().split('\t').collect();
        assert_eq!(first.len(), 5);
        assert_eq!(first[0], "DoSvc");
        assert_eq!(format_list(&[]), "No failed services.");
    }

    #[test]
    fn script_sets_the_events_flag() {
        assert!(script(true).starts_with("$withEvents = $true\n"));
        assert!(script(false).starts_with("$withEvents = $false\n"));
        assert!(script(true).contains("Id = @(7000,7009,7011,7023,7031)"));
    }

    /// Through the real PowerShell parser. Needs `pwsh`: skipped without it
    /// locally, required in CI.
    #[test]
    fn the_script_parses_as_powershell() {
        if std::process::Command::new("pwsh")
            .arg("-Version")
            .output()
            .is_err()
        {
            assert!(
                std::env::var_os("CI").is_none(),
                "pwsh is required for this test in CI"
            );
            return;
        }
        let path = std::env::temp_dir().join(format!("winsvc-{}.ps1", std::process::id()));
        std::fs::write(&path, script(true)).unwrap();
        let out = std::process::Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:SCRIPT, [ref]$t, [ref]$e); foreach ($x in $e) { $x.Message }; if ($e.Count) { exit 1 }"])
            .env("SCRIPT", &path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
