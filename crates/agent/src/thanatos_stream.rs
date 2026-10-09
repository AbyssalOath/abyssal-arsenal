//! Real-time security events (`AgentOperation::ThanatosStream`), Windows.
//!
//! Instead of waiting for the next poll, the agent subscribes to the
//! high-signal Event Log channels and pushes each matching event to the
//! control plane as it happens (`AgentMessage::Telemetry`, which the control
//! plane ingests exactly like scan output).
//!
//! **How.** One long-lived `powershell.exe` holds an `EventLogWatcher` per
//! channel -- .NET's wrapper over `EvtSubscribe`, so this is a real push
//! subscription, not polling -- and writes one line per event. Each event is
//! formatted by `thanatos::WINDOWS_EVENT_LINE`, the same PowerShell the scans
//! use, so a streamed event classifies exactly like a polled one; doing it
//! through raw Win32 calls would mean reproducing that rendering (the
//! formatted message the rules match on) in unsafe code this crate can't run
//! in its own CI. The agent classifies each line with the scans' rules and
//! pushes only matches, batched (at most once a second, 50 lines a message).
//!
//! **Lifecycle.** Started and stopped by the control plane, which re-sends
//! the operation on every connection while Thanatos monitoring is on. The
//! PowerShell process is supervised: restarted with backoff if it exits,
//! killed when streaming stops. Matches made while the connection is down are
//! held (up to `MAX_PENDING`, oldest dropped first) and sent on reconnect.
//! The full sweep keeps running alongside as the complete, offset-tracked
//! record; content-hash dedup control-plane-side collapses the overlap.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use abyssal_agent_protocol::{AgentMessage, CommandOutcome, OperationOutput};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Channels and event IDs streamed: the fast sweep's high-signal set, plus
/// failed logons, lockouts, and account / privileged-group / service / task
/// creation -- things worth seeing within seconds. Everything else (4624
/// logons, PowerShell 4104, posture, FIM...) stays on the full sweep.
pub const REALTIME_CHANNELS: &[(&str, &str, &[u32])] = &[
    (
        "Security",
        "security",
        &[
            1102, 4719, 4648, 4688, 4625, 4740, 4720, 4722, 4728, 4732, 4756, 4697, 4698,
        ],
    ),
    (
        "Microsoft-Windows-Sysmon/Operational",
        "sysmon",
        &[1, 8, 25],
    ),
    (
        "Microsoft-Windows-Windows Defender/Operational",
        "defender",
        &[1116, 5001],
    ),
];

/// Most matches held while disconnected.
const MAX_PENDING: usize = 1000;
/// Most matches in one telemetry message.
const BATCH_LINES: usize = 50;
const FLUSH_EVERY: Duration = Duration::from_secs(1);
/// How long `ThanatosStream { enabled: true }` waits for the subscriptions
/// to report in before answering.
const READY_WAIT: Duration = Duration::from_secs(20);

/// The PowerShell that subscribes to `channels` and writes, one per line:
/// `WATCH\t<source>` / `SKIP\t<source>\t<why>` per channel (a channel that
/// doesn't exist -- Sysmon not installed -- is skipped, not fatal), `READY`,
/// then `EVT\t<source>\t<event line>` per event and `HEARTBEAT` every 30s
/// of quiet. Log names and IDs are fixed constants, never wire input.
pub fn realtime_script(channels: &[(&str, &str, &[u32])]) -> String {
    let list = channels
        .iter()
        .map(|(log, source, ids)| {
            let ids = ids
                .iter()
                .map(|id| format!("EventID={id}"))
                .collect::<Vec<_>>()
                .join(" or ");
            format!("@('{log}', '{source}', '*[System[({ids})]]')")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let event_line = crate::thanatos::WINDOWS_EVENT_LINE;
    format!(
        r#"$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue
$out = [Console]::Out
$watchers = @()
foreach ($c in @({list})) {{
  try {{
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($c[0], [System.Diagnostics.Eventing.Reader.PathType]::LogName, $c[2])
    $w = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($q)
    Register-ObjectEvent -InputObject $w -EventName EventRecordWritten -SourceIdentifier $c[1] | Out-Null
    $w.Enabled = $true
    $watchers += $w
    $out.WriteLine("WATCH`t" + $c[1])
  }} catch {{
    $out.WriteLine("SKIP`t" + $c[1] + "`t" + ($_.Exception.Message -replace '\r?\n', ' '))
  }}
}}
$out.WriteLine('READY'); $out.Flush()
while ($true) {{
  $e = Wait-Event -Timeout 30
  if ($null -eq $e) {{ $out.WriteLine('HEARTBEAT'); $out.Flush(); continue }}
  $src = $e.SourceIdentifier
  $rec = $e.SourceEventArgs.EventRecord
  Remove-Event -EventIdentifier $e.EventIdentifier
  if ($null -eq $rec) {{ continue }}
  try {{
    $rec | Add-Member -NotePropertyName Message -NotePropertyValue ($rec.FormatDescription()) -Force
    $line = $rec | ForEach-Object {{ {event_line} }}
    $out.WriteLine("EVT`t$src`t$line")
  }} catch {{
    $out.WriteLine("ERR`t$src`t" + ($_.Exception.Message -replace '\r?\n', ' '))
  }}
  $out.Flush()
}}
"#
    )
}

#[derive(Debug, PartialEq)]
pub enum StreamLine {
    Watching(String),
    Skipped { source: String, reason: String },
    Ready,
    Heartbeat,
    Event { source: String, line: String },
    Error { source: String, message: String },
    Other,
}

pub fn parse_stream_line(raw: &str) -> StreamLine {
    let raw = raw.trim_end_matches(['\r', '\n']);
    let mut parts = raw.splitn(3, '\t');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("READY"), None, None) => StreamLine::Ready,
        (Some("HEARTBEAT"), None, None) => StreamLine::Heartbeat,
        (Some("WATCH"), Some(source), None) => StreamLine::Watching(source.to_string()),
        (Some("SKIP"), Some(source), reason) => StreamLine::Skipped {
            source: source.to_string(),
            reason: reason.unwrap_or_default().to_string(),
        },
        (Some("EVT"), Some(source), Some(line)) if !line.is_empty() => StreamLine::Event {
            source: source.to_string(),
            line: line.to_string(),
        },
        (Some("ERR"), Some(source), message) => StreamLine::Error {
            source: source.to_string(),
            message: message.unwrap_or_default().to_string(),
        },
        _ => StreamLine::Other,
    }
}

/// The scans' wire line for an event that matches a rule, else `None`.
/// Sources are mapped back to the scans' own `&'static str` names.
pub fn classify_event(source: &str, line: &str, c2_ports: &[u16]) -> Option<String> {
    let source = REALTIME_CHANNELS
        .iter()
        .map(|(_, s, _)| *s)
        .find(|s| *s == source)?;
    let (severity, label) = crate::thanatos::classify_line(source, line, c2_ports)?;
    Some(format!("{severity}\t{label}\t{source}\t{line}"))
}

/// Matches waiting to go out: batched, and held while disconnected.
#[derive(Default)]
pub struct Pending {
    lines: VecDeque<String>,
    pub dropped: u64,
}

impl Pending {
    pub fn push(&mut self, line: String) {
        if self.lines.len() >= MAX_PENDING {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(line);
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Sends batches through `send` until it refuses one (disconnected) or
    /// nothing is left. A refused batch stays at the front.
    pub fn flush(&mut self, mut send: impl FnMut(&str) -> bool) {
        while !self.lines.is_empty() {
            let n = self.lines.len().min(BATCH_LINES);
            let mut stdout = self
                .lines
                .iter()
                .take(n)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            stdout.push('\n');
            if !send(&stdout) {
                return;
            }
            self.lines.drain(..n);
        }
    }
}

/// What the subscriptions reported at startup, for the operation's reply.
#[derive(Debug, Default, Clone)]
pub struct Readiness {
    pub watching: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

/// Runs `program args` until aborted, restarting it with backoff whenever it
/// exits, feeding every matched event to `send`. The first startup's
/// `Readiness` goes to `ready`. Generic over the program so it's tested with
/// a shell script; production runs PowerShell with `realtime_script`.
pub async fn supervise(
    program: String,
    args: Vec<String>,
    c2_ports: Vec<u16>,
    ready: oneshot::Sender<Result<Readiness, String>>,
    send: impl Fn(&str) -> bool + Send + 'static,
) {
    let mut ready = Some(ready);
    let mut pending = Pending::default();
    let mut backoff = Duration::from_secs(5);
    loop {
        let started = tokio::time::Instant::now();
        let child = tokio::process::Command::new(&program)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(e) => {
                if let Some(tx) = ready.take() {
                    let _ = tx.send(Err(format!("couldn't start {program}: {e}")));
                }
                tracing::warn!(error = %e, "thanatos stream: couldn't start the subscriber");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            continue;
        };
        let mut lines = BufReader::new(stdout).lines();
        let mut readiness = Readiness::default();
        let mut tick = tokio::time::interval(FLUSH_EVERY);
        loop {
            tokio::select! {
                next = lines.next_line() => {
                    let Ok(Some(raw)) = next else { break };
                    match parse_stream_line(&raw) {
                        StreamLine::Watching(source) => readiness.watching.push(source),
                        StreamLine::Skipped { source, reason } => {
                            readiness.skipped.push((source, reason));
                        }
                        StreamLine::Ready => {
                            if let Some(tx) = ready.take() {
                                let _ = tx.send(Ok(readiness.clone()));
                            }
                            tracing::info!(watching = ?readiness.watching, skipped = ?readiness.skipped, "thanatos stream: subscribed");
                        }
                        StreamLine::Event { source, line } => {
                            if let Some(wire) = classify_event(&source, &line, &c2_ports) {
                                pending.push(wire);
                                if pending.len() >= BATCH_LINES {
                                    pending.flush(&send);
                                }
                            }
                        }
                        StreamLine::Error { source, message } => {
                            tracing::debug!(%source, %message, "thanatos stream: couldn't format an event");
                        }
                        StreamLine::Heartbeat | StreamLine::Other => {}
                    }
                }
                _ = tick.tick() => pending.flush(&send),
            }
        }
        pending.flush(&send);
        let _ = child.kill().await;
        if let Some(tx) = ready.take() {
            let _ = tx.send(Err(
                "the event subscriber exited before it was ready".to_string()
            ));
        }
        // Healthy for a while: start over with a short delay.
        if started.elapsed() > Duration::from_secs(300) {
            backoff = Duration::from_secs(5);
        }
        tracing::warn!(
            backoff_secs = backoff.as_secs(),
            "thanatos stream: subscriber exited; restarting"
        );
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

struct Running {
    task: JoinHandle<()>,
    c2_ports: Vec<u16>,
    readiness: Readiness,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

fn ok(stdout: String) -> CommandOutcome {
    CommandOutcome::Ok(OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

fn describe(readiness: &Readiness) -> String {
    let mut out = format!("Streaming {}.", readiness.watching.join(", "));
    for (source, reason) in &readiness.skipped {
        out.push_str(&format!(" Not streaming {source}: {reason}."));
    }
    out
}

/// Sends a telemetry batch on the current connection.
fn send_telemetry(stdout: &str) -> bool {
    crate::transport::push_unsolicited(&AgentMessage::Telemetry {
        stdout: stdout.to_string(),
    })
}

pub async fn set_stream(enabled: bool, c2_ports: Vec<u16>) -> CommandOutcome {
    if !enabled {
        if let Some(running) = RUNNING.lock().unwrap().take() {
            running.task.abort();
            return ok("Stopped real-time event streaming.".into());
        }
        return ok("Real-time event streaming wasn't running.".into());
    }
    if !cfg!(windows) {
        return crate::process::platform_unsupported();
    }
    {
        let mut running = RUNNING.lock().unwrap();
        match running.as_ref() {
            Some(r) if r.c2_ports == c2_ports && !r.task.is_finished() => {
                return ok(format!("Already streaming. {}", describe(&r.readiness)));
            }
            Some(_) => {
                if let Some(old) = running.take() {
                    old.task.abort();
                }
            }
            None => {}
        }
    }

    let (tx, rx) = oneshot::channel();
    let script = realtime_script(REALTIME_CHANNELS);
    let task = tokio::spawn(supervise(
        "powershell.exe".to_string(),
        vec![
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script,
        ],
        c2_ports.clone(),
        tx,
        send_telemetry,
    ));
    // Anything short of "subscribed to at least one channel" is a failure:
    // the control plane only stops fast-polling a host whose stream works.
    let readiness = match tokio::time::timeout(READY_WAIT, rx).await {
        Ok(Ok(Ok(readiness))) if !readiness.watching.is_empty() => readiness,
        Ok(Ok(Ok(readiness))) => {
            task.abort();
            return CommandOutcome::Err(format!(
                "no event channel could be subscribed to.{}",
                readiness
                    .skipped
                    .iter()
                    .map(|(source, reason)| format!(" {source}: {reason}."))
                    .collect::<String>()
            ));
        }
        Ok(Ok(Err(e))) => {
            task.abort();
            return CommandOutcome::Err(format!("couldn't start real-time streaming: {e}"));
        }
        _ => {
            task.abort();
            return CommandOutcome::Err(format!(
                "the event subscriber didn't report in within {}s",
                READY_WAIT.as_secs()
            ));
        }
    };
    let message = describe(&readiness);
    *RUNNING.lock().unwrap() = Some(Running {
        task,
        c2_ports,
        readiness,
    });
    ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::sync::Arc;

    #[test]
    fn the_script_subscribes_to_every_channel_and_formats_like_the_scans() {
        let s = realtime_script(REALTIME_CHANNELS);
        assert!(s.contains("@('Security', 'security', '*[System[(EventID=1102 or EventID=4719"));
        assert!(s.contains("@('Microsoft-Windows-Sysmon/Operational', 'sysmon', '*[System[(EventID=1 or EventID=8 or EventID=25)]]')"));
        assert!(s.contains("EventLogWatcher"));
        assert!(
            s.contains(crate::thanatos::WINDOWS_EVENT_LINE),
            "same formatting as the scans"
        );
        assert!(s.contains("$out.WriteLine('READY')"));
        assert!(s.contains("Wait-Event -Timeout 30"));
        // Every curated fast-sweep ID is streamed too.
        for id in [1102, 4719, 4648, 4688, 1116, 5001] {
            assert!(s.contains(&format!("EventID={id}")), "{id}");
        }
    }

    /// The generated script through the real PowerShell parser. Needs `pwsh`
    /// on PATH: skipped without it locally, required in CI (ubuntu-latest and
    /// windows-latest both have it).
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
            eprintln!("skipping: pwsh not on PATH");
            return;
        }
        let path = std::env::temp_dir().join(format!("thanatos-stream-{}.ps1", std::process::id()));
        std::fs::write(&path, realtime_script(REALTIME_CHANNELS)).unwrap();
        let check = "$t = $null; $e = $null; \
             [void][System.Management.Automation.Language.Parser]::ParseFile($env:SCRIPT, [ref]$t, [ref]$e); \
             foreach ($x in $e) { \"$($x.Extent.StartLineNumber): $($x.Message)\" }; \
             if ($e.Count -gt 0) { exit 1 }";
        let out = std::process::Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command", check])
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

    #[test]
    fn parses_the_subscriber_protocol() {
        assert_eq!(parse_stream_line("READY\r\n"), StreamLine::Ready);
        assert_eq!(parse_stream_line("HEARTBEAT"), StreamLine::Heartbeat);
        assert_eq!(
            parse_stream_line("WATCH\tsecurity"),
            StreamLine::Watching("security".into())
        );
        assert_eq!(
            parse_stream_line("SKIP\tsysmon\tThe specified channel could not be found."),
            StreamLine::Skipped {
                source: "sysmon".into(),
                reason: "The specified channel could not be found.".into()
            }
        );
        assert_eq!(
            parse_stream_line(
                "EVT\tsecurity\tEventID=1102\tTime=t\tIpAddress=\tAccount=bob\tThe audit log was cleared."
            ),
            StreamLine::Event {
                source: "security".into(),
                line: "EventID=1102\tTime=t\tIpAddress=\tAccount=bob\tThe audit log was cleared."
                    .into()
            }
        );
        assert_eq!(parse_stream_line("EVT\tsecurity\t"), StreamLine::Other);
        assert_eq!(parse_stream_line("WARNING: something"), StreamLine::Other);
    }

    #[test]
    fn only_rule_matches_from_known_channels_are_sent() {
        let cleared = "EventID=1102\tTime=2026-10-09T10:00:00Z\tIpAddress=\tAccount=bob\tThe audit log was cleared.";
        let wire = classify_event("security", cleared, &[]).expect("1102 is a rule");
        assert!(wire.ends_with(&format!("\tsecurity\t{cleared}")));
        assert_eq!(
            wire.split('\t').count(),
            4 + cleared.split('\t').count() - 1
        );
        // The same line through the scans' own classifier gives the same verdict.
        assert_eq!(
            crate::thanatos::classify_line("security", cleared, &[])
                .map(|(s, l)| format!("{s}\t{l}")),
            Some(wire.splitn(3, '\t').take(2).collect::<Vec<_>>().join("\t"))
        );
        assert_eq!(
            classify_event(
                "security",
                "EventID=4688\tTime=t\tIpAddress=\tAccount=\tA new process has been created. New Process Name: notepad.exe",
                &[]
            ),
            None
        );
        assert_eq!(classify_event("not-a-channel", cleared, &[]), None);
    }

    #[test]
    fn pending_batches_holds_while_disconnected_and_caps() {
        let mut p = Pending::default();
        for i in 0..120 {
            p.push(format!("line{i}"));
        }
        let mut sent: Vec<String> = Vec::new();
        p.flush(|batch| {
            sent.push(batch.to_string());
            true
        });
        assert_eq!(sent.len(), 3, "50 + 50 + 20");
        assert_eq!(sent[0].lines().count(), 50);
        assert!(sent[0].starts_with("line0\n") && sent[2].ends_with("line119\n"));
        assert_eq!(p.len(), 0);

        // Disconnected: nothing leaves, nothing is lost.
        p.push("a".into());
        p.flush(|_| false);
        assert_eq!(p.len(), 1);

        for i in 0..(MAX_PENDING + 5) {
            p.push(format!("x{i}"));
        }
        assert_eq!(p.len(), MAX_PENDING);
        assert_eq!(p.dropped, 6, "the oldest go first");
    }

    /// The supervisor end to end against a shell script standing in for
    /// PowerShell: startup report, events classified and batched, and a
    /// restart after the subscriber exits.
    #[cfg(unix)]
    #[tokio::test]
    async fn supervise_reports_ready_pushes_matches_and_restarts() {
        let dir = std::env::temp_dir().join(format!("thanatos-stream-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let runs = dir.join("runs");
        let script = format!(
            "echo run >> '{runs}'\n\
             printf 'WATCH\\tsecurity\\nSKIP\\tsysmon\\tnot installed\\nREADY\\n'\n\
             printf 'EVT\\tsecurity\\tEventID=4688\\tTime=t\\tIpAddress=\\tAccount=\\tA new process has been created. New Process Name: C:\\\\Windows\\\\System32\\\\notepad.exe\\n'\n\
             printf 'EVT\\tsecurity\\tEventID=1102\\tTime=t\\tIpAddress=\\tAccount=bob\\tThe audit log was cleared.\\n'\n\
             printf 'HEARTBEAT\\n'\n\
             sleep 0.2\n",
            runs = runs.display()
        );
        let sent = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = sent.clone();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(supervise(
            "sh".into(),
            vec!["-c".into(), script],
            vec![],
            tx,
            move |batch: &str| {
                sink.lock().unwrap().push(batch.to_string());
                true
            },
        ));
        let readiness = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(readiness.watching, ["security"]);
        assert_eq!(
            readiness.skipped,
            [("sysmon".to_string(), "not installed".to_string())]
        );

        // The first run's match goes out within a flush; then the script
        // exits and is restarted after the backoff.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        {
            let sent = sent.lock().unwrap();
            let all: String = sent.concat();
            assert!(all.contains("\tsecurity\tEventID=1102"), "{all}");
            assert!(!all.contains("EventID=4688"), "non-matches aren't sent");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        task.abort();
        let runs = std::fs::read_to_string(&runs)
            .unwrap_or_default()
            .lines()
            .count();
        assert!(runs >= 2, "restarted after exiting ({runs} runs)");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
