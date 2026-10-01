//! System health and resource monitoring ("Mortiscope"): load average, top
//! processes by CPU/memory, detailed memory breakdown, disk I/O stats, and
//! failed systemd units. Every op here is read-only observability -- pure
//! monitoring, not management (that's Cystoolbox's job, which owns the
//! only other system-level ops in this app: `SystemInfo`/`ResourceUsage`
//! summaries, plus the actual `SetHostname`/`Reboot` mutations). Nothing
//! here should ever need write/destructive framing.

use std::time::Duration;

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::init_system::{self, InitSystem};
use crate::process::{command_exists, run_command, truncate_lines};

/// How long the rate-based readings (CPU utilization, network throughput)
/// sample across. Two `/proc` snapshots this far apart give a usable
/// instantaneous rate without making the operator wait.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

/// Load average is a Unix concept (runnable-task count over 1/5/15 min) with no
/// native Windows equivalent, so on Windows this is a clean "not applicable"
/// rather than a fabricated number. Windows CPU pressure is covered by
/// `cpu_utilization` instead.
#[cfg(windows)]
pub async fn load_average(_elevation: &ElevationState) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(unix)]
pub async fn load_average(elevation: &ElevationState) -> CommandOutcome {
    let mut output = match elevation.run("uptime", &[]).await {
        Ok(o) => o,
        Err(e) => return CommandOutcome::Err(e),
    };
    // `uptime` reports load but not the CPU count, so the raw numbers can't be
    // normalized to load-per-core on their own. Append the core count in a
    // stable line the control plane parses; best-effort, so an absent `nproc`
    // just omits it (the control plane then falls back to raw load).
    if let Ok(nproc) = elevation.run("nproc", &[]).await {
        let cores = nproc.stdout.trim();
        if !cores.is_empty() {
            output.stdout = format!("{}\nCPU cores: {cores}", output.stdout.trim_end());
        }
    }
    CommandOutcome::Ok(output)
}

const PS_FIELDS: &str = "pid,ppid,user,%cpu,%mem,comm";
/// Header row + 15 processes.
const TOP_PROCESS_LINES: usize = 16;

pub async fn top_processes_by_cpu(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run("ps", &["-eo", PS_FIELDS, "--sort=-%cpu"])
        .await
    {
        Ok(output) => CommandOutcome::Ok(truncate_lines(output, TOP_PROCESS_LINES)),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn top_processes_by_memory(elevation: &ElevationState) -> CommandOutcome {
    match elevation
        .run("ps", &["-eo", PS_FIELDS, "--sort=-%mem"])
        .await
    {
        Ok(output) => CommandOutcome::Ok(truncate_lines(output, TOP_PROCESS_LINES)),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(unix)]
pub async fn memory_detail(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("cat", &["/proc/meminfo"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

/// Windows `MemoryDetail`: emits the `/proc/meminfo`-shaped `MemTotal:` /
/// `MemAvailable:` lines in kB, so the control plane's existing
/// `parse_memory_detail` reads it unchanged. Swap is deliberately omitted --
/// Windows "virtual memory" is a commit limit, not a page-file-only figure, so
/// reporting it as swap would be misleading (the parser then reports 0% swap).
#[cfg(windows)]
pub async fn memory_detail(_elevation: &ElevationState) -> CommandOutcome {
    let script = r#"$os = Get-CimInstance Win32_OperatingSystem
"MemTotal: {0} kB" -f [int]$os.TotalVisibleMemorySize
"MemAvailable: {0} kB" -f [int]$os.FreePhysicalMemory"#;
    match crate::process::run_powershell(script).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

pub async fn disk_io_stats(elevation: &ElevationState) -> CommandOutcome {
    match elevation.run("vmstat", &["-d"]).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(unix)]
struct CpuTimes {
    total: u64,
    idle_all: u64,
    iowait: u64,
}

#[cfg(unix)]
async fn read_cpu_times() -> Option<CpuTimes> {
    let content = tokio::fs::read_to_string("/proc/stat").await.ok()?;
    let line = content.lines().next()?;
    let mut it = line.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = it.filter_map(|t| t.parse::<u64>().ok()).collect();
    if vals.len() < 5 {
        return None;
    }
    let total: u64 = vals.iter().sum();
    // idle_all = idle + iowait, the standard "not doing useful work" figure.
    Some(CpuTimes {
        total,
        idle_all: vals[3] + vals[4],
        iowait: vals[4],
    })
}

/// Real CPU utilization, from the delta between two `/proc/stat` snapshots --
/// distinct from load average, which counts runnable tasks rather than busy
/// time. Reports overall busy % and iowait % (a high iowait points at a
/// disk/storage bottleneck rather than CPU-bound work).
/// Windows `CpuUtilization`: emits the same `busy:` / `iowait:` lines the Linux
/// path does, so `parse_cpu_utilization` reads it unchanged. `iowait` has no
/// direct Windows counter, so it's reported as 0.
#[cfg(windows)]
pub async fn cpu_utilization() -> CommandOutcome {
    let script = r#"$c = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
"CPU utilization:"
"  busy: {0:N1}%" -f [double]$c
"  iowait: 0.0%""#;
    match crate::process::run_powershell(script).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(unix)]
pub async fn cpu_utilization() -> CommandOutcome {
    let a = match read_cpu_times().await {
        Some(x) => x,
        None => return CommandOutcome::Err("could not read /proc/stat".to_string()),
    };
    tokio::time::sleep(SAMPLE_INTERVAL).await;
    let b = match read_cpu_times().await {
        Some(x) => x,
        None => return CommandOutcome::Err("could not read /proc/stat".to_string()),
    };

    let d_total = b.total.saturating_sub(a.total);
    let (busy, iowait) = if d_total == 0 {
        (0.0, 0.0)
    } else {
        let d_idle = b.idle_all.saturating_sub(a.idle_all);
        let d_iowait = b.iowait.saturating_sub(a.iowait);
        (
            (d_total - d_idle) as f64 / d_total as f64 * 100.0,
            d_iowait as f64 / d_total as f64 * 100.0,
        )
    };

    let stdout = format!(
        "CPU utilization (sampled over {}ms):\n  busy: {busy:.1}%\n  iowait: {iowait:.1}%",
        SAMPLE_INTERVAL.as_millis()
    );
    CommandOutcome::Ok(OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// One `(interface, rx_bytes, tx_bytes)` per non-loopback interface.
async fn read_net_bytes() -> Option<Vec<(String, u64, u64)>> {
    let content = tokio::fs::read_to_string("/proc/net/dev").await.ok()?;
    let mut out = Vec::new();
    for line in content.lines() {
        if let Some((iface, rest)) = line.split_once(':') {
            let iface = iface.trim();
            if iface.is_empty() || iface == "lo" {
                continue;
            }
            let f: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|t| t.parse().ok())
                .collect();
            // /proc/net/dev columns: rx_bytes is [0], tx_bytes is [8].
            if f.len() >= 9 {
                out.push((iface.to_string(), f[0], f[8]));
            }
        }
    }
    Some(out)
}

fn kb_per_sec(bytes: u64, secs: f64) -> f64 {
    (bytes as f64 / 1024.0 / secs * 10.0).round() / 10.0
}

/// Per-interface receive/transmit rates, from the delta between two
/// `/proc/net/dev` snapshots. The `total:` line is always in KB/s so the
/// control plane can parse it; per-interface lines are informational.
pub async fn network_throughput() -> CommandOutcome {
    let a = match read_net_bytes().await {
        Some(x) => x,
        None => return CommandOutcome::Err("could not read /proc/net/dev".to_string()),
    };
    tokio::time::sleep(SAMPLE_INTERVAL).await;
    let b = match read_net_bytes().await {
        Some(x) => x,
        None => return CommandOutcome::Err("could not read /proc/net/dev".to_string()),
    };

    let secs = SAMPLE_INTERVAL.as_secs_f64();
    let (mut total_rx, mut total_tx) = (0.0, 0.0);
    let mut lines = Vec::new();
    for (iface, rx1, tx1) in &a {
        if let Some((_, rx2, tx2)) = b.iter().find(|(n, _, _)| n == iface) {
            let rx = kb_per_sec(rx2.saturating_sub(*rx1), secs);
            let tx = kb_per_sec(tx2.saturating_sub(*tx1), secs);
            total_rx += rx;
            total_tx += tx;
            lines.push(format!("  {iface}: rx {rx} KB/s, tx {tx} KB/s"));
        }
    }

    let total_rx = (total_rx * 10.0).round() / 10.0;
    let total_tx = (total_tx * 10.0).round() / 10.0;
    let body = if lines.is_empty() {
        "  (no non-loopback interfaces)".to_string()
    } else {
        lines.join("\n")
    };
    let stdout = format!(
        "Network throughput (sampled over {}ms):\n  total: rx {total_rx} KB/s, tx {total_tx} KB/s\n{body}",
        SAMPLE_INTERVAL.as_millis()
    );
    CommandOutcome::Ok(OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

fn max_temp_from_sensors(out: &str) -> Option<f64> {
    out.split_whitespace()
        .filter_map(|tok| {
            tok.trim_start_matches('+')
                .strip_suffix("\u{00b0}C")
                .and_then(|t| t.parse::<f64>().ok())
        })
        .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.max(v))))
}

async fn read_thermal_zones() -> Vec<(String, f64)> {
    let mut out = Vec::new();
    let mut dir = match tokio::fs::read_dir("/sys/class/thermal").await {
        Ok(d) => d,
        Err(_) => return out,
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("thermal_zone") {
            continue;
        }
        let base = entry.path();
        // /sys temps are in millidegrees Celsius.
        if let Ok(raw) = tokio::fs::read_to_string(base.join("temp")).await
            && let Ok(milli) = raw.trim().parse::<f64>()
        {
            let label = tokio::fs::read_to_string(base.join("type"))
                .await
                .map(|s| s.trim().to_string())
                .unwrap_or(name);
            out.push((label, milli / 1000.0));
        }
    }
    out
}

/// Thermal readings, preferring `lm-sensors` when present and falling back to
/// `/sys/class/thermal`, rather than assuming either -- the same
/// detect-don't-assume approach the firewall and MAC checks take. Emits a
/// `Max temperature: N C` line the control plane parses.
pub async fn thermal_sensors() -> CommandOutcome {
    if command_exists("sensors").await {
        return match run_command("sensors", &[]).await {
            Ok(o) => {
                let header = match max_temp_from_sensors(&o.stdout) {
                    Some(m) => format!("Max temperature: {m:.1} C\n\n"),
                    None => String::new(),
                };
                CommandOutcome::Ok(OperationOutput {
                    stdout: format!("{header}{}", o.stdout.trim_end()),
                    stderr: String::new(),
                    exit_code: Some(0),
                })
            }
            Err(e) => CommandOutcome::Err(e),
        };
    }

    let zones = read_thermal_zones().await;
    if zones.is_empty() {
        return CommandOutcome::Ok(OperationOutput {
            stdout: "No thermal sensors available (no lm-sensors and no /sys/class/thermal zones)."
                .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }
    let max = zones.iter().map(|(_, t)| *t).fold(f64::MIN, f64::max);
    let mut stdout = format!("Max temperature: {max:.1} C\n\nThermal zones:\n");
    for (label, temp) in &zones {
        stdout.push_str(&format!("  {label}: {temp:.1} C\n"));
    }
    CommandOutcome::Ok(OperationOutput {
        stdout: stdout.trim_end().to_string(),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

fn psi_some_avg10(content: &str) -> Option<f64> {
    content
        .lines()
        .find(|l| l.trim_start().starts_with("some"))
        .and_then(|l| l.split_whitespace().find_map(|t| t.strip_prefix("avg10=")))
        .and_then(|v| v.parse::<f64>().ok())
}

/// Pressure Stall Information (PSI): how much time tasks stalled waiting on
/// memory, IO, and CPU (the `some`/avg10 figure). A better "is this host
/// actually struggling" signal than raw utilization. Absent on kernels
/// before 4.20 or with `CONFIG_PSI` off, which is reported plainly.
pub async fn memory_pressure() -> CommandOutcome {
    let mem = tokio::fs::read_to_string("/proc/pressure/memory")
        .await
        .ok();
    let io = tokio::fs::read_to_string("/proc/pressure/io").await.ok();
    let cpu = tokio::fs::read_to_string("/proc/pressure/cpu").await.ok();

    if mem.is_none() && io.is_none() && cpu.is_none() {
        return CommandOutcome::Ok(OperationOutput {
            stdout:
                "Pressure Stall Information not available (kernel < 4.20 or CONFIG_PSI disabled)."
                    .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        });
    }

    let fmt = |c: &Option<String>| {
        c.as_ref()
            .and_then(|s| psi_some_avg10(s))
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "n/a".to_string())
    };
    let stdout = format!(
        "Pressure Stall Information (some, avg10 %):\n  memory: {}\n  io: {}\n  cpu: {}",
        fmt(&mem),
        fmt(&io),
        fmt(&cpu)
    );
    CommandOutcome::Ok(OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

pub async fn failed_services(elevation: &ElevationState) -> CommandOutcome {
    match init_system::detect().await {
        InitSystem::Systemd => match elevation
            .run("systemctl", &["--failed", "--no-pager"])
            .await
        {
            Ok(output) => CommandOutcome::Ok(output),
            Err(e) => CommandOutcome::Err(e),
        },
        InitSystem::Other => CommandOutcome::Ok(OperationOutput {
            stdout: "No systemd on this host -- failed-unit reporting only applies to systemd."
                .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }),
    }
}
