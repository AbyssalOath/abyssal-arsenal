//! Scourge agent engine: network IDS/IPS sensor operations. Linux-only
//! (Suricata today, behind an `Engine` enum so Snort/Zeek can be added as
//! further variants + match arms, the same way `firewall.rs` handles backends).
//! Every public op has a `#[cfg(not(target_os = "linux"))]` stub that returns a
//! clean `process::platform_unsupported()` -- there is no Windows sensor.
//!
//! The read ops here are built to work from **file permissions alone** wherever
//! possible: the unattended collection sweep (`ScourgeCollectEvents`) cannot
//! rely on Apotheosis elevation (that's human-triggered and time-boxed), so it
//! reads `eve.json` directly and, if it can't, returns a single
//! `unreadable\t<reason>` line the control plane surfaces as a "needs
//! permissions" state rather than a hard error.

#[cfg(not(target_os = "linux"))]
mod stubs {
    use abyssal_agent_protocol::CommandOutcome;

    use crate::elevation::ElevationState;

    pub async fn sensor_status() -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn collect_events(_offset: u64, _inode: u64, _max_events: u32) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn list_rules(_query: String) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn pcap_list() -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn install(_e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn apply_config(
        _ifaces: Vec<String>,
        _home: String,
        _ext: String,
        _eve: bool,
        _e: &ElevationState,
    ) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn service_action(_verb: String, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn update_rules(_e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn set_sid_enabled(_sid: u32, _enabled: bool, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn suppress_sid(_sid: u32, _suppress: bool, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn rule_test(_pcap_name: String, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn capture_start(
        _bpf: String,
        _max_seconds: u32,
        _max_mb: u32,
        _retention_days: u32,
        _max_total_mb: u32,
        _e: &ElevationState,
    ) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn capture_status(_id: String, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn capture_cancel(_id: String, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn pcap_delete(_name: String, _passes: u8, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn ips_status(_e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn set_mode(_ips: bool, _cp: &str, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
    pub async fn set_sid_action(_sid: u32, _action: String, _e: &ElevationState) -> CommandOutcome {
        crate::process::platform_unsupported()
    }
}

#[cfg(not(target_os = "linux"))]
pub use stubs::{
    apply_config, capture_cancel, capture_start, capture_status, collect_events, install,
    ips_status, list_rules, pcap_delete, pcap_list, rule_test, sensor_status, service_action,
    set_mode, set_sid_action, set_sid_enabled, suppress_sid, update_rules,
};

#[cfg(target_os = "linux")]
pub use linux::{
    apply_config, capture_cancel, capture_start, capture_status, collect_events, install,
    ips_status, list_rules, pcap_delete, pcap_list, rule_test, sensor_status, service_action,
    set_mode, set_sid_action, set_sid_enabled, suppress_sid, update_rules,
};

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::MetadataExt;

    use abyssal_agent_protocol::{CommandOutcome, OperationOutput};
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

    use crate::elevation::ElevationState;
    use crate::init_system::{self, InitSystem};
    use crate::process::{self, command_exists, run_command_allow_failure};

    // Well-known Suricata paths. Detection prefers these artifacts over a PATH
    // probe, matching `init_system.rs`'s "detect the thing the tool creates"
    // reasoning. These are the upstream defaults on every major distro.
    const SURICATA_YAML: &str = "/etc/suricata/suricata.yaml";
    const SURICATA_LIB_DIR: &str = "/var/lib/suricata";
    const RULES_FILE: &str = "/var/lib/suricata/rules/suricata.rules";
    const EVE_PATH: &str = "/var/log/suricata/eve.json";
    const LOG_DIR: &str = "/var/log/suricata";
    /// Scourge's own root-owned state directory and permission-restricted
    /// capture directory. Pcaps never leave the host; the control plane only ever
    /// sees metadata. Work dirs (e.g. offline rule-test output) are created under
    /// the state dir via `mktemp -d`, never in world-writable `/tmp`.
    const SCOURGE_LIB_DIR: &str = "/var/lib/abyssal-arsenal/scourge";
    const PCAP_DIR: &str = "/var/lib/abyssal-arsenal/scourge/pcaps";

    /// Hard caps so a single collection pull can never read an unbounded file
    /// into memory or produce an unbounded message.
    const MAX_PULL_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_LINE_BYTES: usize = 256 * 1024;

    /// Which IDS/IPS engine is present. One variant today; adding Snort/Zeek is
    /// a new variant plus match arms, never a new detection path per call site.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Engine {
        Suricata,
    }

    const NO_ENGINE: &str = "No IDS/IPS engine detected (checked for Suricata's config, state dir, and binary). \
         Install one via Apothecary first.";

    async fn detect() -> Option<Engine> {
        if tokio::fs::metadata(SURICATA_YAML).await.is_ok()
            || tokio::fs::metadata(SURICATA_LIB_DIR).await.is_ok()
            || command_exists("suricata").await
        {
            return Some(Engine::Suricata);
        }
        None
    }

    fn ok(stdout: String) -> CommandOutcome {
        CommandOutcome::Ok(OperationOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }

    // ---- Sensor status -------------------------------------------------

    pub async fn sensor_status() -> CommandOutcome {
        let Some(engine) = detect().await else {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        };
        match engine {
            Engine::Suricata => suricata_status().await,
        }
    }

    async fn suricata_status() -> CommandOutcome {
        let mut out = String::new();
        out.push_str("Engine: Suricata\n");

        // Version (unprivileged).
        let version = run_command_allow_failure("suricata", &["-V"])
            .await
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_default();
        out.push_str(&format!(
            "Version: {}\n",
            if version.is_empty() {
                "unknown"
            } else {
                &version
            }
        ));

        // Running state (systemd is-active; non-zero exit means not-active, so
        // allow_failure and read the word).
        let running = if init_system::detect().await == InitSystem::Systemd {
            run_command_allow_failure("systemctl", &["is-active", "suricata"])
                .await
                .map(|o| o.stdout.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        } else {
            "unknown (no systemd)".to_string()
        };
        out.push_str(&format!("Service: {running}\n"));

        // Config path.
        let config_present = tokio::fs::metadata(SURICATA_YAML).await.is_ok();
        out.push_str(&format!(
            "Config: {}\n",
            if config_present {
                SURICATA_YAML
            } else {
                "not found"
            }
        ));

        // Monitored interfaces (best-effort grep of the config).
        let interfaces = run_command_allow_failure("grep", &["-E", "interface:", SURICATA_YAML])
            .await
            .map(|o| {
                o.stdout
                    .lines()
                    .filter_map(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "Interfaces: {}\n",
            if interfaces.is_empty() {
                "unknown (see config)".to_string()
            } else {
                interfaces
            }
        ));

        // Rule count (lines beginning with a rule action) + last update.
        let rule_count = run_command_allow_failure(
            "grep",
            &["-cE", "^(alert|drop|reject|pass|log)", RULES_FILE],
        )
        .await
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
        out.push_str(&format!(
            "Rules loaded: {}\n",
            if rule_count.is_empty() || rule_count == "0" {
                "0 (rules file missing or unreadable)".to_string()
            } else {
                rule_count
            }
        ));
        if let Ok(o) = run_command_allow_failure("stat", &["-c", "%y", RULES_FILE]).await
            && !o.stdout.trim().is_empty()
        {
            out.push_str(&format!("Last rule update: {}\n", o.stdout.trim()));
        }

        // EVE log readability -- the thing the unattended sweep depends on.
        let eve_state = match tokio::fs::File::open(EVE_PATH).await {
            Ok(_) => "readable".to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                "not found (is EVE JSON output enabled?)".to_string()
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                "UNREADABLE -- the agent needs read access to it for the collection sweep \
                 (run the agent as root, or grant read on the log dir)"
                    .to_string()
            }
            Err(e) => format!("unreadable: {e}"),
        };
        out.push_str(&format!("EVE log ({EVE_PATH}): {eve_state}\n"));

        // Disk usage of the log and pcap dirs.
        for (label, dir) in [("Log dir", LOG_DIR), ("Pcap dir", PCAP_DIR)] {
            let usage = run_command_allow_failure("du", &["-sh", dir])
                .await
                .ok()
                .and_then(|o| o.stdout.split_whitespace().next().map(str::to_string))
                .unwrap_or_else(|| "n/a".to_string());
            out.push_str(&format!("{label} usage: {usage}\n"));
        }

        ok(out)
    }

    // ---- Event collection (the sweep op) -------------------------------

    pub async fn collect_events(
        eve_offset: u64,
        eve_inode: u64,
        max_events: u32,
    ) -> CommandOutcome {
        // Stat first: distinguishes not-found from permission-denied so the
        // control plane can show the right "needs permissions" message.
        let meta = match tokio::fs::metadata(EVE_PATH).await {
            Ok(m) => m,
            Err(e) => return ok(format!("unreadable\t{}", unreadable_reason(&e))),
        };
        let cur_inode = meta.ino();
        let cur_size = meta.len();

        // Rotation / truncation detection: a changed inode, or a file now
        // smaller than our last offset, means we must restart from the top of
        // the current file -- never rewind into a rotated-away file, never
        // re-ingest from a stale offset.
        let start_offset = if eve_inode != 0 && cur_inode == eve_inode && cur_size >= eve_offset {
            eve_offset
        } else {
            0
        };

        let file = match tokio::fs::File::open(EVE_PATH).await {
            Ok(f) => f,
            Err(e) => return ok(format!("unreadable\t{}", unreadable_reason(&e))),
        };
        let mut reader = BufReader::new(file);
        if start_offset > 0
            && reader
                .seek(std::io::SeekFrom::Start(start_offset))
                .await
                .is_err()
        {
            // Seek failure -> treat as rotation, restart from the top next time.
            return ok(format!("cursor\t{cur_inode}\t0"));
        }

        let max_events = max_events.max(1);
        let mut pos = start_offset;
        let mut emitted = 0u32;
        let mut out = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            let n = match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(_) => break,
            };
            // A line without a trailing newline is a partial record still being
            // written: stop before it, leaving the offset at its start so the
            // next pull reads it whole.
            if !line.ends_with('\n') {
                break;
            }
            // Advance past this complete line regardless of whether it's an
            // alert, so non-alert EVE records don't get re-read next time.
            pos += n as u64;
            if n <= MAX_LINE_BYTES
                && let Some(alert) = parse_eve_alert_line(line.trim_end())
            {
                out.push_str(&alert);
                out.push('\n');
                emitted += 1;
                if emitted >= max_events {
                    break;
                }
            }
            // Bound one pull so a huge backlog can't be read entirely into
            // memory; the rest is picked up on the following sweeps.
            if pos.saturating_sub(start_offset) >= MAX_PULL_BYTES {
                break;
            }
        }

        out.push_str(&format!("cursor\t{cur_inode}\t{pos}"));
        ok(out)
    }

    fn unreadable_reason(e: &std::io::Error) -> String {
        match e.kind() {
            std::io::ErrorKind::NotFound => {
                "eve.json not found (enable EVE JSON output in the sensor config)".to_string()
            }
            std::io::ErrorKind::PermissionDenied => {
                "permission denied reading eve.json (run the agent as root or grant read access)"
                    .to_string()
            }
            other => format!("cannot read eve.json: {other:?}"),
        }
    }

    // ---- Rule listing / search -----------------------------------------

    pub async fn list_rules(query: String) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        let query = query.trim();
        if query.is_empty() {
            // No query: counts + a list of rule files.
            let count = run_command_allow_failure(
                "grep",
                &["-cE", "^(alert|drop|reject|pass|log)", RULES_FILE],
            )
            .await
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_else(|_| "0".to_string());
            let listing = run_command_allow_failure("ls", &["-1", "/var/lib/suricata/rules"])
                .await
                .map(|o| o.stdout)
                .unwrap_or_default();
            return ok(format!(
                "Rules loaded: {count}\nRule files:\n{}",
                if listing.trim().is_empty() {
                    "(none found)".to_string()
                } else {
                    listing
                }
            ));
        }
        // Length-cap the query; it's passed as a literal argv element (`-F`
        // fixed-string, `--` end-of-flags), never a shell string, so there's no
        // injection surface -- the cap is just to keep the match bounded.
        if query.len() > 128 {
            return CommandOutcome::Err("search query too long (max 128 chars)".to_string());
        }
        match run_command_allow_failure("grep", &["-F", "-i", "-n", "--", query, RULES_FILE]).await
        {
            Ok(o) if o.stdout.trim().is_empty() => ok(format!("No rules match \"{query}\".")),
            Ok(o) => ok(process::truncate_lines(o, 100).stdout),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    // ---- Pcap listing --------------------------------------------------

    pub async fn pcap_list() -> CommandOutcome {
        let mut entries = match tokio::fs::read_dir(PCAP_DIR).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return ok("No captures (no pcap directory yet).".to_string());
            }
            Err(e) => return CommandOutcome::Err(format!("cannot read pcap directory: {e}")),
        };
        let mut rows: Vec<String> = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".pcap") {
                continue;
            }
            let (size, mtime) = match entry.metadata().await {
                Ok(m) => (
                    m.len(),
                    run_command_allow_failure("stat", &["-c", "%y", &format!("{PCAP_DIR}/{name}")])
                        .await
                        .map(|o| o.stdout.trim().to_string())
                        .unwrap_or_default(),
                ),
                Err(_) => (0, String::new()),
            };
            rows.push(format!("{name}\t{size} bytes\t{mtime}"));
        }
        if rows.is_empty() {
            return ok("No captures.".to_string());
        }
        rows.sort();
        ok(rows.join("\n"))
    }

    // ---- EVE parsing (pure, unit-tested) -------------------------------

    /// Replaces field-separator and control characters with spaces and caps the
    /// length, so one field can never break the tab-delimited line format or
    /// blow up the message size.
    fn sanitize(s: &str, max: usize) -> String {
        let cleaned: String = s
            .chars()
            .map(|c| {
                if c == '\t' || c == '\n' || c == '\r' {
                    ' '
                } else {
                    c
                }
            })
            .take(max)
            .collect();
        cleaned
    }

    /// Maps Suricata's numeric alert severity (1 = highest) to Scourge/Thanatos
    /// severity keys.
    fn severity_key(sev: i64) -> &'static str {
        match sev {
            1 => "high",
            2 => "medium",
            _ => "low",
        }
    }

    /// Parses one EVE JSON line into a Scourge alert line, or `None` when the
    /// line isn't a well-formed `event_type == "alert"` record. Malformed JSON
    /// is skipped, never fatal.
    fn parse_eve_alert_line(line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        if v.get("event_type").and_then(|e| e.as_str()) != Some("alert") {
            return None;
        }
        let alert = v.get("alert")?;
        let ts = v.get("timestamp").and_then(|t| t.as_str()).unwrap_or("");
        let sev = alert.get("severity").and_then(|s| s.as_i64()).unwrap_or(3);
        let sid = alert
            .get("signature_id")
            .and_then(|s| s.as_i64())
            .unwrap_or(0);
        let signature = alert
            .get("signature")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        let category = alert.get("category").and_then(|s| s.as_str()).unwrap_or("");
        let proto = v.get("proto").and_then(|s| s.as_str()).unwrap_or("");
        let src_ip = v.get("src_ip").and_then(|s| s.as_str()).unwrap_or("");
        let dst_ip = v.get("dest_ip").and_then(|s| s.as_str()).unwrap_or("");
        let src_port = v.get("src_port").and_then(|p| p.as_i64()).unwrap_or(0);
        let dst_port = v.get("dest_port").and_then(|p| p.as_i64()).unwrap_or(0);

        Some(format!(
            "alert\t{ts}\t{sev}\t{sid}\t{sig}\t{cat}\t{proto}\t{src_ip}\t{src_port}\t{dst_ip}\t{dst_port}",
            ts = sanitize(ts, 64),
            sev = severity_key(sev),
            sig = sanitize(signature, 200),
            cat = sanitize(category, 100),
            proto = sanitize(proto, 16),
            src_ip = sanitize(src_ip, 64),
            dst_ip = sanitize(dst_ip, 64),
        ))
    }

    // ---- Mutating management ops (phase 4) -----------------------------
    //
    // Config/ruleset writes follow the Sepulchre discipline: write only
    // Scourge-owned include/override files (plus the one `include:` line the
    // engine needs in the main config), validate with `suricata -T` BEFORE
    // reloading, and restore-the-previous-and-reload on any validation/reload
    // failure, so a bad change can never be left half-applied. All require
    // elevation (Apotheosis `sudo -n`).

    const OVERRIDE_DIR: &str = "/etc/suricata/scourge.d";
    const OVERRIDE_FILE: &str = "/etc/suricata/scourge.d/overrides.yaml";
    const OVERRIDE_INCLUDE: &str = "scourge.d/overrides.yaml";
    const DISABLE_FILE: &str = "/etc/suricata/disable.conf";
    const THRESHOLD_FILE: &str = "/etc/suricata/threshold.conf";
    const MANAGED_HEADER: &str = "# Managed by Abyssal Arsenal (Scourge) -- do not edit by hand.";

    fn valid_interface(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 32
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '@'))
    }

    /// Suricata address-group value syntax is permissive (`any`, CIDRs, lists in
    /// `[...]`, negation `!`). Accept only that character set so the value we
    /// write into a YAML string can't break out of it; `suricata -T` is the real
    /// validator after.
    fn valid_address_group(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 512
            && s.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        '.' | ':' | ',' | '/' | '[' | ']' | '!' | ' ' | '-' | '$' | '_'
                    )
            })
    }

    /// A pcap filename must be a bare name (no path separators, no `..`) ending
    /// in `.pcap` -- prevents path traversal out of the capture directory.
    fn valid_pcap_name(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 128
            && s.ends_with(".pcap")
            && !s.contains('/')
            && !s.contains("..")
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    }

    async fn read_managed(path: &str, elevation: &ElevationState) -> String {
        // Missing file => empty baseline (matches Sepulchre's read_managed_file).
        elevation
            .run_allow_failure("cat", &[path])
            .await
            .map(|o| o.stdout)
            .unwrap_or_default()
    }

    async fn write_managed(
        path: &str,
        content: &str,
        elevation: &ElevationState,
    ) -> Result<(), String> {
        elevation
            .run_with_stdin("tee", &[path], content)
            .await
            .map(|_| ())
    }

    /// Reloads the sensor, preferring a rules-reload-in-place and falling back to
    /// a service reload.
    async fn reload(elevation: &ElevationState) -> Result<OperationOutput, String> {
        if init_system::detect().await != InitSystem::Systemd {
            return Err("service reload requires systemd on this host".to_string());
        }
        elevation.run("systemctl", &["reload", "suricata"]).await
    }

    async fn validate_config(elevation: &ElevationState) -> Result<OperationOutput, String> {
        // -T is config-test mode; allow_failure so we can read the diagnostics
        // on a non-zero exit rather than get a bare error.
        let out = elevation
            .run_allow_failure("suricata", &["-T", "-c", SURICATA_YAML])
            .await?;
        if out.exit_code == Some(0) {
            Ok(out)
        } else {
            Err(format!(
                "config validation failed:\n{}\n{}",
                out.stdout.trim(),
                out.stderr.trim()
            ))
        }
    }

    pub async fn install(elevation: &ElevationState) -> CommandOutcome {
        // Always via Apothecary's package backend, never a raw package call.
        crate::apothecary::install_package("suricata".to_string(), elevation).await
    }

    pub async fn apply_config(
        interfaces: Vec<String>,
        home_net: String,
        external_net: String,
        eve_enabled: bool,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        let home_net = home_net.trim();
        let external_net = external_net.trim();
        if !home_net.is_empty() && !valid_address_group(home_net) {
            return CommandOutcome::Err("invalid HOME_NET value".to_string());
        }
        if !external_net.is_empty() && !valid_address_group(external_net) {
            return CommandOutcome::Err("invalid EXTERNAL_NET value".to_string());
        }
        for iface in &interfaces {
            if !valid_interface(iface) {
                return CommandOutcome::Err(format!("invalid interface name: {iface}"));
            }
        }

        // Build the Scourge-owned override YAML. vars (maps) merge cleanly;
        // af-packet (a list) replaces the main interface list, which is exactly
        // "set interfaces"; outputs is only written when enabling EVE, and then
        // deliberately pins eve.json as the managed output.
        let mut yaml = format!("%YAML 1.1\n---\n{MANAGED_HEADER}\n");
        if !home_net.is_empty() || !external_net.is_empty() {
            yaml.push_str("vars:\n  address-groups:\n");
            if !home_net.is_empty() {
                yaml.push_str(&format!("    HOME_NET: \"{home_net}\"\n"));
            }
            if !external_net.is_empty() {
                yaml.push_str(&format!("    EXTERNAL_NET: \"{external_net}\"\n"));
            }
        }
        if !interfaces.is_empty() {
            yaml.push_str("af-packet:\n");
            for iface in &interfaces {
                yaml.push_str(&format!("  - interface: {iface}\n"));
            }
        }
        if eve_enabled {
            yaml.push_str(
                "outputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      types:\n        - alert\n",
            );
        }

        // Back up the current main config + override for rollback.
        let prev_main = read_managed(SURICATA_YAML, elevation).await;
        if prev_main.is_empty() {
            return CommandOutcome::Err(format!(
                "cannot read {SURICATA_YAML} (is the sensor installed?)"
            ));
        }
        let prev_override = read_managed(OVERRIDE_FILE, elevation).await;

        // Ensure the override dir + write the override file.
        let _ = elevation.run("mkdir", &["-p", OVERRIDE_DIR]).await;
        if let Err(e) = write_managed(OVERRIDE_FILE, &yaml, elevation).await {
            return CommandOutcome::Err(format!("failed to write override file: {e}"));
        }
        // Ensure the main config references the override (idempotent, minimal
        // one-line edit, backed up above).
        if !prev_main.contains(OVERRIDE_INCLUDE) {
            let new_main = format!("{prev_main}\ninclude: {OVERRIDE_INCLUDE}\n");
            if let Err(e) = write_managed(SURICATA_YAML, &new_main, elevation).await {
                return CommandOutcome::Err(format!("failed to add include to main config: {e}"));
            }
        }

        // Validate, then reload -- restoring on any failure.
        match validate_config(elevation).await {
            Ok(_) => match reload(elevation).await {
                Ok(o) => ok(format!(
                    "Applied sensor config and reloaded.\n{}",
                    o.stdout.trim()
                )),
                Err(e) => {
                    restore_config(&prev_main, &prev_override, elevation).await;
                    CommandOutcome::Err(format!(
                        "reload failed after applying config; restored the previous config: {e}"
                    ))
                }
            },
            Err(e) => {
                restore_config(&prev_main, &prev_override, elevation).await;
                CommandOutcome::Err(format!("{e}\nRestored the previous config (not applied)."))
            }
        }
    }

    async fn restore_config(prev_main: &str, prev_override: &str, elevation: &ElevationState) {
        let _ = write_managed(SURICATA_YAML, prev_main, elevation).await;
        if prev_override.is_empty() {
            // There was no override before -- remove the one we wrote.
            let _ = elevation.run("rm", &["-f", OVERRIDE_FILE]).await;
        } else {
            let _ = write_managed(OVERRIDE_FILE, prev_override, elevation).await;
        }
        let _ = reload(elevation).await;
    }

    pub async fn service_action(verb: String, elevation: &ElevationState) -> CommandOutcome {
        match verb.as_str() {
            "start" => crate::incarnation::start_service("suricata".to_string(), elevation).await,
            "stop" => crate::incarnation::stop_service("suricata".to_string(), elevation).await,
            "restart" => {
                crate::incarnation::restart_service("suricata".to_string(), elevation).await
            }
            "reload" => match reload(elevation).await {
                Ok(o) => ok(format!("Reloaded suricata.\n{}", o.stdout.trim())),
                Err(e) => CommandOutcome::Err(e),
            },
            other => CommandOutcome::Err(format!("unknown service action: {other}")),
        }
    }

    pub async fn update_rules(elevation: &ElevationState) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        let update = match elevation.run_allow_failure("suricata-update", &[]).await {
            Ok(o) => o,
            Err(e) => return CommandOutcome::Err(format!("suricata-update failed to run: {e}")),
        };
        // New rules are on disk but not live until a reload; validate first so a
        // bad feed never gets loaded (the running sensor keeps its old ruleset).
        match validate_config(elevation).await {
            Ok(_) => match reload(elevation).await {
                Ok(o) => ok(format!(
                    "Updated rules and reloaded.\n{}\n{}",
                    update.stdout.trim(),
                    o.stdout.trim()
                )),
                Err(e) => CommandOutcome::Err(format!(
                    "rules updated and validated, but reload failed (sensor still running previous ruleset): {e}"
                )),
            },
            Err(e) => CommandOutcome::Err(format!(
                "{e}\nUpdated rules failed validation; NOT reloaded (sensor still running the previous ruleset)."
            )),
        }
    }

    pub async fn set_sid_enabled(
        sid: u32,
        enabled: bool,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        // disable.conf lists SIDs suricata-update should drop from the compiled
        // ruleset. Disable => ensure the SID line is present; enable => remove it.
        let prev = read_managed(DISABLE_FILE, elevation).await;
        let line = sid.to_string();
        let mut lines: Vec<&str> = prev.lines().filter(|l| l.trim() != line).collect();
        let header_present = prev.lines().any(|l| l.trim() == MANAGED_HEADER);
        if !enabled {
            lines.push(&line);
        }
        let mut body = String::new();
        if !header_present {
            body.push_str(MANAGED_HEADER);
            body.push('\n');
        }
        body.push_str(&lines.join("\n"));
        if !body.ends_with('\n') {
            body.push('\n');
        }
        if let Err(e) = write_managed(DISABLE_FILE, &body, elevation).await {
            return CommandOutcome::Err(format!("failed to write disable list: {e}"));
        }
        // Recompile the ruleset honoring disable.conf, then validate + reload.
        let _ = elevation.run_allow_failure("suricata-update", &[]).await;
        match validate_config(elevation).await {
            Ok(_) => match reload(elevation).await {
                Ok(_) => ok(format!(
                    "SID {sid} {}.",
                    if enabled { "enabled" } else { "disabled" }
                )),
                Err(e) => CommandOutcome::Err(format!("applied, but reload failed: {e}")),
            },
            Err(e) => {
                // Restore the previous disable list and recompile.
                let _ = write_managed(DISABLE_FILE, &prev, elevation).await;
                let _ = elevation.run_allow_failure("suricata-update", &[]).await;
                CommandOutcome::Err(format!("{e}\nRestored the previous disable list."))
            }
        }
    }

    pub async fn suppress_sid(
        sid: u32,
        suppress: bool,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        let prev = read_managed(THRESHOLD_FILE, elevation).await;
        let line = format!("suppress gen_id 1, sig_id {sid}");
        let mut lines: Vec<&str> = prev.lines().filter(|l| l.trim() != line).collect();
        let header_present = prev.lines().any(|l| l.trim() == MANAGED_HEADER);
        if suppress {
            lines.push(&line);
        }
        let mut body = String::new();
        if !header_present {
            body.push_str(MANAGED_HEADER);
            body.push('\n');
        }
        body.push_str(&lines.join("\n"));
        if !body.ends_with('\n') {
            body.push('\n');
        }
        if let Err(e) = write_managed(THRESHOLD_FILE, &body, elevation).await {
            return CommandOutcome::Err(format!("failed to write threshold file: {e}"));
        }
        match validate_config(elevation).await {
            Ok(_) => match reload(elevation).await {
                Ok(_) => ok(format!(
                    "SID {sid} suppression {}.",
                    if suppress { "added" } else { "removed" }
                )),
                Err(e) => CommandOutcome::Err(format!("applied, but reload failed: {e}")),
            },
            Err(e) => {
                let _ = write_managed(THRESHOLD_FILE, &prev, elevation).await;
                let _ = reload(elevation).await;
                CommandOutcome::Err(format!("{e}\nRestored the previous threshold file."))
            }
        }
    }

    pub async fn rule_test(pcap_name: String, elevation: &ElevationState) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        if !valid_pcap_name(&pcap_name) {
            return CommandOutcome::Err(
                "invalid pcap name (expected a bare *.pcap filename in the capture directory)"
                    .to_string(),
            );
        }
        let pcap_path = format!("{PCAP_DIR}/{pcap_name}");

        // Create a unique, root-owned output dir atomically UNDER the Scourge
        // state dir -- never a fixed name in world-writable /tmp (which invites a
        // symlink/race). `mktemp -d` run via elevation is atomic and 0700-owned
        // by root; we use exactly the path it reports.
        let _ = elevation.run("mkdir", &["-p", SCOURGE_LIB_DIR]).await;
        let out_dir = match elevation
            .run(
                "mktemp",
                &["-d", &format!("{SCOURGE_LIB_DIR}/ruletest.XXXXXX")],
            )
            .await
        {
            Ok(o) => o.stdout.trim().to_string(),
            Err(e) => {
                return CommandOutcome::Err(format!("could not create a work directory: {e}"));
            }
        };
        // Defense-in-depth: only proceed with a path mktemp actually produced
        // under our own dir.
        if !out_dir.starts_with(&format!("{SCOURGE_LIB_DIR}/ruletest.")) {
            return CommandOutcome::Err("unexpected work directory path".to_string());
        }

        // Replay the pcap through the engine offline (never touching the live
        // sensor), then summarize.
        let run = elevation
            .run_allow_failure(
                "suricata",
                &[
                    "-r",
                    &pcap_path,
                    "-c",
                    SURICATA_YAML,
                    "-l",
                    &out_dir,
                    "-k",
                    "none",
                ],
            )
            .await;
        if let Err(e) = run {
            let _ = elevation.run("rm", &["-rf", &out_dir]).await;
            return CommandOutcome::Err(format!("offline replay failed: {e}"));
        }
        let fast = elevation
            .run_allow_failure("cat", &[&format!("{out_dir}/fast.log")])
            .await
            .map(|o| o.stdout)
            .unwrap_or_default();
        let count = fast.lines().filter(|l| !l.trim().is_empty()).count();
        let summary = process::truncate_lines(
            OperationOutput {
                stdout: fast,
                stderr: String::new(),
                exit_code: Some(0),
            },
            100,
        )
        .stdout;
        let _ = elevation.run("rm", &["-rf", &out_dir]).await;
        ok(format!(
            "Replayed {pcap_name} against the current ruleset: {count} alert(s).\n{summary}"
        ))
    }

    // ---- Packet capture (phase 5) --------------------------------------
    //
    // Captures are bounded (a hard `timeout` duration cap + tcpdump's own file
    // size cap) and run detached via `setsid --fork` -- which forks the capture
    // into its own session (surviving an agent restart) and returns immediately,
    // so the dispatch doesn't block for the capture's lifetime. A capture is
    // identified by its id (and the unique pcap path it writes), so status/cancel
    // need no pid tracking. Pcaps never leave the host.

    /// A BPF filter: alphanumerics + the operators/punctuation tcpdump's filter
    /// language uses, but no shell metacharacters, quotes, or newlines. It is
    /// split on whitespace and passed as separate argv elements (never a shell
    /// string); tcpdump compiles it and rejects anything malformed.
    fn valid_bpf(s: &str) -> bool {
        s.len() <= 1024
            && s.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        ' ' | '.'
                            | ':'
                            | '/'
                            | '('
                            | ')'
                            | '['
                            | ']'
                            | '!'
                            | '&'
                            | '|'
                            | '<'
                            | '>'
                            | '='
                            | '-'
                            | ','
                    )
            })
            // No token may start with '-', so a filter term can never be
            // smuggled in as a tcpdump flag (e.g. `-z <cmd>`, `-r <file>`) --
            // argv flag injection. `--` is also inserted before the filter at
            // the call site as a second line of defense.
            && !s.split_whitespace().any(|t| t.starts_with('-'))
    }

    fn valid_capture_id(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 128
            && !s.contains("..")
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    }

    fn epoch_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Enforces the capture-directory caps BEFORE a new capture: deletes pcaps
    /// older than `retention_days`, then deletes the oldest until the total is
    /// under `max_total_mb`. Best-effort (never fails the capture).
    async fn enforce_pcap_caps(retention_days: u32, max_total_mb: u32, elevation: &ElevationState) {
        // Any capture left past its size cap (its watcher gone with an agent
        // restart): stop it and drop its overflow files.
        let overflow = elevation
            .run_allow_failure(
                "find",
                &[
                    PCAP_DIR,
                    "-maxdepth",
                    "1",
                    "-name",
                    "*.pcap1",
                    "-printf",
                    "%f\\n",
                ],
            )
            .await
            .map(|o| o.stdout)
            .unwrap_or_default();
        for name in overflow.lines() {
            if let Some(base) = name.strip_suffix('1')
                && valid_pcap_name(base)
            {
                stop_if_capped(&format!("{PCAP_DIR}/{base}"), elevation).await;
            }
        }
        if retention_days > 0 {
            let age = format!("+{retention_days}");
            let _ = elevation
                .run_allow_failure(
                    "find",
                    &[
                        PCAP_DIR,
                        "-maxdepth",
                        "1",
                        "-name",
                        "*.pcap",
                        "-mtime",
                        &age,
                        "-delete",
                    ],
                )
                .await;
        }
        if max_total_mb == 0 {
            return;
        }
        // `find -printf` gives "<mtime>\t<size>\t<name>" per pcap, no shell pipe.
        let listing = elevation
            .run_allow_failure(
                "find",
                &[
                    PCAP_DIR,
                    "-maxdepth",
                    "1",
                    "-name",
                    "*.pcap",
                    "-printf",
                    "%T@\\t%s\\t%f\\n",
                ],
            )
            .await
            .map(|o| o.stdout)
            .unwrap_or_default();
        let mut files: Vec<(f64, u64, String)> = listing
            .lines()
            .filter_map(|l| {
                let mut p = l.split('\t');
                let mtime = p.next()?.parse::<f64>().ok()?;
                let size = p.next()?.parse::<u64>().ok()?;
                let name = p.next()?.to_string();
                Some((mtime, size, name))
            })
            .collect();
        files.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let cap_bytes = u64::from(max_total_mb) * 1_000_000;
        let mut total: u64 = files.iter().map(|f| f.1).sum();
        for (_, size, name) in &files {
            if total <= cap_bytes {
                break;
            }
            if !valid_pcap_name(name) {
                continue;
            }
            let _ = elevation
                .run_allow_failure("rm", &["-f", &format!("{PCAP_DIR}/{name}")])
                .await;
            total = total.saturating_sub(*size);
        }
    }

    pub async fn capture_start(
        bpf: String,
        max_seconds: u32,
        max_mb: u32,
        retention_days: u32,
        max_total_mb: u32,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if !command_exists("tcpdump").await {
            return CommandOutcome::Err(
                "tcpdump is not installed (install it via Apothecary first)".to_string(),
            );
        }
        if !valid_bpf(&bpf) {
            return CommandOutcome::Err("invalid BPF filter".to_string());
        }
        let secs = max_seconds.clamp(1, 3600);
        let mb = max_mb.clamp(1, 1024);

        let _ = elevation.run("mkdir", &["-p", PCAP_DIR]).await;
        let _ = elevation.run("chmod", &["700", PCAP_DIR]).await;
        enforce_pcap_caps(retention_days, max_total_mb, elevation).await;

        let id = format!("capture-{}", epoch_secs());
        let pcap = format!("{PCAP_DIR}/{id}.pcap");
        let meta = format!("{PCAP_DIR}/{id}.meta");
        let meta_body = format!("started={}\nmax_seconds={secs}\n", epoch_secs());
        if let Err(e) = write_managed(&meta, &meta_body, elevation).await {
            return CommandOutcome::Err(format!("failed to write capture metadata: {e}"));
        }

        let secs_s = secs.to_string();
        let mb_s = mb.to_string();
        // setsid --fork detaches the capture into its own session and returns
        // immediately; `timeout` hard-caps the duration; tcpdump's -C/-W cap the
        // file size.
        let mut args: Vec<String> = vec![
            "--fork".into(),
            "timeout".into(),
            "--kill-after=5".into(),
            secs_s,
            "tcpdump".into(),
            "-i".into(),
            "any".into(),
            "-w".into(),
            pcap.clone(),
            "-s".into(),
            "0".into(),
            // -C rotates at the cap: the moment `<pcap>1` appears, the first
            // file holds exactly the first N MB, and `watch_capture` stops
            // tcpdump and discards the overflow ("stop at N MB"). Not -W: a
            // ring buffer would overwrite the start of the capture, and -W
            // also renames the first file to `<pcap>0`.
            "-C".into(),
            mb_s,
            "-n".into(),
            // End of tcpdump options: everything after is the filter expression,
            // so a filter term can't be parsed as a flag even if one slipped the
            // validator.
            "--".into(),
        ];
        for tok in bpf.split_whitespace() {
            args.push(tok.to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match elevation.run("setsid", &arg_refs).await {
            Ok(_) => {
                tokio::spawn(watch_capture(pcap, secs, elevation.clone()));
                ok(id)
            }
            Err(e) => CommandOutcome::Err(format!("failed to start capture: {e}")),
        }
    }

    /// The size cap, enforced: polls until the capture ends (time limit,
    /// cancel) or tcpdump rotates to `<pcap>1` -- the first file is then
    /// full -- and stops it there. Bounded by the capture's own time limit.
    /// If the agent restarts mid-capture this task is gone; `capture_status`
    /// and `enforce_pcap_caps` call `stop_if_capped` too, so the next status
    /// check or capture tidies up instead.
    async fn watch_capture(pcap: String, max_seconds: u32, elevation: ElevationState) {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(u64::from(max_seconds) + 10);
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if stop_if_capped(&pcap, &elevation).await || !capture_running(&pcap, &elevation).await
            {
                return;
            }
        }
    }

    async fn capture_running(pcap: &str, elevation: &ElevationState) -> bool {
        elevation
            .run_allow_failure("pgrep", &["-f", pcap])
            .await
            .map(|o| !o.stdout.trim().is_empty())
            .unwrap_or(false)
    }

    /// If `<pcap>` has reached its size cap (tcpdump rotated to `<pcap>1`):
    /// stop the capture and delete the overflow file(s), keeping the first N
    /// MB in `<pcap>`. Returns whether it stopped one.
    async fn stop_if_capped(pcap: &str, elevation: &ElevationState) -> bool {
        let overflow = format!("{pcap}1");
        let rotated = elevation
            .run_allow_failure("stat", &["-c", "%s", &overflow])
            .await
            .is_ok_and(|o| o.exit_code == Some(0));
        if !rotated {
            return false;
        }
        let _ = elevation
            .run_allow_failure("pkill", &["-TERM", "-f", pcap])
            .await;
        let Some(name) = pcap.rsplit('/').next() else {
            return true;
        };
        // `<name>1`, `<name>2`, ...: find's own pattern, no shell glob.
        let _ = elevation
            .run_allow_failure(
                "find",
                &[
                    PCAP_DIR,
                    "-maxdepth",
                    "1",
                    "-name",
                    &format!("{name}[0-9]*"),
                    "-delete",
                ],
            )
            .await;
        true
    }

    pub async fn capture_status(capture_id: String, elevation: &ElevationState) -> CommandOutcome {
        if !valid_capture_id(&capture_id) {
            return CommandOutcome::Err("invalid capture id".to_string());
        }
        let pcap = format!("{PCAP_DIR}/{capture_id}.pcap");
        let meta = format!("{PCAP_DIR}/{capture_id}.meta");
        // Backstop for the size cap if the watcher didn't survive (agent
        // restart): stop it here instead.
        stop_if_capped(&pcap, elevation).await;
        // Running if a process has the unique pcap path in its command line.
        let running = capture_running(&pcap, elevation).await;
        let size = elevation
            .run_allow_failure("stat", &["-c", "%s", &pcap])
            .await
            .ok()
            .and_then(|o| o.stdout.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let meta_body = read_managed(&meta, elevation).await;
        let mut started = 0u64;
        let mut max_seconds = 0u64;
        for line in meta_body.lines() {
            if let Some(v) = line.strip_prefix("started=") {
                started = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("max_seconds=") {
                max_seconds = v.trim().parse().unwrap_or(0);
            }
        }
        let elapsed = epoch_secs().saturating_sub(started);
        let remaining = max_seconds.saturating_sub(elapsed);
        let state = if running { "running" } else { "done" };
        ok(format!("status\t{state}\t{elapsed}\t{size}\t{remaining}"))
    }

    pub async fn capture_cancel(capture_id: String, elevation: &ElevationState) -> CommandOutcome {
        if !valid_capture_id(&capture_id) {
            return CommandOutcome::Err("invalid capture id".to_string());
        }
        let pcap = format!("{PCAP_DIR}/{capture_id}.pcap");
        // Kill whatever is writing this unique pcap path.
        let _ = elevation
            .run_allow_failure("pkill", &["-TERM", "-f", &pcap])
            .await;
        ok(format!("Capture {capture_id} cancelled."))
    }

    pub async fn pcap_delete(
        pcap_name: String,
        shred_passes: u8,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if !valid_pcap_name(&pcap_name) {
            return CommandOutcome::Err("invalid pcap name".to_string());
        }
        if let Err(e) = crate::shred::validate_passes(shred_passes) {
            return CommandOutcome::Err(e);
        }
        let pcap = format!("{PCAP_DIR}/{pcap_name}");
        let removed = if shred_passes == 0 {
            elevation.run("rm", &["-f", &pcap]).await
        } else {
            let args = crate::shred::shred_args(&pcap, shred_passes);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            elevation.run("shred", &args).await
        };
        match removed {
            Ok(_) => {
                // Also drop the sidecar meta if present (best-effort).
                if let Some(stem) = pcap_name.strip_suffix(".pcap") {
                    let _ = elevation
                        .run_allow_failure("rm", &["-f", &format!("{PCAP_DIR}/{stem}.meta")])
                        .await;
                }
                ok(format!(
                    "{} {pcap_name}.",
                    abyssal_agent_protocol::shred_verb(shred_passes)
                ))
            }
            Err(e) => CommandOutcome::Err(format!("failed to delete pcap: {e}")),
        }
    }

    // ---- IPS: inline mode + per-SID drop/reject (phase 6) --------------
    //
    // The highest-risk capability, so it is the most conservative. Enabling
    // inline mode FIRST installs mandatory always-allow lockout rules (loopback,
    // established, the control plane, and SSH) at BOTH the netfilter layer (an
    // iptables ACCEPT bypass before the NFQUEUE jump) and the rule layer
    // (Suricata `pass` rules), derived from the agent's own control-plane address
    // -- never the wire -- so an inline drop can never sever the management
    // channel. Everything validates before reload and rolls back to passive IDS
    // on any failure. Inline hookup is vendor/kernel-dependent (NFQUEUE); the
    // rollback is what keeps a bad enable safe.

    use std::net::IpAddr;

    const IPS_RULES_FILE: &str = "/etc/suricata/scourge.d/scourge-ips.rules";
    const IPS_INCLUDE_FILE: &str = "/etc/suricata/scourge.d/scourge-ips.yaml";
    const IPS_INCLUDE_REF: &str = "scourge.d/scourge-ips.yaml";
    const MODE_FILE: &str = "/etc/suricata/scourge.d/mode";
    const MODIFY_FILE: &str = "/etc/suricata/modify.conf";
    const DROPIN_DIR: &str = "/etc/systemd/system/suricata.service.d";
    const DROPIN_FILE: &str = "/etc/systemd/system/suricata.service.d/50-scourge-ips.conf";
    const IPS_CHAIN: &str = "SCOURGE_IPS";
    const NFQUEUE_NUM: &str = "0";

    fn valid_sid_action(a: &str) -> bool {
        matches!(a, "alert" | "drop" | "reject")
    }

    /// The mandatory always-allow rules (pure, so they can be unit-tested). These
    /// `pass` rules are evaluated ahead of any `drop`, so inline enforcement can
    /// never block the control plane or SSH. SIDs are in a high reserved range.
    fn always_allow_rules(cp_ip: IpAddr) -> String {
        format!(
            "{MANAGED_HEADER}\n\
             # Always-allow lockout rules -- inline drops can never match these.\n\
             pass ip {cp} any -> any any (msg:\"Scourge allow control-plane (to)\"; sid:3200001; rev:1;)\n\
             pass ip any any -> {cp} any (msg:\"Scourge allow control-plane (from)\"; sid:3200002; rev:1;)\n\
             pass tcp any any -> any 22 (msg:\"Scourge allow SSH (in)\"; sid:3200003; rev:1;)\n",
            cp = cp_ip,
        )
    }

    pub async fn ips_status(elevation: &ElevationState) -> CommandOutcome {
        let mode = read_managed(MODE_FILE, elevation).await;
        let mode = if mode.trim() == "ips" {
            "IPS (inline)"
        } else {
            "IDS (passive)"
        };
        let modify = read_managed(MODIFY_FILE, elevation).await;
        let promoted: Vec<&str> = modify
            .lines()
            .filter(|l| l.contains("\"drop\"") || l.contains("\"reject\""))
            .collect();
        let allow = read_managed(IPS_RULES_FILE, elevation).await;
        let lockout = if allow.contains("Scourge allow control-plane") {
            "present"
        } else {
            "NOT installed (passive mode, or never enabled)"
        };
        let mut out = format!("Mode: {mode}\nAlways-allow lockout rules: {lockout}\n");
        out.push_str(&format!(
            "Promoted SIDs (drop/reject): {}\n",
            promoted.len()
        ));
        for l in promoted.iter().take(100) {
            out.push_str(l);
            out.push('\n');
        }
        ok(out)
    }

    pub async fn set_sid_action(
        sid: u32,
        action: String,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        if !valid_sid_action(&action) {
            return CommandOutcome::Err("action must be alert, drop, or reject".to_string());
        }
        // modify.conf rewrites a rule's action during `suricata-update`. Keep any
        // non-Scourge lines; replace our line for this SID. Promoting to alert =
        // remove the override (the rule reverts to its shipped action).
        let prev = read_managed(MODIFY_FILE, elevation).await;
        let sid_prefix = format!("{sid} ");
        let mut lines: Vec<&str> = prev
            .lines()
            .filter(|l| !l.trim_start().starts_with(&sid_prefix))
            .collect();
        let new_line;
        if action != "alert" {
            new_line = format!("{sid} \"^(alert|drop|reject)\" \"{action}\"");
            lines.push(&new_line);
        }
        let header_present = prev.lines().any(|l| l.trim() == MANAGED_HEADER);
        let mut body = String::new();
        if !header_present {
            body.push_str(MANAGED_HEADER);
            body.push('\n');
        }
        body.push_str(&lines.join("\n"));
        if !body.ends_with('\n') {
            body.push('\n');
        }
        if let Err(e) = write_managed(MODIFY_FILE, &body, elevation).await {
            return CommandOutcome::Err(format!("failed to write modify list: {e}"));
        }
        let _ = elevation.run_allow_failure("suricata-update", &[]).await;
        match validate_config(elevation).await {
            Ok(_) => match reload(elevation).await {
                Ok(_) => ok(format!("SID {sid} action set to {action}.")),
                Err(e) => CommandOutcome::Err(format!("applied, but reload failed: {e}")),
            },
            Err(e) => {
                let _ = write_managed(MODIFY_FILE, &prev, elevation).await;
                let _ = elevation.run_allow_failure("suricata-update", &[]).await;
                CommandOutcome::Err(format!("{e}\nRestored the previous rule-action overrides."))
            }
        }
    }

    pub async fn set_mode(
        ips: bool,
        control_plane_host: &str,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if detect().await.is_none() {
            return CommandOutcome::Err(NO_ENGINE.to_string());
        }
        if !ips {
            revert_to_passive(elevation).await;
            return match reload_or_restart(elevation).await {
                Ok(_) => ok("Reverted to passive IDS.".to_string()),
                Err(e) => CommandOutcome::Err(format!(
                    "reverted the IPS config, but the service didn't come back cleanly: {e}"
                )),
            };
        }

        // --- Enable inline IPS ---
        let cp_ip = match crate::inquest::resolve_control_plane_ip(control_plane_host).await {
            Ok(ip) => ip,
            Err(e) => return CommandOutcome::Err(e),
        };
        let prev_main = read_managed(SURICATA_YAML, elevation).await;
        if prev_main.is_empty() {
            return CommandOutcome::Err(format!("cannot read {SURICATA_YAML}"));
        }

        // 1. Always-allow pass rules (rule layer) + an include that loads them.
        let _ = elevation.run("mkdir", &["-p", OVERRIDE_DIR]).await;
        if let Err(e) = write_managed(IPS_RULES_FILE, &always_allow_rules(cp_ip), elevation).await {
            return CommandOutcome::Err(format!("failed to write lockout rules: {e}"));
        }
        let include_yaml = format!(
            "%YAML 1.1\n---\n{MANAGED_HEADER}\nrule-files:\n  - suricata.rules\n  - scourge.d/scourge-ips.rules\n"
        );
        if let Err(e) = write_managed(IPS_INCLUDE_FILE, &include_yaml, elevation).await {
            return CommandOutcome::Err(format!("failed to write IPS include: {e}"));
        }
        if !prev_main.contains(IPS_INCLUDE_REF) {
            let new_main = format!("{prev_main}\ninclude: {IPS_INCLUDE_REF}\n");
            if let Err(e) = write_managed(SURICATA_YAML, &new_main, elevation).await {
                return CommandOutcome::Err(format!("failed to add IPS include to config: {e}"));
            }
        }

        // 2. Netfilter lockout bypass + NFQUEUE hook, IPv4 and IPv6, in the
        //    mangle table (see `nfqueue_rules`). cp/SSH/established ACCEPT come
        //    BEFORE the queue jump; --queue-bypass fails open if the sensor
        //    isn't listening, so a dead sensor never black-holes the host.
        let coverage = install_nfqueue(cp_ip, elevation).await;
        if !coverage.v4 && !coverage.v6 {
            revert_to_passive(elevation).await;
            let _ = write_managed(SURICATA_YAML, &prev_main, elevation).await;
            let _ = reload_or_restart(elevation).await;
            return CommandOutcome::Err(
                "couldn't install the netfilter (iptables/ip6tables) hook for inline mode -- \
                 inline IPS would inspect nothing; stayed in passive IDS"
                    .to_string(),
            );
        }
        // In NFQUEUE mode the sensor only sees queued packets: a family that
        // isn't hooked goes uninspected, so say so instead of implying full
        // coverage.
        let coverage_note = match (coverage.v4, coverage.v6) {
            (true, true) => String::new(),
            (true, false) => "\nNote: IPv6 isn't hooked (ip6tables unavailable or failed) -- IPv6 \
                              traffic is NOT inspected, not even alerted on, while inline IPS is \
                              on."
            .to_string(),
            (false, true) => "\nNote: IPv4 isn't hooked (iptables unavailable or failed) -- IPv4 \
                              traffic is NOT inspected, not even alerted on, while inline IPS is \
                              on."
            .to_string(),
            (false, false) => unreachable!("handled above"),
        };

        // 3. Run the sensor in NFQUEUE mode via a systemd drop-in.
        if let Err(e) = write_ips_dropin(elevation).await {
            revert_to_passive(elevation).await;
            let _ = write_managed(SURICATA_YAML, &prev_main, elevation).await;
            let _ = reload_or_restart(elevation).await;
            return CommandOutcome::Err(format!("failed to configure inline mode; reverted: {e}"));
        }
        let _ = write_managed(MODE_FILE, "ips\n", elevation).await;

        // 4. Validate, then (re)start. Roll back fully on any failure.
        match validate_config(elevation).await {
            Ok(_) => match restart(elevation).await {
                Ok(_) => ok(format!(
                    "Inline IPS enabled. Lockout rules allow the control plane ({cp_ip}) and SSH; \
                     the host's own firewall rules still apply. Promote individual SIDs to \
                     drop/reject after review; revert to passive IDS at any time.{coverage_note}"
                )),
                Err(e) => {
                    revert_to_passive(elevation).await;
                    let _ = write_managed(SURICATA_YAML, &prev_main, elevation).await;
                    let _ = restart(elevation).await;
                    CommandOutcome::Err(format!(
                        "service failed to start inline; reverted to passive IDS: {e}"
                    ))
                }
            },
            Err(e) => {
                revert_to_passive(elevation).await;
                let _ = write_managed(SURICATA_YAML, &prev_main, elevation).await;
                let _ = reload_or_restart(elevation).await;
                CommandOutcome::Err(format!("{e}\nReverted to passive IDS (not applied)."))
            }
        }
    }

    /// Removes everything inline mode installs -- the netfilter hook, the systemd
    /// drop-in -- and marks the mode passive. Best-effort (used on both an
    /// operator revert and an enable-failure rollback). The lockout rules file +
    /// include are left in place (harmless `pass` rules in passive mode).
    async fn revert_to_passive(elevation: &ElevationState) {
        remove_nfqueue(elevation).await;
        let _ = elevation
            .run_allow_failure("rm", &["-f", DROPIN_FILE])
            .await;
        let _ = elevation
            .run_allow_failure("systemctl", &["daemon-reload"])
            .await;
        let _ = write_managed(MODE_FILE, "ids\n", elevation).await;
    }

    /// Which address families inline IPS actually hooked -- reported to the
    /// operator, so "enabled" never overstates what's being inspected.
    struct NfqueueCoverage {
        v4: bool,
        v6: bool,
    }

    /// The netfilter rules for one family (`iptables` or `ip6tables`), each as
    /// that tool's argument list (pure, so it can be unit-tested).
    ///
    /// Everything lives in the **mangle** table. An ACCEPT there -- the
    /// lockout bypasses below, and Suricata's own accept verdict on a queued
    /// packet -- only ends the mangle table's traversal; the packet still goes
    /// on through the host's `filter` rules (ufw/firewalld, Cadavault's
    /// firewall, Inquest's isolation). In `filter`, an ACCEPT at the top of
    /// INPUT would be final and bypass all of them: enabling IPS would open
    /// SSH past the host firewall and keep established sessions alive through
    /// an Inquest isolation. A Suricata drop still drops.
    fn nfqueue_rules(tool: &str, cp_ip: IpAddr) -> Vec<Vec<String>> {
        let v6 = tool == "ip6tables";
        let rule = |args: &[&str]| -> Vec<String> {
            ["-t", "mangle"]
                .iter()
                .chain(args)
                .map(|a| a.to_string())
                .collect()
        };
        let mut rules = vec![
            rule(&["-N", IPS_CHAIN]),
            // Management traffic never reaches the inline engine at all.
            rule(&["-A", IPS_CHAIN, "-i", "lo", "-j", "ACCEPT"]),
            rule(&[
                "-A",
                IPS_CHAIN,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]),
        ];
        // The control plane, in whichever family its address is.
        if cp_ip.is_ipv6() == v6 {
            let cp = cp_ip.to_string();
            rules.push(rule(&["-A", IPS_CHAIN, "-s", &cp, "-j", "ACCEPT"]));
            rules.push(rule(&["-A", IPS_CHAIN, "-d", &cp, "-j", "ACCEPT"]));
        }
        // Inbound new SSH only (--dport 22). SSH reply traffic (packets *from*
        // port 22) is already covered by the ESTABLISHED,RELATED accept above,
        // so there is deliberately no `--sport 22` rule: a blanket
        // source-port-22 accept would let an attacker evade the entire inline
        // engine just by setting their source port to 22.
        rules.push(rule(&[
            "-A", IPS_CHAIN, "-p", "tcp", "--dport", "22", "-j", "ACCEPT",
        ]));
        // `--queue-bypass`: if the sensor isn't listening on the queue, traffic
        // passes instead of being black-holed (fail-open, never strand the host).
        rules.push(rule(&[
            "-A",
            IPS_CHAIN,
            "-j",
            "NFQUEUE",
            "--queue-num",
            NFQUEUE_NUM,
            "--queue-bypass",
        ]));
        for hook in ["INPUT", "FORWARD", "OUTPUT"] {
            rules.push(rule(&["-I", hook, "-j", IPS_CHAIN]));
        }
        rules
    }

    /// Installs the inline hook for IPv4 and IPv6. A family counts as covered
    /// only if all its rules applied; a family that failed partway is removed
    /// again rather than left half-hooked.
    async fn install_nfqueue(cp_ip: IpAddr, elevation: &ElevationState) -> NfqueueCoverage {
        // Clean rebuild: drop any prior chain first (either table -- older
        // builds put it in `filter`).
        remove_nfqueue(elevation).await;
        let mut covered = [false, false];
        for (slot, tool) in ["iptables", "ip6tables"].into_iter().enumerate() {
            if !command_exists(tool).await {
                continue;
            }
            let mut all_ok = true;
            for args in nfqueue_rules(tool, cp_ip) {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                let ok = elevation
                    .run_allow_failure(tool, &args)
                    .await
                    .is_ok_and(|o| o.exit_code == Some(0));
                if !ok {
                    all_ok = false;
                    break;
                }
            }
            if all_ok {
                covered[slot] = true;
            } else {
                remove_family(tool, elevation).await;
            }
        }
        NfqueueCoverage {
            v4: covered[0],
            v6: covered[1],
        }
    }

    async fn remove_nfqueue(elevation: &ElevationState) {
        for tool in ["iptables", "ip6tables"] {
            if command_exists(tool).await {
                remove_family(tool, elevation).await;
            }
        }
    }

    /// Unhooks and deletes the chain for one family, from `mangle` and from
    /// `filter` (where builds before this fix installed it). Best-effort.
    async fn remove_family(tool: &str, elevation: &ElevationState) {
        for table in ["mangle", "filter"] {
            for hook in ["INPUT", "FORWARD", "OUTPUT"] {
                let _ = elevation
                    .run_allow_failure(tool, &["-t", table, "-D", hook, "-j", IPS_CHAIN])
                    .await;
            }
            let _ = elevation
                .run_allow_failure(tool, &["-t", table, "-F", IPS_CHAIN])
                .await;
            let _ = elevation
                .run_allow_failure(tool, &["-t", table, "-X", IPS_CHAIN])
                .await;
        }
    }

    async fn write_ips_dropin(elevation: &ElevationState) -> Result<(), String> {
        // Discover the installed binary; fall back to the common path.
        let bin = elevation
            .run_allow_failure("which", &["suricata"])
            .await
            .ok()
            .map(|o| o.stdout.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/usr/bin/suricata".to_string());
        let _ = elevation.run("mkdir", &["-p", DROPIN_DIR]).await;
        let body = format!(
            "{MANAGED_HEADER}\n[Service]\nExecStart=\nExecStart={bin} -c {SURICATA_YAML} -q {NFQUEUE_NUM}\n"
        );
        write_managed(DROPIN_FILE, &body, elevation).await?;
        elevation
            .run("systemctl", &["daemon-reload"])
            .await
            .map(|_| ())
    }

    async fn restart(elevation: &ElevationState) -> Result<OperationOutput, String> {
        if init_system::detect().await != InitSystem::Systemd {
            return Err("service control requires systemd on this host".to_string());
        }
        elevation.run("systemctl", &["restart", "suricata"]).await
    }

    async fn reload_or_restart(elevation: &ElevationState) -> Result<OperationOutput, String> {
        // After removing a drop-in, a restart is needed to drop `-q`; prefer it.
        restart(elevation).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn alert_json() -> &'static str {
            r#"{"timestamp":"2026-01-02T03:04:05.000Z","event_type":"alert","proto":"TCP","src_ip":"10.0.0.5","src_port":44321,"dest_ip":"203.0.113.9","dest_port":443,"alert":{"severity":1,"signature_id":2001,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak"}}"#
        }

        #[test]
        fn parses_a_well_formed_alert() {
            let line = parse_eve_alert_line(alert_json()).expect("alert parses");
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f[0], "alert");
            assert_eq!(f[2], "high"); // severity 1 -> high
            assert_eq!(f[3], "2001"); // sid
            assert_eq!(f[4], "ET SCAN Potential SSH Scan");
            assert_eq!(f[5], "Attempted Information Leak");
            assert_eq!(f[6], "TCP");
            assert_eq!(f[7], "10.0.0.5");
            assert_eq!(f[8], "44321");
            assert_eq!(f[9], "203.0.113.9");
            assert_eq!(f[10], "443");
        }

        #[test]
        fn skips_non_alert_and_malformed_lines() {
            // A stats event is not an alert.
            assert!(parse_eve_alert_line(r#"{"event_type":"stats","stats":{}}"#).is_none());
            // A DNS event is not an alert.
            assert!(parse_eve_alert_line(r#"{"event_type":"dns"}"#).is_none());
            // Malformed JSON.
            assert!(parse_eve_alert_line("{not json").is_none());
            // Truncated/partial line.
            assert!(parse_eve_alert_line(r#"{"event_type":"al"#).is_none());
            // Empty.
            assert!(parse_eve_alert_line("").is_none());
        }

        #[test]
        fn missing_fields_default_without_breaking_the_line() {
            let line = parse_eve_alert_line(r#"{"event_type":"alert","alert":{"signature":"x"}}"#)
                .expect("parses");
            let f: Vec<&str> = line.split('\t').collect();
            // Exactly 11 tab-separated fields regardless of what's missing.
            assert_eq!(f.len(), 11);
            assert_eq!(f[2], "low"); // default severity -> low
            assert_eq!(f[3], "0"); // default sid
        }

        #[test]
        fn sanitize_strips_tabs_and_caps_length() {
            assert_eq!(sanitize("a\tb\nc", 10), "a b c");
            assert_eq!(sanitize("abcdef", 3), "abc");
        }

        #[test]
        fn embedded_tabs_in_signature_cannot_break_the_format() {
            let line = parse_eve_alert_line(
                r#"{"event_type":"alert","alert":{"signature":"evil\tinjected\tcols","severity":2,"signature_id":9}}"#,
            )
            .expect("parses");
            // Still exactly 11 fields -- the tabs in the signature were neutralized.
            assert_eq!(line.split('\t').count(), 11);
            assert_eq!(line.split('\t').nth(2), Some("medium"));
        }

        #[test]
        fn valid_interface_rejects_injection() {
            assert!(valid_interface("eth0"));
            assert!(valid_interface("ens3.100"));
            assert!(!valid_interface(""));
            assert!(!valid_interface("eth0; rm -rf /"));
            assert!(!valid_interface("a/b"));
            assert!(!valid_interface("$(id)"));
        }

        #[test]
        fn valid_address_group_allows_suricata_syntax_rejects_injection() {
            assert!(valid_address_group("any"));
            assert!(valid_address_group("[192.168.0.0/16,10.0.0.0/8]"));
            assert!(valid_address_group("!$HOME_NET"));
            assert!(!valid_address_group("192.168.0.0/16\nevil"));
            assert!(!valid_address_group("`id`"));
            assert!(!valid_address_group("\"; drop"));
        }

        #[test]
        fn valid_pcap_name_blocks_traversal() {
            assert!(valid_pcap_name("capture-1.pcap"));
            assert!(!valid_pcap_name("../../etc/passwd"));
            assert!(!valid_pcap_name("/etc/shadow"));
            assert!(!valid_pcap_name("foo.txt"));
            assert!(!valid_pcap_name("a/b.pcap"));
            assert!(!valid_pcap_name("x/../y.pcap"));
        }

        #[test]
        fn always_allow_rules_cover_control_plane_and_ssh() {
            let r = always_allow_rules("203.0.113.9".parse().unwrap());
            // Every line that enforces is a `pass` (never a drop), and the
            // control-plane IP + SSH are both covered.
            assert!(r.contains("pass ip 203.0.113.9 any -> any any"));
            assert!(r.contains("pass ip any any -> 203.0.113.9 any"));
            assert!(r.contains("pass tcp any any -> any 22"));
            assert!(!r.contains("drop "));
            // No blanket source-port-22 pass: it would let traffic evade the
            // inline engine simply by originating from port 22. SSH replies are
            // covered by the netfilter ESTABLISHED,RELATED accept instead.
            assert!(!r.contains("any 22 -> any any"));
        }

        #[test]
        fn nfqueue_rules_stay_in_mangle_and_never_bypass_the_host_firewall() {
            for (tool, cp) in [
                ("iptables", "10.0.0.5"),
                ("ip6tables", "10.0.0.5"),
                ("iptables", "fd00::5"),
                ("ip6tables", "fd00::5"),
            ] {
                let cp_ip: IpAddr = cp.parse().unwrap();
                let rules = nfqueue_rules(tool, cp_ip);
                // Every rule in mangle -- an ACCEPT in `filter` would skip the
                // host's own firewall.
                assert!(
                    rules.iter().all(|r| r[..2] == ["-t", "mangle"]),
                    "{tool}: {rules:?}"
                );
                // The control-plane bypass only in the family its address is.
                let has_cp = rules.iter().any(|r| r.contains(&cp.to_string()));
                assert_eq!(
                    has_cp,
                    cp_ip.is_ipv6() == (tool == "ip6tables"),
                    "{tool} {cp}"
                );
                // Never a source-port-22 bypass (evasion by source port).
                assert!(!rules.iter().any(|r| r.contains(&"--sport".to_string())));
                // The queue jump is fail-open and comes before the hooks.
                let queue = rules
                    .iter()
                    .position(|r| r.contains(&"NFQUEUE".to_string()))
                    .unwrap();
                assert!(rules[queue].contains(&"--queue-bypass".to_string()));
                let first_hook = rules
                    .iter()
                    .position(|r| r.get(2).is_some_and(|a| a == "-I"))
                    .unwrap();
                assert!(queue < first_hook);
            }
        }

        #[test]
        fn valid_sid_action_allowlist() {
            assert!(valid_sid_action("alert"));
            assert!(valid_sid_action("drop"));
            assert!(valid_sid_action("reject"));
            assert!(!valid_sid_action("pass"));
            assert!(!valid_sid_action("drop; rm"));
            assert!(!valid_sid_action(""));
        }

        #[test]
        fn valid_bpf_rejects_flag_injection() {
            assert!(valid_bpf("tcp port 443 and host 10.0.0.5"));
            assert!(valid_bpf("")); // empty = capture all
            assert!(valid_bpf("not (udp or arp)"));
            // A token starting with '-' would be a smuggled tcpdump flag.
            assert!(!valid_bpf("-z /tmp/evil.sh"));
            assert!(!valid_bpf("tcp -r /etc/passwd"));
            // Shell metacharacters are still rejected.
            assert!(!valid_bpf("tcp; rm -rf /"));
            assert!(!valid_bpf("tcp `id`"));
        }
    }
}
