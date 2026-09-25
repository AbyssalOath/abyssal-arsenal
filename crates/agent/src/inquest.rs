//! Active incident containment and remediation ("Inquest"): blocking a
//! remote IP, quarantining a suspicious file, and -- the most severe
//! action this whole agent can take -- isolating the host's network
//! entirely except for its own connection back to the control plane.
//!
//! Every other destructive operation in this codebase risks damage to
//! the managed host; `IsolateHost` uniquely risks severing the only
//! channel the control plane has to *fix* that damage, since the agent
//! itself is what's holding the connection this operation could cut.
//! `unix::nft_isolate`'s doc comment covers the specific race that
//! implementation goes out of its way to avoid; `windows::isolate_host`'s
//! doc comment covers the different (and not fully equivalent) risk
//! profile the Windows implementation has instead.
//!
//! Two platform implementations below, `unix` and `windows`, both
//! re-exported at this module's root so `crates/agent/src/ops.rs`'s
//! dispatch (`inquest::block_remote_ip`, etc.) never needs to know or
//! care which one it's actually calling -- the same pattern
//! `crates/agent/src/thanatos.rs` already established for
//! `scan_security_events`. On Unix, there's no single standard
//! packet-filtering interface, so both blocklist and isolation
//! operations detect and dispatch to whichever of nftables/iptables is
//! actually present, preferring nftables (`unix::Backend`, deliberately
//! separate from `firewall.rs`'s own, narrower one). On Windows, both go
//! through Windows Defender Firewall via PowerShell (`New-
//! NetFirewallRule`/`Set-NetFirewallProfile`), shelled out through
//! `powershell.exe` for the same reason `thanatos.rs`'s Windows path
//! does: no Windows machine in this crate's own test/CI loop to verify
//! unsafe native-API FFI against, and every other platform-specific data
//! source in this crate already goes through a CLI tool and text
//! parsing.
//!
//! `percent_encode`/`percent_decode` (quarantine filename encoding) and
//! `resolve_control_plane_ip` are shared by both platforms unchanged --
//! pure logic with no OS dependency. A Windows path round-trips through
//! the same `<unix_ts>__<percent-encoded path>` quarantine filename
//! scheme safely, since percent-encoding already escapes `\` and `:`.

use std::net::IpAddr;

// ---------------------------------------------------------------------
// Shared by both platforms -- pure logic, no OS dependency.
// ---------------------------------------------------------------------

/// Percent-encodes everything except the standard URL-safe unreserved
/// set, so the result is always a valid, single-path-segment filename --
/// most importantly, a `/` or `\` in the original path can never turn
/// into a filename that itself refers to a subdirectory or escapes one,
/// on either platform.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("malformed percent-encoding in quarantine filename".to_string());
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| "malformed percent-encoding in quarantine filename".to_string())?;
            let value = u8::from_str_radix(hex, 16)
                .map_err(|_| "malformed percent-encoding in quarantine filename".to_string())?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| {
        "malformed percent-encoding in quarantine filename (invalid utf-8)".to_string()
    })
}

/// Resolves the agent's own `--control-plane-url` host to a single IP,
/// for whichever platform's isolation implementation needs to carve out
/// an exception for it.
async fn resolve_control_plane_ip(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| format!("failed to resolve control plane host \"{host}\": {e}"))?;
    addrs
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| format!("DNS resolution for \"{host}\" returned no addresses"))
}

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

// =======================================================================
// Unix (Linux/BSD/...): nftables, preferring it, falling back to iptables.
// =======================================================================

#[cfg(unix)]
mod unix {
    use std::net::IpAddr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

    use crate::elevation::ElevationState;
    use crate::process::{command_exists, present};

    use super::{percent_decode, percent_encode, resolve_control_plane_ip};

    const QUARANTINE_DIR: &str = "/var/lib/abyssal-arsenal/quarantine";
    const BLOCKLIST_TABLE: &str = "abyssal_blocklist";
    const ISOLATION_TABLE: &str = "abyssal_isolation";
    const RULE_COMMENT: &str = "abyssal-arsenal-blocklist";

    const NO_BACKEND: &str = "No firewall backend detected (checked nftables, iptables) -- this operation needs one of them.";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Backend {
        Nft,
        Iptables,
    }

    async fn detect() -> Option<Backend> {
        if command_exists("nft").await {
            return Some(Backend::Nft);
        }
        if command_exists("iptables").await {
            return Some(Backend::Iptables);
        }
        None
    }

    // ---------------------------------------------------------------------
    // Quarantine
    // ---------------------------------------------------------------------

    pub async fn list_quarantined_files(elevation: &ElevationState) -> CommandOutcome {
        if tokio::fs::metadata(QUARANTINE_DIR).await.is_err() {
            return CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "No files quarantined yet -- {QUARANTINE_DIR} doesn't exist on this host."
                ),
                stderr: String::new(),
                exit_code: Some(0),
            });
        }
        match elevation
            .run_allow_failure(
                "find",
                &[
                    QUARANTINE_DIR,
                    "-maxdepth",
                    "1",
                    "-type",
                    "f",
                    "-printf",
                    "%f\t%s bytes\t%TY-%Tm-%Td %TH:%TM\n",
                ],
            )
            .await
        {
            Ok(output) => CommandOutcome::Ok(present(output, "No files quarantined.")),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    /// Moves `path` into the quarantine directory under a filename that
    /// encodes its own restoration destination (`<unix_ts>__<percent-encoded
    /// original path>`). This is deliberate: `RestoreQuarantinedFile` never
    /// accepts an admin-typed destination path -- doing so would make
    /// restore an arbitrary-file-write primitive. Instead the only "restore
    /// destination" that can ever exist is one this function itself produced
    /// by quarantining a real file from a real, validated absolute path.
    pub async fn quarantine_file(path: String, elevation: &ElevationState) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_absolute_path(&path) {
            return CommandOutcome::Err(format!("refusing invalid path: {path}"));
        }

        if let Err(e) = elevation.run("mkdir", &["-p", QUARANTINE_DIR]).await {
            return CommandOutcome::Err(format!("failed to create {QUARANTINE_DIR}: {e}"));
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let filename = format!("{timestamp}__{}", percent_encode(&path));
        let dest = format!("{QUARANTINE_DIR}/{filename}");

        match elevation.run("mv", &[path.as_str(), dest.as_str()]).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!("Quarantined {path} as {filename}.\n{}", output.stdout),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn restore_quarantined_file(
        quarantine_filename: String,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_quarantine_filename(&quarantine_filename) {
            return CommandOutcome::Err(format!(
                "refusing invalid quarantine filename: {quarantine_filename}"
            ));
        }
        let Some((_, encoded_path)) = quarantine_filename.split_once("__") else {
            return CommandOutcome::Err(format!(
                "malformed quarantine filename: {quarantine_filename}"
            ));
        };
        let original_path = match percent_decode(encoded_path) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::Err(e),
        };
        if !abyssal_agent_protocol::is_valid_absolute_path(&original_path) {
            return CommandOutcome::Err(format!(
                "decoded restore path looks invalid: {original_path}"
            ));
        }

        let src = format!("{QUARANTINE_DIR}/{quarantine_filename}");
        match elevation
            .run("mv", &[src.as_str(), original_path.as_str()])
            .await
        {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Restored {quarantine_filename} to {original_path}.\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn delete_quarantined_file(
        filename: String,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_quarantine_filename(&filename) {
            return CommandOutcome::Err(format!(
                "refusing invalid quarantine filename: {filename}"
            ));
        }
        let path = format!("{QUARANTINE_DIR}/{filename}");
        match elevation.run("rm", &["-f", path.as_str()]).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!("Deleted quarantined file {filename}.\n{}", output.stdout),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    // ---------------------------------------------------------------------
    // Remote IP blocklist
    // ---------------------------------------------------------------------

    fn nft_family(ip: &str) -> &'static str {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => "ip6",
            _ => "ip",
        }
    }

    async fn ensure_nft_blocklist_skeleton(elevation: &ElevationState) -> Result<(), String> {
        elevation
            .run("nft", &["add", "table", "inet", BLOCKLIST_TABLE])
            .await?;
        elevation
            .run(
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    BLOCKLIST_TABLE,
                    "input",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "input",
                    "priority",
                    "0;",
                    "}",
                ],
            )
            .await?;
        elevation
            .run(
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    BLOCKLIST_TABLE,
                    "output",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "output",
                    "priority",
                    "0;",
                    "}",
                ],
            )
            .await?;
        Ok(())
    }

    async fn nft_block_ip(ip: &str, elevation: &ElevationState) -> CommandOutcome {
        if let Err(e) = ensure_nft_blocklist_skeleton(elevation).await {
            return CommandOutcome::Err(e);
        }
        let fam = nft_family(ip);
        if let Err(e) = elevation
            .run(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    BLOCKLIST_TABLE,
                    "input",
                    fam,
                    "saddr",
                    ip,
                    "drop",
                ],
            )
            .await
        {
            return CommandOutcome::Err(e);
        }
        match elevation
            .run(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    BLOCKLIST_TABLE,
                    "output",
                    fam,
                    "daddr",
                    ip,
                    "drop",
                ],
            )
            .await
        {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Blocked {ip} (nftables, inbound and outbound).\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    async fn nft_find_handle(elevation: &ElevationState, chain: &str, ip: &str) -> Option<u32> {
        let output = elevation
            .run_allow_failure(
                "nft",
                &["-a", "list", "chain", "inet", BLOCKLIST_TABLE, chain],
            )
            .await
            .ok()?;
        output.stdout.lines().find_map(|line| {
            if !line.contains(ip) {
                return None;
            }
            line.rsplit("handle ").next()?.trim().parse::<u32>().ok()
        })
    }

    async fn nft_unblock_ip(ip: &str, elevation: &ElevationState) -> CommandOutcome {
        let mut removed_any = false;
        let mut errors = Vec::new();
        for chain in ["input", "output"] {
            if let Some(handle) = nft_find_handle(elevation, chain, ip).await {
                let handle_str = handle.to_string();
                match elevation
                    .run(
                        "nft",
                        &[
                            "delete",
                            "rule",
                            "inet",
                            BLOCKLIST_TABLE,
                            chain,
                            "handle",
                            &handle_str,
                        ],
                    )
                    .await
                {
                    Ok(_) => removed_any = true,
                    Err(e) => errors.push(format!("{chain}: {e}")),
                }
            }
        }
        if !errors.is_empty() {
            return CommandOutcome::Err(errors.join("; "));
        }
        let stdout = if removed_any {
            format!("Unblocked {ip} (nftables).")
        } else {
            format!("{ip} wasn't blocked -- nothing to remove.")
        };
        CommandOutcome::Ok(OperationOutput {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }

    async fn nft_list_blocked(elevation: &ElevationState) -> CommandOutcome {
        match elevation
            .run_allow_failure("nft", &["list", "table", "inet", BLOCKLIST_TABLE])
            .await
        {
            Ok(output) if output.exit_code == Some(0) => {
                CommandOutcome::Ok(present(output, "No IPs blocked."))
            }
            Ok(_) => CommandOutcome::Ok(OperationOutput {
                stdout: "No IPs blocked (no blocklist table present yet).".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    fn iptables_binary(ip: &str) -> &'static str {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => "ip6tables",
            _ => "iptables",
        }
    }

    async fn iptables_block_ip(ip: &str, elevation: &ElevationState) -> CommandOutcome {
        let bin = iptables_binary(ip);
        if let Err(e) = elevation
            .run(
                bin,
                &[
                    "-A",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    RULE_COMMENT,
                ],
            )
            .await
        {
            return CommandOutcome::Err(e);
        }
        match elevation
            .run(
                bin,
                &[
                    "-A",
                    "OUTPUT",
                    "-d",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    RULE_COMMENT,
                ],
            )
            .await
        {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Blocked {ip} ({bin}, inbound and outbound).\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    async fn iptables_unblock_ip(ip: &str, elevation: &ElevationState) -> CommandOutcome {
        let bin = iptables_binary(ip);
        let in_result = elevation
            .run(
                bin,
                &[
                    "-D",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    RULE_COMMENT,
                ],
            )
            .await;
        let out_result = elevation
            .run(
                bin,
                &[
                    "-D",
                    "OUTPUT",
                    "-d",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    RULE_COMMENT,
                ],
            )
            .await;
        match (in_result, out_result) {
            (Ok(_), Ok(_)) => CommandOutcome::Ok(OperationOutput {
                stdout: format!("Unblocked {ip} ({bin})."),
                stderr: String::new(),
                exit_code: Some(0),
            }),
            (Err(e), _) | (_, Err(e)) => CommandOutcome::Err(format!(
                "{ip} may not have been fully unblocked -- {e} (normal if it wasn't blocked)"
            )),
        }
    }

    async fn iptables_list_blocked(elevation: &ElevationState) -> CommandOutcome {
        let v4 = elevation
            .run_allow_failure("iptables", &["-L", "INPUT", "-n", "-v"])
            .await;
        let v6 = elevation
            .run_allow_failure("ip6tables", &["-L", "INPUT", "-n", "-v"])
            .await;
        let mut stdout = String::new();
        if let Ok(output) = v4 {
            stdout.push_str("== IPv4 (INPUT) ==\n");
            stdout.push_str(output.stdout.trim_end());
            stdout.push('\n');
        }
        if let Ok(output) = v6 {
            stdout.push_str("== IPv6 (INPUT) ==\n");
            stdout.push_str(output.stdout.trim_end());
        }
        CommandOutcome::Ok(present(
            OperationOutput {
                stdout,
                stderr: String::new(),
                exit_code: Some(0),
            },
            "No IPs blocked.",
        ))
    }

    pub async fn list_blocked_ips(elevation: &ElevationState) -> CommandOutcome {
        match detect().await {
            Some(Backend::Nft) => nft_list_blocked(elevation).await,
            Some(Backend::Iptables) => iptables_list_blocked(elevation).await,
            None => CommandOutcome::Err(NO_BACKEND.to_string()),
        }
    }

    pub async fn block_remote_ip(ip: String, elevation: &ElevationState) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_ip_address(&ip) {
            return CommandOutcome::Err(format!("refusing invalid IP address: {ip}"));
        }
        match detect().await {
            Some(Backend::Nft) => nft_block_ip(&ip, elevation).await,
            Some(Backend::Iptables) => iptables_block_ip(&ip, elevation).await,
            None => CommandOutcome::Err(NO_BACKEND.to_string()),
        }
    }

    pub async fn unblock_remote_ip(ip: String, elevation: &ElevationState) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_ip_address(&ip) {
            return CommandOutcome::Err(format!("refusing invalid IP address: {ip}"));
        }
        match detect().await {
            Some(Backend::Nft) => nft_unblock_ip(&ip, elevation).await,
            Some(Backend::Iptables) => iptables_unblock_ip(&ip, elevation).await,
            None => CommandOutcome::Err(NO_BACKEND.to_string()),
        }
    }

    // ---------------------------------------------------------------------
    // Host isolation -- the single most dangerous operation this agent can
    // execute. See the module doc comment and `nft_isolate` below.
    // ---------------------------------------------------------------------

    fn build_isolation_ruleset(cp_ip: IpAddr) -> String {
        let fam = match cp_ip {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        };
        format!(
            "table inet {ISOLATION_TABLE} {{\n\
             \tchain input {{\n\
             \t\ttype filter hook input priority 0; policy drop;\n\
             \t\tiifname \"lo\" accept\n\
             \t\tct state established,related accept\n\
             \t\t{fam} saddr {cp_ip} accept\n\
             \t}}\n\
             \tchain output {{\n\
             \t\ttype filter hook output priority 0; policy drop;\n\
             \t\toifname \"lo\" accept\n\
             \t\tct state established,related accept\n\
             \t\t{fam} daddr {cp_ip} accept\n\
             \t}}\n\
             }}\n"
        )
    }

    /// Builds the entire isolation table -- both chains, both default-drop
    /// policies, and the loopback/established/control-plane accept rules --
    /// as a single atomic `nft -f` transaction fed over stdin. This matters
    /// specifically here and nowhere else in this agent: a chain's `policy
    /// drop` takes effect the instant the chain is created, so creating the
    /// chain and adding its accept rules as separate sequential commands
    /// would open a real window in which the agent's own control-plane
    /// connection has nothing accepting it. A single atomic transaction has
    /// no such window -- the drop policy and its exceptions land together or
    /// not at all.
    async fn nft_isolate(cp_ip: IpAddr, elevation: &ElevationState) -> CommandOutcome {
        // Best-effort: clears any previous isolation table so a repeat call
        // is a clean rebuild rather than an accumulation of duplicate rules.
        // The table not existing yet (the normal first-call case) fails
        // here, which is expected -- and even a genuine failure just leaves
        // the host unrestricted, never half-isolated.
        let _ = elevation
            .run_allow_failure("nft", &["delete", "table", "inet", ISOLATION_TABLE])
            .await;

        let ruleset = build_isolation_ruleset(cp_ip);
        match elevation
            .run_with_stdin("nft", &["-f", "-"], &ruleset)
            .await
        {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Host isolated via nftables. All traffic is blocked except loopback, \
                     established connections, and the control plane at {cp_ip}.\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    async fn nft_deisolate(elevation: &ElevationState) -> CommandOutcome {
        match elevation
            .run_allow_failure("nft", &["delete", "table", "inet", ISOLATION_TABLE])
            .await
        {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: "Host de-isolated (isolation table removed, or was already absent)."
                    .to_string(),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    async fn nft_isolation_status(elevation: &ElevationState) -> CommandOutcome {
        match elevation
            .run_allow_failure("nft", &["list", "table", "inet", ISOLATION_TABLE])
            .await
        {
            Ok(output) if output.exit_code == Some(0) => CommandOutcome::Ok(OperationOutput {
                stdout: format!("Host is ISOLATED.\n{}", output.stdout),
                ..output
            }),
            Ok(_) => CommandOutcome::Ok(OperationOutput {
                stdout: "Host is NOT isolated.".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    /// `iptables-restore`/`ip6tables-restore` replace a table's entire
    /// ruleset atomically in one netlink transaction, exactly the property
    /// this operation needs (see `nft_isolate`'s doc comment) -- unlike a
    /// sequence of individual `iptables -A`/`-P` calls, which would have the
    /// same drop-before-exception race nftables has.
    fn build_iptables_ruleset(cp_match: Option<IpAddr>) -> String {
        let mut out = String::from(
            "*filter\n\
             :INPUT DROP [0:0]\n\
             :OUTPUT DROP [0:0]\n\
             :FORWARD DROP [0:0]\n\
             -A INPUT -i lo -j ACCEPT\n\
             -A OUTPUT -o lo -j ACCEPT\n\
             -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n\
             -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n",
        );
        if let Some(ip) = cp_match {
            out.push_str(&format!(
                "-A INPUT -s {ip} -j ACCEPT\n-A OUTPUT -d {ip} -j ACCEPT\n"
            ));
        }
        out.push_str("COMMIT\n");
        out
    }

    /// Replaces the entire filter table ruleset on both address families --
    /// this necessarily supersedes any existing Firewalld/ufw/manual iptables
    /// rules while isolated, which is the correct behavior for "block
    /// everything except the control plane," not a side effect to work
    /// around.
    async fn iptables_isolate(cp_ip: IpAddr, elevation: &ElevationState) -> CommandOutcome {
        let (v4_match, v6_match) = match cp_ip {
            IpAddr::V4(_) => (Some(cp_ip), None),
            IpAddr::V6(_) => (None, Some(cp_ip)),
        };
        let v4_ruleset = build_iptables_ruleset(v4_match);
        let v6_ruleset = build_iptables_ruleset(v6_match);

        if let Err(e) = elevation
            .run_with_stdin("iptables-restore", &[], &v4_ruleset)
            .await
        {
            return CommandOutcome::Err(format!("IPv4 isolation failed: {e}"));
        }
        match elevation
            .run_with_stdin("ip6tables-restore", &[], &v6_ruleset)
            .await
        {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Host isolated via iptables/ip6tables. All traffic is blocked except loopback, \
                     established connections, and the control plane at {cp_ip}. This replaces the \
                     existing filter table ruleset entirely on both address families.\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(format!(
                "IPv4 isolation was applied, but IPv6 isolation failed: {e}"
            )),
        }
    }

    async fn iptables_deisolate(elevation: &ElevationState) -> CommandOutcome {
        let open_ruleset =
            "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n";
        let v4 = elevation
            .run_with_stdin("iptables-restore", &[], open_ruleset)
            .await;
        let v6 = elevation
            .run_with_stdin("ip6tables-restore", &[], open_ruleset)
            .await;
        match (v4, v6) {
            (Ok(_), Ok(_)) => CommandOutcome::Ok(OperationOutput {
                stdout: "Host de-isolated (filter table policy restored to accept-all on both \
                         address families). This doesn't restore any pre-isolation custom rules \
                         (Firewalld/ufw/manual) -- the agent doesn't retain what they were, so \
                         re-apply those separately if needed."
                    .to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            }),
            (Err(e), _) | (_, Err(e)) => CommandOutcome::Err(e),
        }
    }

    async fn iptables_isolation_status(elevation: &ElevationState) -> CommandOutcome {
        match elevation
            .run_allow_failure("iptables", &["-L", "INPUT", "-n"])
            .await
        {
            Ok(output) => {
                let isolated = output
                    .stdout
                    .lines()
                    .next()
                    .map(|l| l.contains("policy DROP"))
                    .unwrap_or(false);
                let stdout = if isolated {
                    format!(
                        "Host appears ISOLATED (INPUT chain default policy is DROP).\n{}",
                        output.stdout
                    )
                } else {
                    format!(
                        "Host does NOT appear isolated (INPUT chain default policy is not DROP).\n{}",
                        output.stdout
                    )
                };
                CommandOutcome::Ok(OperationOutput { stdout, ..output })
            }
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn isolate_host(
        control_plane_host: &str,
        elevation: &ElevationState,
    ) -> CommandOutcome {
        let cp_ip = match resolve_control_plane_ip(control_plane_host).await {
            Ok(ip) => ip,
            Err(e) => return CommandOutcome::Err(e),
        };
        match detect().await {
            Some(Backend::Nft) => nft_isolate(cp_ip, elevation).await,
            Some(Backend::Iptables) => iptables_isolate(cp_ip, elevation).await,
            None => CommandOutcome::Err(NO_BACKEND.to_string()),
        }
    }

    pub async fn deisolate_host(elevation: &ElevationState) -> CommandOutcome {
        match detect().await {
            Some(Backend::Nft) => nft_deisolate(elevation).await,
            Some(Backend::Iptables) => iptables_deisolate(elevation).await,
            None => CommandOutcome::Err(NO_BACKEND.to_string()),
        }
    }

    pub async fn isolation_status(elevation: &ElevationState) -> CommandOutcome {
        match detect().await {
            Some(Backend::Nft) => nft_isolation_status(elevation).await,
            Some(Backend::Iptables) => iptables_isolation_status(elevation).await,
            None => CommandOutcome::Err(NO_BACKEND.to_string()),
        }
    }
}

// =======================================================================
// Windows: Windows Defender Firewall via PowerShell.
// =======================================================================

#[cfg(windows)]
mod windows {
    use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

    use crate::elevation::ElevationState;
    use crate::process::present;

    use super::{percent_decode, percent_encode, resolve_control_plane_ip};

    const QUARANTINE_DIR: &str = r"C:\ProgramData\abyssal-agent\quarantine";
    const BLOCK_GROUP: &str = "AbyssalArsenal-Blocklist";
    const ISOLATION_GROUP: &str = "AbyssalArsenal-Isolation";
    const ISOLATION_ALLOW_IN: &str = "AbyssalArsenal-Isolation-Allow-In";
    const ISOLATION_ALLOW_OUT: &str = "AbyssalArsenal-Isolation-Allow-Out";

    /// **Every** value that reaches one of this module's PowerShell
    /// scripts -- a path, an IP, a filename -- goes through
    /// `crate::process::ps_quote` first. Unlike the Unix implementation's
    /// `Command::new(prog).arg(x)`, which passes arguments as a real
    /// argv array and never touches a shell at all, every Windows
    /// operation here necessarily builds a single script *string* for
    /// `powershell.exe -Command`. That's a meaningfully weaker safety
    /// property on its own -- this codebase's own `is_valid_absolute_path`
    /// doc comment states the opposite assumption ("argument-injection
    /// safety here comes from never passing this through a shell") --
    /// so this module can't rely on that assumption and escapes
    /// explicitly instead.
    use crate::process::ps_quote;

    use crate::process::ps_checked;

    async fn run_ps(script: &str) -> Result<OperationOutput, String> {
        crate::process::run_command(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        )
        .await
    }

    // ---------------------------------------------------------------------
    // Quarantine
    // ---------------------------------------------------------------------

    pub async fn list_quarantined_files(_elevation: &ElevationState) -> CommandOutcome {
        if tokio::fs::metadata(QUARANTINE_DIR).await.is_err() {
            return CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "No files quarantined yet -- {QUARANTINE_DIR} doesn't exist on this host."
                ),
                stderr: String::new(),
                exit_code: Some(0),
            });
        }
        let script = format!(
            "Get-ChildItem -Path {} -File -ErrorAction SilentlyContinue | Sort-Object Name | \
             ForEach-Object {{ \"$($_.Name)`t$($_.Length) bytes`t$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))\" }}",
            ps_quote(QUARANTINE_DIR),
        );
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(present(output, "No files quarantined.")),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    /// Windows analog of the Unix implementation's own doc comment: moves
    /// `path` into the quarantine directory under a filename that encodes
    /// its own restoration destination. Same `<unix_ts>__<percent-encoded
    /// path>` scheme, same restore-never-accepts-a-typed-destination
    /// reasoning.
    pub async fn quarantine_file(path: String, _elevation: &ElevationState) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_windows_absolute_path(&path) {
            return CommandOutcome::Err(format!("refusing invalid path: {path}"));
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let filename = format!("{timestamp}__{}", percent_encode(&path));
        let dest = format!("{QUARANTINE_DIR}\\{filename}");

        let script = ps_checked(&format!(
            "New-Item -ItemType Directory -Path {} -Force | Out-Null; \
             Move-Item -Path {} -Destination {} -Force",
            ps_quote(QUARANTINE_DIR),
            ps_quote(&path),
            ps_quote(&dest),
        ));
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!("Quarantined {path} as {filename}.\n{}", output.stdout),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn restore_quarantined_file(
        quarantine_filename: String,
        _elevation: &ElevationState,
    ) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_quarantine_filename(&quarantine_filename) {
            return CommandOutcome::Err(format!(
                "refusing invalid quarantine filename: {quarantine_filename}"
            ));
        }
        let Some((_, encoded_path)) = quarantine_filename.split_once("__") else {
            return CommandOutcome::Err(format!(
                "malformed quarantine filename: {quarantine_filename}"
            ));
        };
        let original_path = match percent_decode(encoded_path) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::Err(e),
        };
        if !abyssal_agent_protocol::is_valid_windows_absolute_path(&original_path) {
            return CommandOutcome::Err(format!(
                "decoded restore path looks invalid: {original_path}"
            ));
        }

        let src = format!("{QUARANTINE_DIR}\\{quarantine_filename}");
        let script = ps_checked(&format!(
            "Move-Item -Path {} -Destination {} -Force",
            ps_quote(&src),
            ps_quote(&original_path),
        ));
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Restored {quarantine_filename} to {original_path}.\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn delete_quarantined_file(
        filename: String,
        _elevation: &ElevationState,
    ) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_quarantine_filename(&filename) {
            return CommandOutcome::Err(format!(
                "refusing invalid quarantine filename: {filename}"
            ));
        }
        let path = format!("{QUARANTINE_DIR}\\{filename}");
        let script = ps_checked(&format!("Remove-Item -Path {} -Force", ps_quote(&path)));
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!("Deleted quarantined file {filename}.\n{}", output.stdout),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    // ---------------------------------------------------------------------
    // Remote IP blocklist -- Windows Defender Firewall, both directions per
    // IP, all tagged with `BLOCK_GROUP` so list/unblock can filter cleanly
    // on just this app's own rules without touching unrelated firewall
    // state (the same role `RULE_COMMENT`/`BLOCKLIST_TABLE` play on Unix).
    // ---------------------------------------------------------------------

    fn block_rule_name(ip: &str, direction: &str) -> String {
        format!("AbyssalArsenal-Block-{direction}-{ip}")
    }

    pub async fn list_blocked_ips(_elevation: &ElevationState) -> CommandOutcome {
        let script = format!(
            "Get-NetFirewallRule -Group {} -ErrorAction SilentlyContinue | ForEach-Object {{ \
             $addr = (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ','); \
             \"$($_.DisplayName)`t$($_.Direction)`t$addr\" }}",
            ps_quote(BLOCK_GROUP),
        );
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(present(output, "No IPs blocked.")),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn block_remote_ip(ip: String, _elevation: &ElevationState) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_ip_address(&ip) {
            return CommandOutcome::Err(format!("refusing invalid IP address: {ip}"));
        }
        let script = ps_checked(&format!(
            "New-NetFirewallRule -DisplayName {} -Group {} -Direction Inbound \
             -RemoteAddress {} -Action Block | Out-Null; \
             New-NetFirewallRule -DisplayName {} -Group {} -Direction Outbound \
             -RemoteAddress {} -Action Block | Out-Null",
            ps_quote(&block_rule_name(&ip, "In")),
            ps_quote(BLOCK_GROUP),
            ps_quote(&ip),
            ps_quote(&block_rule_name(&ip, "Out")),
            ps_quote(BLOCK_GROUP),
            ps_quote(&ip),
        ));
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Blocked {ip} (Windows Firewall, inbound and outbound).\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn unblock_remote_ip(ip: String, _elevation: &ElevationState) -> CommandOutcome {
        if !abyssal_agent_protocol::is_valid_ip_address(&ip) {
            return CommandOutcome::Err(format!("refusing invalid IP address: {ip}"));
        }
        // `-like` with a wildcard direction segment catches both the
        // inbound and outbound rule for this IP in one pipeline, rather
        // than reconstructing each direction's exact rule name.
        let pattern = format!("AbyssalArsenal-Block-*-{ip}");
        let script = format!(
            "Get-NetFirewallRule -Group {} -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.DisplayName -like {} }} | Remove-NetFirewallRule -ErrorAction SilentlyContinue",
            ps_quote(BLOCK_GROUP),
            ps_quote(&pattern),
        );
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Unblocked {ip} (Windows Firewall), if it was blocked.\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    // ---------------------------------------------------------------------
    // Host isolation -- the single most dangerous operation this agent can
    // execute, same as on Unix, but with a materially different (not fully
    // equivalent) risk profile -- read this doc comment before touching
    // this function.
    //
    // `unix::nft_isolate` needs single-transaction atomicity because its
    // drop-everything policy and its control-plane exception must land
    // together: creating the chain applies the drop *immediately*, so a
    // sequence of separate commands would risk cutting the agent's own
    // connection in between. Windows Defender Firewall's PowerShell
    // surface (`Set-NetFirewallProfile`/`New-NetFirewallRule`) has no
    // equivalent single-transaction primitive -- a genuine, irreducible
    // gap versus the Unix mechanism, not an implementation detail to
    // paper over.
    //
    // The mitigation here is ordering, not atomicity: add the explicit
    // control-plane allow rules *first*, then flip the default action to
    // Block *second* (reversed on de-isolate). Because the allow rule for
    // the control plane's own address is already in place before the
    // default-block policy takes effect, the agent's live connection is
    // never subject to an unqualified "everything blocked, nothing
    // excepted" state the way an nft/iptables race could produce --
    // unlike Linux, Windows Firewall also never filters loopback traffic
    // at all, so no explicit loopback exception is needed either. The
    // real residual gap runs the *other* direction from Linux's: for the
    // brief window between the two PowerShell statements, isolation
    // simply hasn't fully taken effect yet (other traffic isn't blocked
    // *yet*), not that the control connection is ever at risk of being
    // cut. That's a real gap worth knowing about, not a hypothetical --
    // this has never been exercised against a real Windows Firewall (no
    // Windows machine in this sandbox), so treat it as needing real-world
    // validation before trusting it on a production host.
    // ---------------------------------------------------------------------

    pub async fn isolate_host(
        control_plane_host: &str,
        _elevation: &ElevationState,
    ) -> CommandOutcome {
        let cp_ip = match resolve_control_plane_ip(control_plane_host).await {
            Ok(ip) => ip,
            Err(e) => return CommandOutcome::Err(e),
        };
        let cp_ip_str = cp_ip.to_string();
        let script = ps_checked(&format!(
            "Remove-NetFirewallRule -Group {group} -ErrorAction SilentlyContinue; \
             New-NetFirewallRule -DisplayName {allow_in} -Group {group} -Direction Inbound \
             -RemoteAddress {ip} -Action Allow | Out-Null; \
             New-NetFirewallRule -DisplayName {allow_out} -Group {group} -Direction Outbound \
             -RemoteAddress {ip} -Action Allow | Out-Null; \
             Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block",
            group = ps_quote(ISOLATION_GROUP),
            allow_in = ps_quote(ISOLATION_ALLOW_IN),
            allow_out = ps_quote(ISOLATION_ALLOW_OUT),
            ip = ps_quote(&cp_ip_str),
        ));
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: format!(
                    "Host isolated via Windows Defender Firewall. Default inbound/outbound \
                     policy on every profile is now Block, with an explicit allow already in \
                     place for the control plane at {cp_ip_str} (both directions) before that \
                     policy was applied. See `isolate_host`'s own doc comment for how this \
                     differs from the Linux path's atomicity guarantee.\n{}",
                    output.stdout
                ),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn deisolate_host(_elevation: &ElevationState) -> CommandOutcome {
        // Reversed order from isolate: open the default policy back up
        // first (immediate relief), then clean up the now-redundant allow
        // rules -- leaving them in place a little longer on failure is
        // harmless once the default action is back to Allow.
        let script = ps_checked(&format!(
            "Set-NetFirewallProfile -All -DefaultInboundAction Allow -DefaultOutboundAction Allow; \
             Remove-NetFirewallRule -Group {} -ErrorAction SilentlyContinue",
            ps_quote(ISOLATION_GROUP),
        ));
        match run_ps(&script).await {
            Ok(output) => CommandOutcome::Ok(OperationOutput {
                stdout: "Host de-isolated (default inbound/outbound policy restored to Allow \
                         on every profile, isolation allow-rules removed). This doesn't restore \
                         any pre-isolation custom rules -- the agent doesn't retain what they \
                         were, so re-apply those separately if needed."
                    .to_string(),
                ..output
            }),
            Err(e) => CommandOutcome::Err(e),
        }
    }

    pub async fn isolation_status(_elevation: &ElevationState) -> CommandOutcome {
        let script = "Get-NetFirewallProfile -All | ForEach-Object { \
             \"$($_.Name)`tIn=$($_.DefaultInboundAction)`tOut=$($_.DefaultOutboundAction)\" }";
        match run_ps(script).await {
            Ok(output) => {
                let isolated = !output.stdout.trim().is_empty()
                    && output
                        .stdout
                        .lines()
                        .all(|line| line.contains("Block") && !line.contains("Allow"));
                let stdout = if isolated {
                    format!(
                        "Host is ISOLATED (every firewall profile defaults to Block, both \
                         directions).\n{}",
                        output.stdout
                    )
                } else {
                    format!("Host is NOT isolated.\n{}", output.stdout)
                };
                CommandOutcome::Ok(OperationOutput { stdout, ..output })
            }
            Err(e) => CommandOutcome::Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_round_trips_unix_and_windows_paths() {
        for path in [
            "/etc/passwd",
            r"C:\Users\foo\bad.exe",
            "/has spaces/and'quotes",
        ] {
            let encoded = percent_encode(path);
            assert_eq!(percent_decode(&encoded).as_deref(), Ok(path));
        }
    }

    #[test]
    fn percent_encoding_escapes_both_path_separators() {
        let encoded = percent_encode(r"C:\Users\foo");
        assert!(!encoded.contains('\\'));
        assert!(!encoded.contains(':'));
    }
}
