//! Active incident containment and remediation ("Inquest"): blocking a
//! remote IP, quarantining a suspicious file, and -- the most severe
//! action this whole agent can take -- isolating the host's network
//! entirely except for its own connection back to the control plane.
//!
//! Every other destructive operation in this codebase risks damage to
//! the managed host; `IsolateHost` uniquely risks severing the only
//! channel the control plane has to *fix* that damage, since the agent
//! itself is what's holding the connection this operation could cut.
//! `nft_isolate`'s doc comment covers the specific race this module goes
//! out of its way to avoid.
//!
//! Like Firewall (`firewall.rs`), there's no single standard Linux
//! packet-filtering interface, so both blocklist and isolation operations
//! detect and dispatch to whichever of nftables/iptables is actually
//! present, preferring nftables. This module's `Backend` is deliberately
//! separate from `firewall.rs`'s own (private, and narrower -- it never
//! needed an iptables branch for isolation) rather than shared.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use abyssal_agent_protocol::{CommandOutcome, OperationOutput};

use crate::elevation::ElevationState;
use crate::process::{command_exists, present};

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
// Quarantine filename encoding
// ---------------------------------------------------------------------

/// Percent-encodes everything except the standard URL-safe unreserved
/// set, so the result is always a valid, single-path-segment filename --
/// most importantly, a `/` in the original path can never turn into a
/// filename that itself refers to a subdirectory or escapes one.
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
        return CommandOutcome::Err(format!("refusing invalid quarantine filename: {filename}"));
    }
    let path = format!("{QUARANTINE_DIR}/{filename}");
    match elevation.run("rm", &[path.as_str()]).await {
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

pub async fn isolate_host(control_plane_host: &str, elevation: &ElevationState) -> CommandOutcome {
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
