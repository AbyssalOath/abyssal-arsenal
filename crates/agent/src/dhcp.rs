//! `DhcpLeases`: this host's DHCP server leases, for Panopticon's hostnames
//! (the control plane parses them -- `crates/web/src/panopticon_dhcp.rs`).
//! Read-only.

use abyssal_agent_protocol::CommandOutcome;

/// Lease files are append logs and can grow; this is far beyond any real
/// one's current size.
#[cfg_attr(not(unix), allow(dead_code))]
const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Where Linux DHCP servers keep leases, in the order they're tried.
#[cfg_attr(not(unix), allow(dead_code))]
const LEASE_FILES: &[&str] = &[
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhcpd/dhcpd.leases",
    "/var/lib/kea/kea-leases4.csv",
    "/var/lib/kea/dhcp4.leases",
];

/// Windows DHCP Server: every IPv4 scope's leases as CSV. Expiry is ISO
/// 8601 UTC so parsing never depends on the server's locale; a reservation
/// has none.
#[cfg_attr(not(windows), allow(dead_code))]
const WINDOWS_SCRIPT: &str = r##"$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-DhcpServerv4Lease -ErrorAction SilentlyContinue)) {
  throw 'this host has no DHCP Server role (the DhcpServer PowerShell module is missing)'
}
"# abyssal-dhcp-source: Windows DHCP Server ($env:COMPUTERNAME)"
Get-DhcpServerv4Scope | ForEach-Object { Get-DhcpServerv4Lease -ScopeId $_.ScopeId } |
  Select-Object @{n='IPAddress';e={$_.IPAddress.IPAddressToString}}, ClientId, HostName, AddressState,
    @{n='LeaseExpiryTime';e={ if ($_.LeaseExpiryTime) { $_.LeaseExpiryTime.ToUniversalTime().ToString('o') } else { '' } }} |
  ConvertTo-Csv -NoTypeInformation
"##;

#[cfg(unix)]
fn ok(stdout: String) -> CommandOutcome {
    CommandOutcome::Ok(abyssal_agent_protocol::OperationOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

#[cfg(unix)]
pub async fn leases() -> CommandOutcome {
    for path in LEASE_FILES {
        let Ok(meta) = tokio::fs::metadata(path).await else {
            continue;
        };
        if meta.len() > MAX_BYTES {
            return CommandOutcome::Err(format!(
                "{path} is {} MB, more than this reads ({} MB)",
                meta.len() / 1_048_576,
                MAX_BYTES / 1_048_576
            ));
        }
        return match tokio::fs::read_to_string(path).await {
            Ok(contents) => ok(format!("# abyssal-dhcp-source: {path}\n{contents}")),
            Err(e) => CommandOutcome::Err(format!("couldn't read {path}: {e}")),
        };
    }
    CommandOutcome::Err(format!(
        "no DHCP server lease file on this host (looked for {})",
        LEASE_FILES.join(", ")
    ))
}

#[cfg(windows)]
pub async fn leases() -> CommandOutcome {
    match crate::process::run_powershell(WINDOWS_SCRIPT).await {
        Ok(output) => CommandOutcome::Ok(output),
        Err(e) => CommandOutcome::Err(e),
    }
}

#[cfg(not(any(unix, windows)))]
pub async fn leases() -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs `pwsh`: skipped without it locally, required in CI.
    #[test]
    fn the_windows_script_parses_as_powershell() {
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
        let path = std::env::temp_dir().join(format!("dhcp-{}.ps1", std::process::id()));
        std::fs::write(&path, WINDOWS_SCRIPT).unwrap();
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
