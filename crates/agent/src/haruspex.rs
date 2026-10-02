//! Haruspex: Windows Active Directory / directory-services health diagnostics.
//! Read-only report generators that run the standard domain-controller
//! toolchain (`dcdiag`, `repadmin`, `nltest`, `nslookup`, `w32tm`, `sc`, `net`)
//! and return a sectioned text report -- the control-plane equivalent of the
//! classic "AD health check" batch file, but run on demand through the agent
//! and surfaced in the UI. Windows-only; anything else gets a clean
//! "not supported on this platform".
//!
//! Every command is read-only. Each runs through `run_command_allow_failure`
//! (these tools legitimately exit non-zero when they *find* a problem, which is
//! exactly the output we want to capture), and a tool that isn't installed --
//! i.e. this host isn't a domain controller -- becomes a note in its section
//! rather than failing the whole report. `domain` is validated with
//! `is_valid_hostname` before it reaches any argv, and nothing here touches a
//! shell, so the value can never be misread as a flag or injected.

use abyssal_agent_protocol::CommandOutcome;
#[cfg(windows)]
use abyssal_agent_protocol::OperationOutput;

/// Formats one report section: a `===== TITLE =====` header and the command's
/// output (or a short note when there was none). Pure, so the format is
/// unit-tested on every platform.
#[cfg_attr(not(windows), allow(dead_code))]
fn format_section(title: &str, body: &str) -> String {
    let body = body.trim_end();
    let body = if body.trim().is_empty() {
        "(no output)"
    } else {
        body
    };
    format!("===== {title} =====\n{body}\n\n")
}

#[cfg(windows)]
async fn run_section(title: &str, program: &str, args: &[&str]) -> String {
    let body = match crate::process::run_command_allow_failure(program, args).await {
        Ok(out) => {
            if out.stdout.trim().is_empty() {
                out.stderr
            } else {
                out.stdout
            }
        }
        // A spawn failure (e.g. `dcdiag` not present because this isn't a DC)
        // is reported in-section, not fatal to the whole report.
        Err(e) => format!("({e})"),
    };
    format_section(title, &body)
}

/// AD DNS diagnostics report (`AgentOperation::AdDnsReport`).
#[cfg(windows)]
pub async fn ad_dns_report(domain: String) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_hostname(&domain) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain}"));
    }
    let srv = format!("_ldap._tcp.dc._msdcs.{domain}");
    let mut report = String::new();
    report.push_str(&run_section("DNS DCDIAG", "dcdiag", &["/test:dns", "/v"]).await);
    report.push_str(&run_section("DOMAIN DNS", "nslookup", &[domain.as_str()]).await);
    report.push_str(&run_section("AD LDAP SRV", "nslookup", &["-type=SRV", srv.as_str()]).await);
    CommandOutcome::Ok(OperationOutput {
        stdout: report,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// Broader AD/DC health report (`AgentOperation::AdHealthReport`).
#[cfg(windows)]
pub async fn ad_health_report(domain: String) -> CommandOutcome {
    if !abyssal_agent_protocol::is_valid_hostname(&domain) {
        return CommandOutcome::Err(format!("refusing invalid AD domain: {domain}"));
    }
    let dsgetdc = format!("/dsgetdc:{domain}");
    let dclist = format!("/dclist:{domain}");
    let mut report = String::new();
    report.push_str(&run_section("DC DIAGNOSTICS", "dcdiag", &["/v"]).await);
    report.push_str(&run_section("REPLICATION SUMMARY", "repadmin", &["/replsummary"]).await);
    report.push_str(&run_section("REPLICATION DETAILS", "repadmin", &["/showrepl"]).await);
    report.push_str(&run_section("DC DISCOVERY (dsgetdc)", "nltest", &[dsgetdc.as_str()]).await);
    report.push_str(&run_section("DC DISCOVERY (dclist)", "nltest", &[dclist.as_str()]).await);
    report.push_str(&run_section("DNS CONFIGURATION", "ipconfig", &["/all"]).await);
    report.push_str(&run_section("TIME STATUS", "w32tm", &["/query", "/status"]).await);
    report.push_str(&run_section("TIME SOURCE", "w32tm", &["/query", "/source"]).await);
    report.push_str(&run_section("AD SERVICE: NTDS", "sc", &["query", "ntds"]).await);
    report.push_str(&run_section("AD SERVICE: NETLOGON", "sc", &["query", "netlogon"]).await);
    report.push_str(&run_section("AD SERVICE: DNS", "sc", &["query", "dns"]).await);
    report.push_str(&run_section("AD SERVICE: KDC", "sc", &["query", "kdc"]).await);
    report.push_str(&run_section("SYSVOL / NETLOGON SHARES", "net", &["share"]).await);
    CommandOutcome::Ok(OperationOutput {
        stdout: report,
        stderr: String::new(),
        exit_code: Some(0),
    })
}

#[cfg(unix)]
pub async fn ad_dns_report(_domain: String) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(unix)]
pub async fn ad_health_report(_domain: String) -> CommandOutcome {
    crate::process::platform_unsupported()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_has_header_and_body() {
        let s = format_section("DNS DCDIAG", "all tests passed\n");
        assert!(s.starts_with("===== DNS DCDIAG =====\n"));
        assert!(s.contains("all tests passed"));
        assert!(s.ends_with("\n\n"));
    }

    #[test]
    fn empty_section_notes_no_output() {
        assert!(format_section("TIME SOURCE", "   ").contains("(no output)"));
    }
}
