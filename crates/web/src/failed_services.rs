//! The operator's ignore list for failed services and units (Settings ›
//! Resurrection), applied on the control plane to what agents report: the
//! fleet health check's count and Resurrection's list. The agent applies
//! its own built-in Windows rules first
//! (`abyssal_agent_protocol::failed_services`).

use abyssal_agent_protocol::failed_services::{is_ignored, is_valid_windows_service_name};
use abyssal_core::settings::RESURRECTION_IGNORED_SERVICES;
use abyssal_database::{DbPool, repo};

/// Splits the stored (or submitted) list on newlines and commas.
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split(['\n', ',', '\r'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Checks each entry is a service or unit name (optionally ending in `*`),
/// and returns the list normalized for storage, de-duplicated and one per
/// line.
pub fn validate_list(raw: &str) -> Result<String, String> {
    let mut out: Vec<String> = Vec::new();
    for entry in parse_list(raw) {
        let name = entry.strip_suffix('*').unwrap_or(&entry);
        if !(is_valid_windows_service_name(name)
            || abyssal_agent_protocol::is_valid_unit_name(name))
        {
            return Err(format!(
                "\"{entry}\" isn't a service or unit name (letters, digits and - _ . $ @ : + \
                 {{ }}, optionally ending in *)."
            ));
        }
        if !out.iter().any(|e| e.eq_ignore_ascii_case(&entry)) {
            out.push(entry);
        }
    }
    Ok(out.join("\n"))
}

/// The current list (empty if unset or unreadable).
pub async fn ignore_list(pool: &DbPool) -> Vec<String> {
    match repo::settings::get_string(pool, RESURRECTION_IGNORED_SERVICES, "").await {
        Ok(raw) => parse_list(&raw),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't read the failed-service ignore list");
            Vec::new()
        }
    }
}

/// Whether a reported service or unit is on the list. A systemd unit also
/// matches without its `.service` suffix, so `nginx` covers
/// `nginx.service`.
pub fn is_ignored_name(name: &str, list: &[String]) -> bool {
    is_ignored(name, list)
        || name
            .strip_suffix(".service")
            .is_some_and(|short| is_ignored(short, list))
}

/// The name a row of a `FailedServices` answer is about, if it's a row:
/// the first word, after systemd's `●` marker.
fn row_name(line: &str) -> Option<&str> {
    let mut words = line.split_whitespace();
    let first = words.next()?;
    if first == "●" || first == "*" {
        words.next()
    } else {
        Some(first.trim_start_matches('●'))
    }
}

/// The number of failed services or units in a `FailedServices` answer,
/// minus those on `ignored`. Reads the trailing summary line (`N loaded
/// units listed.` from systemd, `N failed services listed.` from Windows),
/// which is robust against headers and a "No systemd" message.
pub fn count_failed(stdout: &str, ignored: &[String]) -> i32 {
    let suffixes = [
        "loaded units listed.",
        abyssal_agent_protocol::failed_services::WINDOWS_SUMMARY_SUFFIX,
    ];
    let total = stdout
        .lines()
        .rev()
        .find_map(|line| {
            let line = line.trim();
            suffixes
                .iter()
                .find_map(|suffix| line.strip_suffix(suffix))
                .and_then(|n| n.trim().parse::<i32>().ok())
        })
        .unwrap_or(0);
    if ignored.is_empty() || total == 0 {
        return total;
    }
    let hidden = stdout
        .lines()
        .filter_map(row_name)
        .filter(|name| is_ignored_name(name, ignored))
        .count() as i32;
    (total - hidden).max(0)
}

/// A `ListFailedUnits` answer without the rows on `ignored`, and how many
/// were taken out. Every Resurrection view filters here, so they agree.
pub fn strip_ignored(stdout: &str, ignored: &[String]) -> (String, usize) {
    if ignored.is_empty() {
        return (stdout.to_string(), 0);
    }
    let mut hidden = 0;
    let kept: Vec<&str> = stdout
        .lines()
        .filter(|line| {
            let ignore = row_name(line).is_some_and(|name| is_ignored_name(name, ignored));
            hidden += usize::from(ignore);
            !ignore
        })
        .collect();
    (kept.join("\n"), hidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEMD: &str = "  UNIT          LOAD   ACTIVE SUB    DESCRIPTION\n\
                           ● nginx.service loaded failed failed A high performance web server\n\
                           ● foo.mount     loaded failed failed /foo\n\
                           \n\
                           LOAD   = Reflects whether the unit definition was properly loaded.\n\
                           2 loaded units listed.\n";

    const WINDOWS: &str = "SERVICE           STATE     EXIT CODE           DISPLAY NAME\n\
                           MSSQL$SQLEXPRESS  Stopped   17058 (service-specific)  SQL Server\n\
                           Spooler           Stopped   1067                Print Spooler\n\
                           \n\
                           2 failed services listed.\n";

    #[test]
    fn counts_both_formats() {
        assert_eq!(count_failed(SYSTEMD, &[]), 2);
        assert_eq!(count_failed(WINDOWS, &[]), 2);
        assert_eq!(
            count_failed("No failed services.\n\n0 failed services listed.\n", &[]),
            0
        );
        assert_eq!(count_failed("No systemd on this host.", &[]), 0);
    }

    #[test]
    fn ignore_list_reduces_the_count() {
        let list = parse_list("nginx\nspooler");
        assert_eq!(count_failed(SYSTEMD, &list), 1);
        assert_eq!(count_failed(WINDOWS, &list), 1);
        let all = parse_list("MSSQL$*, Spooler");
        assert_eq!(count_failed(WINDOWS, &all), 0);
        // A header word isn't a row it could hide.
        assert_eq!(count_failed(WINDOWS, &parse_list("SERVICE")), 1);
    }

    #[test]
    fn strips_ignored_rows_from_both_list_formats() {
        let windows = "Spooler\tStopped\t1067\tPrint Spooler\t\nDoSvc\tStopped\t1067\tDelivery Optimization\t";
        let (kept, hidden) = strip_ignored(windows, &parse_list("spooler"));
        assert_eq!(
            (kept.as_str(), hidden),
            ("DoSvc\tStopped\t1067\tDelivery Optimization\t", 1)
        );
        let linux = "nginx.service loaded failed failed web\nfoo.mount loaded failed failed /foo";
        let (kept, hidden) = strip_ignored(linux, &parse_list("nginx"));
        assert_eq!(
            (kept.as_str(), hidden),
            ("foo.mount loaded failed failed /foo", 1)
        );
        assert_eq!(strip_ignored(linux, &[]).1, 0);
    }

    #[test]
    fn validation_normalizes() {
        assert_eq!(
            validate_list(" Spooler, MSSQL$SQLEXPRESS\r\nnginx.service\nspooler\nclr_*").unwrap(),
            "Spooler\nMSSQL$SQLEXPRESS\nnginx.service\nclr_*"
        );
        assert_eq!(validate_list("").unwrap(), "");
        assert!(validate_list("Print Spooler").is_err());
        assert!(validate_list("x;rm").is_err());
    }
}
