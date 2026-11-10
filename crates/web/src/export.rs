//! Downloads of filtered alert lists (Scourge alerts, Thanatos event search)
//! as CSV or JSON: the format, the CSV writer, and the response.

use axum::http::header;
use axum::response::{IntoResponse, Response};

/// The most rows one export holds. A filter that matches more is cut off
/// (newest first), and the response says so in `X-Export-Truncated`.
pub const MAX_ROWS: u32 = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Json,
}

impl Format {
    /// `csv` (the default for anything else) or `json`.
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("json") => Format::Json,
            _ => Format::Csv,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Json => "json",
        }
    }
}

/// Quotes a CSV field and defuses spreadsheet formulas: a cell starting with
/// `=`, `+`, `-`, `@`, a tab or a carriage return would otherwise run when
/// the file is opened, and alert text (signatures, log lines, hostnames) can
/// come from whoever is on the network.
pub fn csv_field(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// A CSV document: the header row, then one line per row, CRLF-terminated
/// (RFC 4180).
pub fn csv_document(headers: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> String {
    let mut out = headers
        .iter()
        .map(|h| csv_field(h))
        .collect::<Vec<_>>()
        .join(",");
    out.push_str("\r\n");
    for row in rows {
        out.push_str(
            &row.iter()
                .map(|v| csv_field(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

/// The export as a download named `<stem>.<csv|json>`.
pub fn download(format: Format, stem: &str, body: String, truncated: bool) -> Response {
    let content_type = match format {
        Format::Csv => "text/csv; charset=utf-8",
        Format::Json => "application/json",
    };
    (
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{stem}.{}\"", format.key()),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (
                header::HeaderName::from_static("x-export-truncated"),
                truncated.to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_quoted_and_formulas_defused() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("-1+2"), "\"'-1+2\"");
        assert_eq!(csv_field("@SUM(A1)"), "\"'@SUM(A1)\"");
        assert_eq!(csv_field("a,b\nc"), "\"a,b\nc\"");
    }

    #[test]
    fn documents_have_a_header_and_crlf_lines() {
        let doc = csv_document(&["a", "b"], vec![vec!["1".into(), "x".into()]]);
        assert_eq!(doc, "\"a\",\"b\"\r\n\"1\",\"x\"\r\n");
    }

    #[test]
    fn format_defaults_to_csv() {
        assert_eq!(Format::parse(Some("JSON")), Format::Json);
        assert_eq!(Format::parse(Some("csv")), Format::Csv);
        assert_eq!(Format::parse(Some("xml")), Format::Csv);
        assert_eq!(Format::parse(None), Format::Csv);
    }
}
