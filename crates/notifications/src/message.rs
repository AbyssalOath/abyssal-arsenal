#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// An ordinal for threshold comparisons (`Info` < `Warning` < `Critical`) --
    /// a provider with a `min_severity` sends a message only when
    /// `message.severity.rank() >= min_severity.rank()`.
    pub const fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Warning => 1,
            Severity::Critical => 2,
        }
    }

    /// Parses a provider's configured minimum severity
    /// (`info`/`warning`/`critical`, case-insensitive). Unrecognized input
    /// yields `None` so the caller can fall back to a default.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warning" | "warn" => Some(Severity::Warning),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NotificationMessage {
    pub subject: String,
    pub body: String,
    pub severity: Severity,
    pub recipients: Vec<String>,
}

impl NotificationMessage {
    pub fn test(recipient: impl Into<String>) -> Self {
        Self {
            subject: "Abyssal Arsenal test notification".to_string(),
            body: "This is a test notification from Abyssal Arsenal.".to_string(),
            severity: Severity::Info,
            recipients: vec![recipient.into()],
        }
    }
}
