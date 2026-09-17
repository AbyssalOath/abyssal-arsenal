#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
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
