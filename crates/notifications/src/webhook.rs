use std::time::Duration;

use serde_json::json;

use crate::message::{NotificationMessage, Severity};
use crate::provider::{NotificationError, NotificationProvider};

/// Which service a webhook posts to -- shapes the JSON payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookFlavor {
    /// Generic JSON `{subject, body, severity, text}` POST.
    Generic,
    /// Slack incoming webhook (`{"text": "..."}`).
    Slack,
    /// Microsoft Teams incoming webhook (MessageCard).
    Teams,
}

impl WebhookFlavor {
    const fn provider_name(self) -> &'static str {
        match self {
            WebhookFlavor::Generic => "webhook",
            WebhookFlavor::Slack => "slack",
            WebhookFlavor::Teams => "teams",
        }
    }
}

/// Posts dispatched notifications to a chat/webhook endpoint (Slack, Teams, or a
/// generic JSON webhook). A single configured URL is the destination, so
/// `recipients` is ignored (like the syslog provider). A `min_severity` gate
/// keeps the per-finding firehose off a chat channel: only messages at or above
/// it are POSTed, everything below is a silent no-op -- this is what makes
/// wiring a webhook into the same dispatcher the syslog firehose uses safe
/// (set it to `warning`/`critical` so only real findings reach the channel).
/// Fire-and-forget with a short timeout; a failed POST surfaces as a
/// `SendFailed` the dispatcher logs, never a retry/backpressure loop.
pub struct WebhookProvider {
    client: reqwest::Client,
    url: String,
    flavor: WebhookFlavor,
    min_severity: Severity,
    name: &'static str,
}

impl WebhookProvider {
    pub fn new(url: &str, flavor: WebhookFlavor, min_severity: Severity) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("abyssal-arsenal")
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            url: url.to_string(),
            flavor,
            min_severity,
            name: flavor.provider_name(),
        })
    }

    fn payload(&self, m: &NotificationMessage) -> serde_json::Value {
        let text = format!("{}\n{}", m.subject, m.body);
        match self.flavor {
            WebhookFlavor::Slack => json!({ "text": text }),
            WebhookFlavor::Teams => json!({
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": theme_color(m.severity),
                "summary": m.subject,
                "title": m.subject,
                "text": m.body,
            }),
            WebhookFlavor::Generic => json!({
                "subject": m.subject,
                "body": m.body,
                "severity": severity_key(m.severity),
                "text": text,
            }),
        }
    }
}

fn severity_key(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

fn theme_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "d9534f",
        Severity::Warning => "f0ad4e",
        Severity::Info => "5bc0de",
    }
}

#[async_trait::async_trait]
impl NotificationProvider for WebhookProvider {
    fn name(&self) -> &str {
        self.name
    }

    async fn send(&self, message: &NotificationMessage) -> Result<(), NotificationError> {
        if message.severity.rank() < self.min_severity.rank() {
            // Below this channel's threshold -- deliberately a no-op, not an
            // error, so the dispatcher's firehose doesn't spam a chat channel.
            return Ok(());
        }
        let payload = self.payload(message);
        let response = self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| NotificationError::SendFailed(e.to_string()))?;
        response
            .error_for_status()
            .map_err(|e| NotificationError::SendFailed(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(severity: Severity) -> NotificationMessage {
        NotificationMessage {
            subject: "[Thanatos] host-a: Possible LSASS memory access".to_string(),
            body: "source=sysmon severity=high ...".to_string(),
            severity,
            recipients: Vec::new(),
        }
    }

    #[test]
    fn slack_payload_is_a_text_field() {
        let p =
            WebhookProvider::new("http://example/x", WebhookFlavor::Slack, Severity::Info).unwrap();
        let v = p.payload(&msg(Severity::Warning));
        assert!(
            v.get("text")
                .and_then(|t| t.as_str())
                .unwrap()
                .contains("LSASS")
        );
    }

    #[test]
    fn teams_payload_is_a_message_card_with_theme_color() {
        let p =
            WebhookProvider::new("http://example/x", WebhookFlavor::Teams, Severity::Info).unwrap();
        let v = p.payload(&msg(Severity::Critical));
        assert_eq!(v.get("@type").and_then(|t| t.as_str()), Some("MessageCard"));
        assert_eq!(v.get("themeColor").and_then(|t| t.as_str()), Some("d9534f"));
    }

    #[test]
    fn generic_payload_carries_structured_fields() {
        let p = WebhookProvider::new("http://example/x", WebhookFlavor::Generic, Severity::Info)
            .unwrap();
        let v = p.payload(&msg(Severity::Warning));
        assert_eq!(v.get("severity").and_then(|t| t.as_str()), Some("warning"));
        assert!(v.get("body").is_some());
    }

    #[tokio::test]
    async fn below_min_severity_is_a_silent_noop() {
        // URL is unreachable; if send() tried to POST it would error, so an Ok
        // proves the min-severity gate short-circuited before any network call.
        let p = WebhookProvider::new(
            "http://127.0.0.1:9/never",
            WebhookFlavor::Slack,
            Severity::Critical,
        )
        .unwrap();
        assert!(p.send(&msg(Severity::Warning)).await.is_ok());
    }

    #[test]
    fn provider_name_follows_flavor() {
        assert_eq!(
            WebhookProvider::new("http://x/y", WebhookFlavor::Slack, Severity::Info)
                .unwrap()
                .name(),
            "slack"
        );
        assert_eq!(
            WebhookProvider::new("http://x/y", WebhookFlavor::Teams, Severity::Info)
                .unwrap()
                .name(),
            "teams"
        );
    }
}
