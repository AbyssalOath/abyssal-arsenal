use thiserror::Error;

use crate::message::NotificationMessage;

#[derive(Debug, Error)]
pub enum NotificationError {
    #[error("notification provider is not configured")]
    NotConfigured,
    #[error("failed to send notification: {0}")]
    SendFailed(String),
}

/// A destination a notification can be sent to. Adding a new channel (Telegram,
/// Slack, Teams, Discord, ...) means implementing this trait and registering it
/// with a `NotificationDispatcher` — nothing else in the platform needs to
/// change, since callers only ever depend on this trait and the dispatcher.
#[async_trait::async_trait]
pub trait NotificationProvider: Send + Sync {
    fn name(&self) -> &str;
    /// True for a provider that delivers to each message's `recipients`
    /// privately (email). Broadcast providers -- syslog, chat webhooks --
    /// ignore recipients and publish to a shared channel, so they must never
    /// see a personal message carrying a reset token or temporary password;
    /// `NotificationDispatcher::dispatch_private` sends only to these.
    fn delivers_to_recipients(&self) -> bool {
        false
    }
    async fn send(&self, message: &NotificationMessage) -> Result<(), NotificationError>;
}
