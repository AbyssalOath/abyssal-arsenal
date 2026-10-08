use crate::message::NotificationMessage;
use crate::provider::{NotificationError, NotificationProvider};

/// Routes a message to every registered provider. Holds no configuration of
/// its own — providers are constructed (with their DB-backed config) and
/// registered by the caller at startup / whenever notification settings change.
#[derive(Default)]
pub struct NotificationDispatcher {
    providers: Vec<Box<dyn NotificationProvider>>,
}

impl NotificationDispatcher {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn register(&mut self, provider: Box<dyn NotificationProvider>) {
        self.providers.push(provider);
    }

    /// How many delivery providers are registered -- for the diagnostics page's
    /// "notifications configured?" preflight check.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    pub async fn dispatch(
        &self,
        message: &NotificationMessage,
    ) -> Vec<(String, Result<(), NotificationError>)> {
        tracing::debug!(providers = self.providers.len(), subject = %message.subject, "dispatching notification");
        let mut results = Vec::with_capacity(self.providers.len());
        for provider in &self.providers {
            let result = provider.send(message).await;
            if let Err(ref e) = result {
                tracing::warn!(provider = provider.name(), error = %e, "notification delivery failed");
            }
            results.push((provider.name().to_string(), result));
        }
        results
    }

    /// For a message meant only for its recipients -- a password reset link,
    /// a temporary password. Goes to recipient-delivering providers (email)
    /// only, never to syslog or a chat channel. An empty result means no such
    /// provider is configured, i.e. nothing was sent.
    pub async fn dispatch_private(
        &self,
        message: &NotificationMessage,
    ) -> Vec<(String, Result<(), NotificationError>)> {
        let mut results = Vec::new();
        for provider in self.providers.iter().filter(|p| p.delivers_to_recipients()) {
            let result = provider.send(message).await;
            if let Err(ref e) = result {
                tracing::warn!(provider = provider.name(), error = %e, "notification delivery failed");
            }
            results.push((provider.name().to_string(), result));
        }
        if results.is_empty() {
            tracing::warn!(
                subject = %message.subject,
                "no email provider configured -- personal notification not sent"
            );
        }
        results
    }

    /// Whether an email (recipient-delivering) provider is configured.
    pub fn has_email(&self) -> bool {
        self.providers.iter().any(|p| p.delivers_to_recipients())
    }

    pub async fn send_test(
        &self,
        provider_name: &str,
        recipient: &str,
    ) -> Result<(), NotificationError> {
        let provider = self
            .providers
            .iter()
            .find(|p| p.name() == provider_name)
            .ok_or(NotificationError::NotConfigured)?;
        provider.send(&NotificationMessage::test(recipient)).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::message::Severity;

    struct Counting {
        name: &'static str,
        private: bool,
        sent: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl NotificationProvider for Counting {
        fn name(&self) -> &str {
            self.name
        }
        fn delivers_to_recipients(&self) -> bool {
            self.private
        }
        async fn send(&self, _: &NotificationMessage) -> Result<(), NotificationError> {
            self.sent.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn message() -> NotificationMessage {
        NotificationMessage {
            subject: "Your temporary password".into(),
            body: "secret".into(),
            severity: Severity::Info,
            recipients: vec!["user@example.com".into()],
        }
    }

    #[tokio::test]
    async fn private_messages_never_reach_broadcast_providers() {
        let email = Arc::new(AtomicUsize::new(0));
        let syslog = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = NotificationDispatcher::new();
        dispatcher.register(Box::new(Counting {
            name: "smtp",
            private: true,
            sent: email.clone(),
        }));
        dispatcher.register(Box::new(Counting {
            name: "syslog",
            private: false,
            sent: syslog.clone(),
        }));

        let results = dispatcher.dispatch_private(&message()).await;
        assert_eq!(results.len(), 1);
        assert_eq!(email.load(Ordering::SeqCst), 1);
        assert_eq!(syslog.load(Ordering::SeqCst), 0);

        // An ordinary alert still goes everywhere.
        dispatcher.dispatch(&message()).await;
        assert_eq!(email.load(Ordering::SeqCst), 2);
        assert_eq!(syslog.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn private_dispatch_with_no_email_sends_nothing() {
        let syslog = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = NotificationDispatcher::new();
        dispatcher.register(Box::new(Counting {
            name: "syslog",
            private: false,
            sent: syslog.clone(),
        }));
        assert!(!dispatcher.has_email());
        assert!(dispatcher.dispatch_private(&message()).await.is_empty());
        assert_eq!(syslog.load(Ordering::SeqCst), 0);
    }
}
