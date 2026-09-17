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

    pub async fn dispatch(
        &self,
        message: &NotificationMessage,
    ) -> Vec<(String, Result<(), NotificationError>)> {
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
