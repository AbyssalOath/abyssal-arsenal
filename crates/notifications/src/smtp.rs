use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::message::NotificationMessage;
use crate::provider::{NotificationError, NotificationProvider};

pub struct SmtpProvider {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpProvider {
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        from: &str,
    ) -> anyhow::Result<Self> {
        let from: Mailbox = from.parse()?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(host)?
            .port(port)
            .credentials(Credentials::new(username.to_string(), password.to_string()))
            .build();
        Ok(Self { transport, from })
    }
}

#[async_trait::async_trait]
impl NotificationProvider for SmtpProvider {
    fn name(&self) -> &str {
        "smtp"
    }

    async fn send(&self, message: &NotificationMessage) -> Result<(), NotificationError> {
        for recipient in &message.recipients {
            let to: Mailbox = recipient.parse().map_err(|e| {
                NotificationError::SendFailed(format!("invalid recipient {recipient}: {e}"))
            })?;

            let email = Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(&message.subject)
                .body(message.body.clone())
                .map_err(|e| NotificationError::SendFailed(e.to_string()))?;

            self.transport
                .send(email)
                .await
                .map_err(|e| NotificationError::SendFailed(e.to_string()))?;
        }
        Ok(())
    }
}
