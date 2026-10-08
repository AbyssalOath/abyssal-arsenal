use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::message::NotificationMessage;
use crate::provider::{NotificationError, NotificationProvider};

/// How the connection to the SMTP server is secured (`SMTP_TLS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Connect in plain text, then upgrade with STARTTLS, which is required
    /// (never falls back to plain text). Port 587: Office 365
    /// (`smtp.office365.com`), Gmail, most submission servers.
    StartTls,
    /// TLS from the first byte ("SMTPS", implicit TLS). Port 465.
    Tls,
    /// No encryption at all -- only for a relay on the same host or a
    /// trusted network segment (port 25), never across the internet.
    None,
}

impl SmtpSecurity {
    /// `SMTP_TLS` (`starttls` / `tls` / `none`, case-insensitive); unset or
    /// empty picks by port: implicit TLS on 465, STARTTLS everywhere else.
    /// An unrecognized value is an error rather than a guess.
    pub fn from_setting(setting: Option<&str>, port: u16) -> anyhow::Result<Self> {
        match setting.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") => Ok(if port == 465 {
                Self::Tls
            } else {
                Self::StartTls
            }),
            Some("starttls") => Ok(Self::StartTls),
            Some("tls" | "ssl" | "smtps") => Ok(Self::Tls),
            Some("none" | "off" | "plain") => Ok(Self::None),
            Some(other) => anyhow::bail!(
                "SMTP_TLS={other} isn't one of starttls, tls, none (or empty for automatic)"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::Tls => "tls",
            Self::None => "none",
        }
    }
}

/// Bounds connect + each SMTP exchange, so an unreachable or filtered
/// server (outbound 587 blocked, a wrong host) fails within seconds instead
/// of stalling the request that triggered the email.
const SMTP_TIMEOUT: Duration = Duration::from_secs(20);

pub struct SmtpProvider {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpProvider {
    /// An empty `username` connects without authenticating (an internal
    /// relay that accepts mail by source address).
    pub fn new(
        host: &str,
        port: u16,
        security: SmtpSecurity,
        username: &str,
        password: &str,
        from: &str,
    ) -> anyhow::Result<Self> {
        let from: Mailbox = from
            .parse()
            .map_err(|e| anyhow::anyhow!("SMTP_FROM {from:?} isn't a valid address: {e}"))?;
        // `relay()` alone means implicit TLS -- it's what made every send to
        // a port-587 server (Office 365 included) fail at the handshake.
        let tls = match security {
            SmtpSecurity::StartTls => Tls::Required(TlsParameters::new(host.to_string())?),
            SmtpSecurity::Tls => Tls::Wrapper(TlsParameters::new(host.to_string())?),
            SmtpSecurity::None => Tls::None,
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .tls(tls)
            .timeout(Some(SMTP_TIMEOUT));
        if !username.is_empty() {
            builder =
                builder.credentials(Credentials::new(username.to_string(), password.to_string()));
        }
        Ok(Self {
            transport: builder.build(),
            from,
        })
    }
}

#[async_trait::async_trait]
impl NotificationProvider for SmtpProvider {
    fn name(&self) -> &str {
        "smtp"
    }

    fn delivers_to_recipients(&self) -> bool {
        true
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
                .map_err(|e| NotificationError::SendFailed(describe_smtp_error(&e)))?;
        }
        Ok(())
    }
}

/// lettre's error plus its source chain (where the server's actual reply,
/// e.g. Office 365's "5.7.139 Authentication unsuccessful, SmtpClientAuthentication
/// is disabled for the Tenant", lives) and a hint for the common causes.
fn describe_smtp_error(e: &lettre::transport::smtp::Error) -> String {
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        // lettre's Display often already includes its source; don't repeat it.
        let part = s.to_string();
        if !text.contains(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        source = s.source();
    }
    let hint = if text.contains("5.7.139") || text.contains("SmtpClientAuthentication") {
        " -- SMTP AUTH is disabled for this mailbox or tenant: enable \"Authenticated SMTP\" \
         for the mailbox in the Microsoft 365 admin center (and allow it tenant-wide)"
    } else if text.contains("5.7.60") || text.contains("SendAsDenied") || text.contains("send as") {
        " -- SMTP_FROM must be the authenticated mailbox, or one it has Send As rights for"
    } else if text.contains("535") || text.contains("5.7.3") || text.contains("5.7.8") {
        " -- the server rejected the username/password (for Microsoft 365 with MFA, use an \
         app password, or a mailbox without MFA that has Authenticated SMTP enabled)"
    } else if e.is_timeout() || text.contains("timed out") {
        " -- no answer from the server: check SMTP_HOST/SMTP_PORT and that this machine can \
         reach it (outbound 587/465 is often blocked)"
    } else if text.contains("InvalidContentType")
        || text.contains("corrupt message")
        || text.contains("wrong version number")
    {
        " -- TLS mode doesn't match the port: use SMTP_TLS=starttls for 587, tls for 465"
    } else {
        ""
    };
    format!("{text}{hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_defaults_by_port() {
        assert_eq!(
            SmtpSecurity::from_setting(None, 587).unwrap(),
            SmtpSecurity::StartTls
        );
        assert_eq!(
            SmtpSecurity::from_setting(Some(""), 25).unwrap(),
            SmtpSecurity::StartTls
        );
        assert_eq!(
            SmtpSecurity::from_setting(None, 465).unwrap(),
            SmtpSecurity::Tls
        );
    }

    #[test]
    fn security_explicit_values() {
        assert_eq!(
            SmtpSecurity::from_setting(Some("STARTTLS"), 465).unwrap(),
            SmtpSecurity::StartTls
        );
        assert_eq!(
            SmtpSecurity::from_setting(Some("ssl"), 587).unwrap(),
            SmtpSecurity::Tls
        );
        assert_eq!(
            SmtpSecurity::from_setting(Some("none"), 25).unwrap(),
            SmtpSecurity::None
        );
        assert!(SmtpSecurity::from_setting(Some("bogus"), 587).is_err());
    }

    #[test]
    fn only_email_delivers_to_recipients() {
        let smtp = SmtpProvider::new(
            "smtp.example.com",
            587,
            SmtpSecurity::StartTls,
            "",
            "",
            "Arsenal <arsenal@example.com>",
        )
        .unwrap();
        assert!(smtp.delivers_to_recipients());
    }
}
