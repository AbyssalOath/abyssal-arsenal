mod dispatcher;
mod message;
mod provider;
mod smtp;
mod syslog;
mod webhook;

pub use dispatcher::NotificationDispatcher;
pub use message::{NotificationMessage, Severity};
pub use provider::{NotificationError, NotificationProvider};
pub use smtp::{SmtpProvider, SmtpSecurity};
pub use syslog::SyslogProvider;
pub use webhook::{WebhookFlavor, WebhookProvider};
