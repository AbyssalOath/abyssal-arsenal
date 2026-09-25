use tokio::net::UdpSocket;

use crate::message::{NotificationMessage, Severity};
use crate::provider::{NotificationError, NotificationProvider};

/// RFC 5424 facility "local0" -- one of the eight facilities the RFC
/// reserves for local use, the conventional home for an application's own
/// security telemetry rather than one of the fixed OS-level facilities
/// (auth, kern, ...). Not admin-configurable: picking a facility is a
/// one-time integration decision made against whatever the receiving
/// SIEM/syslog daemon is configured to route, not something that needs to
/// change at runtime.
const FACILITY: u8 = 16;

/// Forwards every dispatched `NotificationMessage` to an external
/// syslog/SIEM destination over UDP, RFC 5424 formatted -- Phase 12 of
/// the Thanatos SIEM/EDR build-out's external-export capability.
/// Deliberately UDP-only (not the also-common TCP/RFC 6587 framing): the
/// traditional, still overwhelmingly common transport for firehose
/// security telemetry, fire-and-forget with no reconnect/backpressure
/// logic needed, and an occasional dropped datagram under load is an
/// accepted, well-understood tradeoff of this transport industry-wide --
/// not something this provider tries to paper over with retries.
/// Structured Data and MSGID are both sent as the RFC's own NILVALUE
/// (`-`): the receiving SIEM parses the free-text `MSG` field itself, so
/// this provider doesn't need to build/escape RFC 5424 SD-ELEMENT syntax
/// for no real benefit.
pub struct SyslogProvider {
    socket: UdpSocket,
    hostname: String,
    app_name: String,
}

impl SyslogProvider {
    pub async fn new(host: &str, port: u16, app_name: &str) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect((host, port)).await?;
        Ok(Self {
            socket,
            hostname: local_hostname(),
            app_name: app_name.to_string(),
        })
    }
}

/// Best-effort, dependency-free hostname for the RFC 5424 HOSTNAME field
/// -- Docker sets `HOSTNAME` to the container's own id/name for every
/// container by default, which covers this app's own documented
/// deployment story (`docker-compose.yml`); falls back to the RFC's own
/// NILVALUE when unset (e.g. running the binary directly outside Docker
/// with nothing exporting it) rather than guessing.
fn local_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

/// RFC 5424 numeric severity (0 = Emergency ... 7 = Debug) -- only the
/// three levels `NotificationMessage::Severity` actually distinguishes
/// are used; this app has no notion of anything above Critical (2) or
/// below Informational (6).
fn syslog_severity(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 2,
        Severity::Warning => 4,
        Severity::Info => 6,
    }
}

#[async_trait::async_trait]
impl NotificationProvider for SyslogProvider {
    fn name(&self) -> &str {
        "syslog"
    }

    async fn send(&self, message: &NotificationMessage) -> Result<(), NotificationError> {
        let pri = u16::from(FACILITY) * 8 + u16::from(syslog_severity(message.severity));
        let timestamp = chrono::Utc::now().to_rfc3339();
        let pid = std::process::id();
        // MSG is meant to read as one line -- a raw line embedded in the
        // body (e.g. a FIM finding's own multi-part description) could
        // otherwise split a single syslog event across several lines at
        // the receiving end.
        let msg = format!("{}: {}", message.subject, message.body).replace('\n', " | ");

        let line = format!(
            "<{pri}>1 {timestamp} {} {} {pid} - - {msg}",
            self.hostname, self.app_name
        );

        self.socket
            .send(line.as_bytes())
            .await
            .map_err(|e| NotificationError::SendFailed(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_three_notification_severities_to_rfc5424_numbers() {
        assert_eq!(syslog_severity(Severity::Critical), 2);
        assert_eq!(syslog_severity(Severity::Warning), 4);
        assert_eq!(syslog_severity(Severity::Info), 6);
    }

    #[tokio::test]
    async fn sends_a_well_formed_rfc5424_line_over_udp() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let provider = SyslogProvider::new("127.0.0.1", receiver_addr.port(), "test-app")
            .await
            .unwrap();
        provider
            .send(&NotificationMessage {
                subject: "[Thanatos] host-a: New listening port".to_string(),
                body: "source=network severity=high New listening port: tcp:4444".to_string(),
                severity: Severity::Warning,
                recipients: Vec::new(),
            })
            .await
            .unwrap();

        let mut buf = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .expect("no datagram received within timeout")
            .unwrap();
        let line = std::str::from_utf8(&buf[..n]).unwrap();

        // PRI = facility(16)*8 + severity(4) = 132.
        assert!(line.starts_with("<132>1 "));
        assert!(line.contains(" test-app "));
        assert!(line.contains("[Thanatos] host-a: New listening port: source=network"));
        assert!(!line.contains('\n'));
    }
}
