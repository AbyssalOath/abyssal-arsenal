pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub session_cookie_name: String,
    pub session_ttl_hours: i64,
    pub cookie_secure: bool,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from: Option<String>,
    /// Base URL this control plane is reachable at (e.g.
    /// `https://arsenal.example.com`), used only to build a clickable link
    /// in outgoing emails (currently just the password-reset email).
    /// Deliberately not inferred from a request's `Host` header -- that's
    /// attacker-controllable and this is a security-sensitive link, so an
    /// admin has to set it explicitly. Without it, the reset email still
    /// includes the raw token itself for the recipient to paste in.
    pub public_url: Option<String>,
    /// Base64-encoded 32-byte AES-256-GCM master key, used only to encrypt
    /// and decrypt Panopticon switches' stored SNMP credentials (v1/v2c
    /// community strings; v3 auth/privacy passwords)
    /// (`abyssal_core::crypto::EncryptionKey`). Optional: a deployment
    /// that never configures a switch shouldn't be forced to generate and
    /// manage a secret it doesn't use. Parsed once at startup rather than
    /// on first use so a malformed key fails loudly at boot, not silently
    /// on the first switch someone tries to add.
    pub encryption_key: Option<abyssal_core::EncryptionKey>,
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .map_err(|_| anyhow::anyhow!("DATABASE_URL must be set"))?,
            port: env_opt("PORT").and_then(|v| v.parse().ok()).unwrap_or(8080),
            session_cookie_name: env_opt("SESSION_COOKIE_NAME")
                .unwrap_or_else(|| "abyssal_session".to_string()),
            session_ttl_hours: env_opt("SESSION_TTL_HOURS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(12),
            cookie_secure: env_opt("COOKIE_SECURE")
                .map(|v| v != "false")
                .unwrap_or(true),
            smtp_host: env_opt("SMTP_HOST"),
            smtp_port: env_opt("SMTP_PORT")
                .and_then(|v| v.parse().ok())
                .unwrap_or(587),
            smtp_username: env_opt("SMTP_USERNAME"),
            smtp_password: env_opt("SMTP_PASSWORD"),
            smtp_from: env_opt("SMTP_FROM"),
            public_url: env_opt("PUBLIC_URL").map(|v| v.trim_end_matches('/').to_string()),
            encryption_key: env_opt("ENCRYPTION_KEY")
                .map(|v| abyssal_core::EncryptionKey::from_base64(&v))
                .transpose()
                .map_err(|e| anyhow::anyhow!("ENCRYPTION_KEY is invalid: {e}"))?,
        })
    }
}
