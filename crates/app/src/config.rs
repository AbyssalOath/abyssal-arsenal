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
        })
    }
}
