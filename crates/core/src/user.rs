use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which mechanism authenticated a given user. Stored as free text in the
/// database so future SSO providers (`oidc`, `saml`, ...) don't need a schema
/// change — the auth crate's `AuthProvider` trait is the real extension point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProviderKind(pub String);

impl AuthProviderKind {
    pub const LOCAL: &'static str = "local";

    pub fn local() -> Self {
        Self(Self::LOCAL.to_string())
    }

    pub fn is_local(&self) -> bool {
        self.0 == Self::LOCAL
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    /// `None` for SSO-only accounts once SSO providers exist.
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub auth_provider: AuthProviderKind,
    pub is_active: bool,
    pub must_change_password: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    /// An IANA timezone name (e.g. `"America/Chicago"`), used to render
    /// this user's own view of every timestamp in the app. Defaults to
    /// `"UTC"` at the database level; this crate stores it as a plain
    /// string rather than depending on `chrono-tz` itself -- parsing and
    /// display are display-layer concerns, handled in `abyssal-web`.
    pub timezone: String,
}
