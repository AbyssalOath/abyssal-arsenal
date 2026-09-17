use abyssal_database::repo::audit::NewAuditEntry;
use abyssal_database::DbPool;
use serde_json::Value;
use uuid::Uuid;

use crate::action::{AuditAction, AuditOutcome};

/// The user who performed the action, or `None` for system-initiated events
/// (e.g. a scheduled job) — audit rows always have a `username_snapshot` even
/// when there's no `user_id` to attribute them to.
pub struct Actor<'a> {
    pub user_id: Uuid,
    pub username: &'a str,
}

pub struct AuditEvent<'a> {
    pub actor: Option<Actor<'a>>,
    pub action: AuditAction,
    pub outcome: AuditOutcome,
    pub resource: Option<&'a str>,
    pub source_ip: Option<&'a str>,
    pub auth_method: Option<&'a str>,
    pub metadata: Option<Value>,
}

impl<'a> AuditEvent<'a> {
    pub fn new(action: AuditAction, outcome: AuditOutcome) -> Self {
        Self {
            actor: None,
            action,
            outcome,
            resource: None,
            source_ip: None,
            auth_method: None,
            metadata: None,
        }
    }

    pub fn actor(mut self, actor: Actor<'a>) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn resource(mut self, resource: &'a str) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn source_ip(mut self, ip: &'a str) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn auth_method(mut self, method: &'a str) -> Self {
        self.auth_method = Some(method);
        self
    }

    pub fn metadata(mut self, metadata: Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// The only path by which anything gets written to `audit_log`. There is
/// deliberately no update/delete counterpart anywhere in the codebase — audit
/// history is append-only by construction, not just by convention.
pub async fn record(pool: &DbPool, event: AuditEvent<'_>) -> anyhow::Result<()> {
    let (user_id, username_snapshot) = match &event.actor {
        Some(actor) => (Some(actor.user_id), actor.username),
        None => (None, "system"),
    };

    abyssal_database::repo::audit::record(
        pool,
        NewAuditEntry {
            user_id,
            username_snapshot,
            action: event.action.as_key(),
            resource: event.resource,
            result: event.outcome.as_key(),
            source_ip: event.source_ip,
            auth_method: event.auth_method,
            metadata: event.metadata,
        },
    )
    .await
}
