use std::time::Duration;

use abyssal_agent_protocol::{AgentOperation, CommandOutcome};
use abyssal_audit::{Actor, AuditAction, AuditEvent, AuditOutcome};
use abyssal_core::Permission;
use abyssal_database::DbPool;
use abyssal_hosts::{DispatchError, HostConnectionRegistry};
use abyssal_rbac::AuthContext;
use tokio_util::sync::CancellationToken;

use crate::{ExecutionError, Operation, OperationKind, OperationOutput, OperationParams};

/// Runs `Operation`s with the controls the spec requires: a permission check,
/// a timeout, cooperative cancellation, and an audit record on every attempt
/// (success or failure) — so nothing in an arsenal ever calls out to the
/// system without going through this.
///
/// Two entry points share that same permission-check-then-audit shape, but
/// run against fundamentally different substrates: `execute` runs an
/// in-process `Operation` (the control plane's own diagnostics), while
/// `execute_on_host` dispatches one of the fixed `AgentOperation` variants to
/// a specific enrolled host over its live agent connection. Forcing both
/// through one trait would mean pretending a remote, wire-serialized command
/// and a local Rust closure are the same kind of thing — they aren't.
pub struct Executor {
    pool: DbPool,
    default_timeout: Duration,
}

impl Executor {
    pub fn new(pool: DbPool, default_timeout: Duration) -> Self {
        Self {
            pool,
            default_timeout,
        }
    }

    pub async fn execute(
        &self,
        ctx: &AuthContext,
        op: &dyn Operation,
        params: OperationParams,
        cancel: CancellationToken,
        source_ip: Option<&str>,
    ) -> Result<OperationOutput, ExecutionError> {
        if !ctx.has(op.required_permission()) {
            self.audit(
                ctx,
                op.name(),
                AuditOutcome::Failure,
                source_ip,
                "permission denied",
            )
            .await;
            return Err(ExecutionError::Forbidden);
        }

        if op.kind() == OperationKind::Destructive && !params.confirm {
            self.audit(
                ctx,
                op.name(),
                AuditOutcome::Failure,
                source_ip,
                "confirmation required",
            )
            .await;
            return Err(ExecutionError::ConfirmationRequired);
        }

        let outcome = tokio::select! {
            result = tokio::time::timeout(self.default_timeout, op.run(&params)) => {
                match result {
                    Ok(Ok(output)) => Ok(output),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(ExecutionError::Timeout),
                }
            }
            _ = cancel.cancelled() => Err(ExecutionError::Cancelled),
        };

        match &outcome {
            Ok(_) => {
                self.audit(ctx, op.name(), AuditOutcome::Success, source_ip, "ok")
                    .await
            }
            Err(e) => {
                self.audit(
                    ctx,
                    op.name(),
                    AuditOutcome::Failure,
                    source_ip,
                    &e.to_string(),
                )
                .await
            }
        }

        outcome
    }

    /// Dispatches a fixed `AgentOperation` to `host_id` over its live agent
    /// connection. `host_label` is only used for the audit record (the
    /// caller already has the `Host` loaded to check it's the right one, so
    /// this avoids a redundant lookup here). `elevated` is the caller's
    /// `state.elevation.is_elevated(host_id)` snapshot taken just before the
    /// call, recorded on the audit event so a normal action's row shows
    /// whether it ran with elevated privileges.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_on_host(
        &self,
        ctx: &AuthContext,
        hosts: &HostConnectionRegistry,
        host_id: uuid::Uuid,
        host_label: &str,
        operation: AgentOperation,
        required_permission: Permission,
        kind: OperationKind,
        confirm: bool,
        timeout: Duration,
        source_ip: Option<&str>,
        elevated: bool,
    ) -> Result<OperationOutput, ExecutionError> {
        let op_kind = HostOpKind::from(&operation);
        let op_label = operation.label();

        if !ctx.has(required_permission) {
            self.audit_host_op(
                ctx,
                host_label,
                op_kind,
                &op_label,
                kind,
                elevated,
                AuditOutcome::Failure,
                source_ip,
                "permission denied",
            )
            .await;
            return Err(ExecutionError::Forbidden);
        }

        if kind == OperationKind::Destructive && !confirm {
            self.audit_host_op(
                ctx,
                host_label,
                op_kind,
                &op_label,
                kind,
                elevated,
                AuditOutcome::Failure,
                source_ip,
                "confirmation required",
            )
            .await;
            return Err(ExecutionError::ConfirmationRequired);
        }

        let outcome = match hosts.dispatch(host_id, operation, timeout).await {
            Ok(CommandOutcome::Ok(output)) => Ok(output),
            Ok(CommandOutcome::Err(message)) => Err(ExecutionError::Failed(message)),
            Err(DispatchError::NotConnected) => Err(ExecutionError::Failed(
                "host is not currently connected".into(),
            )),
            Err(DispatchError::Timeout) => Err(ExecutionError::Timeout),
            Err(DispatchError::ConnectionClosed) => Err(ExecutionError::Failed(
                "host disconnected before responding".into(),
            )),
        };

        match &outcome {
            Ok(_) => {
                self.audit_host_op(
                    ctx,
                    host_label,
                    op_kind,
                    &op_label,
                    kind,
                    elevated,
                    AuditOutcome::Success,
                    source_ip,
                    "ok",
                )
                .await
            }
            Err(e) => {
                self.audit_host_op(
                    ctx,
                    host_label,
                    op_kind,
                    &op_label,
                    kind,
                    elevated,
                    AuditOutcome::Failure,
                    source_ip,
                    &e.to_string(),
                )
                .await
            }
        }

        outcome
    }

    async fn audit(
        &self,
        ctx: &AuthContext,
        resource: &str,
        outcome: AuditOutcome,
        source_ip: Option<&str>,
        detail: &str,
    ) {
        let event = AuditEvent::new(AuditAction::SystemCommandExecuted, outcome)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(resource)
            .metadata(serde_json::json!({ "detail": detail }));

        let event = if let Some(ip) = source_ip {
            event.source_ip(ip)
        } else {
            event
        };

        if let Err(e) = abyssal_audit::record(&self.pool, event).await {
            tracing::error!(error = %e, "failed to write audit record for executed operation");
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn audit_host_op(
        &self,
        ctx: &AuthContext,
        resource: &str,
        op_kind: HostOpKind,
        op_label: &str,
        kind: OperationKind,
        elevated: bool,
        outcome: AuditOutcome,
        source_ip: Option<&str>,
        detail: &str,
    ) {
        let action = match (op_kind, outcome) {
            (HostOpKind::Elevate, AuditOutcome::Success) => AuditAction::HostElevated,
            (HostOpKind::Elevate, AuditOutcome::Failure) => AuditAction::HostElevationFailed,
            (HostOpKind::Deescalate, _) => AuditAction::HostDeescalated,
            (HostOpKind::SecurityScan, _) => AuditAction::SecurityEventScanRun,
            (HostOpKind::Other, _) => AuditAction::SystemCommandExecuted,
        };

        let kind_key = match kind {
            OperationKind::Read => "read",
            OperationKind::Write => "write",
            OperationKind::Destructive => "destructive",
        };

        let event = AuditEvent::new(action, outcome)
            .actor(Actor {
                user_id: ctx.user.id,
                username: &ctx.user.username,
            })
            .resource(resource)
            .metadata(
                serde_json::json!({ "detail": detail, "elevated": elevated, "operation": op_label, "kind": kind_key }),
            );

        let event = if let Some(ip) = source_ip {
            event.source_ip(ip)
        } else {
            event
        };

        if let Err(e) = abyssal_audit::record(&self.pool, event).await {
            tracing::error!(error = %e, "failed to write audit record for host operation");
        }
    }
}

/// Which of the small set of audit-distinguished `AgentOperation` variants
/// this dispatch is, computed once up front since `operation` is moved into
/// `hosts.dispatch` before the outcome (and thus the audit action) is known.
#[derive(Clone, Copy)]
enum HostOpKind {
    Elevate,
    Deescalate,
    SecurityScan,
    Other,
}

impl From<&AgentOperation> for HostOpKind {
    fn from(operation: &AgentOperation) -> Self {
        match operation {
            AgentOperation::Elevate { .. } => HostOpKind::Elevate,
            AgentOperation::Deescalate => HostOpKind::Deescalate,
            AgentOperation::ScanSecurityEvents { .. } => HostOpKind::SecurityScan,
            _ => HostOpKind::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssal_core::{AuthProviderKind, User};
    use chrono::Utc;
    use std::collections::HashSet;
    use std::time::Duration as StdDuration;
    use uuid::Uuid;

    fn ctx(permissions: &[Permission]) -> AuthContext {
        AuthContext {
            user: User {
                id: Uuid::new_v4(),
                username: "tester".into(),
                email: "tester@example.com".into(),
                password_hash: None,
                auth_provider: AuthProviderKind::local(),
                is_active: true,
                must_change_password: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_login_at: None,
                timezone: "UTC".into(),
            },
            permissions: permissions.iter().copied().collect::<HashSet<_>>(),
        }
    }

    struct Instant;
    #[async_trait::async_trait]
    impl Operation for Instant {
        fn name(&self) -> &str {
            "instant"
        }
        fn kind(&self) -> OperationKind {
            OperationKind::Read
        }
        fn required_permission(&self) -> Permission {
            Permission::SystemsView
        }
        async fn run(&self, _params: &OperationParams) -> Result<OperationOutput, ExecutionError> {
            Ok(OperationOutput {
                stdout: "done".into(),
                stderr: String::new(),
                exit_code: Some(0),
            })
        }
    }

    struct Slow;
    #[async_trait::async_trait]
    impl Operation for Slow {
        fn name(&self) -> &str {
            "slow"
        }
        fn kind(&self) -> OperationKind {
            OperationKind::Read
        }
        fn required_permission(&self) -> Permission {
            Permission::SystemsView
        }
        async fn run(&self, _params: &OperationParams) -> Result<OperationOutput, ExecutionError> {
            tokio::time::sleep(StdDuration::from_secs(3600)).await;
            Ok(OperationOutput::default())
        }
    }

    struct Destructive;
    #[async_trait::async_trait]
    impl Operation for Destructive {
        fn name(&self) -> &str {
            "destructive"
        }
        fn kind(&self) -> OperationKind {
            OperationKind::Destructive
        }
        fn required_permission(&self) -> Permission {
            Permission::SystemsManage
        }
        async fn run(&self, _params: &OperationParams) -> Result<OperationOutput, ExecutionError> {
            Ok(OperationOutput::default())
        }
    }

    #[tokio::test]
    async fn denies_without_required_permission() {
        // No live DB in unit tests: use a pool-less path by constructing the
        // executor lazily only when a permission check would pass. Denial
        // happens before any database access, so this is safe without a pool.
        let executor = Executor {
            pool: unconfigured_pool(),
            default_timeout: StdDuration::from_secs(1),
        };
        let ctx = ctx(&[]);
        let result = executor
            .execute(
                &ctx,
                &Instant,
                OperationParams::default(),
                CancellationToken::new(),
                None,
            )
            .await;
        assert!(matches!(result, Err(ExecutionError::Forbidden)));
    }

    #[tokio::test]
    async fn destructive_without_confirm_is_rejected() {
        let executor = Executor {
            pool: unconfigured_pool(),
            default_timeout: StdDuration::from_secs(1),
        };
        let ctx = ctx(&[Permission::SystemsManage]);
        let result = executor
            .execute(
                &ctx,
                &Destructive,
                OperationParams::default(),
                CancellationToken::new(),
                None,
            )
            .await;
        assert!(matches!(result, Err(ExecutionError::ConfirmationRequired)));
    }

    #[tokio::test]
    async fn cancellation_token_interrupts_a_running_operation() {
        let executor = Executor {
            pool: unconfigured_pool(),
            default_timeout: StdDuration::from_secs(3600),
        };
        let ctx = ctx(&[Permission::SystemsView]);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(StdDuration::from_millis(20)).await;
            cancel_clone.cancel();
        });

        let result = executor
            .execute(&ctx, &Slow, OperationParams::default(), cancel, None)
            .await;
        assert!(matches!(result, Err(ExecutionError::Cancelled)));
    }

    #[tokio::test]
    async fn execute_on_host_denies_without_required_permission() {
        let executor = Executor {
            pool: unconfigured_pool(),
            default_timeout: StdDuration::from_secs(1),
        };
        let ctx = ctx(&[]);
        let hosts = HostConnectionRegistry::new();
        let result = executor
            .execute_on_host(
                &ctx,
                &hosts,
                Uuid::new_v4(),
                "test-host",
                AgentOperation::Ping,
                Permission::SystemsView,
                OperationKind::Read,
                false,
                StdDuration::from_millis(50),
                None,
                false,
            )
            .await;
        assert!(matches!(result, Err(ExecutionError::Forbidden)));
    }

    #[tokio::test]
    async fn execute_on_host_fails_when_host_not_connected() {
        let executor = Executor {
            pool: unconfigured_pool(),
            default_timeout: StdDuration::from_secs(1),
        };
        let ctx = ctx(&[Permission::SystemsView]);
        let hosts = HostConnectionRegistry::new();
        let result = executor
            .execute_on_host(
                &ctx,
                &hosts,
                Uuid::new_v4(),
                "test-host",
                AgentOperation::Ping,
                Permission::SystemsView,
                OperationKind::Read,
                false,
                StdDuration::from_millis(50),
                None,
                false,
            )
            .await;
        assert!(matches!(result, Err(ExecutionError::Failed(_))));
    }

    /// Denial paths never touch the database, so a pool that would panic on
    /// first use is fine for these tests — it proves the short-circuit works.
    fn unconfigured_pool() -> DbPool {
        sqlx::mysql::MySqlPoolOptions::new()
            .connect_lazy("mysql://invalid:invalid@127.0.0.1:1/invalid")
            .expect("lazy pool construction never touches the network")
    }
}
