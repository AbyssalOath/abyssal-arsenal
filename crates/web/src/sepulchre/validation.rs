//! Method-aware connection validation. Runs an ordered list of checks
//! against a connection's control-plane (`native_client`) backend,
//! stopping dependent checks on a hard failure, and records every
//! result -- see `docs/sepulchre.md`'s Phase 3 for the full check list
//! and the `error_kind` this maps failures onto.
//!
//! Host-side `mount` access methods are validated separately, by
//! `provisioning`'s own apply-then-verify-mounted step (recorded on the
//! `mount_definitions` row itself, not here) -- see that module's doc
//! comment for why a generic `validation_runs` row doesn't fit a mount
//! check the same way it fits a control-plane backend check.

use std::collections::HashSet;
use std::time::Instant;

use abyssal_core::{
    AccessMethod, Capability, ErrorKind, StorageConnection, ValidationCheckResult, ValidationMode,
    ValidationStatus,
};
use uuid::Uuid;

use super::SepulchreError;
use super::backend::{self, StorageBackend};
use crate::state::AppState;

/// A private, reserved subdirectory every connection's read/write test
/// writes its scratch file into -- never a name a legitimate consumer
/// would also use, so a validation run's temp file can never collide
/// with real data.
const SCRATCH_SUBDIR: &str = ".sepulchre-validation";

fn error_kind_for(message: &str) -> ErrorKind {
    let lower = message.to_lowercase();
    if lower.contains(backend::sftp::HOST_KEY_MISMATCH_MARKER) {
        ErrorKind::HostKeyMismatch
    } else if lower.contains("auth_failed")
        || lower.contains("authentication")
        // `smbclient`'s own NT_STATUS codes for a rejected username/password
        // or an expired/locked account -- caught live against a real Samba
        // server, which never says "auth" or "authentication" at all.
        || lower.contains("nt_status_logon_failure")
        || lower.contains("nt_status_password_expired")
        || lower.contains("nt_status_account_locked_out")
        || lower.contains("nt_status_account_disabled")
    {
        ErrorKind::AuthFailed
    } else if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("nt_status_io_timeout")
    {
        ErrorKind::Timeout
    } else if lower.contains("not_found")
        || lower.contains("no such file")
        || lower.contains("nt_status_bad_network_name")
        || lower.contains("nt_status_object_name_not_found")
    {
        ErrorKind::NotFound
    } else if lower.contains("permission")
        || lower.contains("denied")
        || lower.contains("nt_status_access_denied")
    {
        ErrorKind::PermissionDenied
    } else if lower.contains("path not allowed") || lower.contains("path_not_allowed") {
        ErrorKind::PathNotAllowed
    } else if lower.contains("connection failed")
        || lower.contains("unreachable")
        || lower.contains("nt_status_connection_refused")
        || lower.contains("nt_status_host_unreachable")
    {
        ErrorKind::Unreachable
    } else {
        ErrorKind::Unknown
    }
}

struct Recorder {
    checks: Vec<ValidationCheckResult>,
    stop: bool,
}

impl Recorder {
    fn record(
        &mut self,
        check: &str,
        method: AccessMethod,
        status: ValidationStatus,
        error_kind: Option<ErrorKind>,
        message: String,
        started: Instant,
    ) {
        self.checks.push(ValidationCheckResult {
            check: check.to_string(),
            method: Some(method),
            status,
            error_kind,
            message,
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    fn ok(&mut self, check: &str, method: AccessMethod, message: String, started: Instant) {
        self.record(check, method, ValidationStatus::Ok, None, message, started);
    }

    fn fail(&mut self, check: &str, method: AccessMethod, message: String, started: Instant) {
        let kind = error_kind_for(&message);
        self.record(
            check,
            method,
            ValidationStatus::Failed,
            Some(kind),
            message,
            started,
        );
        self.stop = true;
    }

    fn skip(&mut self, check: &str, method: AccessMethod, message: String) {
        self.record(
            check,
            method,
            ValidationStatus::Skipped,
            None,
            message,
            Instant::now(),
        );
    }
}

/// Runs a full validation pass against `connection`'s control-plane
/// backend and persists the result. `mode` gates whether the
/// destructive-ish read/write test runs at all -- `ReadOnly` never
/// writes anything.
pub async fn validate(
    state: &AppState,
    connection: &StorageConnection,
    mode: ValidationMode,
    triggered_by: Option<Uuid>,
) -> Result<Uuid, SepulchreError> {
    let run_id = abyssal_database::repo::validation_runs::start(
        &state.pool,
        connection.id,
        mode,
        triggered_by,
    )
    .await?;

    let mut recorder = Recorder {
        checks: Vec::new(),
        stop: false,
    };
    let method = AccessMethod::NativeClient;

    // 1+2+3+4: constructing the backend itself performs reachability,
    // the protocol handshake, host-key verification, and
    // authentication, in that order -- a single "connect" check covers
    // all four, since none of this codebase's protocol clients expose
    // a way to observe them as separate steps without redialing.
    let started = Instant::now();
    let backend_result = backend::build_backend(state, connection).await;
    let backend = match backend_result {
        Ok(backend) => {
            recorder.ok(
                "connect",
                method,
                "connected, authenticated, and (for SFTP) host key verified".to_string(),
                started,
            );
            backend
        }
        Err(e) => {
            recorder.fail(
                "connect",
                method,
                format!("unable to establish a usable connection: {e}"),
                started,
            );
            return finish(state, connection.id, run_id, recorder.checks).await;
        }
    };

    // 5: path/share exists and is listable.
    let started = Instant::now();
    match backend.list("").await {
        Ok(entries) => {
            recorder.ok(
                "list",
                method,
                format!(
                    "listed {} entry(ies) at the connection's base path",
                    entries.len()
                ),
                started,
            );
        }
        Err(e) => {
            recorder.fail(
                "list",
                method,
                format!("could not list base path: {e}"),
                started,
            );
            return finish(state, connection.id, run_id, recorder.checks).await;
        }
    }

    // 6: read permission check -- attempt to stat the base path itself.
    let started = Instant::now();
    let can_read = match backend.stat("").await {
        Ok(_) => {
            recorder.ok(
                "read_permission",
                method,
                "base path is readable".to_string(),
                started,
            );
            true
        }
        Err(e) => {
            recorder.fail("read_permission", method, format!("{e}"), started);
            false
        }
    };

    let possible = backend.possible_capabilities();
    let mut verified: HashSet<Capability> = HashSet::new();
    if can_read {
        verified.insert(Capability::Read);
        verified.insert(Capability::List);
    }

    // 7: the read/write test -- opt-in (`ReadWrite` mode only), clearly
    // labeled, always attempts cleanup even on failure.
    if matches!(mode, ValidationMode::ReadWrite) && !recorder.stop {
        if !possible.contains(&Capability::Write) {
            recorder.skip(
                "read_write_test",
                method,
                "this backend/config cannot write (e.g. a read-only SMB share) -- skipped"
                    .to_string(),
            );
        } else {
            run_read_write_test(backend.as_ref(), &mut recorder, method, &mut verified).await;
        }
    } else if matches!(mode, ValidationMode::ReadOnly) {
        recorder.skip(
            "read_write_test",
            method,
            "read-only validation mode -- write/delete were not tested".to_string(),
        );
    }

    // 8: free space (best effort).
    let started = Instant::now();
    match backend.free_space().await {
        Ok(Some(bytes)) => recorder.ok(
            "free_space",
            method,
            format!("{bytes} bytes free (best effort)"),
            started,
        ),
        Ok(None) => recorder.skip(
            "free_space",
            method,
            "this protocol/server doesn't expose free space".to_string(),
        ),
        Err(e) => recorder.skip("free_space", method, format!("could not determine: {e}")),
    }

    // Persist verified capabilities -- every capability not proven this
    // run is explicitly cleared, not left stale from a previous pass.
    for cap in Capability::ALL {
        abyssal_database::repo::storage_connections::set_verified_capability(
            &state.pool,
            connection.id,
            *cap,
            verified.contains(cap),
            run_id,
        )
        .await?;
    }

    finish(state, connection.id, run_id, recorder.checks).await
}

async fn run_read_write_test(
    backend: &dyn StorageBackend,
    recorder: &mut Recorder,
    method: AccessMethod,
    verified: &mut HashSet<Capability>,
) {
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let started = Instant::now();
    let file_name = format!("{SCRATCH_SUBDIR}/validate-{}.tmp", Uuid::new_v4());
    let payload = format!("sepulchre-validation-{}", Uuid::new_v4()).into_bytes();
    let expected_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        hasher.finalize().to_vec()
    };

    let write_result: Result<(), SepulchreError> = async {
        backend.ensure_dir(SCRATCH_SUBDIR).await?;
        let mut writer = backend.open_write(&file_name).await?;
        writer.write_all(&payload).await?;
        writer.shutdown().await?;
        Ok(())
    }
    .await;
    if let Err(e) = write_result {
        recorder.fail(
            "read_write_test",
            method,
            format!("write failed: {e}"),
            started,
        );
        // Always attempt cleanup even on failure -- best-effort, the
        // file may not exist at all.
        let _ = backend.delete(&file_name).await;
        return;
    }
    verified.insert(Capability::Write);

    let read_result: Result<Vec<u8>, SepulchreError> = async {
        let mut reader = backend.open_read(&file_name).await?;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        Ok(buf)
    }
    .await;
    let delete_result = backend.delete(&file_name).await;

    match read_result {
        Ok(read_back) => {
            let mut hasher = Sha256::new();
            hasher.update(&read_back);
            let actual_hash = hasher.finalize().to_vec();
            if actual_hash != expected_hash {
                recorder.fail(
                    "read_write_test",
                    method,
                    "read-back checksum did not match what was written".to_string(),
                    started,
                );
            } else {
                recorder.ok(
                    "read_write_test",
                    method,
                    "wrote, read back, and checksum-verified a scratch file".to_string(),
                    started,
                );
                verified.insert(Capability::Read);
            }
        }
        Err(e) => {
            recorder.fail(
                "read_write_test",
                method,
                format!("read-back failed: {e}"),
                started,
            );
        }
    }

    if delete_result.is_ok() {
        verified.insert(Capability::Delete);
    } else {
        recorder.record(
            "read_write_test_cleanup",
            method,
            ValidationStatus::Failed,
            Some(ErrorKind::Unknown),
            "could not remove the scratch file used for this test -- it may need manual cleanup"
                .to_string(),
            started,
        );
    }
}

async fn finish(
    state: &AppState,
    connection_id: Uuid,
    run_id: Uuid,
    checks: Vec<ValidationCheckResult>,
) -> Result<Uuid, SepulchreError> {
    let overall = if checks.iter().any(|c| c.status == ValidationStatus::Failed) {
        ValidationStatus::Failed
    } else {
        ValidationStatus::Ok
    };
    abyssal_database::repo::validation_runs::finish(&state.pool, run_id, &checks, overall).await?;
    abyssal_database::repo::storage_connections::record_validation_summary(
        &state.pool,
        connection_id,
        overall,
    )
    .await?;
    Ok(run_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_host_key_mismatch_marker_correctly() {
        assert_eq!(
            error_kind_for("host_key_mismatch: server presented a different host key than pinned"),
            ErrorKind::HostKeyMismatch
        );
    }

    #[test]
    fn maps_auth_failure_messages() {
        assert_eq!(error_kind_for("auth_failed"), ErrorKind::AuthFailed);
    }

    #[test]
    fn maps_timeout_messages() {
        assert_eq!(error_kind_for("operation timed out"), ErrorKind::Timeout);
    }

    #[test]
    fn falls_back_to_unknown_for_an_unrecognized_message() {
        assert_eq!(
            error_kind_for("something bizarre happened"),
            ErrorKind::Unknown
        );
    }

    /// Regression test: caught live against a real Samba server, whose
    /// `smbclient` rejects a wrong password with `NT_STATUS_LOGON_FAILURE`
    /// -- a string containing neither "auth" nor "authentication", so it
    /// fell through to `Unknown` before this mapping existed.
    #[test]
    fn maps_smbclient_nt_status_codes() {
        assert_eq!(
            error_kind_for(
                "smbclient exited with exit status: 1: session setup failed: NT_STATUS_LOGON_FAILURE"
            ),
            ErrorKind::AuthFailed
        );
        assert_eq!(
            error_kind_for("tree connect failed: NT_STATUS_BAD_NETWORK_NAME"),
            ErrorKind::NotFound
        );
        assert_eq!(
            error_kind_for("NT_STATUS_ACCESS_DENIED opening file"),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            error_kind_for("NT_STATUS_CONNECTION_REFUSED"),
            ErrorKind::Unreachable
        );
    }
}
