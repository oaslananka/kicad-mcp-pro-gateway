//! Processes envelopes arriving over a (mock, for now) relay transport.
//! This is the only path by which remote/relay-originated input can affect
//! daemon state, and it goes through exactly the same session/policy
//! pipeline local IPC callers use — see `docs/architecture/data-flow.md`
//! and `docs/security/threat-model.md` (T1: cloud input bypassing policy).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use companion_core::{
    AccessGrant, ApprovalDecisionKind, AuditEvent, AuthorizationPrincipal, CapabilityProfile,
    CompanionError, DeviceId, ExecutionStatus, GrantKind, GrantRequest, OperationId,
    OperationRequest, PolicyResultKind, RiskLevel, Session, SessionId, WorkspaceId,
};
use companion_policy::PolicyDecision;
use companion_protocol::{Envelope, MessageType};
use companion_sessions::{new_unpaired_session, SessionEvent, SessionTransition};
use companion_transport::{Transport, TransportError};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::errors::DaemonError;
use crate::state::{DaemonState, PendingOperation};

/// Fixed refusal message for a failed pre-execution audit write. Deliberately
/// constant: nothing derived from the storage error (or from the request) is
/// ever echoed back across the untrusted transport.
const AUDIT_FAIL_CLOSED_MESSAGE: &str =
    "durable audit record could not be persisted; operation was not executed";

/// Payload shape for a `MessageType::SessionRequest` envelope.
#[derive(Debug, Deserialize)]
struct SessionRequestPayload {
    remote_principal: String,
    workspace_id: WorkspaceId,
    capability_profile: CapabilityProfile,
    task_scope: String,
    ttl_minutes: i64,
}

pub async fn run_remote_processor(
    state: Arc<DaemonState>,
    transport: Arc<dyn Transport>,
) -> Result<(), TransportError> {
    *state.transport.lock().expect("transport mutex poisoned") = Some(Arc::clone(&transport));
    let shutdown = Arc::clone(&state.shutdown);

    loop {
        tokio::select! {
            received = transport.receive() => {
                match received {
                    Ok(envelope) => handle_envelope(&state, transport.as_ref(), envelope).await,
                    Err(TransportError::NoMessage) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
            _ = shutdown.cancelled() => return Ok(()),
        }
    }
}

/// The protocol adapter: everything that can arrive on the transport goes
/// through here, and nothing here can change authorization authority. Each
/// branch may only *record* a remote access request (as a grant awaiting
/// local approval), consume an already-approved grant, or be refused.
///
/// A replayed, duplicated, or out-of-order envelope therefore lands in
/// exactly the same place as the first one: the request is recorded at most
/// once per live grant, and no branch can widen, extend, or revive authority.
pub async fn handle_envelope(
    state: &Arc<DaemonState>,
    transport: &dyn Transport,
    envelope: Envelope,
) {
    if envelope.check_protocol_version().is_err() {
        tracing::warn!("dropping envelope with incompatible protocol version");
        return;
    }
    match envelope.message_type {
        MessageType::SessionRequest => handle_session_request(state, envelope).await,
        MessageType::OperationRequest => handle_operation_request(state, transport, envelope).await,
        _ => {}
    }
}

async fn handle_session_request(state: &Arc<DaemonState>, envelope: Envelope) {
    let claimed_device_id = envelope.device_id;
    let payload: SessionRequestPayload = match serde_json::from_value(envelope.payload) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "malformed session request envelope, dropping");
            return;
        }
    };

    let state = Arc::clone(state);
    let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let Some(device_id) = bound_local_device_id(&state, claimed_device_id) else {
            tracing::warn!("session request device binding rejected");
            return Ok(());
        };
        let Some(workspace) = state.workspace_repo.load(payload.workspace_id)? else {
            tracing::warn!(workspace_id = %payload.workspace_id, "session request for unauthorized/unknown workspace, dropping");
            return Ok(());
        };
        let mut workspace_ids = BTreeSet::new();
        workspace_ids.insert(workspace.workspace_id);
        let effective_ttl = state.policy_engine.effective_authorization_ttl(
            &payload.capability_profile,
            payload.ttl_minutes,
        );
        let ttl = time::Duration::minutes(effective_ttl.effective_minutes);

        // The transport-era subject record. Retained so existing clients,
        // audit rows, and checkpoints keep correlating on `session_id`; it
        // carries no authority of its own.
        let session = new_unpaired_session(
            device_id,
            payload.remote_principal.clone(),
            workspace_ids.clone(),
            payload.capability_profile.clone(),
            payload.task_scope.clone(),
            ttl,
            state.clock.as_ref(),
        );
        let session = session.transition(SessionEvent::Pair, state.clock.as_ref())?;
        let session = session.transition(SessionEvent::TransportConnected, state.clock.as_ref())?;
        let session = session.transition(SessionEvent::RequestAccess, state.clock.as_ref())?;

        // The authorization record, and the only thing that can ever grant
        // access. It is created `PendingApproval`: a request arriving over a
        // connected pipe is not an approval, so nothing here mints authority.
        let grant = AccessGrant::requested(
            GrantRequest {
                subject_session_id: session.session_id,
                device_id,
                principal: AuthorizationPrincipal::unverified(payload.remote_principal),
                workspace_ids,
                capability_profile: payload.capability_profile,
                task_scope: payload.task_scope,
                kind: GrantKind::Standing,
                lifetime: ttl,
            },
            state.clock.as_ref().now(),
        );

        // A replayed or duplicated `session.request` must not be able to
        // stack up extra pending authority, and must never move an existing
        // grant's deadline or widen its scope. An identical live request for
        // the same device/principal/workspace/scope is dropped instead.
        if let Some(existing) = state.authorization_repo.find_live_request(&grant)? {
            tracing::info!(
                grant_id = %existing.grant_id,
                subject_session_id = %existing.subject_session_id,
                expires_at = %existing.expires_at,
                "duplicate or replayed session request ignored; existing grant untouched"
            );
            return Ok(());
        }

        state.session_repo.save(&session)?;
        state.authorization_repo.save_grant(&grant)?;
        tracing::info!(
            grant_id = %grant.grant_id,
            session_id = %session.session_id,
            requested_ttl_minutes = effective_ttl.requested_minutes,
            effective_ttl_minutes = effective_ttl.effective_minutes,
            expires_at = %grant.expires_at,
            "access grant now pending local approval with policy-limited lifetime"
        );
        Ok(())
    })
    .await;

    if let Ok(Err(e)) = outcome {
        tracing::warn!(error = %e, "failed to process session request");
    }
}

async fn handle_operation_request(
    state: &Arc<DaemonState>,
    transport: &dyn Transport,
    envelope: Envelope,
) {
    let claimed_device_id = envelope.device_id;
    let state_for_binding = Arc::clone(state);
    let binding = tokio::task::spawn_blocking(move || {
        bound_local_device_id(&state_for_binding, claimed_device_id)
    })
    .await;
    let Ok(Some(local_device_id)) = binding else {
        tracing::warn!("operation request device binding rejected");
        return;
    };

    let request: OperationRequest = match serde_json::from_value(envelope.payload) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "malformed operation request envelope, dropping");
            return;
        }
    };

    let state_for_eval = Arc::clone(state);
    let request_for_eval = request.clone();
    let eval = tokio::task::spawn_blocking(move || {
        evaluate_operation_request(&state_for_eval, &request_for_eval)
    })
    .await;

    let Ok((decision, grant, session)) = eval else {
        tracing::warn!("policy evaluation task panicked");
        return;
    };

    // The grant's device binding is the one that matters; the transport-era
    // row is only a mirror of it.
    let bound_device = grant
        .as_ref()
        .map(|grant| grant.device_id)
        .or_else(|| session.as_ref().map(|session| session.device_id));
    if bound_device != Some(local_device_id) {
        tracing::warn!(session_id = %request.session_id, "operation request device binding rejected");
        return;
    }

    let audit_event = build_audit_event(&request, grant.as_ref(), session.as_ref(), &decision);
    // Fail closed: the durable pre-execution audit record is the only proof
    // that this decision was made at all. Without it the operation is refused
    // — it never reaches kicad-mcp-pro and it is never queued for approval.
    // This applies to remote reads and remote writes alike; see
    // `docs/security/audit-fail-closed.md`.
    if let Err(audit_error) = state.audit_repo.record(&audit_event) {
        tracing::error!(
            operation_id = %request.operation_id,
            code = audit_error.code(),
            error = %audit_error,
            "pre-execution audit record could not be persisted; refusing operation"
        );
        let envelope =
            audit_refusal_envelope(&request, audit_error.code(), audit_error.retryable());
        let _ = transport.send(envelope).await;
        return;
    }

    match decision {
        PolicyDecision::Allow { .. } => {
            execute_and_respond(state, transport, request).await;
        }
        PolicyDecision::Deny { reason } => {
            let envelope = operation_result_envelope(
                &request,
                false,
                serde_json::json!({ "denied": format!("{reason:?}") }),
            );
            let _ = transport.send(envelope).await;
        }
        PolicyDecision::RequireApproval {
            capability, risk, ..
        } => {
            tracing::info!(operation_id = %request.operation_id, ?risk, "high-risk operation pending local approval");
            state
                .pending_operations
                .lock()
                .expect("pending mutex poisoned")
                .insert(
                    request.operation_id,
                    PendingOperation {
                        request,
                        capability,
                        risk,
                    },
                );
        }
    }
}

fn bound_local_device_id(
    state: &DaemonState,
    claimed_device_id: Option<DeviceId>,
) -> Option<DeviceId> {
    let claimed_device_id = claimed_device_id?;
    match state.identity_store.load() {
        Ok(Some(identity)) if identity.device_id == claimed_device_id => Some(identity.device_id),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(error = %error, "failed to load persistent device identity");
            None
        }
    }
}

/// Resolves the authority behind an operation request, if any exists.
///
/// Order matters: a persisted access grant is the authority. The
/// transport-era `sessions` row is consulted only as the compatibility
/// adapter the schema migration uses, and even then the decision is made on
/// a grant, never on the row. A request whose subject has neither is denied.
fn resolve_grant(
    state: &DaemonState,
    request: &OperationRequest,
) -> (Option<AccessGrant>, Option<Session>) {
    let session = state.session_repo.load(request.session_id).ok().flatten();
    let persisted = state
        .authorization_repo
        .load_grant_for_subject(request.session_id)
        .ok()
        .flatten();
    if let Some(grant) = persisted {
        return (Some(grant), session);
    }
    let derived = session
        .as_ref()
        .and_then(|row| companion_core::grant_from_legacy_session(row).ok())
        .flatten();
    (derived, session)
}

fn evaluate_operation_request(
    state: &DaemonState,
    request: &OperationRequest,
) -> (PolicyDecision, Option<AccessGrant>, Option<Session>) {
    let (grant, session) = resolve_grant(state, request);
    let workspace = state
        .workspace_repo
        .load(request.workspace_id)
        .ok()
        .flatten();
    let decision = match (&grant, &workspace) {
        (Some(grant), Some(workspace)) => {
            state
                .policy_engine
                .evaluate_with_grant(request, grant, workspace, state.clock.as_ref())
        }
        // No authority, or no such workspace: both are refusals, never a
        // reason to fall back to "the transport is connected, so allow".
        _ => PolicyDecision::Deny {
            reason: match workspace {
                Some(_) => companion_policy::DenyReason::AuthorizationNotEstablished,
                None => companion_policy::DenyReason::WorkspaceNotAuthorized,
            },
        },
    };
    (decision, grant, session)
}

fn build_audit_event(
    request: &OperationRequest,
    grant: Option<&AccessGrant>,
    session: Option<&Session>,
    decision: &PolicyDecision,
) -> AuditEvent {
    let (policy_result, capability, risk) = match decision {
        PolicyDecision::Allow { capability, risk } => {
            (PolicyResultKind::Allow, Some(*capability), Some(*risk))
        }
        PolicyDecision::Deny { .. } => (PolicyResultKind::Deny, None, None),
        PolicyDecision::RequireApproval {
            capability, risk, ..
        } => (
            PolicyResultKind::RequireApproval,
            Some(*capability),
            Some(*risk),
        ),
    };
    AuditEvent {
        operation_id: request.operation_id,
        timestamp: OffsetDateTime::now_utc(),
        session_id: Some(request.session_id),
        workspace_id: Some(request.workspace_id),
        // The grant is the authority, so its principal is what the audit
        // record names when one exists; the legacy row is the fallback for
        // pre-migration history.
        remote_principal: grant
            .map(|grant| grant.principal.name.clone())
            .or_else(|| session.map(|session| session.remote_principal.clone())),
        requested_tool: request.tool_name.clone(),
        capability,
        risk,
        policy_result,
        approval_decision: None,
        execution_status: ExecutionStatus::NotExecuted,
        error_class: None,
        duration_ms: None,
    }
}

async fn execute_and_respond(
    state: &Arc<DaemonState>,
    transport: &dyn Transport,
    request: OperationRequest,
) {
    let start = std::time::Instant::now();
    let call_result = state
        .core_bridge
        .call_tool(
            &request.tool_name,
            serde_json::Value::Object(request.arguments.clone()),
            &request.operation_id.to_string(),
        )
        .await;
    let duration_ms = start.elapsed().as_millis() as u64;

    let (success, payload, error_class) = match &call_result {
        Ok(value) => (true, value.clone(), None),
        Err(e) => (
            false,
            serde_json::json!({ "error": e.to_string() }),
            Some(e.code().to_string()),
        ),
    };

    let status = if success {
        ExecutionStatus::Success
    } else {
        ExecutionStatus::Failed
    };
    // Post-execution only: the pre-execution record (the trust-boundary
    // evidence that this call was authorized) is already durable, so a
    // failure here never blocks or undoes the execution — it is logged as an
    // operational error carrying the operation id for reconciliation instead
    // of being silently downgraded to a warning.
    if let Err(e) = state.audit_repo.update_execution(
        request.operation_id,
        status,
        error_class,
        Some(duration_ms),
    ) {
        tracing::error!(
            operation_id = %request.operation_id,
            code = e.code(),
            error = %e,
            "post-execution audit status update failed; pre-execution record exists and must be reconciled"
        );
    }

    let envelope = operation_result_envelope(&request, success, payload);
    let _ = transport.send(envelope).await;
}

fn operation_result_envelope(
    request: &OperationRequest,
    success: bool,
    payload: serde_json::Value,
) -> Envelope {
    Envelope::new(
        MessageType::OperationResult,
        serde_json::json!({ "operation_id": request.operation_id, "success": success, "result": payload }),
    )
    .with_correlation_id(request.operation_id.to_string())
}

/// Typed, secret-free refusal returned to the remote caller when the daemon
/// could not durably record the pre-execution audit event. Only a stable
/// error class and a fixed message cross the transport: storage error detail
/// (which may name local files or SQL objects) stays in the local log.
/// See `docs/security/audit-fail-closed.md`.
fn audit_refusal_envelope(
    request: &OperationRequest,
    error_class: &str,
    retryable: bool,
) -> Envelope {
    operation_result_envelope(
        request,
        false,
        serde_json::json!({
            "error_class": error_class,
            "error": AUDIT_FAIL_CLOSED_MESSAGE,
            "retryable": retryable,
            "executed": false,
        }),
    )
}

/// "Allow once": approves exactly one pending high-risk operation and
/// executes it. Never grants standing session access.
///
/// Fail-closed: the approval decision is persisted *before* execution may
/// start. If it cannot be persisted, nothing executes and the operation is
/// put back into the pending queue so the decision can be retried once
/// storage recovers — it is never executed on a best-effort approval.
pub async fn approve_pending_operation(
    state: &Arc<DaemonState>,
    operation_id: OperationId,
) -> Result<(), DaemonError> {
    let pending = state
        .pending_operations
        .lock()
        .expect("pending mutex poisoned")
        .remove(&operation_id);
    let Some(pending) = pending else {
        return Err(DaemonError::Internal("no such pending operation".into()));
    };

    let state_for_eval = Arc::clone(state);
    let request_for_eval = pending.request.clone();
    let current_decision = tokio::task::spawn_blocking(move || {
        evaluate_operation_request(&state_for_eval, &request_for_eval).0
    })
    .await
    .map_err(|_| DaemonError::Internal("policy revalidation task panicked".into()))?;

    let still_authorized = matches!(
        current_decision,
        PolicyDecision::RequireApproval { capability, risk, .. }
            if capability == pending.capability && risk == pending.risk
    );

    if let Err(audit_error) = state
        .audit_repo
        .update_approval_decision(operation_id, ApprovalDecisionKind::AllowOnce)
    {
        // Nothing has executed yet, so the safe outcome is to refuse and to
        // re-queue: the operator sees a typed error, the operation stays
        // visible as pending, and no unaudited execution can happen.
        tracing::error!(
            operation_id = %operation_id,
            code = audit_error.code(),
            error = %audit_error,
            "approval decision could not be persisted; refusing to execute the approved operation"
        );
        requeue_pending_operation(state, operation_id, pending);
        return Err(DaemonError::AuditPersistence {
            code: audit_error.code(),
        });
    }

    if !still_authorized {
        if let Err(e) = state.audit_repo.update_execution(
            operation_id,
            ExecutionStatus::Failed,
            Some("POLICY_REVALIDATION_DENIED".into()),
            None,
        ) {
            tracing::error!(
                operation_id = %operation_id,
                code = e.code(),
                error = %e,
                "failed to record stale approval denial"
            );
        }
        let transport = state
            .transport
            .lock()
            .expect("transport mutex poisoned")
            .clone();
        if let Some(transport) = transport {
            let envelope = operation_result_envelope(
                &pending.request,
                false,
                serde_json::json!({ "denied": "authorization changed before approval" }),
            );
            let _ = transport.send(envelope).await;
        }
        return Err(DaemonError::Internal(
            "pending operation is no longer authorized".into(),
        ));
    }

    let transport = state
        .transport
        .lock()
        .expect("transport mutex poisoned")
        .clone();
    if let Some(transport) = transport {
        execute_and_respond(state, transport.as_ref(), pending.request).await;
    }
    Ok(())
}

/// Puts an operation back into the pending queue after its approval decision
/// could not be persisted. Nothing executed at that point, so the operation
/// must stay visible for a retry instead of being silently dropped; an entry
/// that has already been re-decided elsewhere is never overwritten.
fn requeue_pending_operation(
    state: &Arc<DaemonState>,
    operation_id: OperationId,
    pending: PendingOperation,
) {
    let mut pending_operations = state
        .pending_operations
        .lock()
        .expect("pending mutex poisoned");
    pending_operations.entry(operation_id).or_insert(pending);
}

/// Removes a pending high-risk operation from the queue and records the
/// denial. The denial itself is fail-safe and is never undone: once the
/// operation leaves the pending queue nothing can execute it, so even if the
/// denial cannot be written to the audit store the operation is *not*
/// re-queued (a forgotten denial must never become an executable operation)
/// — the caller receives a typed error instead.
pub async fn deny_pending_operation(
    state: &Arc<DaemonState>,
    operation_id: OperationId,
) -> Result<(), DaemonError> {
    let pending = state
        .pending_operations
        .lock()
        .expect("pending mutex poisoned")
        .remove(&operation_id);
    let Some(pending) = pending else {
        return Err(DaemonError::Internal("no such pending operation".into()));
    };

    let approval_error = match state
        .audit_repo
        .update_approval_decision(operation_id, ApprovalDecisionKind::Denied)
    {
        Ok(()) => None,
        Err(e) => {
            tracing::error!(
                operation_id = %operation_id,
                code = e.code(),
                error = %e,
                "approval decision could not be persisted; the denial is still enforced but is not durably recorded"
            );
            Some(e.code())
        }
    };
    if let Err(e) = state.audit_repo.update_execution(
        operation_id,
        ExecutionStatus::Failed,
        Some("DENIED_BY_USER".into()),
        None,
    ) {
        tracing::error!(
            operation_id = %operation_id,
            code = e.code(),
            error = %e,
            "failed to update execution status for denied operation"
        );
    }

    let transport = state
        .transport
        .lock()
        .expect("transport mutex poisoned")
        .clone();
    if let Some(transport) = transport {
        let envelope = operation_result_envelope(
            &pending.request,
            false,
            serde_json::json!({ "denied": "by user" }),
        );
        let _ = transport.send(envelope).await;
    }
    match approval_error {
        None => Ok(()),
        Some(code) => Err(DaemonError::AuditPersistence { code }),
    }
}

/// Removes all pending high-risk operations belonging to a revoked session.
/// Their audit rows are finalized as failed so no operation remains forever
/// in an ambiguous `NotExecuted` state.
pub fn invalidate_pending_for_session(state: &Arc<DaemonState>, session_id: SessionId) -> usize {
    let removed_ids = {
        let mut pending = state
            .pending_operations
            .lock()
            .expect("pending mutex poisoned");
        let mut removed = Vec::new();
        pending.retain(|operation_id, item| {
            if item.request.session_id == session_id {
                removed.push(*operation_id);
                false
            } else {
                true
            }
        });
        removed
    };

    for operation_id in &removed_ids {
        if let Err(e) = state.audit_repo.update_execution(
            *operation_id,
            ExecutionStatus::Failed,
            Some("SESSION_REVOKED".into()),
            None,
        ) {
            tracing::warn!(error = %e, %operation_id, "failed to finalize revoked pending operation audit");
        }
    }
    removed_ids.len()
}

pub struct PendingSummary {
    pub operation_id: OperationId,
    pub session_id: SessionId,
    pub workspace_id: WorkspaceId,
    pub tool_name: String,
    pub risk: RiskLevel,
}

pub fn list_pending_operations(state: &Arc<DaemonState>) -> Vec<PendingSummary> {
    state
        .pending_operations
        .lock()
        .expect("pending mutex poisoned")
        .values()
        .map(|p| PendingSummary {
            operation_id: p.request.operation_id,
            session_id: p.request.session_id,
            workspace_id: p.request.workspace_id,
            tool_name: p.request.tool_name.clone(),
            risk: p.risk,
        })
        .collect()
}

#[cfg(test)]
mod device_binding_tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use companion_core::config::{self, CliOverrides};
    use companion_core::{CapabilityProfile, DeviceId, OperationId, OperationRequest, Session};
    use companion_core_bridge::MockMcpServer;
    use companion_identity::InMemorySecretStore;
    use companion_transport::{MockTransport, Transport};
    use companion_workspace::WorkspaceAuthorization;
    use serde_json::json;

    use super::*;

    const TEST_AUTHORIZATION_TTL_CONFIG: &str = r#"
[authorization_ttl]
low_risk_max_minutes = 30
normal_risk_max_minutes = 7
high_risk_max_minutes = 3
critical_risk_max_minutes = 1

[authorization_ttl.inspect]
max_minutes = 90
risk = "low"

[authorization_ttl.design]
max_minutes = 47
risk = "normal"

[authorization_ttl.manufacturing]
max_minutes = 20
risk = "high"

[authorization_ttl.custom]
max_minutes = 5
risk = "critical"
"#;

    fn build_test_state(endpoint: String) -> Arc<DaemonState> {
        build_test_state_with_config(endpoint, None)
    }

    fn build_test_state_with_config(
        endpoint: String,
        config_file: Option<&str>,
    ) -> Arc<DaemonState> {
        let data_dir = tempfile::tempdir().unwrap().keep();
        if let Some(contents) = config_file {
            std::fs::write(data_dir.join("config.toml"), contents).unwrap();
        }
        let cfg = config::load(CliOverrides {
            data_dir: Some(data_dir),
            core_bridge_endpoint: Some(endpoint),
            ..Default::default()
        })
        .unwrap();
        crate::build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap()
    }

    fn authorize_workspace(state: &Arc<DaemonState>) -> WorkspaceId {
        let root = tempfile::tempdir().unwrap().keep();
        let workspace = WorkspaceAuthorization::new("test".into(), &root).unwrap();
        let id = workspace.workspace_id;
        state.workspace_repo.save(&workspace).unwrap();
        id
    }

    fn session_request(workspace_id: WorkspaceId) -> Envelope {
        session_request_with(workspace_id, CapabilityProfile::Design, 30)
    }

    fn session_request_with(
        workspace_id: WorkspaceId,
        capability_profile: CapabilityProfile,
        ttl_minutes: i64,
    ) -> Envelope {
        Envelope::new(
            MessageType::SessionRequest,
            json!({
                "remote_principal": "agent:test",
                "workspace_id": workspace_id,
                "capability_profile": capability_profile,
                "task_scope": "device binding test",
                "ttl_minutes": ttl_minutes,
            }),
        )
    }

    fn active_session(
        state: &Arc<DaemonState>,
        device_id: DeviceId,
        workspace_id: WorkspaceId,
    ) -> Session {
        let mut workspace_ids = BTreeSet::new();
        workspace_ids.insert(workspace_id);
        let session = new_unpaired_session(
            device_id,
            "agent:test".into(),
            workspace_ids,
            CapabilityProfile::Design,
            "device binding test".into(),
            time::Duration::minutes(30),
            state.clock.as_ref(),
        )
        .transition(SessionEvent::Pair, state.clock.as_ref())
        .unwrap()
        .transition(SessionEvent::TransportConnected, state.clock.as_ref())
        .unwrap()
        .transition(SessionEvent::RequestAccess, state.clock.as_ref())
        .unwrap()
        .transition(SessionEvent::Approve, state.clock.as_ref())
        .unwrap();
        state.session_repo.save(&session).unwrap();
        session
    }

    fn low_risk_operation(session: &Session, workspace_id: WorkspaceId) -> OperationRequest {
        OperationRequest {
            operation_id: OperationId::new(),
            session_id: session.session_id,
            workspace_id,
            tool_name: "sch_get_symbols".into(),
            arguments: Default::default(),
            target_path: None,
            requested_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[tokio::test]
    async fn session_request_requires_persistent_local_device_id() {
        let state = build_test_state("http://127.0.0.1:9/mcp".into());
        let identity = state.identity_store.create("test-device").unwrap();
        let workspace_id = authorize_workspace(&state);

        handle_session_request(&state, session_request(workspace_id)).await;
        assert!(state.session_repo.list_all().unwrap().is_empty());

        handle_session_request(
            &state,
            session_request(workspace_id).with_device_id(DeviceId::new()),
        )
        .await;
        assert!(state.session_repo.list_all().unwrap().is_empty());

        handle_session_request(
            &state,
            session_request(workspace_id).with_device_id(identity.device_id),
        )
        .await;
        let sessions = state.session_repo.list_all().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].device_id, identity.device_id);
    }

    #[tokio::test]
    async fn session_request_persists_and_exposes_policy_limited_expiry() {
        let state = build_test_state_with_config(
            "http://127.0.0.1:9/mcp".into(),
            Some(TEST_AUTHORIZATION_TTL_CONFIG),
        );
        let identity = state.identity_store.create("test-device").unwrap();
        let workspace_id = authorize_workspace(&state);

        handle_session_request(
            &state,
            session_request_with(workspace_id, CapabilityProfile::Design, i64::MAX)
                .with_device_id(identity.device_id),
        )
        .await;

        let sessions = state.session_repo.list_all().unwrap();
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(
            session.status,
            companion_core::SessionStatus::PendingApproval
        );
        assert_eq!(
            session.expires_at - session.issued_at,
            time::Duration::minutes(7),
            "the durable session record must contain the policy-limited lifetime"
        );

        let persisted = state
            .session_repo
            .load(session.session_id)
            .unwrap()
            .expect("session remains auditable after persistence");
        assert_eq!(persisted.expires_at, session.expires_at);

        let response =
            crate::handlers::handle_request(&state, companion_protocol::IpcRequest::ListSessions)
                .await;
        let companion_protocol::IpcResponse::Sessions(views) = response else {
            panic!("ListSessions must return session views");
        };
        assert_eq!(views.len(), 1);
        assert_eq!(
            views[0].expires_at,
            session
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn operation_request_rejects_missing_or_wrong_local_device_id() {
        let fake_kicad = MockMcpServer::start().await;
        let state = build_test_state(fake_kicad.endpoint().to_string());
        let identity = state.identity_store.create("test-device").unwrap();
        let workspace_id = authorize_workspace(&state);
        let session = active_session(&state, identity.device_id, workspace_id);
        let relay = Arc::new(MockTransport::new());
        relay.connect().await.unwrap();
        let transport: Arc<dyn Transport> = relay;

        let request = low_risk_operation(&session, workspace_id);
        handle_operation_request(
            &state,
            transport.as_ref(),
            Envelope::new(
                MessageType::OperationRequest,
                serde_json::to_value(&request).unwrap(),
            ),
        )
        .await;
        assert_eq!(fake_kicad.tool_call_count(), 0);

        let request = low_risk_operation(&session, workspace_id);
        handle_operation_request(
            &state,
            transport.as_ref(),
            Envelope::new(
                MessageType::OperationRequest,
                serde_json::to_value(&request).unwrap(),
            )
            .with_device_id(DeviceId::new()),
        )
        .await;
        assert_eq!(fake_kicad.tool_call_count(), 0);
        fake_kicad.stop();
    }

    #[tokio::test]
    async fn operation_request_requires_session_to_belong_to_local_device() {
        let fake_kicad = MockMcpServer::start().await;
        let state = build_test_state(fake_kicad.endpoint().to_string());
        let identity = state.identity_store.create("test-device").unwrap();
        let workspace_id = authorize_workspace(&state);
        let foreign_session = active_session(&state, DeviceId::new(), workspace_id);
        let relay = Arc::new(MockTransport::new());
        relay.connect().await.unwrap();
        let transport: Arc<dyn Transport> = relay;
        let request = low_risk_operation(&foreign_session, workspace_id);

        handle_operation_request(
            &state,
            transport.as_ref(),
            Envelope::new(
                MessageType::OperationRequest,
                serde_json::to_value(&request).unwrap(),
            )
            .with_device_id(identity.device_id),
        )
        .await;

        assert_eq!(fake_kicad.tool_call_count(), 0);
        fake_kicad.stop();
    }

    #[tokio::test]
    async fn receive_failure_is_returned_to_the_runtime_supervisor() {
        let state = build_test_state("http://127.0.0.1:9/mcp".into());
        let relay = Arc::new(MockTransport::new());
        relay.connect().await.unwrap();
        relay.fail_next_receives(1);
        let transport: Arc<dyn Transport> = relay;

        let result = run_remote_processor(state, transport).await;
        assert!(matches!(result, Err(TransportError::ReceiveFailed(_))));
    }

    #[test]
    fn persistent_identity_keeps_same_device_id_after_state_reopen() {
        let data_dir = tempfile::tempdir().unwrap().keep();
        let cfg = config::load(CliOverrides {
            data_dir: Some(data_dir.clone()),
            core_bridge_endpoint: Some("http://127.0.0.1:9/mcp".into()),
            ..Default::default()
        })
        .unwrap();
        let first = crate::build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
        let created = first.identity_store.create("test-device").unwrap();
        drop(first);

        let reopened =
            crate::build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
        let loaded = reopened.identity_store.load().unwrap().unwrap();
        assert_eq!(loaded.device_id, created.device_id);
    }
}

#[cfg(test)]
mod audit_fail_closed_tests {
    //! Failure-injection coverage for the pre-execution audit gate: disk
    //! full, read-only, locked, corrupt audit store, an injected write error
    //! and a replayed operation id must all leave the upstream `tools/call`
    //! counter at zero and answer the remote caller with the same typed,
    //! secret-free refusal. Policy: `docs/security/audit-fail-closed.md`.

    use std::path::PathBuf;

    use companion_core::config::{self, CliOverrides};
    use companion_core_bridge::MockMcpServer;
    use companion_identity::InMemorySecretStore;
    use companion_transport::MockTransport;
    use companion_workspace::WorkspaceAuthorization;
    use serde_json::json;

    use super::*;

    /// Remote write at normal risk: policy `Allow`, so it exercises the
    /// "must be durably auditable before it runs" path directly. Use a
    /// reviewed effect contract; unmodelled tools are intentionally denied.
    const REMOTE_WRITE_TOOL: &str = "lib_create_custom_symbol";
    /// Read-only tool at low risk: policy `Allow`, exercises the documented
    /// read fail-closed rule.
    const REMOTE_READ_TOOL: &str = "sch_get_symbols";
    /// High-risk tool: policy `RequireApproval`, so a durable approval
    /// decision is required before anything may execute.
    const HIGH_RISK_TOOL: &str = "pcb_auto_place_by_schematic";

    struct Harness {
        state: Arc<DaemonState>,
        data_dir: PathBuf,
        relay: Arc<MockTransport>,
        transport: Arc<dyn Transport>,
        fake_kicad: MockMcpServer,
        device_id: DeviceId,
        workspace_id: WorkspaceId,
        session: Session,
    }

    impl Harness {
        async fn new() -> Self {
            let fake_kicad = MockMcpServer::start().await;
            let data_dir = tempfile::tempdir().unwrap().keep();
            let cfg = config::load(CliOverrides {
                data_dir: Some(data_dir.clone()),
                core_bridge_endpoint: Some(fake_kicad.endpoint().to_string()),
                ..Default::default()
            })
            .unwrap();
            let state =
                crate::build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
            let device_id = state
                .identity_store
                .create("test-device")
                .unwrap()
                .device_id;
            let workspace_id = authorize_workspace(&state);
            let session = active_session(&state, device_id, workspace_id);
            let relay = Arc::new(MockTransport::new());
            relay.connect().await.unwrap();
            let transport: Arc<dyn Transport> = relay.clone();
            // The approval/denial path answers over whichever transport the
            // runtime has connected — the same one `run_remote_processor`
            // records in `state.transport`.
            *state.transport.lock().expect("transport mutex poisoned") = Some(transport.clone());
            Self {
                state,
                data_dir,
                relay,
                transport,
                fake_kicad,
                device_id,
                workspace_id,
                session,
            }
        }

        /// A request whose arguments carry a marker that must never be echoed
        /// back in a refusal response.
        fn operation(&self, tool_name: &str) -> OperationRequest {
            let argument_name = match tool_name {
                REMOTE_WRITE_TOOL => "name",
                HIGH_RISK_TOOL => "strategy",
                _ => "sheet",
            };
            let mut arguments = serde_json::Map::new();
            arguments.insert(argument_name.into(), json!("super-secret-argument-value"));
            if tool_name == REMOTE_WRITE_TOOL {
                arguments.insert("pins".into(), json!([]));
            }
            OperationRequest {
                operation_id: OperationId::new(),
                session_id: self.session.session_id,
                workspace_id: self.workspace_id,
                tool_name: tool_name.into(),
                arguments,
                target_path: None,
                requested_at: time::OffsetDateTime::now_utc(),
            }
        }

        async fn submit(&self, request: &OperationRequest) {
            handle_operation_request(
                &self.state,
                self.transport.as_ref(),
                Envelope::new(
                    MessageType::OperationRequest,
                    serde_json::to_value(request).unwrap(),
                )
                .with_device_id(self.device_id),
            )
            .await;
        }

        /// Applies a failure injection to the daemon's own database handle.
        fn inject_failure(&self, sql: &str) {
            let conn = self
                .state
                .storage
                .connection()
                .lock()
                .expect("storage mutex poisoned");
            conn.execute_batch(sql).expect("failure injection applies");
        }

        /// Asserts the whole refusal contract: kicad-mcp-pro was never called
        /// and the caller received exactly one typed refusal whose payload
        /// holds nothing but a stable error class, a fixed message and the
        /// (never executed) flag.
        fn assert_refused_without_execution(&self, request: &OperationRequest) {
            assert_eq!(
                self.fake_kicad.tool_call_count(),
                0,
                "kicad-mcp-pro must not be called without a durable audit record"
            );
            let sent = self.relay.sent_messages();
            let last = sent
                .last()
                .expect("the remote caller must be told the operation was refused");
            assert_eq!(last.message_type, MessageType::OperationResult);
            assert_eq!(last.correlation_id, Some(request.operation_id.to_string()));
            assert_eq!(
                last.payload,
                json!({
                    "operation_id": request.operation_id,
                    "success": false,
                    "result": {
                        "error_class": "AUDIT_STORAGE",
                        "error": AUDIT_FAIL_CLOSED_MESSAGE,
                        "retryable": false,
                        "executed": false,
                    },
                }),
                "the refusal must be typed and must not echo storage detail or tool arguments"
            );
            let rendered = last.payload.to_string();
            assert!(!rendered.contains("super-secret-argument-value"));
            assert!(!rendered.to_lowercase().contains("database"));
        }

        fn shutdown(&self) {
            self.fake_kicad.stop();
        }
    }

    fn authorize_workspace(state: &Arc<DaemonState>) -> WorkspaceId {
        let root = tempfile::tempdir().unwrap().keep();
        let workspace = WorkspaceAuthorization::new("test".into(), &root).unwrap();
        let id = workspace.workspace_id;
        state.workspace_repo.save(&workspace).unwrap();
        id
    }

    fn active_session(
        state: &Arc<DaemonState>,
        device_id: DeviceId,
        workspace_id: WorkspaceId,
    ) -> Session {
        let mut workspace_ids = BTreeSet::new();
        workspace_ids.insert(workspace_id);
        let session = new_unpaired_session(
            device_id,
            "agent:test".into(),
            workspace_ids,
            CapabilityProfile::Design,
            "audit fail-closed test".into(),
            time::Duration::minutes(30),
            state.clock.as_ref(),
        )
        .transition(SessionEvent::Pair, state.clock.as_ref())
        .unwrap()
        .transition(SessionEvent::TransportConnected, state.clock.as_ref())
        .unwrap()
        .transition(SessionEvent::RequestAccess, state.clock.as_ref())
        .unwrap()
        .transition(SessionEvent::Approve, state.clock.as_ref())
        .unwrap();
        state.session_repo.save(&session).unwrap();
        session
    }

    fn filler_event() -> AuditEvent {
        AuditEvent {
            operation_id: OperationId::new(),
            timestamp: OffsetDateTime::now_utc(),
            session_id: None,
            workspace_id: None,
            remote_principal: Some("agent:test".into()),
            requested_tool: "filler".into(),
            capability: None,
            risk: None,
            policy_result: PolicyResultKind::Allow,
            approval_decision: None,
            execution_status: ExecutionStatus::NotExecuted,
            error_class: None,
            duration_ms: None,
        }
    }

    /// Caps the database at its current size and consumes the free space that
    /// is left, so the next audit write fails with a genuine `SQLITE_FULL`
    /// ("database or disk is full") instead of a simulated one. Returns the
    /// resulting error text for the caller to classify.
    fn fill_database_until_full(state: &Arc<DaemonState>) -> String {
        let page_count: i64 = {
            let conn = state
                .storage
                .connection()
                .lock()
                .expect("storage mutex poisoned");
            conn.query_row("PRAGMA page_count", [], |row| row.get(0))
                .expect("page count is readable")
        };
        {
            let conn = state
                .storage
                .connection()
                .lock()
                .expect("storage mutex poisoned");
            conn.execute_batch(&format!("PRAGMA max_page_count = {page_count};"))
                .expect("database size is capped");
        }

        let mut attempts = 0usize;
        loop {
            attempts += 1;
            assert!(attempts < 100_000, "the capped database never filled up");
            if let Err(e) = state.audit_repo.record(&filler_event()) {
                return e.to_string();
            }
            // Eat a page-sized slice of whatever free space remains. A filler
            // insert that fails is fine: the audit row above already consumed
            // space, so the loop is guaranteed to converge.
            let conn = state
                .storage
                .connection()
                .lock()
                .expect("storage mutex poisoned");
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS audit_fill (data BLOB);
                 INSERT INTO audit_fill (data) VALUES (randomblob(3000));",
            );
        }
    }

    #[tokio::test]
    async fn healthy_audit_store_executes_a_remote_write() {
        let harness = Harness::new().await;
        let request = harness.operation(REMOTE_WRITE_TOOL);
        harness.submit(&request).await;

        assert_eq!(harness.fake_kicad.tool_call_count(), 1);
        let recent = harness.state.audit_repo.list_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].execution_status, ExecutionStatus::Success);
        harness.shutdown();
    }

    #[tokio::test]
    async fn injected_persistence_failure_blocks_remote_write_before_tools_call() {
        let harness = Harness::new().await;
        harness.inject_failure(
            "CREATE TRIGGER reject_audit_insert BEFORE INSERT ON audit_events \
             BEGIN SELECT RAISE(ABORT, 'injected audit persistence failure'); END;",
        );

        let request = harness.operation(REMOTE_WRITE_TOOL);
        harness.submit(&request).await;

        harness.assert_refused_without_execution(&request);
        assert!(harness.state.audit_repo.list_recent(10).unwrap().is_empty());
        harness.shutdown();
    }

    #[tokio::test]
    async fn read_only_audit_store_blocks_remote_read_before_tools_call() {
        let harness = Harness::new().await;
        // `query_only` fails every write on the daemon's own connection with
        // SQLITE_READONLY while reads keep working, so policy still decides
        // `Allow` for this read and only the audit gate refuses it.
        harness.inject_failure("PRAGMA query_only = TRUE;");

        let request = harness.operation(REMOTE_READ_TOOL);
        harness.submit(&request).await;

        harness.assert_refused_without_execution(&request);
        harness.shutdown();
    }

    #[tokio::test]
    async fn full_database_blocks_execution_before_tools_call() {
        let harness = Harness::new().await;
        let failure = fill_database_until_full(&harness.state);
        assert!(
            failure.to_lowercase().contains("full"),
            "expected a genuine disk-full failure, got: {failure}"
        );

        let request = harness.operation(REMOTE_WRITE_TOOL);
        harness.submit(&request).await;

        harness.assert_refused_without_execution(&request);
        harness.shutdown();
    }

    #[tokio::test]
    async fn locked_database_blocks_execution_before_tools_call() {
        let harness = Harness::new().await;
        // rusqlite waits up to 5s by default; shortened here so the test
        // observes the fail-closed branch immediately. In production the wait
        // is bounded the same way and still ends in a refusal, never in an
        // execution.
        {
            let conn = harness
                .state
                .storage
                .connection()
                .lock()
                .expect("storage mutex poisoned");
            conn.busy_timeout(Duration::from_millis(0))
                .expect("busy window shortened");
        }
        // A second connection holds the write lock for the whole test. The
        // daemon can still read sessions and workspaces (so policy reaches
        // `Allow`), but the audit INSERT hits SQLITE_BUSY.
        // `Storage` owns `gateway.db`; the blocker must lock that same file,
        // otherwise the daemon connection is never actually contended.
        let blocker =
            rusqlite::Connection::open(harness.data_dir.join("gateway.db")).expect("second db");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("write lock taken");

        let request = harness.operation(REMOTE_WRITE_TOOL);
        harness.submit(&request).await;

        harness.assert_refused_without_execution(&request);
        drop(blocker);
        harness.shutdown();
    }

    #[tokio::test]
    async fn corrupt_audit_store_blocks_execution_before_tools_call() {
        let harness = Harness::new().await;
        // Schema-level corruption of the audit store: the deterministic form
        // of a corrupt database (byte-level corruption also breaks the
        // unrelated session reads, which would mask the gate under test).
        harness.inject_failure("DROP TABLE audit_events;");

        let request = harness.operation(REMOTE_WRITE_TOOL);
        harness.submit(&request).await;

        harness.assert_refused_without_execution(&request);
        harness.shutdown();
    }

    #[tokio::test]
    async fn replayed_operation_id_is_refused_without_a_second_tool_call() {
        let harness = Harness::new().await;
        let request = harness.operation(REMOTE_WRITE_TOOL);
        harness.submit(&request).await;
        assert_eq!(harness.fake_kicad.tool_call_count(), 1);

        // The durable record for this operation id already exists, so the
        // duplicate insert fails and the replay is refused instead of being
        // executed a second time.
        harness.submit(&request).await;

        assert_eq!(
            harness.fake_kicad.tool_call_count(),
            1,
            "a replayed operation id must not reach kicad-mcp-pro"
        );
        let sent = harness.relay.sent_messages();
        assert_eq!(sent.len(), 2);
        let last = sent.last().unwrap();
        assert_eq!(last.payload["success"].as_bool(), Some(false));
        assert_eq!(
            last.payload["result"]["error_class"].as_str(),
            Some("AUDIT_STORAGE")
        );
        harness.shutdown();
    }

    #[tokio::test]
    async fn approval_decision_must_be_durable_before_high_risk_execution() {
        let harness = Harness::new().await;
        let request = harness.operation(HIGH_RISK_TOOL);
        harness.submit(&request).await;

        let pending = list_pending_operations(&harness.state);
        assert_eq!(pending.len(), 1, "the operation waits for local approval");
        assert_eq!(harness.fake_kicad.tool_call_count(), 0);

        // The approval write itself fails: read-only store at decision time.
        harness.inject_failure("PRAGMA query_only = TRUE;");

        let result = approve_pending_operation(&harness.state, request.operation_id).await;
        assert!(
            matches!(
                result,
                Err(DaemonError::AuditPersistence {
                    code: "AUDIT_STORAGE"
                })
            ),
            "expected a typed audit persistence error, got {result:?}"
        );

        assert_eq!(
            harness.fake_kicad.tool_call_count(),
            0,
            "an approved high-risk operation must not run without a durable approval record"
        );
        let pending = list_pending_operations(&harness.state);
        assert_eq!(
            pending.len(),
            1,
            "the operation stays queued for a retry instead of being dropped"
        );
        assert_eq!(pending[0].operation_id, request.operation_id);
        harness.shutdown();
    }

    #[tokio::test]
    async fn denial_is_enforced_but_never_resurrected_when_persistence_fails() {
        let harness = Harness::new().await;
        let request = harness.operation(HIGH_RISK_TOOL);
        harness.submit(&request).await;
        assert_eq!(list_pending_operations(&harness.state).len(), 1);

        harness.inject_failure("PRAGMA query_only = TRUE;");

        let result = deny_pending_operation(&harness.state, request.operation_id).await;
        assert!(matches!(
            result,
            Err(DaemonError::AuditPersistence {
                code: "AUDIT_STORAGE"
            })
        ));

        assert_eq!(harness.fake_kicad.tool_call_count(), 0);
        assert!(
            list_pending_operations(&harness.state).is_empty(),
            "a denial must never be re-queued: a forgotten denial must not become executable"
        );
        let sent = harness.relay.sent_messages();
        let last = sent.last().expect("the remote caller is told it is denied");
        assert_eq!(last.payload["success"].as_bool(), Some(false));
        assert_eq!(last.payload["result"]["denied"].as_str(), Some("by user"));
        harness.shutdown();
    }
}
