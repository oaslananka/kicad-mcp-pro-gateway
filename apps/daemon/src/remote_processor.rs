//! Processes envelopes arriving over a (mock, for now) relay transport.
//! This is the only path by which remote/relay-originated input can affect
//! daemon state, and it goes through exactly the same session/policy
//! pipeline local IPC callers use — see `docs/architecture/data-flow.md`
//! and `docs/security/threat-model.md` (T1: cloud input bypassing policy).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use companion_core::{
    ApprovalDecisionKind, AuditEvent, CapabilityProfile, CompanionError, DeviceId, ExecutionStatus,
    OperationId, OperationRequest, PolicyResultKind, RiskLevel, Session, SessionId, WorkspaceId,
};
use companion_policy::PolicyDecision;
use companion_protocol::{Envelope, MessageType};
use companion_sessions::{new_unpaired_session, SessionEvent, SessionTransition};
use companion_transport::{Transport, TransportError};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::state::{DaemonState, PendingOperation};

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
                    Ok(envelope) => {
                        if envelope.check_protocol_version().is_err() {
                            tracing::warn!("dropping envelope with incompatible protocol version");
                            continue;
                        }
                        match envelope.message_type {
                            MessageType::SessionRequest => handle_session_request(&state, envelope).await,
                            MessageType::OperationRequest => handle_operation_request(&state, &transport, envelope).await,
                            _ => {}
                        }
                    }
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
        let ttl = time::Duration::minutes(payload.ttl_minutes.max(1));

        let session = new_unpaired_session(
            device_id,
            payload.remote_principal,
            workspace_ids,
            payload.capability_profile,
            payload.task_scope,
            ttl,
            state.clock.as_ref(),
        );
        let session = session.transition(SessionEvent::Pair, state.clock.as_ref())?;
        let session = session.transition(SessionEvent::TransportConnected, state.clock.as_ref())?;
        let session = session.transition(SessionEvent::RequestAccess, state.clock.as_ref())?;
        state.session_repo.save(&session)?;
        tracing::info!(session_id = %session.session_id, "session now pending local approval");
        Ok(())
    })
    .await;

    if let Ok(Err(e)) = outcome {
        tracing::warn!(error = %e, "failed to process session request");
    }
}

async fn handle_operation_request(
    state: &Arc<DaemonState>,
    transport: &Arc<dyn Transport>,
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

    let Ok((decision, session)) = eval else {
        tracing::warn!("policy evaluation task panicked");
        return;
    };

    if session
        .as_ref()
        .is_some_and(|session| session.device_id != local_device_id)
    {
        tracing::warn!(session_id = %request.session_id, "operation request session device binding rejected");
        return;
    }

    let audit_event = build_audit_event(&request, session.as_ref(), &decision);
    if let Err(e) = state.audit_repo.record(&audit_event) {
        tracing::warn!(error = %e, "failed to record audit event");
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

fn evaluate_operation_request(
    state: &DaemonState,
    request: &OperationRequest,
) -> (PolicyDecision, Option<Session>) {
    let session = state.session_repo.load(request.session_id).ok().flatten();
    let workspace = state
        .workspace_repo
        .load(request.workspace_id)
        .ok()
        .flatten();
    let decision = match (&session, &workspace) {
        (Some(session), Some(workspace)) => {
            state
                .policy_engine
                .evaluate(request, session, workspace, state.clock.as_ref())
        }
        _ => PolicyDecision::Deny {
            reason: companion_policy::DenyReason::WorkspaceNotAuthorized,
        },
    };
    (decision, session)
}

fn build_audit_event(
    request: &OperationRequest,
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
        remote_principal: session.map(|s| s.remote_principal.clone()),
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
    transport: &Arc<dyn Transport>,
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
    if let Err(e) = state.audit_repo.update_execution(
        request.operation_id,
        status,
        error_class,
        Some(duration_ms),
    ) {
        tracing::warn!(error = %e, "failed to update audit execution status");
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

/// "Allow once": approves exactly one pending high-risk operation and
/// executes it. Never grants standing session access.
pub async fn approve_pending_operation(
    state: &Arc<DaemonState>,
    operation_id: OperationId,
) -> Result<(), &'static str> {
    let pending = state
        .pending_operations
        .lock()
        .expect("pending mutex poisoned")
        .remove(&operation_id);
    let Some(pending) = pending else {
        return Err("no such pending operation");
    };

    let state_for_eval = Arc::clone(state);
    let request_for_eval = pending.request.clone();
    let current_decision = tokio::task::spawn_blocking(move || {
        evaluate_operation_request(&state_for_eval, &request_for_eval).0
    })
    .await
    .map_err(|_| "policy revalidation task panicked")?;

    let still_authorized = matches!(
        current_decision,
        PolicyDecision::RequireApproval { capability, risk, .. }
            if capability == pending.capability && risk == pending.risk
    );

    if let Err(e) = state
        .audit_repo
        .update_approval_decision(operation_id, ApprovalDecisionKind::AllowOnce)
    {
        tracing::warn!(error = %e, "failed to record approval decision");
    }

    if !still_authorized {
        if let Err(e) = state.audit_repo.update_execution(
            operation_id,
            ExecutionStatus::Failed,
            Some("POLICY_REVALIDATION_DENIED".into()),
            None,
        ) {
            tracing::warn!(error = %e, "failed to record stale approval denial");
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
        return Err("pending operation is no longer authorized");
    }

    let transport = state
        .transport
        .lock()
        .expect("transport mutex poisoned")
        .clone();
    if let Some(transport) = transport {
        execute_and_respond(state, &transport, pending.request).await;
    }
    Ok(())
}

pub async fn deny_pending_operation(
    state: &Arc<DaemonState>,
    operation_id: OperationId,
) -> Result<(), &'static str> {
    let pending = state
        .pending_operations
        .lock()
        .expect("pending mutex poisoned")
        .remove(&operation_id);
    let Some(pending) = pending else {
        return Err("no such pending operation");
    };

    if let Err(e) = state
        .audit_repo
        .update_approval_decision(operation_id, ApprovalDecisionKind::Denied)
    {
        tracing::warn!(error = %e, "failed to record approval decision");
    }
    if let Err(e) = state.audit_repo.update_execution(
        operation_id,
        ExecutionStatus::Failed,
        Some("DENIED_BY_USER".into()),
        None,
    ) {
        tracing::warn!(error = %e, "failed to update execution status for denied operation");
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
    Ok(())
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

    fn build_test_state(endpoint: String) -> Arc<DaemonState> {
        let data_dir = tempfile::tempdir().unwrap().keep();
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
        Envelope::new(
            MessageType::SessionRequest,
            json!({
                "remote_principal": "agent:test",
                "workspace_id": workspace_id,
                "capability_profile": "Design",
                "task_scope": "device binding test",
                "ttl_minutes": 30,
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
            &transport,
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
            &transport,
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
            &transport,
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
