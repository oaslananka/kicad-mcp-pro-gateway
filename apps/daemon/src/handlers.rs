//! Maps each [`IpcRequest`] to a state mutation and an [`IpcResponse`].
//! This is the only place daemon-side that decides what the desktop UI/CLI
//! may do — see `docs/architecture/component-boundaries.md`. There is
//! deliberately no handler that runs an arbitrary tool against
//! kicad-mcp-pro; that only ever happens through the policy-gated
//! operation path built in later phases.

use std::sync::Arc;

use companion_core::{OperationId, Session, SessionId, SessionStatus, WorkspaceId};
use companion_core_bridge::CoreBridgeClient;
use companion_protocol::{
    AuditSummaryView, DaemonStatusView, IpcRequest, IpcResponse, PairingBegunView,
    PairingStatusView, PendingApprovalView, SessionView, WorkspaceView,
};
use companion_sessions::{SessionEvent, SessionTransition};
use companion_workspace::WorkspaceAuthorization;

use crate::errors::DaemonError;
use crate::remote_processor;
use crate::state::DaemonState;

pub async fn handle_request(state: &Arc<DaemonState>, request: IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::Status => status(state).await,
        IpcRequest::PairingStatus => pairing_status(state).await,
        IpcRequest::BeginPairing => begin_pairing(state).await,
        IpcRequest::ListSessions => list_sessions(state).await,
        IpcRequest::ApproveSession { session_id } => {
            decide_session(state, session_id, SessionEvent::Approve).await
        }
        IpcRequest::DenySession { session_id, reason } => {
            decide_session(state, session_id, SessionEvent::Deny { reason }).await
        }
        IpcRequest::PauseSession { session_id } => {
            decide_session(state, session_id, SessionEvent::Pause).await
        }
        IpcRequest::ResumeSession { session_id } => {
            decide_session(state, session_id, SessionEvent::Resume).await
        }
        IpcRequest::RevokeSession { session_id } => {
            decide_session(state, session_id, SessionEvent::Revoke).await
        }
        IpcRequest::ListWorkspaces => list_workspaces(state).await,
        IpcRequest::AuthorizeWorkspace { path, display_name } => {
            authorize_workspace(state, path, display_name).await
        }
        IpcRequest::RemoveWorkspace { workspace_id } => remove_workspace(state, workspace_id).await,
        IpcRequest::AuditSummary => audit_summary(state).await,
        IpcRequest::ListPendingApprovals => list_pending_approvals(state).await,
        IpcRequest::ApproveOperation { operation_id } => {
            approve_operation(state, operation_id).await
        }
        IpcRequest::DenyOperation {
            operation_id,
            reason: _,
        } => deny_operation(state, operation_id).await,
        IpcRequest::DaemonShutdown => {
            state.shutdown.request();
            IpcResponse::Ack
        }
    }
}

fn error_response(e: DaemonError) -> IpcResponse {
    IpcResponse::Error(e.to_ipc_error())
}

fn join_error(context: &str) -> IpcResponse {
    error_response(DaemonError::Internal(format!("{context} task panicked")))
}

fn to_session_view(session: &Session) -> SessionView {
    SessionView {
        session_id: session.session_id,
        remote_principal: session.remote_principal.clone(),
        status: format!("{:?}", session.status),
        capability_profile: format!("{:?}", session.capability_profile),
        task_scope: session.task_scope.clone(),
        expires_at: session
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "invalid-timestamp".into()),
    }
}

fn to_workspace_view(workspace: &WorkspaceAuthorization) -> WorkspaceView {
    WorkspaceView {
        workspace_id: workspace.workspace_id,
        display_name: workspace.display_name.clone(),
        canonical_root: workspace.canonical_root.to_string_lossy().to_string(),
        enabled: workspace.enabled,
    }
}

async fn status(state: &Arc<DaemonState>) -> IpcResponse {
    let state_for_db = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        let identity = state_for_db.identity_store.public_identity()?;
        let active_sessions = state_for_db.session_repo.list_active()?;
        let workspaces = state_for_db.workspace_repo.list()?;
        Ok::<_, DaemonError>((identity, active_sessions.len(), workspaces.len()))
    })
    .await;

    match result {
        Ok(Ok((identity, active_session_count, workspace_count))) => {
            let paired = identity.is_some();
            let core_bridge_reachable =
                match CoreBridgeClient::new(state.core_health_probe_config.clone()) {
                    Ok(client) => client.initialize("status-core-health").await.is_ok(),
                    Err(_) => false,
                };
            IpcResponse::Status(DaemonStatusView {
                device_fingerprint: identity.map(|i| i.fingerprint.0),
                paired,
                core_bridge_reachable,
                active_session_count,
                workspace_count,
            })
        }
        Ok(Err(e)) => error_response(e),
        Err(_) => join_error("status"),
    }
}

async fn pairing_status(state: &Arc<DaemonState>) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || state.identity_store.public_identity()).await;

    match result {
        // "paired" requires a cloud/relay round trip that does not exist
        // yet in this repository (see docs/protocol/README.md); reporting
        // true here without one would fake production pairing.
        Ok(Ok(identity)) => IpcResponse::PairingStatus(PairingStatusView {
            paired: false,
            device_fingerprint: identity.map(|i| i.fingerprint.0),
        }),
        Ok(Err(e)) => error_response(DaemonError::Identity(e)),
        Err(_) => join_error("pairing_status"),
    }
}

async fn begin_pairing(state: &Arc<DaemonState>) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        let identity = match state.identity_store.load()? {
            Some(identity) => identity,
            None => state.identity_store.create("this-device")?,
        };
        Ok::<_, DaemonError>(identity)
    })
    .await;

    match result {
        Ok(Ok(identity)) => {
            let compact: String = identity
                .fingerprint
                .0
                .chars()
                .filter(|c| *c != '-')
                .take(8)
                .collect();
            IpcResponse::PairingBegun(PairingBegunView {
                pairing_code: format!(
                    "KMP-{}-{}",
                    &compact[..4.min(compact.len())],
                    &compact[4.min(compact.len())..]
                ),
                mock_provider: true,
            })
        }
        Ok(Err(e)) => error_response(e),
        Err(_) => join_error("begin_pairing"),
    }
}

async fn list_sessions(state: &Arc<DaemonState>) -> IpcResponse {
    let state = Arc::clone(state);
    // All sessions regardless of status: a caller (desktop/CLI) needs to
    // see PendingApproval sessions to approve them, Suspended ones to
    // resume them, etc. — not just the currently-Active ones.
    let result = tokio::task::spawn_blocking(move || state.session_repo.list_all()).await;
    match result {
        Ok(Ok(sessions)) => IpcResponse::Sessions(sessions.iter().map(to_session_view).collect()),
        Ok(Err(e)) => error_response(DaemonError::Session(e)),
        Err(_) => join_error("list_sessions"),
    }
}

async fn decide_session(
    state: &Arc<DaemonState>,
    session_id: SessionId,
    event: SessionEvent,
) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        let session = state
            .session_repo
            .load(session_id)?
            .ok_or(DaemonError::SessionNotFound)?;
        let next = session.transition(event, state.clock.as_ref())?;
        state.session_repo.save(&next)?;
        if next.status == SessionStatus::Revoked {
            remote_processor::invalidate_pending_for_session(&state, session_id);
        }
        Ok::<_, DaemonError>(())
    })
    .await;

    match result {
        Ok(Ok(())) => IpcResponse::Ack,
        Ok(Err(e)) => error_response(e),
        Err(_) => join_error("decide_session"),
    }
}

async fn list_workspaces(state: &Arc<DaemonState>) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || state.workspace_repo.list()).await;
    match result {
        Ok(Ok(workspaces)) => {
            IpcResponse::Workspaces(workspaces.iter().map(to_workspace_view).collect())
        }
        Ok(Err(e)) => error_response(DaemonError::Workspace(e)),
        Err(_) => join_error("list_workspaces"),
    }
}

async fn authorize_workspace(
    state: &Arc<DaemonState>,
    path: String,
    display_name: String,
) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        let workspace = WorkspaceAuthorization::new(display_name, std::path::Path::new(&path))?;
        state.workspace_repo.save(&workspace)?;
        Ok::<_, DaemonError>(workspace)
    })
    .await;

    match result {
        Ok(Ok(workspace)) => IpcResponse::WorkspaceAuthorized(to_workspace_view(&workspace)),
        Ok(Err(e)) => error_response(e),
        Err(_) => join_error("authorize_workspace"),
    }
}

async fn remove_workspace(state: &Arc<DaemonState>, workspace_id: WorkspaceId) -> IpcResponse {
    let state = Arc::clone(state);
    let result =
        tokio::task::spawn_blocking(move || state.workspace_repo.remove(workspace_id)).await;
    match result {
        Ok(Ok(())) => IpcResponse::Ack,
        Ok(Err(e)) => error_response(DaemonError::Workspace(e)),
        Err(_) => join_error("remove_workspace"),
    }
}

async fn audit_summary(state: &Arc<DaemonState>) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || state.audit_repo.list_recent(1000)).await;
    match result {
        Ok(Ok(events)) => IpcResponse::AuditSummary(AuditSummaryView {
            total_events: events.len(),
            note: "most recent 1000 events".into(),
        }),
        Ok(Err(e)) => error_response(DaemonError::Internal(e.to_string())),
        Err(_) => join_error("audit_summary"),
    }
}

async fn list_pending_approvals(state: &Arc<DaemonState>) -> IpcResponse {
    let summaries = remote_processor::list_pending_operations(state);
    IpcResponse::PendingApprovals(
        summaries
            .into_iter()
            .map(|s| PendingApprovalView {
                operation_id: s.operation_id,
                session_id: s.session_id,
                tool_name: s.tool_name,
                risk: format!("{:?}", s.risk),
            })
            .collect(),
    )
}

async fn approve_operation(state: &Arc<DaemonState>, operation_id: OperationId) -> IpcResponse {
    match remote_processor::approve_pending_operation(state, operation_id).await {
        Ok(()) => IpcResponse::Ack,
        Err(e) => error_response(e),
    }
}

async fn deny_operation(state: &Arc<DaemonState>, operation_id: OperationId) -> IpcResponse {
    match remote_processor::deny_pending_operation(state, operation_id).await {
        Ok(()) => IpcResponse::Ack,
        Err(e) => error_response(e),
    }
}
