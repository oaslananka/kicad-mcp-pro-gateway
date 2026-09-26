//! Maps each [`IpcRequest`] to a state mutation and an [`IpcResponse`].
//! This is the only place daemon-side that decides what the desktop UI/CLI
//! may do — see `docs/architecture/component-boundaries.md`. There is
//! deliberately no handler that runs an arbitrary tool against
//! kicad-mcp-pro; that only ever happens through the policy-gated
//! operation path built in later phases.

use std::sync::Arc;

use companion_core::{
    AccessGrant, AuthorizationLease, AuthorizationStatus, GrantId, OperationId, Session, SessionId,
    WorkspaceId,
};
use companion_core_bridge::CoreBridgeClient;
use companion_protocol::{
    AccessGrantView, AuditSummaryView, AuthorizationLeaseView, DaemonIdentityView,
    DaemonStatusView, IpcRequest, IpcResponse, PairingBegunView, PairingStatusView,
    PendingApprovalView, SessionView, WorkspaceInfo, WorkspaceView, DAEMON_PRODUCT_ID,
    LOCAL_IPC_PROTOCOL_VERSION,
};
use companion_sessions::{
    authorization_event_for, GrantTransition, SessionEvent, SessionTransition,
};
use companion_workspace::{WorkspaceAuthorization, WorkspaceRepository};

use crate::errors::DaemonError;
use crate::remote_processor;
use crate::state::DaemonState;

pub async fn handle_request(state: &Arc<DaemonState>, request: IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::Identity => identity(state),
        IpcRequest::Status => status(state).await,
        IpcRequest::PairingStatus => pairing_status(state).await,
        IpcRequest::BeginPairing => begin_pairing(state).await,
        IpcRequest::ListSessions => list_sessions(state).await,
        IpcRequest::ListAccessGrants => list_access_grants(state).await,
        IpcRequest::ListAuthorizationLeases { grant_id } => {
            list_authorization_leases(state, grant_id).await
        }
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

fn workspace_infos(
    workspace_ids: impl Iterator<Item = WorkspaceId>,
    workspace_repo: &WorkspaceRepository,
) -> Vec<WorkspaceInfo> {
    workspace_ids
        .filter_map(|id| {
            workspace_repo
                .load(id)
                .ok()
                .flatten()
                .map(|ws| WorkspaceInfo {
                    workspace_id: ws.workspace_id,
                    display_name: ws.display_name,
                })
        })
        .collect()
}

fn format_timestamp(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "invalid-timestamp".into())
}

/// A transport-era subject record plus, next to it, the authorization state
/// and the transport state — reported as three separate facts so a client
/// cannot read a healthy pipe as an approval, or a revoked grant as a
/// disconnect.
fn to_session_view(
    session: &Session,
    authorization_status: &str,
    transport_state: &str,
    workspace_repo: &WorkspaceRepository,
) -> SessionView {
    SessionView {
        session_id: session.session_id,
        remote_principal: session.remote_principal.clone(),
        status: format!("{:?}", session.status),
        authorization_status: authorization_status.to_string(),
        transport_state: transport_state.to_string(),
        capability_profile: format!("{:?}", session.capability_profile),
        task_scope: session.task_scope.clone(),
        expires_at: format_timestamp(session.expires_at),
        workspace_ids: session.workspace_ids.iter().cloned().collect(),
        workspaces: workspace_infos(session.workspace_ids.iter().copied(), workspace_repo),
    }
}

fn to_grant_view(
    grant: &AccessGrant,
    transport_state: &str,
    workspace_repo: &WorkspaceRepository,
) -> AccessGrantView {
    AccessGrantView {
        grant_id: grant.grant_id,
        subject_session_id: grant.subject_session_id,
        device_id: grant.device_id,
        remote_principal: grant.principal.name.clone(),
        principal_assurance: format!("{:?}", grant.principal.assurance).to_lowercase(),
        authorization_status: format!("{:?}", grant.status).to_lowercase(),
        grant_kind: format!("{:?}", grant.kind).to_lowercase(),
        capability_profile: format!("{:?}", grant.capability_profile),
        task_scope: grant.task_scope.clone(),
        issued_at: format_timestamp(grant.issued_at),
        approved_at: grant.approved_at.map(format_timestamp),
        expires_at: format_timestamp(grant.expires_at),
        revoked_at: grant.revoked_at.map(format_timestamp),
        revocation_reason: grant.revocation_reason.clone(),
        consumed_at: grant.consumed_at.map(format_timestamp),
        workspace_ids: grant.workspace_ids.iter().cloned().collect(),
        workspaces: workspace_infos(grant.workspace_ids.iter().copied(), workspace_repo),
        transport_state: transport_state.to_string(),
    }
}

fn to_lease_view(lease: &AuthorizationLease) -> AuthorizationLeaseView {
    AuthorizationLeaseView {
        lease_id: lease.lease_id,
        grant_id: lease.grant_id,
        subject_session_id: lease.subject_session_id,
        device_id: lease.device_id,
        issued_at: format_timestamp(lease.issued_at),
        expires_at: format_timestamp(lease.expires_at),
        consumed_at: lease.consumed_at.map(format_timestamp),
        consumed_by_operation: lease.consumed_by_operation,
        workspace_ids: lease.workspace_ids.iter().cloned().collect(),
        capabilities: lease.capabilities.iter().map(|c| c.to_string()).collect(),
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

fn identity(state: &Arc<DaemonState>) -> IpcResponse {
    IpcResponse::Identity(DaemonIdentityView {
        product_id: DAEMON_PRODUCT_ID.to_string(),
        protocol_version: LOCAL_IPC_PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        instance_id: state.instance_id.clone(),
    })
}

async fn status(state: &Arc<DaemonState>) -> IpcResponse {
    let state_for_db = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        let identity = state_for_db.identity_store.public_identity()?;
        let active_sessions = state_for_db.session_repo.list_active()?;
        let grants = state_for_db.authorization_repo.list_all_grants()?;
        let now = state_for_db.clock.as_ref().now();
        let active_grant_count = grants
            .iter()
            .filter(|grant| grant.is_usable_at(now))
            .count();
        let pending_approval_grant_count = grants
            .iter()
            .filter(|grant| grant.status == AuthorizationStatus::PendingApproval)
            .count();
        let workspaces = state_for_db.workspace_repo.list()?;
        Ok::<_, DaemonError>((
            identity,
            active_sessions.len(),
            active_grant_count,
            pending_approval_grant_count,
            workspaces.len(),
        ))
    })
    .await;

    match result {
        Ok(Ok((
            identity,
            active_session_count,
            active_grant_count,
            pending_approval_grant_count,
            workspace_count,
        ))) => {
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
                active_grant_count,
                pending_approval_grant_count,
                transport_state: format!("{:?}", state.transport_state()),
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
    let workspace_repo = state.workspace_repo.clone();
    let transport_state = format!("{:?}", state.transport_state());
    // All sessions regardless of status: a caller (desktop/CLI) needs to
    // see PendingApproval sessions to approve them, Suspended ones to
    // resume them, etc. — not just the currently-Active ones.
    let result = tokio::task::spawn_blocking(move || {
        let grants = state
            .authorization_repo
            .list_all_grants()
            .map_err(DaemonError::Authorization)?;
        let statuses: Vec<(SessionId, AuthorizationStatus)> = grants
            .into_iter()
            .map(|grant| (grant.subject_session_id, grant.status))
            .collect();
        Ok::<_, DaemonError>((state.session_repo.list_all()?, statuses))
    })
    .await;
    match result {
        Ok(Ok((sessions, grants))) => IpcResponse::Sessions(
            sessions
                .iter()
                .map(|session| {
                    let authorization_status = grants
                        .iter()
                        .find(|(subject, _)| *subject == session.session_id)
                        .map(|(_, status)| format!("{:?}", status).to_lowercase())
                        .unwrap_or_else(|| "none".to_string());
                    to_session_view(
                        session,
                        &authorization_status,
                        &transport_state,
                        &workspace_repo,
                    )
                })
                .collect(),
        ),
        Ok(Err(e)) => error_response(e),
        Err(_) => join_error("list_sessions"),
    }
}

/// The authorization view: every access grant, whatever its state, plus the
/// transport connectivity reported beside it rather than inside it.
async fn list_access_grants(state: &Arc<DaemonState>) -> IpcResponse {
    let state = Arc::clone(state);
    let workspace_repo = state.workspace_repo.clone();
    let transport_state = format!("{:?}", state.transport_state());
    let result =
        tokio::task::spawn_blocking(move || state.authorization_repo.list_all_grants()).await;
    match result {
        Ok(Ok(grants)) => IpcResponse::AccessGrants(
            grants
                .iter()
                .map(|grant| to_grant_view(grant, &transport_state, &workspace_repo))
                .collect(),
        ),
        Ok(Err(e)) => error_response(DaemonError::Authorization(e)),
        Err(_) => join_error("list_access_grants"),
    }
}

async fn list_authorization_leases(state: &Arc<DaemonState>, grant_id: GrantId) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        state.authorization_repo.list_leases_for_grant(grant_id)
    })
    .await;
    match result {
        Ok(Ok(leases)) => {
            IpcResponse::AuthorizationLeases(leases.iter().map(to_lease_view).collect())
        }
        Ok(Err(e)) => error_response(DaemonError::Authorization(e)),
        Err(_) => join_error("list_authorization_leases"),
    }
}

/// Applies a local decision to the *authorization* record first, then mirrors
/// it onto the transport-era session row for compatibility.
///
/// The legacy event has no authorization mapping at all (see
/// [`authorization_event_for`]), so a decision that only concerns a pipe can
/// never reach a grant. Conversely, revoking or expiring authority here does
/// not touch the transport: `state.transport` and `state.transport_state`
/// are left exactly as they are.
async fn decide_session(
    state: &Arc<DaemonState>,
    session_id: SessionId,
    event: SessionEvent,
) -> IpcResponse {
    let state = Arc::clone(state);
    let result = tokio::task::spawn_blocking(move || {
        let grant =
            authority_for_subject(&state, session_id)?.ok_or(DaemonError::SessionNotFound)?;
        let authorization_event =
            authorization_event_for(&event).ok_or(DaemonError::NoAuthorizationDecision)?;
        let next_grant = grant.transition(&authorization_event, state.clock.as_ref())?;
        state.authorization_repo.save_grant(&next_grant)?;

        // Compatibility mirror for existing clients. A mirror that cannot be
        // applied (e.g. a row already terminal) is not allowed to fail the
        // decision the authority record already accepted.
        if let Some(session) = state.session_repo.load(session_id)? {
            if let Ok(next_session) = session.transition(event, state.clock.as_ref()) {
                state.session_repo.save(&next_session)?;
            }
        }
        if next_grant.status == AuthorizationStatus::Revoked {
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

/// The grant that authorizes a subject: a persisted grant, or the same
/// deterministic legacy adapter the schema migration uses. `None` means no
/// authority exists, which callers must treat as a refusal.
fn authority_for_subject(
    state: &Arc<DaemonState>,
    session_id: SessionId,
) -> Result<Option<AccessGrant>, DaemonError> {
    if let Some(grant) = state
        .authorization_repo
        .load_grant_for_subject(session_id)?
    {
        return Ok(Some(grant));
    }
    let session = state.session_repo.load(session_id)?;
    Ok(session
        .as_ref()
        .and_then(|row| companion_core::grant_from_legacy_session(row).ok())
        .flatten())
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
    let workspace_repo = state.workspace_repo.clone();
    let result = tokio::task::spawn_blocking(move || {
        summaries
            .into_iter()
            .map(|s| {
                let workspace = workspace_repo
                    .load(s.workspace_id)
                    .map_err(DaemonError::Workspace)?
                    .map(|ws| WorkspaceInfo {
                        workspace_id: ws.workspace_id,
                        display_name: ws.display_name,
                    });
                Ok::<_, DaemonError>(PendingApprovalView {
                    operation_id: s.operation_id,
                    session_id: s.session_id,
                    workspace_id: s.workspace_id,
                    workspace,
                    tool_name: s.tool_name,
                    risk: format!("{:?}", s.risk),
                })
            })
            .collect::<Result<Vec<_>, DaemonError>>()
    })
    .await;

    match result {
        Ok(Ok(approvals)) => IpcResponse::PendingApprovals(approvals),
        Ok(Err(e)) => error_response(e),
        Err(_) => join_error("list_pending_approvals"),
    }
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
