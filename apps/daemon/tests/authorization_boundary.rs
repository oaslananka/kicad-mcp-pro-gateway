//! Protocol-adapter evidence for the transport/authorization boundary.
//!
//! Every test here drives the real envelope entry point
//! ([`kicad_mcp_gateway_daemon::remote_processor::handle_envelope`]) and the
//! real IPC surface, with real reconnect churn, and asserts that no
//! transport event can mint, extend, widen, or resurrect access authority.

use std::collections::BTreeSet;
use std::sync::Arc;

use companion_core::config::{self, CliOverrides};
use companion_core::{
    AccessGrant, AuthorizationPrincipal, AuthorizationStatus, CapabilityProfile, GrantKind,
    GrantRequest, OperationId, OperationRequest, SessionId, TransportState, WorkspaceId,
};
use companion_core_bridge::MockMcpServer;
use companion_identity::InMemorySecretStore;
use companion_protocol::{Envelope, IpcRequest, IpcResponse, MessageType};
use companion_sessions::{AuthorizationEvent, GrantTransition, TransportConnectivityEvent};
use companion_transport::{MockTransport, Transport};
use companion_workspace::WorkspaceAuthorization;
use kicad_mcp_gateway_daemon::{
    build_state_with_secret_store, remote_processor, state::DaemonState,
};
use serde_json::json;
use std::path::PathBuf;
use time::Duration;

/// The full connect/disconnect/reconnect cycle a relay pipe can go through.
fn churn_transport(state: &Arc<DaemonState>) {
    for event in [
        TransportConnectivityEvent::Connecting,
        TransportConnectivityEvent::Connected,
        TransportConnectivityEvent::Disconnected,
        TransportConnectivityEvent::Reconnecting,
        TransportConnectivityEvent::Connected,
        TransportConnectivityEvent::Disconnected,
        TransportConnectivityEvent::ConnectFailed,
        TransportConnectivityEvent::Connecting,
        TransportConnectivityEvent::Connected,
    ] {
        state.record_transport_event(event);
    }
}

fn state_with_core(endpoint: String) -> Arc<DaemonState> {
    let data_dir: PathBuf = tempfile::tempdir().unwrap().keep();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir),
        core_bridge_endpoint: Some(endpoint),
        ..Default::default()
    })
    .unwrap();
    build_state_with_secret_store(&cfg, InMemorySecretStore::new())
        .expect("daemon state builds with an in-memory secret store")
}

fn authorize_workspace(state: &Arc<DaemonState>) -> WorkspaceId {
    let root = tempfile::tempdir().unwrap().keep();
    let workspace = WorkspaceAuthorization::new("boundary".into(), &root).unwrap();
    state.workspace_repo.save(&workspace).unwrap();
    workspace.workspace_id
}

fn session_request(workspace_id: WorkspaceId) -> Envelope {
    Envelope::new(
        MessageType::SessionRequest,
        json!({
            "remote_principal": "agent:boundary",
            "workspace_id": workspace_id,
            "capability_profile": CapabilityProfile::Inspect,
            "task_scope": "boundary test",
            "ttl_minutes": 30,
        }),
    )
}

fn active_grant(state: &Arc<DaemonState>, workspace_id: WorkspaceId) -> AccessGrant {
    let grant = AccessGrant::requested(
        GrantRequest {
            subject_session_id: SessionId::new(),
            device_id: state
                .identity_store
                .create("boundary-device")
                .unwrap()
                .device_id,
            principal: AuthorizationPrincipal::unverified("agent:boundary"),
            workspace_ids: BTreeSet::from([workspace_id]),
            capability_profile: CapabilityProfile::Inspect,
            task_scope: "boundary test".into(),
            kind: GrantKind::Standing,
            lifetime: Duration::hours(1),
        },
        state.clock.as_ref().now(),
    );
    let grant = grant
        .transition(&AuthorizationEvent::Approve, state.clock.as_ref())
        .unwrap();
    state.authorization_repo.save_grant(&grant).unwrap();
    grant
}

fn operation_request(grant: &AccessGrant, workspace_id: WorkspaceId) -> OperationRequest {
    OperationRequest {
        operation_id: OperationId::new(),
        session_id: grant.subject_session_id,
        workspace_id,
        tool_name: "sch_get_symbols".into(),
        arguments: Default::default(),
        target_path: None,
        requested_at: time::OffsetDateTime::now_utc(),
    }
}

#[tokio::test]
async fn a_replayed_or_duplicated_session_request_mints_exactly_one_pending_grant() {
    let state = state_with_core("http://127.0.0.1:9/mcp".into());
    let identity = state.identity_store.create("replay-device").unwrap();
    let workspace_id = authorize_workspace(&state);
    let relay = MockTransport::new();
    relay.connect().await.unwrap();
    let transport: &dyn Transport = &relay;
    state.record_transport_event(TransportConnectivityEvent::Connected);

    let envelope = session_request(workspace_id).with_device_id(identity.device_id);
    for _ in 0..3 {
        remote_processor::handle_envelope(&state, transport, envelope.clone()).await;
    }

    let grants = state.authorization_repo.list_all_grants().unwrap();
    assert_eq!(
        grants.len(),
        1,
        "three copies of one request must not become three pending grants"
    );
    let grant = &grants[0];
    assert_eq!(
        grant.status,
        AuthorizationStatus::PendingApproval,
        "a request that arrived over a connected pipe is still not an approval"
    );
    assert!(!grant.is_usable_at(state.clock.as_ref().now()));

    // Churn the pipe, then replay the very same envelope again.
    churn_transport(&state);
    let before = state
        .authorization_repo
        .load_grant(grant.grant_id)
        .unwrap()
        .unwrap();
    remote_processor::handle_envelope(&state, transport, envelope.clone()).await;
    remote_processor::handle_envelope(&state, transport, envelope).await;
    let after = state
        .authorization_repo
        .load_grant(grant.grant_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        before, after,
        "replay must not move a deadline or widen scope"
    );
    assert_eq!(state.authorization_repo.list_all_grants().unwrap().len(), 1);
    assert_eq!(
        state.session_repo.list_all().unwrap().len(),
        1,
        "the transport-era mirror is deduplicated the same way"
    );
}

#[tokio::test]
async fn revoking_authority_leaves_a_connected_pipe_connected_and_uncharged() {
    let state = state_with_core("http://127.0.0.1:9/mcp".into());
    let workspace_id = authorize_workspace(&state);
    let grant = active_grant(&state, workspace_id);
    state.record_transport_event(TransportConnectivityEvent::Connected);
    assert_eq!(state.transport_state(), TransportState::Connected);

    let response = kicad_mcp_gateway_daemon::handlers::handle_request(
        &state,
        IpcRequest::RevokeSession {
            session_id: grant.subject_session_id,
        },
    )
    .await;
    assert!(matches!(response, IpcResponse::Ack), "{response:?}");

    assert_eq!(
        state.transport_state(),
        TransportState::Connected,
        "revocation is an authority decision, not a disconnect"
    );
    assert!(state.transport.lock().unwrap().is_none());
    let revoked = state
        .authorization_repo
        .load_grant(grant.grant_id)
        .unwrap()
        .unwrap();
    assert_eq!(revoked.status, AuthorizationStatus::Revoked);
    assert!(revoked.revoked_at.is_some());
    assert!(!revoked.is_usable_at(state.clock.as_ref().now()));

    // A full reconnect cycle, and a brand-new transport object to go with it,
    // changes the pipe and nothing else.
    churn_transport(&state);
    let replacement = MockTransport::new();
    replacement.connect().await.unwrap();
    state.record_transport_event(TransportConnectivityEvent::Disconnected);
    state.record_transport_event(TransportConnectivityEvent::Connected);
    assert_eq!(state.transport_state(), TransportState::Connected);

    let after_reconnect = state
        .authorization_repo
        .load_grant(grant.grant_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after_reconnect, revoked,
        "a reconnect must not alter the grant"
    );
    assert!(!after_reconnect.is_usable_at(state.clock.as_ref().now()));

    // And no local decision can resurrect it either.
    let revive = kicad_mcp_gateway_daemon::handlers::handle_request(
        &state,
        IpcRequest::ApproveSession {
            session_id: grant.subject_session_id,
        },
    )
    .await;
    let IpcResponse::Error(error) = revive else {
        panic!("approving a revoked grant must fail");
    };
    assert_eq!(error.code, "AUTHORIZATION_TERMINAL_STATE");
    assert_eq!(
        state
            .authorization_repo
            .load_grant(grant.grant_id)
            .unwrap()
            .unwrap()
            .status,
        AuthorizationStatus::Revoked
    );
}

#[tokio::test]
async fn an_operation_request_over_a_reconnected_pipe_is_still_refused_after_revocation() {
    let fake_kicad = MockMcpServer::start().await;
    let state = state_with_core(fake_kicad.endpoint().to_string());
    let workspace_id = authorize_workspace(&state);
    let grant = active_grant(&state, workspace_id);
    let relay = MockTransport::new();
    relay.connect().await.unwrap();
    let transport: &dyn Transport = &relay;

    // The grant works while it is in force...
    let allowed = operation_request(&grant, workspace_id);
    remote_processor::handle_envelope(
        &state,
        transport,
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(&allowed).unwrap(),
        )
        .with_device_id(grant.device_id),
    )
    .await;
    assert_eq!(fake_kicad.tool_call_count(), 1);

    // ...then the local user revokes it, and the pipe drops and comes back.
    kicad_mcp_gateway_daemon::handlers::handle_request(
        &state,
        IpcRequest::RevokeSession {
            session_id: grant.subject_session_id,
        },
    )
    .await;
    churn_transport(&state);
    let replacement = MockTransport::new();
    replacement.connect().await.unwrap();
    state.record_transport_event(TransportConnectivityEvent::Connected);

    for _ in 0..3 {
        let denied = operation_request(&grant, workspace_id);
        remote_processor::handle_envelope(
            &state,
            transport,
            Envelope::new(
                MessageType::OperationRequest,
                serde_json::to_value(&denied).unwrap(),
            )
            .with_device_id(grant.device_id),
        )
        .await;
    }
    assert_eq!(
        fake_kicad.tool_call_count(),
        1,
        "a reconnected pipe must not execute anything for a revoked grant"
    );

    // The refusal is recorded durably, with the grant's principal.
    let events = state.audit_repo.list_recent(100).unwrap();
    let denials: Vec<_> = events
        .iter()
        .filter(|event| event.session_id == Some(grant.subject_session_id))
        .collect();
    assert!(denials.len() >= 3, "every refused replay is audited");
    fake_kicad.stop();
}

#[tokio::test]
async fn ipc_views_report_authorization_and_transport_as_separate_facts() {
    let state = state_with_core("http://127.0.0.1:9/mcp".into());
    let workspace_id = authorize_workspace(&state);
    active_grant(&state, workspace_id);

    let IpcResponse::AccessGrants(grants) =
        kicad_mcp_gateway_daemon::handlers::handle_request(&state, IpcRequest::ListAccessGrants)
            .await
    else {
        panic!("ListAccessGrants must return grant views");
    };
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].authorization_status, "active");
    assert_eq!(grants[0].grant_kind, "standing");
    assert_eq!(grants[0].principal_assurance, "unverified");
    assert_eq!(grants[0].transport_state, "Disconnected");

    let IpcResponse::Status(status) =
        kicad_mcp_gateway_daemon::handlers::handle_request(&state, IpcRequest::Status).await
    else {
        panic!("Status must return a status view");
    };
    assert_eq!(status.active_grant_count, 1);
    assert_eq!(
        status.active_session_count, 0,
        "a grant with no transport-era session row is still counted as authority"
    );
    assert_eq!(status.transport_state, "Disconnected");

    state.record_transport_event(TransportConnectivityEvent::Connected);
    let IpcResponse::Status(status) =
        kicad_mcp_gateway_daemon::handlers::handle_request(&state, IpcRequest::Status).await
    else {
        panic!("Status must return a status view");
    };
    assert_eq!(status.transport_state, "Connected");
    assert_eq!(
        status.active_grant_count, 1,
        "connectivity is not an authorization input"
    );

    let IpcResponse::AccessGrants(grants) =
        kicad_mcp_gateway_daemon::handlers::handle_request(&state, IpcRequest::ListAccessGrants)
            .await
    else {
        panic!("ListAccessGrants must return grant views");
    };
    assert_eq!(grants[0].transport_state, "Connected");
    assert_eq!(grants[0].authorization_status, "active");
}

#[tokio::test]
async fn a_pending_request_that_is_never_approved_never_becomes_usable_however_often_the_pipe_flaps(
) {
    let state = state_with_core("http://127.0.0.1:9/mcp".into());
    let identity = state.identity_store.create("flap-device").unwrap();
    let workspace_id = authorize_workspace(&state);
    let relay = MockTransport::new();
    relay.connect().await.unwrap();
    let transport: &dyn Transport = &relay;

    let envelope = session_request(workspace_id).with_device_id(identity.device_id);
    remote_processor::handle_envelope(&state, transport, envelope.clone()).await;
    let grant = state
        .authorization_repo
        .list_all_grants()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    for _ in 0..5 {
        churn_transport(&state);
        remote_processor::handle_envelope(&state, transport, envelope.clone()).await;
    }

    let after = state
        .authorization_repo
        .load_grant(grant.grant_id)
        .unwrap()
        .unwrap();
    assert_eq!(after, grant);
    assert_eq!(after.status, AuthorizationStatus::PendingApproval);
    assert!(!after.is_usable_at(state.clock.as_ref().now()));
    assert_eq!(after.approved_at, None);
    assert_eq!(state.authorization_repo.list_all_grants().unwrap().len(), 1);
}
