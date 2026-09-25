//! Security-critical race conditions and failure recovery regression tests (#31, #42).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use companion_core::config::{self, CliOverrides};
use companion_core::{OperationId, SessionId};
use companion_core_bridge::MockMcpServer;
use companion_identity::InMemorySecretStore;
use companion_protocol::{
    read_message, write_message, Envelope, IpcRequest, IpcResponse, MessageType,
    PendingApprovalView, SessionView,
};
use companion_transport::{MockTransport, Transport};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};
use kicad_mcp_gateway_daemon::{build_state_with_secret_store, ipc_server, remote_processor};
use serde_json::json;

async fn send_request(data_dir: &Path, request: IpcRequest) -> IpcResponse {
    let name = companion_protocol::socket_name(data_dir)
        .to_ns_name::<GenericNamespaced>()
        .unwrap();
    let mut stream = interprocess::local_socket::tokio::Stream::connect(name)
        .await
        .expect("connect to daemon ipc");
    write_message(&mut stream, &request).await.unwrap();
    read_message(&mut stream).await.unwrap()
}

async fn wait_for_sessions(data_dir: &Path) -> Vec<SessionView> {
    let start = tokio::time::Instant::now();
    loop {
        if let IpcResponse::Sessions(s) = send_request(data_dir, IpcRequest::ListSessions).await {
            if !s.is_empty() {
                return s;
            }
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("timed out waiting for active session");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_pending_approvals(data_dir: &Path) -> Vec<PendingApprovalView> {
    let start = tokio::time::Instant::now();
    loop {
        if let IpcResponse::PendingApprovals(p) =
            send_request(data_dir, IpcRequest::ListPendingApprovals).await
        {
            if !p.is_empty() {
                return p;
            }
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("timed out waiting for pending approvals");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn fresh_dir() -> PathBuf {
    tempfile::tempdir().unwrap().keep()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_racing_operation_execution_fails_closed() {
    let fake_kicad = MockMcpServer::start().await;
    let data_dir = fresh_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some(fake_kicad.endpoint().to_string()),
        ..Default::default()
    })
    .unwrap();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
    tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&state),
        data_dir.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Authorize workspace
    let proj_dir = data_dir.join("test-proj");
    std::fs::create_dir_all(&proj_dir).unwrap();
    let ws_res = send_request(
        &data_dir,
        IpcRequest::AuthorizeWorkspace {
            path: proj_dir.to_string_lossy().into_owned(),
            display_name: "Test Project".into(),
        },
    )
    .await;
    let workspace_id = match ws_res {
        IpcResponse::WorkspaceAuthorized(ws) => ws.workspace_id,
        _ => panic!("expected workspace authorized"),
    };

    // Start paired mock transport
    send_request(&data_dir, IpcRequest::BeginPairing).await;

    let device_id = state.identity_store.load().unwrap().unwrap().device_id;
    let transport = Arc::new(MockTransport::new());
    transport.connect().await.unwrap();

    tokio::spawn(remote_processor::run_remote_processor(
        Arc::clone(&state),
        Arc::clone(&transport) as Arc<dyn Transport>,
    ));

    // Request session
    transport.push_incoming(
        Envelope::new(
            MessageType::SessionRequest,
            json!({
                "remote_principal": "agent@cloud",
                "workspace_id": workspace_id,
                "capability_profile": "Design",
                "task_scope": "Testing races",
                "ttl_minutes": 30
            }),
        )
        .with_device_id(device_id),
    );

    let sessions = wait_for_sessions(&data_dir).await;
    let session_id = sessions[0].session_id;

    // Approve session
    send_request(&data_dir, IpcRequest::ApproveSession { session_id }).await;

    // Queue high-risk operation
    let op_id = OperationId::new();
    transport.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: op_id,
                session_id,
                workspace_id,
                tool_name: "pcb_auto_place_by_schematic".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: time::OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    let pending = wait_for_pending_approvals(&data_dir).await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].workspace_id, workspace_id);
    assert_eq!(
        pending[0]
            .workspace
            .as_ref()
            .map(|workspace| workspace.display_name.as_str()),
        Some("Test Project")
    );

    // RACE CONDITION: Revoke the session BEFORE approving the queued operation
    send_request(&data_dir, IpcRequest::RevokeSession { session_id }).await;

    // Now attempt to approve the queued operation
    let approve_res = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: op_id,
        },
    )
    .await;

    // Operation must fail closed (Error / not found or denied)
    assert!(matches!(approve_res, IpcResponse::Error(_)));

    // Core tool call count MUST remain zero
    assert_eq!(fake_kicad.tool_call_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approval_consumed_twice_replay_is_rejected() {
    let fake_kicad = MockMcpServer::start().await;
    let data_dir = fresh_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some(fake_kicad.endpoint().to_string()),
        ..Default::default()
    })
    .unwrap();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
    tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&state),
        data_dir.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proj_dir = data_dir.join("test-proj");
    std::fs::create_dir_all(&proj_dir).unwrap();
    let ws_res = send_request(
        &data_dir,
        IpcRequest::AuthorizeWorkspace {
            path: proj_dir.to_string_lossy().into_owned(),
            display_name: "Test Project".into(),
        },
    )
    .await;
    let workspace_id = match ws_res {
        IpcResponse::WorkspaceAuthorized(ws) => ws.workspace_id,
        _ => panic!("expected workspace authorized"),
    };

    send_request(&data_dir, IpcRequest::BeginPairing).await;
    let device_id = state.identity_store.load().unwrap().unwrap().device_id;
    let transport = Arc::new(MockTransport::new());
    transport.connect().await.unwrap();

    tokio::spawn(remote_processor::run_remote_processor(
        Arc::clone(&state),
        Arc::clone(&transport) as Arc<dyn Transport>,
    ));

    transport.push_incoming(
        Envelope::new(
            MessageType::SessionRequest,
            json!({
                "remote_principal": "agent@cloud",
                "workspace_id": workspace_id,
                "capability_profile": "Design",
                "task_scope": "Testing replay",
                "ttl_minutes": 30
            }),
        )
        .with_device_id(device_id),
    );

    let sessions = wait_for_sessions(&data_dir).await;
    let session_id = sessions[0].session_id;
    send_request(&data_dir, IpcRequest::ApproveSession { session_id }).await;

    // Queue operation
    let op_id = OperationId::new();
    transport.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: op_id,
                session_id,
                workspace_id,
                tool_name: "pcb_auto_place_by_schematic".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: time::OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    let pending = wait_for_pending_approvals(&data_dir).await;
    assert_eq!(pending.len(), 1);

    // First approval: succeeds and executes tool
    let res1 = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: op_id,
        },
    )
    .await;
    assert!(matches!(res1, IpcResponse::Ack));
    assert_eq!(fake_kicad.tool_call_count(), 1);

    // Second approval replay: MUST be rejected
    let res2 = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: op_id,
        },
    )
    .await;
    assert!(matches!(res2, IpcResponse::Error(_)));

    // Calls count remains 1 (no duplicate execution)
    assert_eq!(fake_kicad.tool_call_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_session_or_operation_approval_is_rejected() {
    let fake_kicad = MockMcpServer::start().await;
    let data_dir = fresh_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some(fake_kicad.endpoint().to_string()),
        ..Default::default()
    })
    .unwrap();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
    tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&state),
        data_dir.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Approve unknown session
    let random_session = SessionId::new();
    let res = send_request(
        &data_dir,
        IpcRequest::ApproveSession {
            session_id: random_session,
        },
    )
    .await;
    assert!(matches!(res, IpcResponse::Error(_)));

    // Approve unknown operation
    let random_op = OperationId::new();
    let res_op = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: random_op,
        },
    )
    .await;
    assert!(matches!(res_op, IpcResponse::Error(_)));

    assert_eq!(fake_kicad.tool_call_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn workspace_removal_racing_operation_execution_fails_closed() {
    let fake_kicad = MockMcpServer::start().await;
    let data_dir = fresh_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some(fake_kicad.endpoint().to_string()),
        ..Default::default()
    })
    .unwrap();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
    tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&state),
        data_dir.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proj_dir = data_dir.join("test-proj");
    std::fs::create_dir_all(&proj_dir).unwrap();
    let ws_res = send_request(
        &data_dir,
        IpcRequest::AuthorizeWorkspace {
            path: proj_dir.to_string_lossy().into_owned(),
            display_name: "Test Project".into(),
        },
    )
    .await;
    let workspace_id = match ws_res {
        IpcResponse::WorkspaceAuthorized(ws) => ws.workspace_id,
        _ => panic!("expected workspace authorized"),
    };

    send_request(&data_dir, IpcRequest::BeginPairing).await;
    let device_id = state.identity_store.load().unwrap().unwrap().device_id;
    let transport = Arc::new(MockTransport::new());
    transport.connect().await.unwrap();

    tokio::spawn(remote_processor::run_remote_processor(
        Arc::clone(&state),
        Arc::clone(&transport) as Arc<dyn Transport>,
    ));

    transport.push_incoming(
        Envelope::new(
            MessageType::SessionRequest,
            json!({
                "remote_principal": "agent@cloud",
                "workspace_id": workspace_id,
                "capability_profile": "Design",
                "task_scope": "Testing workspace removal race",
                "ttl_minutes": 30
            }),
        )
        .with_device_id(device_id),
    );

    let sessions = wait_for_sessions(&data_dir).await;
    let session_id = sessions[0].session_id;
    send_request(&data_dir, IpcRequest::ApproveSession { session_id }).await;

    // Queue operation
    let op_id = OperationId::new();
    transport.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: op_id,
                session_id,
                workspace_id,
                tool_name: "pcb_auto_place_by_schematic".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: time::OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    let pending = wait_for_pending_approvals(&data_dir).await;
    assert_eq!(pending.len(), 1);

    // RACE CONDITION: Workspace is removed BEFORE approval
    send_request(&data_dir, IpcRequest::RemoveWorkspace { workspace_id }).await;

    // Approve operation
    let approve_res = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: op_id,
        },
    )
    .await;

    // Operation MUST fail closed because workspace no longer exists
    assert!(matches!(approve_res, IpcResponse::Error(_)));
    assert_eq!(fake_kicad.tool_call_count(), 0);
}
