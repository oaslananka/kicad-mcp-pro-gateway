//! Automates the full V1 vertical slice from the product spec: fake
//! kicad-mcp-pro server -> daemon -> mock relay -> pending session -> CLI
//! approve -> low-risk operation -> audit -> high-risk operation -> pending
//! approval -> allow-once -> revoke -> reconnect -> still denied.
//!
//! This is the single strongest proof in the repository of the project's
//! core claim: a mock remote client cannot call arbitrary KiCad MCP tools
//! merely because it has network connectivity to Companion.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use companion_core::config::{self, CliOverrides};
use companion_core::{CapabilityProfile, SessionStatus};
use companion_core_bridge::MockMcpServer;
use companion_identity::InMemorySecretStore;
use companion_protocol::{
    read_message, write_message, Envelope, IpcRequest, IpcResponse, MessageType,
};
use companion_transport::{MockTransport, Transport};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};
use kicad_mcp_companion_daemon::{build_state_with_secret_store, ipc_server, remote_processor};
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

async fn wait_until<F>(mut predicate: F, timeout: Duration, description: &str)
where
    F: FnMut() -> bool,
{
    let start = tokio::time::Instant::now();
    loop {
        if predicate() {
            return;
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for: {description}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn fresh_dir() -> PathBuf {
    tempfile::tempdir().unwrap().keep()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_vertical_slice_from_pairing_through_revocation() {
    // 1. Start fake KiCad MCP test server.
    let fake_kicad = MockMcpServer::start().await;

    // 2-3. Start the Companion daemon (creates/loads device identity lazily).
    let data_dir = fresh_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some(fake_kicad.endpoint().to_string()),
        ..Default::default()
    })
    .unwrap();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new())
        .expect("daemon state builds with test secret store");
    tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&state),
        data_dir.clone(),
    ));
    // Give the listener a moment to actually bind before the first connect.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = send_request(&data_dir, IpcRequest::BeginPairing).await;
    assert!(
        matches!(response, IpcResponse::PairingBegun(_)),
        "device identity is created on first pairing: {response:?}"
    );
    let device_id = state
        .identity_store
        .load()
        .unwrap()
        .expect("pairing created a persistent device identity")
        .device_id;

    // 4. Add a temporary test workspace.
    let workspace_dir = fresh_dir();
    std::fs::write(workspace_dir.join("board.kicad_pcb"), "(kicad_pcb)").unwrap();
    let response = send_request(
        &data_dir,
        IpcRequest::AuthorizeWorkspace {
            path: workspace_dir.to_string_lossy().to_string(),
            display_name: "SensorBoard".into(),
        },
    )
    .await;
    let workspace_id = match response {
        IpcResponse::WorkspaceAuthorized(view) => view.workspace_id,
        other => panic!("unexpected response authorizing workspace: {other:?}"),
    };

    // 5. Connect Companion to MOCK relay.
    let mock_relay = Arc::new(MockTransport::new());
    mock_relay.connect().await.unwrap();
    tokio::spawn(remote_processor::run_remote_processor(
        Arc::clone(&state),
        mock_relay.clone() as Arc<dyn Transport>,
    ));

    // 6. Mock relay requests a Design session for that workspace.
    let session_request = Envelope::new(
        MessageType::SessionRequest,
        json!({
            "remote_principal": "agent:chatgpt-mock",
            "workspace_id": workspace_id,
            "capability_profile": "Design",
            "task_scope": "Complete STM32 sensor schematic",
            "ttl_minutes": 30,
        }),
    )
    .with_device_id(device_id);
    mock_relay.push_incoming(session_request);

    // 7. Session appears as PendingApproval.
    wait_until(
        || {
            state
                .session_repo
                .list_all()
                .map(|s| s.iter().any(|s| s.status == SessionStatus::PendingApproval))
                .unwrap_or(false)
        },
        Duration::from_secs(2),
        "session to appear as PendingApproval",
    )
    .await;
    let session_id = state
        .session_repo
        .list_all()
        .unwrap()
        .into_iter()
        .find(|s| s.status == SessionStatus::PendingApproval)
        .unwrap()
        .session_id;

    // 8. CLI approves it.
    let response = send_request(&data_dir, IpcRequest::ApproveSession { session_id }).await;
    assert!(matches!(response, IpcResponse::Ack), "{response:?}");
    let approved = state.session_repo.load(session_id).unwrap().unwrap();
    assert_eq!(approved.status, SessionStatus::Active);
    assert_eq!(approved.capability_profile, CapabilityProfile::Design);

    // 9. Mock remote sends a LOW-risk known tool operation.
    let low_risk_op_id = companion_core::OperationId::new();
    mock_relay.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: low_risk_op_id,
                session_id,
                workspace_id,
                tool_name: "sch_get_symbols".into(),
                arguments: [("sheet".into(), json!("Power"))].into_iter().collect(),
                target_path: None,
                requested_at: time::OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    // 10-12. Policy validates, proxies to the fake KiCad MCP server, result comes back.
    wait_until(
        || fake_kicad.tool_call_count() == 1,
        Duration::from_secs(2),
        "low-risk tool call to reach the fake kicad-mcp-pro server",
    )
    .await;
    wait_until(
        || !mock_relay.sent_messages().is_empty(),
        Duration::from_secs(2),
        "an OperationResult to be sent back over the mock relay",
    )
    .await;
    let result_envelope = mock_relay
        .sent_messages()
        .into_iter()
        .find(|e| e.correlation_id.as_deref() == Some(&low_risk_op_id.to_string()))
        .expect("result for the low-risk operation");
    assert_eq!(result_envelope.payload["success"], true);
    let tool_calls = fake_kicad.tool_calls();
    assert_eq!(
        tool_calls[0]["arguments"],
        json!({ "sheet": "Power" }),
        "remote MCP arguments must arrive unchanged at kicad-mcp-pro"
    );

    // 13. Audit record is written.
    let audit_events = state.audit_repo.list_recent(50).unwrap();
    let low_risk_audit = audit_events
        .iter()
        .find(|e| e.operation_id == low_risk_op_id)
        .expect("audit record for low-risk operation");
    assert_eq!(
        low_risk_audit.policy_result,
        companion_core::PolicyResultKind::Allow
    );
    assert_eq!(
        low_risk_audit.execution_status,
        companion_core::ExecutionStatus::Success
    );

    // 14. Mock remote requests a high-risk operation (pcb_auto_place_by_schematic: pcb.write/High, which the Design profile does hold).
    let high_risk_op_id = companion_core::OperationId::new();
    mock_relay.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: high_risk_op_id,
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

    // 16. Additional approval becomes pending.
    wait_until(
        || {
            remote_processor::list_pending_operations(&state)
                .iter()
                .any(|p| p.operation_id == high_risk_op_id)
        },
        Duration::from_secs(2),
        "high-risk operation to become pending approval",
    )
    .await;

    // Also verify the same fact is visible over local IPC, since that's
    // what the desktop/CLI actually use.
    let response = send_request(&data_dir, IpcRequest::ListPendingApprovals).await;
    assert!(
        matches!(&response, IpcResponse::PendingApprovals(list) if list.iter().any(|p| p.operation_id == high_risk_op_id)),
        "{response:?}"
    );

    // 15. Companion does NOT execute immediately: still only 1 call reached the fake server.
    assert_eq!(
        fake_kicad.tool_call_count(),
        1,
        "high-risk operation must not execute before approval"
    );

    // 17. CLI approves once.
    let response = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: high_risk_op_id,
        },
    )
    .await;
    assert!(matches!(response, IpcResponse::Ack), "{response:?}");

    // 18. Operation executes.
    wait_until(
        || fake_kicad.tool_call_count() == 2,
        Duration::from_secs(2),
        "high-risk tool call to reach the fake kicad-mcp-pro server after approval",
    )
    .await;
    let high_risk_result = mock_relay
        .sent_messages()
        .into_iter()
        .find(|e| e.correlation_id.as_deref() == Some(&high_risk_op_id.to_string()))
        .expect("result for the high-risk operation");
    assert_eq!(high_risk_result.payload["success"], true);
    let audit_events = state.audit_repo.list_recent(50).unwrap();
    let high_risk_audit = audit_events
        .iter()
        .find(|e| e.operation_id == high_risk_op_id)
        .unwrap();
    assert_eq!(
        high_risk_audit.policy_result,
        companion_core::PolicyResultKind::RequireApproval
    );
    assert_eq!(
        high_risk_audit.approval_decision,
        Some(companion_core::ApprovalDecisionKind::AllowOnce)
    );
    assert_eq!(
        high_risk_audit.execution_status,
        companion_core::ExecutionStatus::Success
    );

    // Approval-time authorization must be revalidated. Queue another
    // high-risk operation, suspend the session, then try to approve it.
    let suspended_op_id = companion_core::OperationId::new();
    mock_relay.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: suspended_op_id,
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
    wait_until(
        || {
            remote_processor::list_pending_operations(&state)
                .iter()
                .any(|p| p.operation_id == suspended_op_id)
        },
        Duration::from_secs(2),
        "second high-risk operation to become pending approval",
    )
    .await;
    let response = send_request(&data_dir, IpcRequest::PauseSession { session_id }).await;
    assert!(matches!(response, IpcResponse::Ack), "{response:?}");
    let response = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: suspended_op_id,
        },
    )
    .await;
    assert!(
        matches!(response, IpcResponse::Error(_)),
        "approval must fail after the session is suspended: {response:?}"
    );
    assert_eq!(
        fake_kicad.tool_call_count(),
        2,
        "a stale high-risk approval must never reach kicad-mcp-pro"
    );
    let response = send_request(&data_dir, IpcRequest::ResumeSession { session_id }).await;
    assert!(matches!(response, IpcResponse::Ack), "{response:?}");

    // Queue one more high-risk operation so revocation can prove it purges
    // pending approvals rather than leaving stale actions in the UI/runtime.
    let revoke_pending_op_id = companion_core::OperationId::new();
    mock_relay.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: revoke_pending_op_id,
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
    wait_until(
        || {
            remote_processor::list_pending_operations(&state)
                .iter()
                .any(|p| p.operation_id == revoke_pending_op_id)
        },
        Duration::from_secs(2),
        "high-risk operation to be pending before session revocation",
    )
    .await;

    // 19. Session is revoked locally.
    let response = send_request(&data_dir, IpcRequest::RevokeSession { session_id }).await;
    assert!(matches!(response, IpcResponse::Ack), "{response:?}");
    assert_eq!(
        state.session_repo.load(session_id).unwrap().unwrap().status,
        SessionStatus::Revoked
    );
    assert!(
        !remote_processor::list_pending_operations(&state)
            .iter()
            .any(|p| p.operation_id == revoke_pending_op_id),
        "revocation must purge pending operations for that session"
    );
    let response = send_request(
        &data_dir,
        IpcRequest::ApproveOperation {
            operation_id: revoke_pending_op_id,
        },
    )
    .await;
    assert!(matches!(response, IpcResponse::Error(_)), "{response:?}");
    assert_eq!(fake_kicad.tool_call_count(), 2);

    // 20-21. Mock relay tries another command; it is denied.
    let post_revoke_op_id = companion_core::OperationId::new();
    mock_relay.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: post_revoke_op_id,
                session_id,
                workspace_id,
                tool_name: "sch_get_symbols".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: time::OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );
    wait_until(
        || {
            mock_relay.sent_messages().into_iter().any(|e| {
                e.correlation_id.as_deref() == Some(&post_revoke_op_id.to_string())
                    && e.payload["success"] == false
            })
        },
        Duration::from_secs(2),
        "denial result for the post-revoke operation",
    )
    .await;
    assert_eq!(
        fake_kicad.tool_call_count(),
        2,
        "a revoked session's operation must never reach kicad-mcp-pro"
    );

    // 22. Restart/reconnect transport.
    mock_relay.disconnect().await.unwrap();
    mock_relay.connect().await.unwrap();

    // 23. Revoked session remains unusable after reconnect.
    let after_reconnect_op_id = companion_core::OperationId::new();
    mock_relay.push_incoming(
        Envelope::new(
            MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: after_reconnect_op_id,
                session_id,
                workspace_id,
                tool_name: "sch_get_symbols".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: time::OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );
    wait_until(
        || {
            mock_relay.sent_messages().into_iter().any(|e| {
                e.correlation_id.as_deref() == Some(&after_reconnect_op_id.to_string())
                    && e.payload["success"] == false
            })
        },
        Duration::from_secs(2),
        "denial result for the post-reconnect operation on a revoked session",
    )
    .await;
    assert_eq!(
        fake_kicad.tool_call_count(),
        2,
        "reconnect must never resurrect a revoked session's access"
    );

    fake_kicad.stop();
    send_request(&data_dir, IpcRequest::DaemonShutdown).await;
}
