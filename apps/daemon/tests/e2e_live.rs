//! Live E2E tests against a real kicad-mcp-pro server.
//!
//! These tests require a running kicad-mcp-pro server on the endpoint
// specified by GATEWAY_CORE_BRIDGE_ENDPOINT (default: http://127.0.0.1:3334/mcp).
//!
//! The test fixture is a minimal KiCad project in tests/fixtures/kicad-test-project.
//!
//! Run with: cargo test -p kicad-mcp-gateway-daemon --test e2e_live -- --nocapture

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use companion_core::config::{self, CliOverrides};
use companion_core::{CapabilityProfile, OperationId, SessionStatus};
use companion_core_bridge::{CoreBridgeClient, CoreBridgeConfig};
use companion_identity::InMemorySecretStore;
use companion_policy::{TomlToolRegistry, ToolCapabilityResolver};
use companion_transport::{MockTransport, Transport};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};
use kicad_mcp_gateway_daemon::{build_state_with_secret_store, ipc_server, remote_processor};
use serde_json::json;
use time::OffsetDateTime;

async fn send_request(
    data_dir: &Path,
    request: companion_protocol::IpcRequest,
) -> companion_protocol::IpcResponse {
    let name = companion_protocol::socket_name(data_dir)
        .to_ns_name::<GenericNamespaced>()
        .unwrap();
    let mut stream = interprocess::local_socket::tokio::Stream::connect(name)
        .await
        .expect("connect to daemon ipc");
    companion_protocol::write_message(&mut stream, &request)
        .await
        .unwrap();
    companion_protocol::read_message(&mut stream).await.unwrap()
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

fn fixture_project_dir() -> PathBuf {
    // Get the fixture directory from the environment or use a default
    std::env::var("KICAD_TEST_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("tests/fixtures/kicad-test-project"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a real kicad-mcp-pro HTTP server"]
async fn live_e2e_full_vertical_slice() {
    // 1. Verify the kicad-mcp-pro server is reachable
    let endpoint = std::env::var("GATEWAY_CORE_BRIDGE_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:3334/mcp".to_string());
    let bridge = CoreBridgeClient::new(CoreBridgeConfig::new(endpoint.parse().unwrap()))
        .expect("valid core bridge endpoint");

    let init_result = bridge
        .initialize("e2e-init")
        .await
        .expect("live kicad-mcp-pro server must be reachable and initialize successfully");
    println!("Initialized with server: {:?}", init_result["serverInfo"]);

    let tools = bridge
        .list_tools("e2e-tools")
        .await
        .expect("tools/list must succeed against live server");
    println!("Available tools: {}", tools.len());

    // 2. Start the Gateway daemon with the live core bridge endpoint
    let data_dir = fresh_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some(endpoint.clone()),
        transport_mode: Some(companion_core::TransportMode::Mock),
        ..Default::default()
    })
    .unwrap();

    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new())
        .expect("daemon state builds with test secret store");

    tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&state),
        data_dir.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Pair the device
    let response = send_request(&data_dir, companion_protocol::IpcRequest::BeginPairing).await;
    assert!(
        matches!(response, companion_protocol::IpcResponse::PairingBegun(_)),
        "device identity is created on first pairing: {response:?}"
    );
    let device_id = state
        .identity_store
        .load()
        .unwrap()
        .expect("pairing created a persistent device identity")
        .device_id;

    // 4. Authorize the test workspace (fixture project)
    let workspace_dir = fixture_project_dir();
    assert!(
        workspace_dir.exists(),
        "test fixture must exist at {}",
        workspace_dir.display()
    );

    let response = send_request(
        &data_dir,
        companion_protocol::IpcRequest::AuthorizeWorkspace {
            path: workspace_dir.to_string_lossy().to_string(),
            display_name: "E2E-Test-Project".into(),
        },
    )
    .await;
    let workspace_id = match response {
        companion_protocol::IpcResponse::WorkspaceAuthorized(view) => view.workspace_id,
        other => panic!("unexpected response authorizing workspace: {other:?}"),
    };

    // 5. Connect Gateway to MOCK relay
    let mock_relay = Arc::new(MockTransport::new());
    mock_relay.connect().await.unwrap();
    tokio::spawn(remote_processor::run_remote_processor(
        Arc::clone(&state),
        mock_relay.clone() as Arc<dyn Transport>,
    ));

    // 6. Mock relay requests a Design session for that workspace
    let session_request = companion_protocol::Envelope::new(
        companion_protocol::MessageType::SessionRequest,
        json!({
            "remote_principal": "agent:e2e-test",
            "workspace_id": workspace_id,
            "capability_profile": "Design",
            "task_scope": "E2E test operations",
            "ttl_minutes": 30,
        }),
    )
    .with_device_id(device_id);
    mock_relay.push_incoming(session_request);

    // 7. Session appears as PendingApproval
    wait_until(
        || {
            state
                .session_repo
                .list_all()
                .map(|s| s.iter().any(|s| s.status == SessionStatus::PendingApproval))
                .unwrap_or(false)
        },
        Duration::from_secs(5),
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

    // 8. CLI approves it
    let response = send_request(
        &data_dir,
        companion_protocol::IpcRequest::ApproveSession { session_id },
    )
    .await;
    assert!(
        matches!(response, companion_protocol::IpcResponse::Ack),
        "{response:?}"
    );
    let approved = state.session_repo.load(session_id).unwrap().unwrap();
    assert_eq!(approved.status, SessionStatus::Active);
    assert_eq!(approved.capability_profile, CapabilityProfile::Design);

    // 9. Test READ operation: sch_get_symbols (schematic.read, low risk)
    println!("Testing READ operation: sch_get_symbols");
    let read_op_id = OperationId::new();
    mock_relay.push_incoming(
        companion_protocol::Envelope::new(
            companion_protocol::MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: read_op_id,
                session_id,
                workspace_id,
                tool_name: "sch_get_symbols".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    wait_until(
        || {
            mock_relay.sent_messages().into_iter().any(|e| {
                e.correlation_id.as_deref() == Some(&read_op_id.to_string())
                    && e.payload["success"] == true
            })
        },
        Duration::from_secs(10),
        "READ operation result to be sent back over the mock relay",
    )
    .await;

    let result_envelope = mock_relay
        .sent_messages()
        .into_iter()
        .find(|e| e.correlation_id.as_deref() == Some(&read_op_id.to_string()))
        .expect("result for the READ operation");
    assert_eq!(
        result_envelope.payload["success"], true,
        "READ operation must succeed: {:?}",
        result_envelope.payload
    );
    println!("READ operation succeeded");

    // 10. Verify audit record for READ
    let audit_events = state.audit_repo.list_recent(50).unwrap();
    let read_audit = audit_events
        .iter()
        .find(|e| e.operation_id == read_op_id)
        .expect("audit record for READ operation");
    assert_eq!(
        read_audit.policy_result,
        companion_core::PolicyResultKind::Allow
    );
    assert_eq!(
        read_audit.execution_status,
        companion_core::ExecutionStatus::Success
    );
    println!("READ audit verified");

    // 11. Test BOUNDED WRITE operation: sch_add_symbol (schematic.write, normal risk)
    println!("Testing BOUNDED WRITE operation: sch_add_symbol");
    let write_op_id = OperationId::new();
    mock_relay.push_incoming(
        companion_protocol::Envelope::new(
            companion_protocol::MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: write_op_id,
                session_id,
                workspace_id,
                tool_name: "sch_add_symbol".into(),
                arguments: {
                    let mut map = serde_json::Map::new();
                    map.insert("lib_id".to_string(), json!("Device:R"));
                    map.insert("reference".to_string(), json!("R1"));
                    map.insert("value".to_string(), json!("10k"));
                    map.insert("position".to_string(), json!([100, 100]));
                    map
                },
                target_path: None,
                requested_at: OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    wait_until(
        || {
            mock_relay
                .sent_messages()
                .into_iter()
                .any(|e| e.correlation_id.as_deref() == Some(&write_op_id.to_string()))
        },
        Duration::from_secs(10),
        "BOUNDED WRITE operation result to be sent back",
    )
    .await;

    let write_result = mock_relay
        .sent_messages()
        .into_iter()
        .find(|e| e.correlation_id.as_deref() == Some(&write_op_id.to_string()))
        .expect("result for the WRITE operation");
    println!("WRITE operation result: {:?}", write_result.payload);
    // The operation may succeed or fail depending on the fixture, but it should not be a policy denial
    assert_ne!(
        write_result.payload["success"], false,
        "WRITE operation must not be denied by policy"
    );

    // 12. Verify audit record for WRITE
    let audit_events = state.audit_repo.list_recent(50).unwrap();
    let write_audit = audit_events
        .iter()
        .find(|e| e.operation_id == write_op_id)
        .expect("audit record for WRITE operation");
    println!(
        "WRITE audit: policy_result={:?}, execution_status={:?}",
        write_audit.policy_result, write_audit.execution_status
    );
    assert_eq!(
        write_audit.policy_result,
        companion_core::PolicyResultKind::Allow
    );

    // 13. Test HIGH-RISK operation: pcb_auto_place_by_schematic (pcb.write, high risk)
    println!("Testing HIGH-RISK operation: pcb_auto_place_by_schematic");
    let high_risk_op_id = OperationId::new();
    mock_relay.push_incoming(
        companion_protocol::Envelope::new(
            companion_protocol::MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: high_risk_op_id,
                session_id,
                workspace_id,
                tool_name: "pcb_auto_place_by_schematic".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    // 14. Additional approval becomes pending
    wait_until(
        || {
            remote_processor::list_pending_operations(&state)
                .iter()
                .any(|p| p.operation_id == high_risk_op_id)
        },
        Duration::from_secs(5),
        "high-risk operation to become pending approval",
    )
    .await;

    // 15. Verify it does NOT execute before approval
    let high_risk_pending = remote_processor::list_pending_operations(&state)
        .iter()
        .any(|p| p.operation_id == high_risk_op_id);
    assert!(
        high_risk_pending,
        "high-risk operation must be pending approval"
    );
    println!("HIGH-RISK operation correctly pending approval");

    // 16. Approve the high-risk operation
    let response = send_request(
        &data_dir,
        companion_protocol::IpcRequest::ApproveOperation {
            operation_id: high_risk_op_id,
        },
    )
    .await;
    assert!(
        matches!(response, companion_protocol::IpcResponse::Ack),
        "{response:?}"
    );

    // 17. Operation executes
    wait_until(
        || {
            mock_relay
                .sent_messages()
                .into_iter()
                .any(|e| e.correlation_id.as_deref() == Some(&high_risk_op_id.to_string()))
        },
        Duration::from_secs(15),
        "high-risk tool call to complete after approval",
    )
    .await;

    let high_risk_result = mock_relay
        .sent_messages()
        .into_iter()
        .find(|e| e.correlation_id.as_deref() == Some(&high_risk_op_id.to_string()))
        .expect("result for the high-risk operation");
    println!("HIGH-RISK operation result: {:?}", high_risk_result.payload);
    // Should not be a policy denial
    assert_ne!(
        high_risk_result.payload["success"], false,
        "HIGH-RISK operation must not be denied by policy after approval"
    );

    // 18. Verify audit record for HIGH-RISK
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
    println!("HIGH-RISK audit verified");

    // 19. Test REVOCATION: revoke session and verify it's unusable
    println!("Testing REVOCATION");
    let response = send_request(
        &data_dir,
        companion_protocol::IpcRequest::RevokeSession { session_id },
    )
    .await;
    assert!(
        matches!(response, companion_protocol::IpcResponse::Ack),
        "{response:?}"
    );
    assert_eq!(
        state.session_repo.load(session_id).unwrap().unwrap().status,
        SessionStatus::Revoked
    );

    // Try an operation after revocation - should be denied
    let post_revoke_op_id = OperationId::new();
    mock_relay.push_incoming(
        companion_protocol::Envelope::new(
            companion_protocol::MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: post_revoke_op_id,
                session_id,
                workspace_id,
                tool_name: "sch_get_symbols".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: OffsetDateTime::now_utc(),
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
        Duration::from_secs(5),
        "denial result for the post-revoke operation",
    )
    .await;
    println!("REVOCATION verified - post-revoke operation denied");

    // 20. Test WORKSPACE DENIAL: try to access a different workspace
    println!("Testing WORKSPACE DENIAL");
    let other_workspace_dir = fresh_dir();
    std::fs::write(other_workspace_dir.join("board.kicad_pcb"), "(kicad_pcb)").unwrap();

    let response = send_request(
        &data_dir,
        companion_protocol::IpcRequest::AuthorizeWorkspace {
            path: other_workspace_dir.to_string_lossy().to_string(),
            display_name: "OtherProject".into(),
        },
    )
    .await;
    let other_workspace_id = match response {
        companion_protocol::IpcResponse::WorkspaceAuthorized(view) => view.workspace_id,
        other => panic!("unexpected response authorizing other workspace: {other:?}"),
    };

    // Try to use the session with the other workspace - should fail
    let cross_workspace_op_id = OperationId::new();
    mock_relay.push_incoming(
        companion_protocol::Envelope::new(
            companion_protocol::MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: cross_workspace_op_id,
                session_id,
                workspace_id: other_workspace_id,
                tool_name: "sch_get_symbols".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: OffsetDateTime::now_utc(),
            })
            .unwrap(),
        )
        .with_device_id(device_id),
    );

    wait_until(
        || {
            mock_relay.sent_messages().into_iter().any(|e| {
                e.correlation_id.as_deref() == Some(&cross_workspace_op_id.to_string())
                    && e.payload["success"] == false
            })
        },
        Duration::from_secs(5),
        "denial result for cross-workspace operation",
    )
    .await;
    println!("WORKSPACE DENIAL verified - cross-workspace operation denied");

    // 21. Test RECONNECT: restart transport and verify revoked session stays revoked
    println!("Testing RECONNECT after revocation");
    mock_relay.disconnect().await.unwrap();
    mock_relay.connect().await.unwrap();

    let after_reconnect_op_id = OperationId::new();
    mock_relay.push_incoming(
        companion_protocol::Envelope::new(
            companion_protocol::MessageType::OperationRequest,
            serde_json::to_value(companion_core::OperationRequest {
                operation_id: after_reconnect_op_id,
                session_id,
                workspace_id,
                tool_name: "sch_get_symbols".into(),
                arguments: Default::default(),
                target_path: None,
                requested_at: OffsetDateTime::now_utc(),
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
        Duration::from_secs(5),
        "denial result for the post-reconnect operation on a revoked session",
    )
    .await;
    println!("RECONNECT verified - revoked session remains unusable");

    // Cleanup
    send_request(&data_dir, companion_protocol::IpcRequest::DaemonShutdown).await;
    println!("=== Live E2E test completed successfully ===");
}

#[tokio::test]
#[ignore = "requires a real kicad-mcp-pro HTTP server"]
async fn live_core_health_check() {
    // Simple health check to verify the live server is working
    let endpoint = std::env::var("GATEWAY_CORE_BRIDGE_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:3334/mcp".to_string());
    let bridge = CoreBridgeClient::new(CoreBridgeConfig::new(endpoint.parse().unwrap()))
        .expect("valid core bridge endpoint");

    let init_result = bridge
        .initialize("health-check")
        .await
        .expect("live kicad-mcp-pro server must be reachable");

    assert_eq!(init_result["jsonrpc"], "2.0");
    assert!(init_result["result"]["serverInfo"]["name"]
        .as_str()
        .unwrap()
        .contains("kicad-mcp-pro"));

    let tools = bridge
        .list_tools("health-tools")
        .await
        .expect("tools/list must succeed");

    assert!(!tools.is_empty(), "server must expose at least one tool");
    println!(
        "Live server health check passed: {} tools available",
        tools.len()
    );
}

#[tokio::test]
#[ignore = "requires a real kicad-mcp-pro HTTP server"]
async fn live_tool_reconciliation() {
    // Run the tool reconciliation against the live server
    let endpoint = std::env::var("GATEWAY_CORE_BRIDGE_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:3334/mcp".to_string());
    let bridge = CoreBridgeClient::new(CoreBridgeConfig::new(endpoint.parse().unwrap()))
        .expect("valid core bridge endpoint");

    let registry = TomlToolRegistry::embedded();
    let snapshot = companion_policy::ToolCatalogSnapshot::embedded();

    let report = kicad_mcp_gateway_daemon::tool_reconciliation::reconcile_live_tool_registry(
        &bridge, &registry, &snapshot,
    )
    .await
    .expect("live MCP reconciliation succeeds");

    println!(
        "Live reconciliation: catalog_total={} classified={} unclassified={} stale={} live_not_snapshot={} snapshot_not_live={}",
        report.registry_coverage.catalog_total,
        report.registry_coverage.classified.len(),
        report.registry_coverage.unclassified.len(),
        report.registry_coverage.stale.len(),
        report.live_not_in_snapshot.len(),
        report.snapshot_not_live.len()
    );

    // Unclassified tools must remain fail-closed
    for tool in &report.registry_coverage.unclassified {
        assert_eq!(
            registry.resolve(tool),
            None,
            "{tool} must remain fail-closed"
        );
    }

    println!("Live tool reconciliation passed");
}
