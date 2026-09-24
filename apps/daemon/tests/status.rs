use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use companion_core::config::{self, CliOverrides};
use companion_core::{CapabilityProfile, SessionStatus};
use companion_core_bridge::MockMcpServer;
use companion_identity::InMemorySecretStore;
use companion_protocol::{IpcRequest, IpcResponse};
use companion_sessions::new_unpaired_session;
use companion_workspace::WorkspaceAuthorization;
use kicad_mcp_gateway_daemon::{build_state_with_secret_store, handlers};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn build_test_state(
    endpoint: String,
) -> (
    tempfile::TempDir,
    Arc<kicad_mcp_gateway_daemon::state::DaemonState>,
) {
    let data_dir = tempfile::tempdir().unwrap();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.path().to_path_buf()),
        core_bridge_endpoint: Some(endpoint),
        ..Default::default()
    })
    .unwrap();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new())
        .expect("daemon state builds with test secret store");
    (data_dir, state)
}

async fn status(
    state: &Arc<kicad_mcp_gateway_daemon::state::DaemonState>,
) -> companion_protocol::DaemonStatusView {
    match handlers::handle_request(state, IpcRequest::Status).await {
        IpcResponse::Status(view) => view,
        other => panic!("expected status response, got {other:?}"),
    }
}

async fn start_hanging_http_server() -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicBool::new(false));
    let accepted_task = Arc::clone(&accepted);

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            accepted_task.store(true, Ordering::SeqCst);
            let _stream = stream;
            std::future::pending::<()>().await;
        }
    });

    (format!("http://{addr}/mcp"), accepted)
}

async fn start_malformed_http_server() -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicBool::new(false));
    let accepted_task = Arc::clone(&accepted);

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            accepted_task.store(true, Ordering::SeqCst);
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot-json";
            let _ = stream.write_all(response).await;
            let _ = stream.flush().await;
        }
    });

    (format!("http://{addr}/mcp"), accepted)
}

#[tokio::test]
async fn status_reports_core_reachable_after_successful_mcp_initialize() {
    let server = MockMcpServer::start().await;
    let (_data_dir, state) = build_test_state(server.endpoint().to_string());

    let view = status(&state).await;

    assert!(view.core_bridge_reachable);
    server.stop();
}

#[tokio::test]
async fn status_reports_core_unreachable_for_refused_loopback_endpoint() {
    let (_data_dir, state) = build_test_state("http://127.0.0.1:1/mcp".into());

    let view = status(&state).await;

    assert!(!view.core_bridge_reachable);
}

#[tokio::test]
async fn status_core_probe_times_out_within_a_short_bound() {
    let (endpoint, accepted) = start_hanging_http_server().await;
    let (_data_dir, state) = build_test_state(endpoint);

    let view = tokio::time::timeout(Duration::from_secs(2), status(&state))
        .await
        .expect("status core probe must be bounded");

    assert!(!view.core_bridge_reachable);
    assert!(
        accepted.load(Ordering::SeqCst),
        "status must attempt the MCP initialize probe"
    );
}

#[tokio::test]
async fn status_maps_core_protocol_error_to_unreachable_without_failing_status() {
    let (endpoint, accepted) = start_malformed_http_server().await;
    let (_data_dir, state) = build_test_state(endpoint);

    let view = status(&state).await;

    assert!(!view.core_bridge_reachable);
    assert!(
        accepted.load(Ordering::SeqCst),
        "status must attempt the MCP initialize probe"
    );
}

#[tokio::test]
async fn status_preserves_device_session_and_workspace_fields_while_probing_core() {
    let server = MockMcpServer::start().await;
    let (_data_dir, state) = build_test_state(server.endpoint().to_string());

    let identity = state.identity_store.create("status-test-device").unwrap();

    let workspace_a_dir = tempfile::tempdir().unwrap();
    let workspace_b_dir = tempfile::tempdir().unwrap();
    let workspace_a = WorkspaceAuthorization::new("A".into(), workspace_a_dir.path()).unwrap();
    let workspace_b = WorkspaceAuthorization::new("B".into(), workspace_b_dir.path()).unwrap();
    state.workspace_repo.save(&workspace_a).unwrap();
    state.workspace_repo.save(&workspace_b).unwrap();

    let mut session = new_unpaired_session(
        identity.device_id,
        "agent:status-test".into(),
        BTreeSet::from([workspace_a.workspace_id]),
        CapabilityProfile::Inspect,
        "status regression".into(),
        time::Duration::hours(1),
        state.clock.as_ref(),
    );
    session.status = SessionStatus::Active;
    state.session_repo.save(&session).unwrap();

    let view = status(&state).await;

    assert_eq!(view.device_fingerprint, Some(identity.fingerprint.0));
    assert!(view.paired);
    assert!(view.core_bridge_reachable);
    assert_eq!(view.active_session_count, 1);
    assert_eq!(view.workspace_count, 2);

    server.stop();
}
