use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use companion_core::config::{self, CliOverrides};
use companion_identity::InMemorySecretStore;
use companion_protocol::{read_message, write_message, IpcRequest, IpcResponse};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};
use kicad_mcp_companion_daemon::{build_state_with_secret_store, run_runtime};

fn fresh_dir() -> PathBuf {
    tempfile::tempdir().unwrap().keep()
}

fn build_test_state(data_dir: PathBuf) -> Arc<kicad_mcp_companion_daemon::state::DaemonState> {
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir),
        core_bridge_endpoint: Some("http://127.0.0.1:1/mcp".into()),
        ..Default::default()
    })
    .unwrap();
    build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap()
}

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

async fn wait_for_ipc(data_dir: &Path) {
    for _ in 0..100 {
        let name = companion_protocol::socket_name(data_dir)
            .to_ns_name::<GenericNamespaced>()
            .unwrap();
        if interprocess::local_socket::tokio::Stream::connect(name)
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("ipc listener did not become ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_without_transport_keeps_local_ipc_available_and_shuts_down_cleanly() {
    let data_dir = fresh_dir();
    let state = build_test_state(data_dir.clone());
    let runtime = tokio::spawn(run_runtime(Arc::clone(&state), data_dir.clone(), None));

    wait_for_ipc(&data_dir).await;
    let response = send_request(&data_dir, IpcRequest::Status).await;
    assert!(matches!(response, IpcResponse::Status(_)));

    let response = send_request(&data_dir, IpcRequest::DaemonShutdown).await;
    assert!(matches!(response, IpcResponse::Ack));

    let result = tokio::time::timeout(Duration::from_secs(1), runtime)
        .await
        .expect("runtime must stop after daemon shutdown")
        .expect("runtime task must not panic");
    result.expect("runtime shutdown must be clean");
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
        if start.elapsed() >= timeout {
            panic!("timed out waiting for {description}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_mock_transport_connects_and_malformed_remote_input_does_not_stop_processing() {
    use companion_core::SessionStatus;
    use companion_protocol::{Envelope, MessageType};
    use companion_transport::{MockTransport, Transport};
    use companion_workspace::WorkspaceAuthorization;
    use serde_json::json;

    let data_dir = fresh_dir();
    let state = build_test_state(data_dir.clone());
    let identity = state.identity_store.create("runtime-test-device").unwrap();
    let workspace_dir = tempfile::tempdir().unwrap().keep();
    let workspace = WorkspaceAuthorization::new("runtime".into(), &workspace_dir).unwrap();
    state.workspace_repo.save(&workspace).unwrap();

    let relay = Arc::new(MockTransport::new());
    relay.push_incoming(
        Envelope::new(MessageType::SessionRequest, json!({"malformed": true}))
            .with_device_id(identity.device_id),
    );
    relay.push_incoming(
        Envelope::new(
            MessageType::SessionRequest,
            json!({
                "remote_principal": "agent:runtime-test",
                "workspace_id": workspace.workspace_id,
                "capability_profile": "Inspect",
                "task_scope": "runtime lifecycle test",
                "ttl_minutes": 30
            }),
        )
        .with_device_id(identity.device_id),
    );

    let transport: Arc<dyn Transport> = relay.clone();
    let runtime = tokio::spawn(run_runtime(
        Arc::clone(&state),
        data_dir.clone(),
        Some(transport),
    ));

    wait_for_ipc(&data_dir).await;
    wait_until(
        || relay.connect_attempt_count() >= 1,
        Duration::from_secs(1),
        "mock transport connection",
    )
    .await;
    wait_until(
        || {
            state
                .session_repo
                .list_all()
                .map(|sessions| {
                    sessions
                        .iter()
                        .any(|session| session.status == SessionStatus::PendingApproval)
                })
                .unwrap_or(false)
        },
        Duration::from_secs(1),
        "valid session request after malformed envelope",
    )
    .await;

    assert_eq!(relay.connect_attempt_count(), 1);

    let response = send_request(&data_dir, IpcRequest::DaemonShutdown).await;
    assert!(matches!(response, IpcResponse::Ack));
    tokio::time::timeout(Duration::from_secs(1), runtime)
        .await
        .expect("runtime must stop")
        .expect("runtime task must not panic")
        .expect("runtime shutdown must be clean");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_connect_failure_retries_with_backoff_while_ipc_stays_available() {
    use companion_transport::{MockTransport, Transport};

    let data_dir = fresh_dir();
    let state = build_test_state(data_dir.clone());
    let relay = Arc::new(MockTransport::new());
    relay.fail_next_connects(1);
    let transport: Arc<dyn Transport> = relay.clone();

    let started = tokio::time::Instant::now();
    let runtime = tokio::spawn(run_runtime(
        Arc::clone(&state),
        data_dir.clone(),
        Some(transport),
    ));

    wait_for_ipc(&data_dir).await;
    let response = send_request(&data_dir, IpcRequest::Status).await;
    assert!(matches!(response, IpcResponse::Status(_)));

    wait_until(
        || relay.connect_attempt_count() >= 2,
        Duration::from_secs(2),
        "transport reconnect after initial failure",
    )
    .await;
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "reconnect happened without a meaningful backoff"
    );

    let response = send_request(&data_dir, IpcRequest::DaemonShutdown).await;
    assert!(matches!(response, IpcResponse::Ack));
    tokio::time::timeout(Duration::from_secs(1), runtime)
        .await
        .expect("runtime must stop")
        .expect("runtime task must not panic")
        .expect("runtime shutdown must be clean");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_closes_existing_ipc_connections_instead_of_leaving_detached_handlers() {
    let data_dir = fresh_dir();
    let state = build_test_state(data_dir.clone());
    let runtime = tokio::spawn(run_runtime(Arc::clone(&state), data_dir.clone(), None));

    wait_for_ipc(&data_dir).await;
    let name = companion_protocol::socket_name(&data_dir)
        .to_ns_name::<GenericNamespaced>()
        .unwrap();
    let mut persistent = interprocess::local_socket::tokio::Stream::connect(name)
        .await
        .expect("open persistent ipc connection");
    write_message(&mut persistent, &IpcRequest::Status)
        .await
        .unwrap();
    assert!(matches!(
        read_message::<_, IpcResponse>(&mut persistent)
            .await
            .unwrap(),
        IpcResponse::Status(_)
    ));

    assert!(matches!(
        send_request(&data_dir, IpcRequest::DaemonShutdown).await,
        IpcResponse::Ack
    ));
    tokio::time::timeout(Duration::from_secs(1), runtime)
        .await
        .expect("runtime must stop")
        .expect("runtime task must not panic")
        .expect("runtime shutdown must be clean");

    let post_shutdown_round_trip = tokio::time::timeout(Duration::from_millis(500), async {
        write_message(&mut persistent, &IpcRequest::Status).await?;
        read_message::<_, IpcResponse>(&mut persistent).await
    })
    .await;

    assert!(
        !matches!(post_shutdown_round_trip, Ok(Ok(IpcResponse::Status(_)))),
        "an IPC handler remained alive after runtime shutdown"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_receive_failure_disconnects_backs_off_and_reconnects() {
    use companion_transport::{MockTransport, Transport};

    let data_dir = fresh_dir();
    let state = build_test_state(data_dir.clone());
    let relay = Arc::new(MockTransport::new());
    relay.fail_next_receives(1);
    let transport: Arc<dyn Transport> = relay.clone();

    let started = tokio::time::Instant::now();
    let runtime = tokio::spawn(run_runtime(
        Arc::clone(&state),
        data_dir.clone(),
        Some(transport),
    ));

    wait_for_ipc(&data_dir).await;
    wait_until(
        || relay.connect_attempt_count() >= 2,
        Duration::from_secs(2),
        "transport reconnect after receive failure",
    )
    .await;
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "receive failure reconnect happened without a meaningful backoff"
    );

    let response = send_request(&data_dir, IpcRequest::Status).await;
    assert!(matches!(response, IpcResponse::Status(_)));
    let response = send_request(&data_dir, IpcRequest::DaemonShutdown).await;
    assert!(matches!(response, IpcResponse::Ack));
    tokio::time::timeout(Duration::from_secs(1), runtime)
        .await
        .expect("runtime must stop")
        .expect("runtime task must not panic")
        .expect("runtime shutdown must be clean");
}
