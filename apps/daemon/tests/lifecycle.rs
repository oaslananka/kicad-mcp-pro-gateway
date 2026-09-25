//! Native lifecycle evidence for identity, duplicate detection, and restart
//! invariants. This test runs in the repository's Linux/macOS/Windows CI matrix.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use companion_core::config::{self, CliOverrides};
use companion_core::{
    ApprovalPolicy, CapabilityProfile, DeviceId, Session, SessionId, SessionStatus,
};
use companion_identity::InMemorySecretStore;
use companion_protocol::{read_message, write_message, IpcRequest, IpcResponse};
use companion_storage::StorageError;
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};
use kicad_mcp_gateway_daemon::{build_state_with_secret_store, ipc_server};

async fn send_request(data_dir: &Path, request: IpcRequest) -> IpcResponse {
    let name = companion_protocol::socket_name(data_dir)
        .to_ns_name::<GenericNamespaced>()
        .unwrap();
    let mut stream = interprocess::local_socket::tokio::Stream::connect(name)
        .await
        .expect("connect to daemon IPC");
    write_message(&mut stream, &request).await.unwrap();
    read_message(&mut stream).await.unwrap()
}

async fn wait_for_identity(data_dir: &Path) -> companion_protocol::DaemonIdentityView {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let name = companion_protocol::socket_name(data_dir)
            .to_ns_name::<GenericNamespaced>()
            .unwrap();
        if let Ok(mut stream) = interprocess::local_socket::tokio::Stream::connect(name).await {
            write_message(&mut stream, &IpcRequest::Identity)
                .await
                .unwrap();
            let response: IpcResponse = read_message(&mut stream).await.unwrap();
            if let IpcResponse::Identity(identity) = response {
                identity.validate_for_client().unwrap();
                return identity;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "daemon IPC did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn revoked_session() -> Session {
    Session {
        session_id: SessionId::new(),
        device_id: DeviceId::new(),
        remote_principal: "agent:lifecycle-test".to_string(),
        workspace_ids: BTreeSet::new(),
        capability_profile: CapabilityProfile::Inspect,
        effective_capabilities: CapabilityProfile::Inspect.effective_capabilities(),
        task_scope: "lifecycle test".to_string(),
        issued_at: time::OffsetDateTime::UNIX_EPOCH,
        approved_at: Some(time::OffsetDateTime::UNIX_EPOCH),
        expires_at: time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
        risk_policy_version: 1,
        approval_policy: ApprovalPolicy::Standard,
        status: SessionStatus::Revoked,
    }
}

fn fresh_data_dir() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    (temp, data_dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_identity_duplicate_and_restart_preserve_revocation() {
    let (_data_dir_guard, data_dir) = fresh_data_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        ..Default::default()
    })
    .unwrap();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
    let session = revoked_session();
    state.session_repo.save(&session).unwrap();

    let first_server = tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&state),
        data_dir.clone(),
    ));
    let first_identity = wait_for_identity(&data_dir).await;
    assert_eq!(first_identity.daemon_version, env!("CARGO_PKG_VERSION"));

    // A second process cannot open the same data directory, so it cannot
    // mutate state or displace the live IPC listener.
    let duplicate = match build_state_with_secret_store(&cfg, InMemorySecretStore::new()) {
        Ok(_) => panic!("a duplicate daemon must not open the same data directory"),
        Err(error) => error,
    };
    assert!(matches!(
        duplicate.downcast_ref::<StorageError>(),
        Some(StorageError::AnotherInstanceRunning)
    ));

    // Aborting the server task models an abrupt runtime loss from the
    // caller's perspective. The advisory lock and socket name must be
    // reclaimable, while persisted revocation remains terminal.
    first_server.abort();
    assert!(first_server.await.unwrap_err().is_cancelled());
    drop(state);

    let restarted = build_state_with_secret_store(&cfg, InMemorySecretStore::new()).unwrap();
    assert_eq!(
        restarted
            .session_repo
            .load(session.session_id)
            .unwrap()
            .unwrap()
            .status,
        SessionStatus::Revoked
    );
    let second_server = tokio::spawn(ipc_server::run_ipc_server(
        Arc::clone(&restarted),
        data_dir.clone(),
    ));
    let second_identity = wait_for_identity(&data_dir).await;
    assert_ne!(
        first_identity.instance_id, second_identity.instance_id,
        "a restarted daemon must advertise a new process instance"
    );

    assert!(matches!(
        send_request(&data_dir, IpcRequest::DaemonShutdown).await,
        IpcResponse::Ack
    ));
    second_server
        .await
        .unwrap()
        .expect("restarted daemon shuts down cleanly");
    drop(restarted);
}
