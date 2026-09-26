//! CLI <-> daemon local IPC integration tests. The daemon runs in-process
//! (via `kicad_mcp_gateway_daemon::run`) against a temp data directory,
//! and the CLI's own `ipc_client` is used to talk to it — exactly the path
//! the real `kicad-mcp-gateway` binary takes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use companion_core::config::{self, CliOverrides};
use companion_core_bridge::MockMcpServer;
use companion_identity::InMemorySecretStore;
use companion_protocol::{IpcRequest, IpcResponse};
use kicad_mcp_gateway_cli::ipc_client::send_request;
use kicad_mcp_gateway_daemon::{build_state_with_secret_store, ipc_server};

async fn wait_for_daemon(data_dir: &Path) {
    for _ in 0..100 {
        if send_request(data_dir, IpcRequest::Status).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("daemon did not become reachable within the retry budget");
}

fn fresh_data_dir() -> PathBuf {
    tempfile::tempdir().unwrap().keep()
}

fn spawn_test_daemon(cfg: companion_core::CompanionConfig) {
    let data_dir = cfg.data_dir.clone();
    let state = build_state_with_secret_store(&cfg, InMemorySecretStore::new())
        .expect("test daemon state builds with in-memory secret store");
    tokio::spawn(async move {
        let _ = ipc_server::run_ipc_server(state, data_dir).await;
    });
}

fn run_setup_cli(data_dir: &Path) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kicad-mcp-gateway"))
        .arg("--data-dir")
        .arg(data_dir)
        .arg("setup")
        .output()
        .expect("setup CLI process starts");
    assert!(
        output.status.success(),
        "setup CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("setup CLI writes UTF-8")
}

fn run_cli(data_dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kicad-mcp-gateway"))
        .arg("--data-dir")
        .arg(data_dir)
        .args(args)
        .output()
        .expect("CLI process starts");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("CLI writes UTF-8")
}

/// The transport-era list, asserted the same way at every step: exactly one
/// record, the expected legacy status, and the authorization state reported
/// beside it rather than inferred from it.
async fn assert_single_session(data_dir: &Path, status: &str, authorization_status: &str) {
    match send_request(data_dir, IpcRequest::ListSessions)
        .await
        .unwrap()
    {
        IpcResponse::Sessions(sessions) => {
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].status, status);
            assert_eq!(
                sessions[0].authorization_status, authorization_status,
                "the authority in force is reported next to the legacy status"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

/// The authorization view is the authoritative one and a separate surface
/// from the transport-era list: one standing grant for this subject, and
/// transport connectivity reported beside the authority, never inside it.
async fn assert_only_active_grant(data_dir: &Path, session_id: companion_core::SessionId) {
    match send_request(data_dir, IpcRequest::ListAccessGrants)
        .await
        .unwrap()
    {
        IpcResponse::AccessGrants(grants) => {
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].subject_session_id, session_id);
            assert_eq!(grants[0].authorization_status, "active");
            assert_eq!(grants[0].grant_kind, "standing");
            assert_eq!(
                grants[0].principal_assurance, "unverified",
                "V1 never verifies a remote principal and must not pretend to"
            );
            assert_eq!(
                grants[0].transport_state, "Disconnected",
                "transport connectivity is reported beside the authority, not inside it"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_reports_core_offline_when_daemon_cannot_reach_kicad_mcp_pro() {
    let data_dir = fresh_data_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some("http://127.0.0.1:1/mcp".into()),
        ..Default::default()
    })
    .unwrap();

    spawn_test_daemon(cfg);
    wait_for_daemon(&data_dir).await;

    let stdout = run_setup_cli(&data_dir);
    assert!(stdout.contains("✗ KiCad MCP Pro offline"), "{stdout}");
    assert!(
        !stdout.contains("detection is not implemented yet"),
        "{stdout}"
    );

    send_request(&data_dir, IpcRequest::DaemonShutdown)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_reports_core_detected_when_daemon_reaches_kicad_mcp_pro() {
    let server = MockMcpServer::start().await;
    let data_dir = fresh_data_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        core_bridge_endpoint: Some(server.endpoint().to_string()),
        ..Default::default()
    })
    .unwrap();

    spawn_test_daemon(cfg);
    wait_for_daemon(&data_dir).await;

    let stdout = run_setup_cli(&data_dir);
    assert!(stdout.contains("✓ KiCad MCP Pro detected"), "{stdout}");
    assert!(
        !stdout.contains("detection is not implemented yet"),
        "{stdout}"
    );

    send_request(&data_dir, IpcRequest::DaemonShutdown)
        .await
        .unwrap();
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_reports_zero_sessions_and_workspaces_on_a_fresh_daemon() {
    let data_dir = fresh_data_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        ..Default::default()
    })
    .unwrap();

    spawn_test_daemon(cfg);
    wait_for_daemon(&data_dir).await;

    let response = send_request(&data_dir, IpcRequest::Status).await.unwrap();
    match response {
        IpcResponse::Status(view) => {
            assert_eq!(view.active_session_count, 0);
            assert_eq!(view.workspace_count, 0);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    send_request(&data_dir, IpcRequest::DaemonShutdown)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorize_workspace_then_list_it_then_remove_it() {
    let data_dir = fresh_data_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        ..Default::default()
    })
    .unwrap();

    spawn_test_daemon(cfg);
    wait_for_daemon(&data_dir).await;

    let workspace_dir = fresh_data_dir();
    let response = send_request(
        &data_dir,
        IpcRequest::AuthorizeWorkspace {
            path: workspace_dir.to_string_lossy().to_string(),
            display_name: "SensorBoard".into(),
        },
    )
    .await
    .unwrap();
    let workspace_id = match response {
        IpcResponse::WorkspaceAuthorized(view) => {
            assert_eq!(view.display_name, "SensorBoard");
            view.workspace_id
        }
        other => panic!("unexpected response: {other:?}"),
    };

    let response = send_request(&data_dir, IpcRequest::ListWorkspaces)
        .await
        .unwrap();
    match response {
        IpcResponse::Workspaces(workspaces) => {
            assert_eq!(workspaces.len(), 1);
            assert_eq!(workspaces[0].workspace_id, workspace_id);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    send_request(&data_dir, IpcRequest::RemoveWorkspace { workspace_id })
        .await
        .unwrap();
    let response = send_request(&data_dir, IpcRequest::ListWorkspaces)
        .await
        .unwrap();
    match response {
        IpcResponse::Workspaces(workspaces) => assert!(workspaces.is_empty()),
        other => panic!("unexpected response: {other:?}"),
    }

    send_request(&data_dir, IpcRequest::DaemonShutdown)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approve_pause_resume_revoke_session_round_trip() {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use companion_core::{CapabilityProfile, SessionStatus};
    use companion_sessions::{new_unpaired_session, SessionRepository};
    use companion_storage::Storage;
    use companion_workspace::{WorkspaceAuthorization, WorkspaceRepository};

    let data_dir = fresh_data_dir();

    // Seed a PendingApproval session directly via storage before the daemon
    // starts (it would otherwise hold the single-instance lock). There is
    // no IPC request to create a session — sessions only ever originate
    // from a remote transport request (Phase 7), which is exactly the
    // property this test relies on: the CLI can decide on an existing
    // session, never invent one.
    //
    // The row is seeded the transport-era way on purpose: the daemon's
    // startup migration is what turns it into the access grant that the
    // approve/pause/resume/revoke path actually acts on.
    let session_id = {
        let storage = Arc::new(Storage::open(&data_dir).unwrap());
        let repo = SessionRepository::new(Arc::clone(&storage));
        let clock = companion_core::SystemClock;
        let workspace =
            WorkspaceAuthorization::new("cli test".into(), &tempfile::tempdir().unwrap().keep())
                .unwrap();
        WorkspaceRepository::new(Arc::clone(&storage))
            .save(&workspace)
            .unwrap();
        let mut session = new_unpaired_session(
            companion_core::DeviceId::new(),
            "agent:test".into(),
            BTreeSet::from([workspace.workspace_id]),
            CapabilityProfile::Inspect,
            "read schematic".into(),
            time::Duration::hours(1),
            &clock,
        );
        session.status = SessionStatus::PendingApproval;
        let id = session.session_id;
        repo.save(&session).unwrap();
        id
        // storage (and its single-instance lock) drops here.
    };

    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        ..Default::default()
    })
    .unwrap();
    spawn_test_daemon(cfg);
    wait_for_daemon(&data_dir).await;

    let session_id_text = session_id.to_string();
    let approve_output = run_cli(&data_dir, &["session", "approve", session_id_text.as_str()]);
    assert_eq!(approve_output, "approved session\n");
    assert!(!approve_output.contains(session_id_text.as_str()));

    let list_output = run_cli(&data_dir, &["session", "list"]);
    assert!(!list_output.contains(session_id_text.as_str()));
    assert!(list_output.contains("effective expiry"));

    assert_single_session(&data_dir, "Active", "active").await;
    assert_only_active_grant(&data_dir, session_id).await;

    send_request(&data_dir, IpcRequest::PauseSession { session_id })
        .await
        .unwrap();
    assert_single_session(&data_dir, "Suspended", "suspended").await;

    send_request(&data_dir, IpcRequest::ResumeSession { session_id })
        .await
        .unwrap();
    assert_single_session(&data_dir, "Active", "active").await;
    assert_only_active_grant(&data_dir, session_id).await;

    send_request(&data_dir, IpcRequest::RevokeSession { session_id })
        .await
        .unwrap();
    assert_single_session(&data_dir, "Revoked", "revoked").await;

    // Revocation is terminal: approving again must fail, not resurrect it.
    let response = send_request(&data_dir, IpcRequest::ApproveSession { session_id })
        .await
        .unwrap();
    assert!(matches!(response, IpcResponse::Error(_)));

    send_request(&data_dir, IpcRequest::DaemonShutdown)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_session_id_is_a_clean_error_not_a_crash() {
    let data_dir = fresh_data_dir();
    let cfg = config::load(CliOverrides {
        data_dir: Some(data_dir.clone()),
        ..Default::default()
    })
    .unwrap();

    spawn_test_daemon(cfg);
    wait_for_daemon(&data_dir).await;

    let response = send_request(
        &data_dir,
        IpcRequest::ApproveSession {
            session_id: companion_core::SessionId::new(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(response, IpcResponse::Error(_)));

    // The daemon must still be alive and responsive after a denied/errored request.
    let response = send_request(&data_dir, IpcRequest::Status).await.unwrap();
    assert!(matches!(response, IpcResponse::Status(_)));

    send_request(&data_dir, IpcRequest::DaemonShutdown)
        .await
        .unwrap();
}
