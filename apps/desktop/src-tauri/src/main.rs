//! The Gateway desktop shell's Tauri backend. Every command here is a
//! thin forwarder to the daemon's local IPC API — no policy logic lives in
//! this process. See `docs/architecture/component-boundaries.md`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon_lifecycle;
mod ipc_client;

use companion_core::{OperationId, SessionId, WorkspaceId};
use companion_protocol::{
    AuditSummaryView, DaemonStatusView, IpcRequest, IpcResponse, PairingBegunView,
    PairingStatusView, PendingApprovalView, SessionView, WorkspaceView,
};
use tauri::{Manager, State};

use daemon_lifecycle::{DaemonLauncher, DaemonLifecycleView};

async fn send(launcher: &DaemonLauncher, request: IpcRequest) -> Result<IpcResponse, String> {
    let data_dir = launcher.ensure_ready().await?;
    let response = ipc_client::send_request(&data_dir, request).await?;
    ok_or_err(response)
}

fn ok_or_err(response: IpcResponse) -> Result<IpcResponse, String> {
    if let IpcResponse::Error(e) = &response {
        return Err(format!("{} ({})", e.message, e.code));
    }
    Ok(response)
}

#[tauri::command]
async fn daemon_lifecycle(
    launcher: State<'_, DaemonLauncher>,
) -> Result<DaemonLifecycleView, String> {
    let _ = launcher.ensure_ready().await;
    Ok(launcher.lifecycle_view())
}

#[tauri::command]
async fn status(launcher: State<'_, DaemonLauncher>) -> Result<DaemonStatusView, String> {
    match send(launcher.inner(), IpcRequest::Status).await? {
        IpcResponse::Status(view) => Ok(view),
        _ => Err("daemon returned an unexpected status response variant".to_string()),
    }
}

#[tauri::command]
async fn pairing_status(launcher: State<'_, DaemonLauncher>) -> Result<PairingStatusView, String> {
    match send(launcher.inner(), IpcRequest::PairingStatus).await? {
        IpcResponse::PairingStatus(view) => Ok(view),
        _ => Err("daemon returned an unexpected pairing-status response variant".to_string()),
    }
}

#[tauri::command]
async fn begin_pairing(launcher: State<'_, DaemonLauncher>) -> Result<PairingBegunView, String> {
    match send(launcher.inner(), IpcRequest::BeginPairing).await? {
        IpcResponse::PairingBegun(view) => Ok(view),
        _ => Err("daemon returned an unexpected pairing response variant".to_string()),
    }
}

#[tauri::command]
async fn list_sessions(launcher: State<'_, DaemonLauncher>) -> Result<Vec<SessionView>, String> {
    match send(launcher.inner(), IpcRequest::ListSessions).await? {
        IpcResponse::Sessions(views) => Ok(views),
        _ => Err("daemon returned an unexpected sessions response variant".to_string()),
    }
}

#[tauri::command]
async fn approve_session(
    launcher: State<'_, DaemonLauncher>,
    session_id: SessionId,
) -> Result<(), String> {
    send(launcher.inner(), IpcRequest::ApproveSession { session_id })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn deny_session(
    launcher: State<'_, DaemonLauncher>,
    session_id: SessionId,
    reason: String,
) -> Result<(), String> {
    send(
        launcher.inner(),
        IpcRequest::DenySession { session_id, reason },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
async fn pause_session(
    launcher: State<'_, DaemonLauncher>,
    session_id: SessionId,
) -> Result<(), String> {
    send(launcher.inner(), IpcRequest::PauseSession { session_id })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn resume_session(
    launcher: State<'_, DaemonLauncher>,
    session_id: SessionId,
) -> Result<(), String> {
    send(launcher.inner(), IpcRequest::ResumeSession { session_id })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn revoke_session(
    launcher: State<'_, DaemonLauncher>,
    session_id: SessionId,
) -> Result<(), String> {
    send(launcher.inner(), IpcRequest::RevokeSession { session_id })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn list_workspaces(
    launcher: State<'_, DaemonLauncher>,
) -> Result<Vec<WorkspaceView>, String> {
    match send(launcher.inner(), IpcRequest::ListWorkspaces).await? {
        IpcResponse::Workspaces(views) => Ok(views),
        _ => Err("daemon returned an unexpected workspaces response variant".to_string()),
    }
}

#[tauri::command]
async fn authorize_workspace(
    launcher: State<'_, DaemonLauncher>,
    path: String,
    display_name: String,
) -> Result<WorkspaceView, String> {
    match send(
        launcher.inner(),
        IpcRequest::AuthorizeWorkspace { path, display_name },
    )
    .await?
    {
        IpcResponse::WorkspaceAuthorized(view) => Ok(view),
        _ => Err("daemon returned an unexpected workspace response variant".to_string()),
    }
}

#[tauri::command]
async fn remove_workspace(
    launcher: State<'_, DaemonLauncher>,
    workspace_id: WorkspaceId,
) -> Result<(), String> {
    send(
        launcher.inner(),
        IpcRequest::RemoveWorkspace { workspace_id },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
async fn audit_summary(launcher: State<'_, DaemonLauncher>) -> Result<AuditSummaryView, String> {
    match send(launcher.inner(), IpcRequest::AuditSummary).await? {
        IpcResponse::AuditSummary(view) => Ok(view),
        _ => Err("daemon returned an unexpected audit response variant".to_string()),
    }
}

#[tauri::command]
async fn list_pending_approvals(
    launcher: State<'_, DaemonLauncher>,
) -> Result<Vec<PendingApprovalView>, String> {
    match send(launcher.inner(), IpcRequest::ListPendingApprovals).await? {
        IpcResponse::PendingApprovals(views) => Ok(views),
        _ => Err("daemon returned an unexpected approvals response variant".to_string()),
    }
}

#[tauri::command]
async fn approve_operation(
    launcher: State<'_, DaemonLauncher>,
    operation_id: OperationId,
) -> Result<(), String> {
    send(
        launcher.inner(),
        IpcRequest::ApproveOperation { operation_id },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
async fn deny_operation(
    launcher: State<'_, DaemonLauncher>,
    operation_id: OperationId,
    reason: String,
) -> Result<(), String> {
    send(
        launcher.inner(),
        IpcRequest::DenyOperation {
            operation_id,
            reason,
        },
    )
    .await
    .map(|_| ())
}

#[derive(serde::Serialize)]
pub struct ConfigView {
    pub data_dir: String,
    pub log_level: String,
    pub core_bridge_endpoint: String,
    pub transport_mode: String,
}

#[tauri::command]
fn get_config() -> Result<ConfigView, String> {
    let cfg = companion_core::config::load(companion_core::config::CliOverrides::default())
        .map_err(|e| e.to_string())?;
    Ok(ConfigView {
        data_dir: cfg.data_dir.to_string_lossy().into_owned(),
        log_level: cfg.log_level,
        core_bridge_endpoint: cfg.core_bridge_endpoint.to_string(),
        transport_mode: cfg.transport_mode.to_string(),
    })
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let launcher = DaemonLauncher::new(app.handle().clone());
            app.manage(launcher.clone());
            daemon_lifecycle::spawn_watchdog(launcher);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            daemon_lifecycle,
            status,
            pairing_status,
            begin_pairing,
            list_sessions,
            approve_session,
            deny_session,
            pause_session,
            resume_session,
            revoke_session,
            list_workspaces,
            authorize_workspace,
            remove_workspace,
            audit_summary,
            list_pending_approvals,
            approve_operation,
            deny_operation,
            get_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Gateway desktop shell");
}

#[cfg(test)]
mod osv_expiry_test;
