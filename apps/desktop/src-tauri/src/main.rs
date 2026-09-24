//! The Gateway desktop shell's Tauri backend. Every command here is a
//! thin forwarder to the daemon's local IPC API — no policy logic lives in
//! this process. See `docs/architecture/component-boundaries.md`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::time::Duration;

use companion_core::{OperationId, SessionId, WorkspaceId};
use companion_protocol::{
    read_message, write_message, AuditSummaryView, DaemonStatusView, IpcRequest, IpcResponse,
    PairingBegunView, PairingStatusView, PendingApprovalView, SessionView, WorkspaceView,
};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericNamespaced, ToNsName};

fn data_dir() -> PathBuf {
    // Mirrors the same precedence the CLI/daemon use, so the desktop app
    // always talks to the same daemon instance those would.
    companion_core::config::load(companion_core::config::CliOverrides::default())
        .map(|c| c.data_dir)
        .unwrap_or_else(|_| std::env::temp_dir().join("kicad-mcp-gateway"))
}

async fn try_connect(
    name: &interprocess::local_socket::Name<'_>,
) -> Result<interprocess::local_socket::tokio::Stream, std::io::Error> {
    interprocess::local_socket::tokio::Stream::connect(name.clone()).await
}

async fn send(request: IpcRequest) -> Result<IpcResponse, String> {
    let dir = data_dir();
    let name = companion_protocol::socket_name(&dir)
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| e.to_string())?;

    let mut stream = match try_connect(&name).await {
        Ok(s) => s,
        Err(_) => {
            // Attempt short retry polling if daemon was just launched
            let mut connected = None;
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Ok(s) = try_connect(&name).await {
                    connected = Some(s);
                    break;
                }
            }
            connected.ok_or_else(|| {
                "cannot reach the Gateway daemon: connection refused. Is the kicad-mcp-gateway-daemon process running?".to_string()
            })?
        }
    };

    write_message(&mut stream, &request)
        .await
        .map_err(|e| e.to_string())?;
    read_message(&mut stream).await.map_err(|e| e.to_string())
}

fn ok_or_err(response: IpcResponse) -> Result<IpcResponse, String> {
    if let IpcResponse::Error(e) = &response {
        return Err(format!("{} ({})", e.message, e.code));
    }
    Ok(response)
}

#[tauri::command]
async fn status() -> Result<DaemonStatusView, String> {
    match ok_or_err(send(IpcRequest::Status).await?)? {
        IpcResponse::Status(view) => Ok(view),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn pairing_status() -> Result<PairingStatusView, String> {
    match ok_or_err(send(IpcRequest::PairingStatus).await?)? {
        IpcResponse::PairingStatus(view) => Ok(view),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn begin_pairing() -> Result<PairingBegunView, String> {
    match ok_or_err(send(IpcRequest::BeginPairing).await?)? {
        IpcResponse::PairingBegun(view) => Ok(view),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn list_sessions() -> Result<Vec<SessionView>, String> {
    match ok_or_err(send(IpcRequest::ListSessions).await?)? {
        IpcResponse::Sessions(views) => Ok(views),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn approve_session(session_id: SessionId) -> Result<(), String> {
    ok_or_err(send(IpcRequest::ApproveSession { session_id }).await?).map(|_| ())
}

#[tauri::command]
async fn deny_session(session_id: SessionId, reason: String) -> Result<(), String> {
    ok_or_err(send(IpcRequest::DenySession { session_id, reason }).await?).map(|_| ())
}

#[tauri::command]
async fn pause_session(session_id: SessionId) -> Result<(), String> {
    ok_or_err(send(IpcRequest::PauseSession { session_id }).await?).map(|_| ())
}

#[tauri::command]
async fn resume_session(session_id: SessionId) -> Result<(), String> {
    ok_or_err(send(IpcRequest::ResumeSession { session_id }).await?).map(|_| ())
}

#[tauri::command]
async fn revoke_session(session_id: SessionId) -> Result<(), String> {
    ok_or_err(send(IpcRequest::RevokeSession { session_id }).await?).map(|_| ())
}

#[tauri::command]
async fn list_workspaces() -> Result<Vec<WorkspaceView>, String> {
    match ok_or_err(send(IpcRequest::ListWorkspaces).await?)? {
        IpcResponse::Workspaces(views) => Ok(views),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn authorize_workspace(path: String, display_name: String) -> Result<WorkspaceView, String> {
    match ok_or_err(send(IpcRequest::AuthorizeWorkspace { path, display_name }).await?)? {
        IpcResponse::WorkspaceAuthorized(view) => Ok(view),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn remove_workspace(workspace_id: WorkspaceId) -> Result<(), String> {
    ok_or_err(send(IpcRequest::RemoveWorkspace { workspace_id }).await?).map(|_| ())
}

#[tauri::command]
async fn audit_summary() -> Result<AuditSummaryView, String> {
    match ok_or_err(send(IpcRequest::AuditSummary).await?)? {
        IpcResponse::AuditSummary(view) => Ok(view),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn list_pending_approvals() -> Result<Vec<PendingApprovalView>, String> {
    match ok_or_err(send(IpcRequest::ListPendingApprovals).await?)? {
        IpcResponse::PendingApprovals(views) => Ok(views),
        other => Err(format!("unexpected response: {other:?}")),
    }
}

#[tauri::command]
async fn approve_operation(operation_id: OperationId) -> Result<(), String> {
    ok_or_err(send(IpcRequest::ApproveOperation { operation_id }).await?).map(|_| ())
}

#[tauri::command]
async fn deny_operation(operation_id: OperationId, reason: String) -> Result<(), String> {
    ok_or_err(
        send(IpcRequest::DenyOperation {
            operation_id,
            reason,
        })
        .await?,
    )
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
        .invoke_handler(tauri::generate_handler![
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
