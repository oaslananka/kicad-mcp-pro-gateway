//! Typed request/response DTOs for the daemon's local IPC control API.
//!
//! This is the ONLY surface the desktop UI and CLI are allowed to use to
//! reach the daemon (see `docs/architecture/component-boundaries.md`).
//! There is deliberately no "run arbitrary tool" request variant — every
//! variant here is itself policy-safe (status, approve/deny, pause/
//! resume/revoke, workspace CRUD, audit read).

use companion_core::{OperationId, SessionId, WorkspaceId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "request", content = "payload")]
pub enum IpcRequest {
    Status,
    PairingStatus,
    BeginPairing,
    ListSessions,
    ApproveSession {
        session_id: SessionId,
    },
    DenySession {
        session_id: SessionId,
        reason: String,
    },
    PauseSession {
        session_id: SessionId,
    },
    ResumeSession {
        session_id: SessionId,
    },
    RevokeSession {
        session_id: SessionId,
    },
    ListWorkspaces,
    AuthorizeWorkspace {
        path: String,
        display_name: String,
    },
    RemoveWorkspace {
        workspace_id: WorkspaceId,
    },
    AuditSummary,
    ListPendingApprovals,
    /// "Allow once": approves exactly one already-pending high-risk
    /// operation. Never grants standing session access — see
    /// `crates/sessions` docs on why this is distinct from
    /// `ApproveSession`.
    ApproveOperation {
        operation_id: OperationId,
    },
    DenyOperation {
        operation_id: OperationId,
        reason: String,
    },
    DaemonShutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonStatusView {
    pub device_fingerprint: Option<String>,
    pub paired: bool,
    pub core_bridge_reachable: bool,
    pub active_session_count: usize,
    pub workspace_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairingStatusView {
    pub paired: bool,
    pub device_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairingBegunView {
    pub pairing_code: String,
    /// Always `true` until a real cloud pairing provider exists. Surfaces
    /// must display this honestly (see `docs/protocol/README.md`).
    pub mock_provider: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionView {
    pub session_id: SessionId,
    pub remote_principal: String,
    pub status: String,
    pub capability_profile: String,
    pub task_scope: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceView {
    pub workspace_id: WorkspaceId,
    pub display_name: String,
    pub canonical_root: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditSummaryView {
    pub total_events: usize,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingApprovalView {
    pub operation_id: OperationId,
    pub session_id: SessionId,
    pub tool_name: String,
    pub risk: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpcErrorView {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "response", content = "payload")]
pub enum IpcResponse {
    Status(DaemonStatusView),
    PairingStatus(PairingStatusView),
    PairingBegun(PairingBegunView),
    Sessions(Vec<SessionView>),
    Workspaces(Vec<WorkspaceView>),
    WorkspaceAuthorized(WorkspaceView),
    AuditSummary(AuditSummaryView),
    PendingApprovals(Vec<PendingApprovalView>),
    Ack,
    Error(IpcErrorView),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_json() {
        let request = IpcRequest::ApproveSession {
            session_id: SessionId::new(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let back: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request, back);
    }

    #[test]
    fn response_round_trips_through_json() {
        let response = IpcResponse::Error(IpcErrorView {
            code: "WORKSPACE_PATH_ESCAPES_ROOT".into(),
            message: "requested path escapes the authorized workspace".into(),
            retryable: false,
        });
        let json = serde_json::to_string(&response).unwrap();
        let back: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, back);
    }

    #[test]
    fn unknown_request_tag_fails_to_deserialize_rather_than_defaulting() {
        let result: Result<IpcRequest, _> =
            serde_json::from_str(r#"{"request":"RunArbitraryTool"}"#);
        assert!(result.is_err());
    }
}
