//! Typed request/response DTOs for the daemon's local IPC control API.
//!
//! This is the ONLY surface the desktop UI and CLI are allowed to use to
//! reach the daemon (see `docs/architecture/component-boundaries.md`).
//! There is deliberately no "run arbitrary tool" request variant — every
//! variant here is itself policy-safe (status, approve/deny, pause/
//! resume/revoke, workspace CRUD, audit read).

use companion_core::{OperationId, SessionId, WorkspaceId};
use serde::{Deserialize, Serialize};

/// Stable product identifier returned by the local IPC readiness handshake.
pub const DAEMON_PRODUCT_ID: &str = "kicad-mcp-gateway";
/// Version of the local desktop/CLI IPC contract. The major version is
/// checked before any privileged request is forwarded.
pub const LOCAL_IPC_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonIdentityView {
    pub product_id: String,
    pub protocol_version: u32,
    pub daemon_version: String,
    /// Unique for one daemon process. Clients use it for diagnostics and to
    /// distinguish a crash/restart from the same process still serving IPC.
    pub instance_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DaemonIdentityError {
    #[error("unexpected daemon product")]
    ProductMismatch,
    #[error("incompatible local IPC protocol: expected {expected}, found {actual}")]
    ProtocolMismatch { expected: u32, actual: u32 },
    #[error("daemon readiness response is missing its instance id")]
    MissingInstanceId,
    #[error("daemon readiness response contains an invalid version")]
    InvalidDaemonVersion,
    #[error("incompatible Gateway daemon version: expected {expected}, found {actual}")]
    DaemonVersionMismatch { expected: String, actual: String },
}

impl DaemonIdentityView {
    /// Fail closed unless the endpoint is the intended Gateway daemon and
    /// speaks the local IPC contract understood by this client.
    pub fn validate_for_client(&self) -> Result<(), DaemonIdentityError> {
        if self.product_id != DAEMON_PRODUCT_ID {
            return Err(DaemonIdentityError::ProductMismatch);
        }
        if self.protocol_version != LOCAL_IPC_PROTOCOL_VERSION {
            return Err(DaemonIdentityError::ProtocolMismatch {
                expected: LOCAL_IPC_PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        if self.instance_id.trim().is_empty() {
            return Err(DaemonIdentityError::MissingInstanceId);
        }
        if !valid_daemon_version(&self.daemon_version) {
            return Err(DaemonIdentityError::InvalidDaemonVersion);
        }
        Ok(())
    }

    /// Desktop and CLI releases are packaged with the daemon of the same
    /// version. A process from another Gateway release is a stale lifecycle
    /// owner and must be stopped before the packaged binary is started.
    pub fn validate_daemon_version(&self, expected: &str) -> Result<(), DaemonIdentityError> {
        if self.daemon_version != expected {
            return Err(DaemonIdentityError::DaemonVersionMismatch {
                expected: expected.to_string(),
                actual: self.daemon_version.clone(),
            });
        }
        Ok(())
    }
}

fn valid_daemon_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+')
        })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "request", content = "payload")]
pub enum IpcRequest {
    /// Zero-side-effect readiness/identity handshake. Clients must validate
    /// this response before forwarding any privileged request.
    Identity,
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
    /// Policy-bounded effective expiry shown to the approver. This is the
    /// timestamp persisted with the session, not the remote requested TTL.
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
    Identity(DaemonIdentityView),
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

    #[test]
    fn daemon_identity_round_trips_and_validates() {
        let identity = DaemonIdentityView {
            product_id: DAEMON_PRODUCT_ID.to_string(),
            protocol_version: LOCAL_IPC_PROTOCOL_VERSION,
            daemon_version: "0.1.0".to_string(),
            instance_id: "01J00000000000000000000000".to_string(),
        };
        let json = serde_json::to_string(&IpcResponse::Identity(identity.clone())).unwrap();
        let response: IpcResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(response, IpcResponse::Identity(identity.clone()));
        assert_eq!(identity.validate_for_client(), Ok(()));
        assert_eq!(identity.validate_daemon_version("0.1.0"), Ok(()));
    }

    #[test]
    fn daemon_identity_rejects_wrong_product_protocol_instance_or_version() {
        let base = DaemonIdentityView {
            product_id: DAEMON_PRODUCT_ID.to_string(),
            protocol_version: LOCAL_IPC_PROTOCOL_VERSION,
            daemon_version: "0.1.0".to_string(),
            instance_id: "instance".to_string(),
        };

        let mut wrong_product = base.clone();
        wrong_product.product_id = "untrusted-local-process".to_string();
        assert_eq!(
            wrong_product.validate_for_client(),
            Err(DaemonIdentityError::ProductMismatch)
        );

        let mut wrong_protocol = base.clone();
        wrong_protocol.protocol_version = LOCAL_IPC_PROTOCOL_VERSION + 1;
        assert_eq!(
            wrong_protocol.validate_for_client(),
            Err(DaemonIdentityError::ProtocolMismatch {
                expected: LOCAL_IPC_PROTOCOL_VERSION,
                actual: LOCAL_IPC_PROTOCOL_VERSION + 1,
            })
        );

        let mut missing_instance = base.clone();
        missing_instance.instance_id = "  ".to_string();
        assert_eq!(
            missing_instance.validate_for_client(),
            Err(DaemonIdentityError::MissingInstanceId)
        );

        let mut invalid_version = base.clone();
        invalid_version.daemon_version = "0.1.0\nspoofed".to_string();
        assert_eq!(
            invalid_version.validate_for_client(),
            Err(DaemonIdentityError::InvalidDaemonVersion)
        );

        let mut wrong_version = base;
        wrong_version.daemon_version = "9.9.9".to_string();
        assert_eq!(
            wrong_version.validate_daemon_version("0.1.0"),
            Err(DaemonIdentityError::DaemonVersionMismatch {
                expected: "0.1.0".to_string(),
                actual: "9.9.9".to_string(),
            })
        );
    }
}
