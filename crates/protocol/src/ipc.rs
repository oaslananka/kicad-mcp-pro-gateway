//! Typed request/response DTOs for the daemon's local IPC control API.
//!
//! This is the ONLY surface the desktop UI and CLI are allowed to use to
//! reach the daemon (see `docs/architecture/component-boundaries.md`).
//! There is deliberately no "run arbitrary tool" request variant — every
//! variant here is itself policy-safe (status, approve/deny, pause/
//! resume/revoke, workspace CRUD, audit read).

use companion_core::{DeviceId, GrantId, LeaseId, OperationId, SessionId, WorkspaceId};
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
    /// Transport-era subject records. Retained for existing clients; the
    /// authority itself is reported by `ListAccessGrants`.
    ListSessions,
    /// Explicit authorization authority — the records an operation is
    /// actually evaluated against. Distinct from transport connectivity.
    ListAccessGrants,
    /// Every lease ever cut from a grant, including spent ones. Audit-facing.
    ListAuthorizationLeases {
        grant_id: GrantId,
    },
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
    /// Transport-era subject records in `Active` status. Retained for
    /// existing clients; it is not an authority count.
    pub active_session_count: usize,
    /// Access grants that currently carry authority: `Active`, unexpired,
    /// unrevoked, unconsumed. This is the number that says how much the
    /// Gateway has actually authorized.
    pub active_grant_count: usize,
    /// Whether any access grant is waiting for a local approve/deny.
    pub pending_approval_grant_count: usize,
    /// Connectivity of the outbound transport. Reported here so a client
    /// never has to infer it from authorization state.
    pub transport_state: String,
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
pub struct WorkspaceInfo {
    pub workspace_id: WorkspaceId,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionView {
    pub session_id: SessionId,
    pub remote_principal: String,
    /// The transport-era status of this subject record, kept for existing
    /// clients. It is a compatibility field, not an authorization signal —
    /// see `authorization_status` for the authority that is actually in
    /// force.
    pub status: String,
    /// The authorization status of the access grant that carries authority
    /// for this subject (`pending_approval`, `active`, `suspended`,
    /// `expired`, `revoked`, `consumed`, or `none` when no grant exists).
    pub authorization_status: String,
    /// Transport connectivity, as last observed by the daemon. Never an
    /// authorization signal in either direction: a connected pipe grants
    /// nothing, and a disconnected one takes nothing away.
    pub transport_state: String,
    pub capability_profile: String,
    pub task_scope: String,
    /// Policy-bounded effective expiry shown to the approver. This is the
    /// timestamp persisted with the session, not the remote requested TTL.
    pub expires_at: String,
    pub workspace_ids: Vec<WorkspaceId>,
    pub workspaces: Vec<WorkspaceInfo>,
}

/// One explicit authorization grant. Everything a UI needs to show what the
/// Gateway has actually authorized, and nothing about the pipe it arrived
/// over.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessGrantView {
    pub grant_id: GrantId,
    /// The transport-era subject record this grant answers. Correlation
    /// only — it carries no authority of its own.
    pub subject_session_id: SessionId,
    pub device_id: DeviceId,
    pub remote_principal: String,
    /// `unverified` until a real remote-identity verification exists; a UI
    /// must not present this as a proven identity.
    pub principal_assurance: String,
    pub authorization_status: String,
    /// `standing` or `one_shot`. A one-shot grant authorizes a single lease,
    /// which is not the same thing as a per-operation "allow once".
    pub grant_kind: String,
    pub capability_profile: String,
    pub task_scope: String,
    pub issued_at: String,
    pub approved_at: Option<String>,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
    pub consumed_at: Option<String>,
    pub workspace_ids: Vec<WorkspaceId>,
    pub workspaces: Vec<WorkspaceInfo>,
    /// Connectivity of the pipe, reported next to (never inside) the
    /// authority fields above.
    pub transport_state: String,
}

/// One authorization lease, including whether it has been spent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationLeaseView {
    pub lease_id: LeaseId,
    pub grant_id: GrantId,
    pub subject_session_id: SessionId,
    pub device_id: DeviceId,
    pub issued_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub consumed_by_operation: Option<OperationId>,
    pub workspace_ids: Vec<WorkspaceId>,
    pub capabilities: Vec<String>,
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
    pub workspace_id: WorkspaceId,
    pub workspace: Option<WorkspaceInfo>,
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
    AccessGrants(Vec<AccessGrantView>),
    AuthorizationLeases(Vec<AuthorizationLeaseView>),
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

#[cfg(test)]
mod authorization_view_tests {
    use super::*;

    fn grant_view() -> AccessGrantView {
        AccessGrantView {
            grant_id: GrantId::new(),
            subject_session_id: SessionId::new(),
            device_id: DeviceId::new(),
            remote_principal: "agent:test".into(),
            principal_assurance: "unverified".into(),
            authorization_status: "active".into(),
            grant_kind: "standing".into(),
            capability_profile: "Inspect".into(),
            task_scope: "inspect the board".into(),
            issued_at: "2026-09-26T00:00:00Z".into(),
            approved_at: Some("2026-09-26T00:00:01Z".into()),
            expires_at: "2026-09-26T01:00:00Z".into(),
            revoked_at: None,
            revocation_reason: None,
            consumed_at: None,
            workspace_ids: vec![WorkspaceId::new()],
            workspaces: Vec::new(),
            transport_state: "Disconnected".into(),
        }
    }

    #[test]
    fn an_access_grant_view_round_trips_and_keeps_authorization_separate_from_transport() {
        let view = grant_view();
        let json = serde_json::to_string(&IpcResponse::AccessGrants(vec![view.clone()])).unwrap();
        let back: IpcResponse = serde_json::from_str(&json).unwrap();
        let IpcResponse::AccessGrants(views) = back else {
            panic!("expected AccessGrants");
        };
        assert_eq!(views, vec![view.clone()]);

        let value: serde_json::Value = serde_json::to_value(&view).unwrap();
        assert_eq!(value["authorization_status"], "active");
        assert_eq!(
            value["transport_state"], "Disconnected",
            "connectivity is reported next to the authority, not inside it"
        );
        assert_eq!(value["principal_assurance"], "unverified");
    }

    #[test]
    fn a_session_view_reports_authorization_and_transport_separately() {
        let view = SessionView {
            session_id: SessionId::new(),
            remote_principal: "agent:test".into(),
            status: "Connected".into(),
            authorization_status: "pending_approval".into(),
            transport_state: "Connected".into(),
            capability_profile: "Inspect".into(),
            task_scope: "inspect the board".into(),
            expires_at: "2026-09-26T01:00:00Z".into(),
            workspace_ids: Vec::new(),
            workspaces: Vec::new(),
        };
        let value: serde_json::Value =
            serde_json::to_value(IpcResponse::Sessions(vec![view.clone()])).unwrap();
        assert_eq!(value["payload"][0]["status"], "Connected");
        assert_eq!(
            value["payload"][0]["authorization_status"],
            "pending_approval"
        );
        assert_eq!(value["payload"][0]["transport_state"], "Connected");

        let json = serde_json::to_string(&IpcResponse::Sessions(vec![view])).unwrap();
        let back: IpcResponse = serde_json::from_str(&json).unwrap();
        let IpcResponse::Sessions(views) = back else {
            panic!("expected Sessions");
        };
        assert_eq!(views[0].authorization_status, "pending_approval");
    }

    #[test]
    fn the_new_authorization_requests_round_trip() {
        for request in [
            IpcRequest::ListAccessGrants,
            IpcRequest::ListAuthorizationLeases {
                grant_id: GrantId::new(),
            },
        ] {
            let json = serde_json::to_string(&request).unwrap();
            let back: IpcRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(request, back);
        }
    }

    #[test]
    fn an_authorization_lease_view_reports_its_consumption() {
        let view = AuthorizationLeaseView {
            lease_id: LeaseId::new(),
            grant_id: GrantId::new(),
            subject_session_id: SessionId::new(),
            device_id: DeviceId::new(),
            issued_at: "2026-09-26T00:00:00Z".into(),
            expires_at: "2026-09-26T00:15:00Z".into(),
            consumed_at: Some("2026-09-26T00:01:00Z".into()),
            consumed_by_operation: Some(OperationId::new()),
            workspace_ids: vec![WorkspaceId::new()],
            capabilities: vec!["schematic.read".into()],
        };
        let json =
            serde_json::to_string(&IpcResponse::AuthorizationLeases(vec![view.clone()])).unwrap();
        let back: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, IpcResponse::AuthorizationLeases(vec![view]));
    }
}
