use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::capability::Capability;
use crate::ids::{OperationId, SessionId, WorkspaceId};
use crate::risk::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyResultKind {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecisionKind {
    Approved,
    AllowOnce,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    NotExecuted,
    Success,
    Failed,
}

/// A structured, append-only record of one policy decision (and, when
/// allowed, its execution outcome). Never contains secret material or raw
/// project source contents — only metadata about what was requested and
/// what happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub operation_id: OperationId,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub session_id: Option<SessionId>,
    pub workspace_id: Option<WorkspaceId>,
    pub remote_principal: Option<String>,
    pub requested_tool: String,
    pub capability: Option<Capability>,
    pub risk: Option<RiskLevel>,
    pub policy_result: PolicyResultKind,
    pub approval_decision: Option<ApprovalDecisionKind>,
    pub execution_status: ExecutionStatus,
    pub error_class: Option<String>,
    pub duration_ms: Option<u64>,
}
