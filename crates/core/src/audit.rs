use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::authorization::{PrincipalAssurance, PrincipalVerificationSource};
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
    /// Untrusted remote-supplied display claim, retained for correlation.
    pub remote_principal: Option<String>,
    /// Whether authenticated remote-actor evidence existed for the authority
    /// used by this policy decision. Old/pre-verification rows are unverified.
    pub principal_assurance: PrincipalAssurance,
    /// Safe verified identity metadata only. These are null unless principal
    /// assurance is verified.
    pub verified_principal_issuer: Option<String>,
    pub verified_principal_subject: Option<String>,
    pub principal_verification_source: Option<PrincipalVerificationSource>,
    pub authentication_strength: Option<String>,
    pub requested_tool: String,
    pub capability: Option<Capability>,
    pub risk: Option<RiskLevel>,
    pub policy_result: PolicyResultKind,
    pub approval_decision: Option<ApprovalDecisionKind>,
    pub execution_status: ExecutionStatus,
    pub error_class: Option<String>,
    pub duration_ms: Option<u64>,
}

impl AuditEvent {
    /// Reject internally inconsistent identity provenance rather than writing
    /// an audit row that claims verification without its safe evidence.
    pub fn has_consistent_principal_evidence(&self) -> bool {
        match self.principal_assurance {
            PrincipalAssurance::Unverified => {
                self.verified_principal_issuer.is_none()
                    && self.verified_principal_subject.is_none()
                    && self.principal_verification_source.is_none()
                    && self.authentication_strength.is_none()
            }
            PrincipalAssurance::Verified => {
                self.verified_principal_issuer
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty())
                    && self
                        .verified_principal_subject
                        .as_ref()
                        .is_some_and(|value| !value.trim().is_empty())
                    && self.principal_verification_source.is_some()
                    && self
                        .authentication_strength
                        .as_ref()
                        .is_some_and(|value| !value.trim().is_empty())
            }
        }
    }
}
