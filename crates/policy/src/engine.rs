//! The deterministic policy evaluator. Given an [`OperationRequest`], the
//! requesting [`Session`], and the target [`WorkspaceAuthorization`], it
//! decides `Allow` / `Deny` / `RequireApproval`. This function performs no
//! I/O and has no side effects — the same inputs always produce the same
//! decision. It implements exactly the ordered checks in
//! `docs/architecture/data-flow.md` steps 4-10, in the same order.

use companion_core::{Capability, Clock, OperationRequest, RiskLevel, Session, SessionStatus};
use companion_workspace::{WorkspaceAuthorization, WorkspaceBoundary};

use crate::tool_registry::ToolCapabilityResolver;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    MalformedRequest,
    SessionNotActive,
    SessionExpired,
    SessionRevoked,
    WorkspaceNotAuthorized,
    PathEscapesWorkspace,
    UnknownTool,
    CapabilityNotGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalReason {
    HighRiskOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow {
        capability: Capability,
        risk: RiskLevel,
    },
    Deny {
        reason: DenyReason,
    },
    RequireApproval {
        reason: ApprovalReason,
        risk: RiskLevel,
        capability: Capability,
    },
}

pub struct PolicyEngine<R: ToolCapabilityResolver> {
    resolver: R,
}

impl<R: ToolCapabilityResolver> PolicyEngine<R> {
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub fn evaluate(
        &self,
        request: &OperationRequest,
        session: &Session,
        workspace: &WorkspaceAuthorization,
        clock: &dyn Clock,
    ) -> PolicyDecision {
        if request.tool_name.trim().is_empty() {
            return PolicyDecision::Deny {
                reason: DenyReason::MalformedRequest,
            };
        }

        match session.status {
            SessionStatus::Active => {}
            SessionStatus::Revoked => {
                return PolicyDecision::Deny {
                    reason: DenyReason::SessionRevoked,
                }
            }
            _ => {
                return PolicyDecision::Deny {
                    reason: DenyReason::SessionNotActive,
                }
            }
        }

        if clock.now() >= session.expires_at {
            return PolicyDecision::Deny {
                reason: DenyReason::SessionExpired,
            };
        }

        if request.workspace_id != workspace.workspace_id
            || !session.workspace_ids.contains(&request.workspace_id)
        {
            return PolicyDecision::Deny {
                reason: DenyReason::WorkspaceNotAuthorized,
            };
        }

        if let Some(target) = &request.target_path {
            if workspace.resolve_within(target).is_err() {
                return PolicyDecision::Deny {
                    reason: DenyReason::PathEscapesWorkspace,
                };
            }
        }

        let Some((capability, risk)) = self.resolver.resolve(&request.tool_name) else {
            return PolicyDecision::Deny {
                reason: DenyReason::UnknownTool,
            };
        };

        if !session.effective_capabilities.contains(&capability) {
            return PolicyDecision::Deny {
                reason: DenyReason::CapabilityNotGranted,
            };
        }

        if risk >= RiskLevel::High {
            return PolicyDecision::RequireApproval {
                reason: ApprovalReason::HighRiskOperation,
                risk,
                capability,
            };
        }

        PolicyDecision::Allow { capability, risk }
    }
}
