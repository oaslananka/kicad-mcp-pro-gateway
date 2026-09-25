//! The deterministic policy evaluator. Given an [`OperationRequest`], the
//! requesting [`Session`], and the target [`WorkspaceAuthorization`], it
//! decides `Allow` / `Deny` / `RequireApproval`. This function performs no
//! I/O and has no side effects — the same inputs always produce the same
//! decision. It implements exactly the ordered checks in
//! `docs/architecture/data-flow.md` steps 4-10, in the same order.

use companion_core::{
    Capability, CapabilityProfile, Clock, OperationRequest, RiskLevel, Session, SessionStatus,
};
use companion_workspace::{WorkspaceAuthorization, WorkspaceBoundary};

use crate::authorization_ttl::{AuthorizationTtlPolicy, EffectiveAuthorizationTtl};
use crate::operation_effects::{NormalizedOperationEffects, OperationEffectNormalizationError};
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
    UnmodelledToolContract,
    MalformedToolArguments,
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
    authorization_ttl_policy: AuthorizationTtlPolicy,
}

impl<R: ToolCapabilityResolver> PolicyEngine<R> {
    pub fn new(resolver: R) -> Self {
        Self::with_authorization_ttl_policy(resolver, AuthorizationTtlPolicy::default())
    }

    pub fn with_authorization_ttl_policy(
        resolver: R,
        authorization_ttl_policy: AuthorizationTtlPolicy,
    ) -> Self {
        Self {
            resolver,
            authorization_ttl_policy,
        }
    }

    pub fn effective_authorization_ttl(
        &self,
        capability_profile: &CapabilityProfile,
        requested_minutes: i64,
    ) -> EffectiveAuthorizationTtl {
        self.authorization_ttl_policy
            .effective_ttl(capability_profile, requested_minutes)
    }

    /// Derives operation effects from the tool name, forwarded arguments, and
    /// the reviewed contract pinned in the trusted registry. Caller-supplied
    /// `target_path` is intentionally ignored as authorization evidence.
    pub fn normalize_operation_effects(
        &self,
        request: &OperationRequest,
        workspace: &WorkspaceAuthorization,
    ) -> Result<NormalizedOperationEffects, DenyReason> {
        if request.tool_name.trim().is_empty() {
            return Err(DenyReason::MalformedRequest);
        }
        if self.resolver.resolve(&request.tool_name).is_none() {
            return Err(DenyReason::UnknownTool);
        }
        let contract = self
            .resolver
            .effect_contract(&request.tool_name)
            .ok_or(DenyReason::UnmodelledToolContract)?;
        contract
            .normalize(&request.arguments, &workspace.canonical_root)
            .map_err(|error| match error {
                OperationEffectNormalizationError::NoEffects => DenyReason::UnmodelledToolContract,
                _ => DenyReason::MalformedToolArguments,
            })
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

        let effects = match self.normalize_operation_effects(request, workspace) {
            Ok(effects) => effects,
            Err(reason) => return PolicyDecision::Deny { reason },
        };
        if effects
            .iter()
            .any(|(_, path)| workspace.resolve_within(path).is_err())
        {
            return PolicyDecision::Deny {
                reason: DenyReason::PathEscapesWorkspace,
            };
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
