//! The deterministic policy evaluator. Given an [`OperationRequest`], the
//! [`AccessGrant`] that authorizes it, and the target
//! [`WorkspaceAuthorization`], it decides `Allow` / `Deny` /
//! `RequireApproval`. This function performs no I/O and has no side
//! effects — the same inputs always produce the same decision. It implements
//! exactly the ordered checks in `docs/architecture/data-flow.md` steps
//! 4-10, in the same order.
//!
//! Authority comes from an [`AccessGrant`], never from a transport-era
//! [`Session`]. [`PolicyEngine::evaluate`] exists only as the compatibility
//! adapter that maps a legacy session row onto a grant first.

use companion_core::{
    grant_from_legacy_session, AccessGrant, AuthorizationStatus, Capability, CapabilityProfile,
    Clock, OperationRequest, RiskLevel, Session, SessionStatus,
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
    /// The one-shot grant behind this request already spent its single lease.
    OneShotGrantConsumed,
    /// No usable authorization authority could be established for the subject
    /// the request names — including a legacy row that never carried
    /// authority or that this build refuses to interpret.
    AuthorizationNotEstablished,
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

    /// Evaluates an operation against the grant that authorizes it.
    ///
    /// The grant is the only thing that can grant access here: no transport
    /// state, no connection, and no reconnect is consulted, so the answer
    /// for a given grant is the same whether the pipe just came up, has been
    /// up for hours, or is down.
    pub fn evaluate_with_grant(
        &self,
        request: &OperationRequest,
        grant: &AccessGrant,
        workspace: &WorkspaceAuthorization,
        clock: &dyn Clock,
    ) -> PolicyDecision {
        if request.tool_name.trim().is_empty() {
            return PolicyDecision::Deny {
                reason: DenyReason::MalformedRequest,
            };
        }

        // The grant must be the one that answers the subject this request
        // names. A grant for some other subject carries no authority here,
        // however active and unexpired it is.
        if request.session_id != grant.subject_session_id {
            return PolicyDecision::Deny {
                reason: DenyReason::AuthorizationNotEstablished,
            };
        }

        match grant.status {
            AuthorizationStatus::Active => {}
            AuthorizationStatus::Revoked => {
                return PolicyDecision::Deny {
                    reason: DenyReason::SessionRevoked,
                }
            }
            AuthorizationStatus::Expired => {
                return PolicyDecision::Deny {
                    reason: DenyReason::SessionExpired,
                }
            }
            AuthorizationStatus::Consumed => {
                return PolicyDecision::Deny {
                    reason: DenyReason::OneShotGrantConsumed,
                }
            }
            _ => {
                return PolicyDecision::Deny {
                    reason: DenyReason::SessionNotActive,
                }
            }
        }

        if clock.now() >= grant.expires_at {
            return PolicyDecision::Deny {
                reason: DenyReason::SessionExpired,
            };
        }

        if request.workspace_id != workspace.workspace_id
            || !grant.allows_workspace(&request.workspace_id)
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

        if !grant.allows_capability(&capability) {
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

    /// Compatibility adapter for callers that only have a transport-era
    /// [`Session`]. The row is mapped onto a grant with the same
    /// [`companion_core::grant_from_legacy_session`] the schema migration
    /// uses, and the decision is then made on that grant — so there is still
    /// exactly one place where authority is judged.
    ///
    /// A row that never carried authority, or one this build refuses to
    /// interpret, is denied.
    pub fn evaluate(
        &self,
        request: &OperationRequest,
        session: &Session,
        workspace: &WorkspaceAuthorization,
        clock: &dyn Clock,
    ) -> PolicyDecision {
        match grant_from_legacy_session(session) {
            Ok(Some(grant)) => self.evaluate_with_grant(request, &grant, workspace, clock),
            Ok(None) => {
                // `Unpaired`/`Paired`/`Connected`/`Disconnected` rows never
                // held authority. A request that names one is not asking
                // with a grant in hand.
                PolicyDecision::Deny {
                    reason: match session.status {
                        SessionStatus::Revoked => DenyReason::SessionRevoked,
                        SessionStatus::Expired => DenyReason::SessionExpired,
                        _ => DenyReason::AuthorizationNotEstablished,
                    },
                }
            }
            Err(_) => PolicyDecision::Deny {
                reason: DenyReason::AuthorizationNotEstablished,
            },
        }
    }
}
