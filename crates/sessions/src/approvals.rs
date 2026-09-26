//! Applies a local approval decision to a session's pending state.
//!
//! `AllowOnce` is intentionally not handled here: it authorizes a single
//! high-risk *operation* within an already-`Active` session and never
//! changes session status. That decision is applied at the
//! operation-execution layer (daemon, Phase 5/6), not the session state
//! machine. The same rule holds for the authorization model: see
//! [`apply_grant_decision`].

use companion_core::{AccessGrant, ApprovalDecision, Clock, Session};

use crate::grant_machine::{AuthorizationEvent, GrantError, GrantTransition};
use crate::state_machine::{SessionError, SessionEvent, SessionTransition};

pub fn apply_session_decision(
    session: &Session,
    decision: &ApprovalDecision,
    clock: &dyn Clock,
) -> Result<Session, SessionError> {
    match decision {
        ApprovalDecision::Approved { .. } => session.transition(SessionEvent::Approve, clock),
        ApprovalDecision::Denied { reason, .. } => session.transition(
            SessionEvent::Deny {
                reason: reason.clone(),
            },
            clock,
        ),
        ApprovalDecision::AllowOnce { .. } => Err(SessionError::NotASessionLevelDecision),
    }
}

/// The authorization-model counterpart of [`apply_session_decision`]. A
/// standing `Approved` decision activates the grant; `Denied` revokes it;
/// `AllowOnce` is rejected because per-operation approval is not standing
/// authorization and must not leave a usable grant behind.
pub fn apply_grant_decision(
    grant: &AccessGrant,
    decision: &ApprovalDecision,
    clock: &dyn Clock,
) -> Result<AccessGrant, GrantError> {
    match decision {
        ApprovalDecision::Approved { .. } => grant.transition(&AuthorizationEvent::Approve, clock),
        ApprovalDecision::Denied { reason, .. } => grant.transition(
            &AuthorizationEvent::Deny {
                reason: reason.clone(),
            },
            clock,
        ),
        ApprovalDecision::AllowOnce { .. } => Err(GrantError::NotAGrantLevelDecision),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use companion_core::{CapabilityProfile, Clock, DeviceId, FakeClock, SessionId, SessionStatus};
    use time::OffsetDateTime;

    use super::*;
    use crate::state_machine::new_unpaired_session;

    fn pending_session(clock: &FakeClock) -> Session {
        let mut session = new_unpaired_session(
            DeviceId::new(),
            "agent:test".into(),
            BTreeSet::new(),
            CapabilityProfile::Inspect,
            "task".into(),
            time::Duration::hours(1),
            clock,
        );
        session.status = SessionStatus::PendingApproval;
        session
    }

    #[test]
    fn approved_decision_activates_the_session() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = pending_session(&clock);
        let decision = ApprovalDecision::Approved {
            decided_at: clock.now(),
        };
        let result = apply_session_decision(&session, &decision, &clock).unwrap();
        assert_eq!(result.status, SessionStatus::Active);
    }

    #[test]
    fn denied_decision_revokes_the_session() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = pending_session(&clock);
        let decision = ApprovalDecision::Denied {
            decided_at: clock.now(),
            reason: "not authorized".into(),
        };
        let result = apply_session_decision(&session, &decision, &clock).unwrap();
        assert_eq!(result.status, SessionStatus::Revoked);
    }

    #[test]
    fn allow_once_is_rejected_as_a_session_level_decision() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = pending_session(&clock);
        let decision = ApprovalDecision::AllowOnce {
            decided_at: clock.now(),
        };
        let result = apply_session_decision(&session, &decision, &clock);
        assert!(matches!(
            result,
            Err(SessionError::NotASessionLevelDecision)
        ));
    }

    #[test]
    fn allow_once_is_rejected_as_standing_authorization_too() {
        use companion_core::{AuthorizationPrincipal, GrantKind, GrantRequest, WorkspaceId};

        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = AccessGrant::requested(
            GrantRequest {
                subject_session_id: SessionId::new(),
                device_id: DeviceId::new(),
                principal: AuthorizationPrincipal::unverified("agent:test"),
                workspace_ids: BTreeSet::from([WorkspaceId::new()]),
                capability_profile: CapabilityProfile::Inspect,
                task_scope: "task".into(),
                kind: GrantKind::OneShot,
                lifetime: time::Duration::hours(1),
            },
            clock.now(),
        );
        let decision = ApprovalDecision::AllowOnce {
            decided_at: clock.now(),
        };
        let result = apply_grant_decision(&grant, &decision, &clock);
        assert!(matches!(result, Err(GrantError::NotAGrantLevelDecision)));
        assert!(
            !result.unwrap_or(grant).is_usable_at(clock.now()),
            "a per-operation decision must never leave standing authority behind"
        );
    }

    #[test]
    fn approved_and_denied_decisions_drive_the_authorization_lifecycle() {
        use companion_core::{AuthorizationPrincipal, GrantKind, GrantRequest, WorkspaceId};

        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let requested = || {
            AccessGrant::requested(
                GrantRequest {
                    subject_session_id: SessionId::new(),
                    device_id: DeviceId::new(),
                    principal: AuthorizationPrincipal::unverified("agent:test"),
                    workspace_ids: BTreeSet::from([WorkspaceId::new()]),
                    capability_profile: CapabilityProfile::Inspect,
                    task_scope: "task".into(),
                    kind: GrantKind::Standing,
                    lifetime: time::Duration::hours(1),
                },
                clock.now(),
            )
        };

        let approved = apply_grant_decision(
            &requested(),
            &ApprovalDecision::Approved {
                decided_at: clock.now(),
            },
            &clock,
        )
        .unwrap();
        assert!(approved.is_usable_at(clock.now()));
        assert_eq!(approved.approved_at, Some(clock.now()));

        let denied = apply_grant_decision(
            &requested(),
            &ApprovalDecision::Denied {
                decided_at: clock.now(),
                reason: "not authorized".into(),
            },
            &clock,
        )
        .unwrap();
        assert!(!denied.is_usable_at(clock.now()));
        assert_eq!(denied.revocation_reason.as_deref(), Some("not authorized"));
    }
}
