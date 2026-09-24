//! Applies a local approval decision to a session's pending state.
//!
//! `AllowOnce` is intentionally not handled here: it authorizes a single
//! high-risk *operation* within an already-`Active` session and never
//! changes session status. That decision is applied at the
//! operation-execution layer (daemon, Phase 5/6), not the session state
//! machine.

use companion_core::{ApprovalDecision, Clock, Session};

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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use companion_core::{CapabilityProfile, DeviceId, FakeClock, SessionStatus};
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
}
