//! The explicit session state machine. See
//! `docs/architecture/session-lifecycle.md` for the full transition table
//! this module implements verbatim — every arm below corresponds to a row
//! in that table, and every combination not listed there is rejected.
//!
//! [`Session::transition`] never mutates a session in place: it consumes
//! `&self` and returns a new [`Session`], so a caller can never
//! accidentally skip validating a transition by mutating `status` directly.

use companion_core::{ApprovalPolicy, Clock, Session, SessionStatus};

/// Events that can be applied to a session. Kept deliberately small: this
/// is a state machine for *session* lifecycle, not a general event bus.
/// Per-operation approvals ("allow once" for a single high-risk operation)
/// do not change session status and are not modeled here — see
/// `docs/architecture/data-flow.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Pair,
    TransportConnected,
    TransportDisconnected,
    RequestAccess,
    Approve,
    Deny { reason: String },
    Pause,
    Resume,
    CheckExpiry,
    Revoke,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session is in terminal state {current:?} and cannot accept further events")]
    TerminalState { current: SessionStatus },
    #[error("event {event:?} is not valid from state {from:?}")]
    InvalidTransition {
        from: SessionStatus,
        event: SessionEvent,
    },
    #[error("storage error: {0}")]
    Storage(String),
    #[error("AllowOnce is a per-operation decision and does not change session status")]
    NotASessionLevelDecision,
}

impl companion_core::CompanionError for SessionError {
    fn code(&self) -> &'static str {
        match self {
            SessionError::TerminalState { .. } => "SESSION_TERMINAL_STATE",
            SessionError::InvalidTransition { .. } => "SESSION_INVALID_TRANSITION",
            SessionError::Storage(_) => "SESSION_STORAGE",
            SessionError::NotASessionLevelDecision => "SESSION_NOT_A_SESSION_LEVEL_DECISION",
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}

pub trait SessionTransition {
    /// Applies `event` to this session, returning the resulting session on
    /// a legal transition, or a typed error otherwise. Never mutates
    /// `self`.
    fn transition(&self, event: SessionEvent, clock: &dyn Clock) -> Result<Session, SessionError>;
}

impl SessionTransition for Session {
    fn transition(&self, event: SessionEvent, clock: &dyn Clock) -> Result<Session, SessionError> {
        // Revoked and Expired are terminal for this session id. A new
        // session (new SessionId) is required to resume access; this
        // record never comes back to life.
        if matches!(self.status, SessionStatus::Revoked | SessionStatus::Expired) {
            return Err(SessionError::TerminalState {
                current: self.status,
            });
        }

        // Revoke is accepted from any non-terminal state, unconditionally.
        if matches!(event, SessionEvent::Revoke) {
            let mut next = self.clone();
            next.status = SessionStatus::Revoked;
            return Ok(next);
        }

        let new_status = match (self.status, &event) {
            (SessionStatus::Unpaired, SessionEvent::Pair) => SessionStatus::Paired,
            (SessionStatus::Paired, SessionEvent::TransportConnected) => SessionStatus::Connected,
            (SessionStatus::Disconnected, SessionEvent::TransportConnected) => {
                SessionStatus::Connected
            }
            (SessionStatus::Connected, SessionEvent::TransportDisconnected) => {
                SessionStatus::Disconnected
            }
            (SessionStatus::Connected, SessionEvent::RequestAccess) => {
                SessionStatus::PendingApproval
            }
            (SessionStatus::PendingApproval, SessionEvent::Approve) => SessionStatus::Active,
            (SessionStatus::PendingApproval, SessionEvent::Deny { .. }) => SessionStatus::Revoked,
            (SessionStatus::Active, SessionEvent::Pause) => SessionStatus::Suspended,
            (SessionStatus::Suspended, SessionEvent::Resume) => SessionStatus::Active,
            (SessionStatus::Active, SessionEvent::CheckExpiry) => {
                if clock.now() >= self.expires_at {
                    SessionStatus::Expired
                } else {
                    SessionStatus::Active
                }
            }
            (from, _) => {
                return Err(SessionError::InvalidTransition { from, event });
            }
        };

        let mut next = self.clone();
        if matches!(event, SessionEvent::Approve) {
            next.approved_at = Some(clock.now());
        }
        next.status = new_status;
        Ok(next)
    }
}

/// Convenience constructor for tests and for the daemon's pairing flow: a
/// brand-new, not-yet-connected session record in `Unpaired` status.
pub fn new_unpaired_session(
    device_id: companion_core::DeviceId,
    remote_principal: String,
    workspace_ids: std::collections::BTreeSet<companion_core::WorkspaceId>,
    capability_profile: companion_core::CapabilityProfile,
    task_scope: String,
    ttl: time::Duration,
    clock: &dyn Clock,
) -> Session {
    let effective_capabilities = capability_profile.effective_capabilities();
    Session {
        session_id: companion_core::SessionId::new(),
        device_id,
        remote_principal,
        workspace_ids,
        capability_profile,
        effective_capabilities,
        task_scope,
        issued_at: clock.now(),
        approved_at: None,
        expires_at: clock.now() + ttl,
        risk_policy_version: 1,
        approval_policy: ApprovalPolicy::Standard,
        status: SessionStatus::Unpaired,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use companion_core::{CapabilityProfile, DeviceId, FakeClock};
    use time::OffsetDateTime;

    use super::*;

    fn fresh_session(clock: &FakeClock) -> Session {
        new_unpaired_session(
            DeviceId::new(),
            "agent:test".into(),
            BTreeSet::new(),
            CapabilityProfile::Inspect,
            "test task".into(),
            time::Duration::hours(1),
            clock,
        )
    }

    #[test]
    fn unpaired_to_paired_on_pair() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = fresh_session(&clock);
        let next = session.transition(SessionEvent::Pair, &clock).unwrap();
        assert_eq!(next.status, SessionStatus::Paired);
    }

    #[test]
    fn full_happy_path_to_active() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = fresh_session(&clock);
        let session = session.transition(SessionEvent::Pair, &clock).unwrap();
        let session = session
            .transition(SessionEvent::TransportConnected, &clock)
            .unwrap();
        let session = session
            .transition(SessionEvent::RequestAccess, &clock)
            .unwrap();
        assert_eq!(session.status, SessionStatus::PendingApproval);
        let session = session.transition(SessionEvent::Approve, &clock).unwrap();
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.approved_at, Some(clock.now()));
    }

    #[test]
    fn pending_approval_denied_goes_to_revoked() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = fresh_session(&clock);
        let session = session.transition(SessionEvent::Pair, &clock).unwrap();
        let session = session
            .transition(SessionEvent::TransportConnected, &clock)
            .unwrap();
        let session = session
            .transition(SessionEvent::RequestAccess, &clock)
            .unwrap();
        let session = session
            .transition(
                SessionEvent::Deny {
                    reason: "no".into(),
                },
                &clock,
            )
            .unwrap();
        assert_eq!(session.status, SessionStatus::Revoked);
    }

    #[test]
    fn pause_then_resume_round_trips_through_active() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = fresh_session(&clock);
        let session = session.transition(SessionEvent::Pair, &clock).unwrap();
        let session = session
            .transition(SessionEvent::TransportConnected, &clock)
            .unwrap();
        let session = session
            .transition(SessionEvent::RequestAccess, &clock)
            .unwrap();
        let session = session.transition(SessionEvent::Approve, &clock).unwrap();
        let session = session.transition(SessionEvent::Pause, &clock).unwrap();
        assert_eq!(session.status, SessionStatus::Suspended);
        let session = session.transition(SessionEvent::Resume, &clock).unwrap();
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn check_expiry_moves_active_session_to_expired_once_past_expiry() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = fresh_session(&clock);
        let session = session.transition(SessionEvent::Pair, &clock).unwrap();
        let session = session
            .transition(SessionEvent::TransportConnected, &clock)
            .unwrap();
        let session = session
            .transition(SessionEvent::RequestAccess, &clock)
            .unwrap();
        let session = session.transition(SessionEvent::Approve, &clock).unwrap();

        clock.advance(time::Duration::hours(2));
        let session = session
            .transition(SessionEvent::CheckExpiry, &clock)
            .unwrap();
        assert_eq!(session.status, SessionStatus::Expired);
    }

    #[test]
    fn check_expiry_is_a_no_op_before_expiry() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = fresh_session(&clock);
        let session = session.transition(SessionEvent::Pair, &clock).unwrap();
        let session = session
            .transition(SessionEvent::TransportConnected, &clock)
            .unwrap();
        let session = session
            .transition(SessionEvent::RequestAccess, &clock)
            .unwrap();
        let session = session.transition(SessionEvent::Approve, &clock).unwrap();

        let session = session
            .transition(SessionEvent::CheckExpiry, &clock)
            .unwrap();
        assert_eq!(session.status, SessionStatus::Active);
    }

    #[test]
    fn revoke_works_from_any_non_terminal_state() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        for status in [
            SessionStatus::Unpaired,
            SessionStatus::Paired,
            SessionStatus::Disconnected,
            SessionStatus::Connected,
            SessionStatus::PendingApproval,
            SessionStatus::Active,
            SessionStatus::Suspended,
        ] {
            let mut session = fresh_session(&clock);
            session.status = status;
            let next = session.transition(SessionEvent::Revoke, &clock).unwrap();
            assert_eq!(
                next.status,
                SessionStatus::Revoked,
                "starting from {status:?}"
            );
        }
    }

    #[test]
    fn revoked_session_rejects_all_further_events() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let mut session = fresh_session(&clock);
        session.status = SessionStatus::Revoked;

        for event in [
            SessionEvent::Pair,
            SessionEvent::TransportConnected,
            SessionEvent::Revoke,
        ] {
            let result = session.transition(event, &clock);
            assert!(matches!(
                result,
                Err(SessionError::TerminalState {
                    current: SessionStatus::Revoked
                })
            ));
        }
    }

    #[test]
    fn expired_session_rejects_all_further_events() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let mut session = fresh_session(&clock);
        session.status = SessionStatus::Expired;

        let result = session.transition(SessionEvent::Approve, &clock);
        assert!(matches!(
            result,
            Err(SessionError::TerminalState {
                current: SessionStatus::Expired
            })
        ));
    }

    #[test]
    fn reconnect_never_resurrects_an_active_session_directly() {
        // An Active session does not respond to raw transport connect/
        // disconnect events at all in this state machine: transport
        // liveness is tracked separately (TransportState), and the
        // existing Active session record is what continues to be used —
        // there is no transition that re-derives "Active" from a
        // transport event.
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let mut session = fresh_session(&clock);
        session.status = SessionStatus::Disconnected;

        let result = session
            .transition(SessionEvent::TransportConnected, &clock)
            .unwrap();
        assert_eq!(
            result.status,
            SessionStatus::Connected,
            "reconnect lands on Connected, not Active"
        );
    }

    #[test]
    fn arbitrary_invalid_transition_is_rejected() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let session = fresh_session(&clock); // Unpaired
        let result = session.transition(SessionEvent::Approve, &clock);
        assert!(matches!(
            result,
            Err(SessionError::InvalidTransition {
                from: SessionStatus::Unpaired,
                ..
            })
        ));
    }
}
