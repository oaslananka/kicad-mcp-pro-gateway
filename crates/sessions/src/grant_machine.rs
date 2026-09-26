//! The explicit authorization state machine. See
//! `docs/architecture/session-lifecycle.md` for the transition table and
//! the boundary this module exists to enforce.
//!
//! **No variant of [`AuthorizationEvent`] is a transport event.** There is
//! no `Connected`, `Disconnected`, `Reconnect`, `Pair`, or `RequestAccess`
//! arm here, and [`crate::transport_boundary`] is the only place transport
//! connectivity is folded into a state. That is what makes it structurally
//! impossible for a transport event to mint, extend, refresh, widen, or
//! resurrect authority: the machine that owns authority cannot be called with
//! one.
//!
//! Like [`crate::state_machine::SessionTransition`], this never mutates in
//! place: it consumes `&self` and returns a new [`AccessGrant`], so a caller
//! cannot skip validation by assigning to `status`.

use crate::state_machine::SessionError;
use companion_core::{
    AccessGrant, AuthorizationError, AuthorizationLease, AuthorizationStatus, Clock, GrantKind,
    LeaseId, LeaseRequest, OperationId, SessionId,
};
use time::{Duration, OffsetDateTime};

/// What may change about a grant. Every event is either a local user's
/// decision or the grant's own clock. A per-operation "allow once" is *not*
/// here: it authorizes a single operation inside an already-approved grant
/// and is handled at the operation layer, so it can never be mistaken for
/// standing authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationEvent {
    /// Local user approved the request. `PendingApproval` → `Active`.
    Approve,
    /// Local user denied the request. `PendingApproval` → `Revoked`.
    Deny { reason: String },
    /// Local user paused an approved grant. `Active` → `Suspended`.
    Suspend,
    /// Local user resumed a paused grant. `Suspended` → `Active`.
    Resume,
    /// Re-evaluate the grant's own TTL. Never reschedules it.
    CheckExpiry,
    /// Local user revoked the grant, from any non-terminal state.
    Revoke { reason: Option<String> },
    /// A one-shot grant's single lease was spent. `Active` → `Consumed`.
    ConsumeLease { lease_id: LeaseId },
}

#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    #[error("access grant is in terminal state {current:?} and cannot accept further events")]
    TerminalState { current: AuthorizationStatus },
    #[error("event {event:?} is not valid from state {from:?}")]
    InvalidTransition {
        from: AuthorizationStatus,
        event: AuthorizationEvent,
    },
    #[error("lease {lease_id} was not issued by this access grant")]
    LeaseNotIssuedByGrant { lease_id: LeaseId },
    #[error("AllowOnce is a per-operation decision and is not standing authorization")]
    NotAGrantLevelDecision,
    #[error("storage error: {0}")]
    Storage(String),
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
    #[error(transparent)]
    LegacySession(#[from] companion_core::LegacySessionMappingError),
    /// Reading the legacy transport-era row this migration reads from failed.
    /// The underlying [`SessionError`] code is preserved.
    #[error(transparent)]
    Session(#[from] SessionError),
}

impl companion_core::CompanionError for GrantError {
    fn code(&self) -> &'static str {
        match self {
            GrantError::TerminalState { .. } => "AUTHORIZATION_TERMINAL_STATE",
            GrantError::InvalidTransition { .. } => "AUTHORIZATION_INVALID_TRANSITION",
            GrantError::LeaseNotIssuedByGrant { .. } => "AUTHORIZATION_LEASE_NOT_ISSUED",
            GrantError::NotAGrantLevelDecision => "AUTHORIZATION_NOT_A_GRANT_LEVEL_DECISION",
            GrantError::Storage(_) => "AUTHORIZATION_STORAGE",
            GrantError::Authorization(_) => "AUTHORIZATION_CONSTRAINT_VIOLATION",
            GrantError::LegacySession(_) => "AUTHORIZATION_LEGACY_STATE_UNUSABLE",
            GrantError::Session(e) => e.code(),
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}

pub trait GrantTransition {
    /// Applies `event` to this grant, returning the resulting grant on a
    /// legal transition, or a typed error otherwise. Never mutates `self`.
    fn transition(
        &self,
        event: &AuthorizationEvent,
        clock: &dyn Clock,
    ) -> Result<AccessGrant, GrantError>;
}

impl GrantTransition for AccessGrant {
    fn transition(
        &self,
        event: &AuthorizationEvent,
        clock: &dyn Clock,
    ) -> Result<AccessGrant, GrantError> {
        // Revoked, Expired and Consumed are terminal for this grant id.
        // Resuming access needs a brand-new grant and a brand-new local
        // approval; this record never comes back to life.
        if self.is_terminal() {
            return Err(GrantError::TerminalState {
                current: self.status,
            });
        }

        // Revoke is accepted from any non-terminal state, unconditionally.
        if let AuthorizationEvent::Revoke { reason } = event {
            let mut next = self.clone();
            next.status = AuthorizationStatus::Revoked;
            next.revoked_at = Some(clock.now());
            next.revocation_reason = reason.clone();
            return Ok(next);
        }

        let next_status = match (self.status, event) {
            (AuthorizationStatus::PendingApproval, AuthorizationEvent::Approve) => {
                AuthorizationStatus::Active
            }
            (AuthorizationStatus::PendingApproval, AuthorizationEvent::Deny { .. }) => {
                AuthorizationStatus::Revoked
            }
            (AuthorizationStatus::Active, AuthorizationEvent::Suspend) => {
                AuthorizationStatus::Suspended
            }
            (AuthorizationStatus::Suspended, AuthorizationEvent::Resume) => {
                AuthorizationStatus::Active
            }
            (
                AuthorizationStatus::PendingApproval
                | AuthorizationStatus::Active
                | AuthorizationStatus::Suspended,
                AuthorizationEvent::CheckExpiry,
            ) => {
                if clock.now() >= self.expires_at {
                    AuthorizationStatus::Expired
                } else {
                    self.status
                }
            }
            (AuthorizationStatus::Active, AuthorizationEvent::ConsumeLease { lease_id }) => {
                if self.kind != GrantKind::OneShot {
                    return Err(GrantError::InvalidTransition {
                        from: self.status,
                        event: event.clone(),
                    });
                }
                if self.issued_lease_id != Some(*lease_id) {
                    return Err(GrantError::LeaseNotIssuedByGrant {
                        lease_id: *lease_id,
                    });
                }
                AuthorizationStatus::Consumed
            }
            (from, _) => {
                return Err(GrantError::InvalidTransition {
                    from,
                    event: event.clone(),
                })
            }
        };

        let mut next = self.clone();
        match event {
            AuthorizationEvent::Approve => next.approved_at = Some(clock.now()),
            AuthorizationEvent::Deny { reason } => {
                next.revoked_at = Some(clock.now());
                next.revocation_reason = Some(reason.clone());
            }
            AuthorizationEvent::ConsumeLease { .. } => next.consumed_at = Some(clock.now()),
            AuthorizationEvent::Revoke { .. }
            | AuthorizationEvent::Suspend
            | AuthorizationEvent::Resume
            | AuthorizationEvent::CheckExpiry => {}
        }
        next.status = next_status;
        Ok(next)
    }
}

/// Cuts a lease from `grant` and records it on the grant. The lease is
/// always narrower than, and never outlives, the grant; a one-shot grant can
/// only ever do this once (the second attempt is refused, not merely
/// ignored). Returns both records so the caller can persist them together.
pub fn issue_lease(
    grant: &AccessGrant,
    request: LeaseRequest,
    now: OffsetDateTime,
) -> Result<(AccessGrant, AuthorizationLease), GrantError> {
    let lease = AuthorizationLease::issued_for(grant, request, now)?;
    let mut next = grant.clone();
    next.issued_lease_id = Some(lease.lease_id);
    Ok((next, lease))
}

/// Spends `lease` against `grant` and, for a one-shot grant, consumes the
/// grant in the same step. Spending a lease on a standing grant leaves the
/// grant standing.
pub fn consume_lease(
    grant: &AccessGrant,
    lease: &AuthorizationLease,
    operation_id: OperationId,
    now: OffsetDateTime,
) -> Result<(AccessGrant, AuthorizationLease), GrantError> {
    lease.validate_against(grant, now)?;
    let spent = lease.consumed_by(operation_id, now)?;
    let mut next = grant.clone();
    if grant.kind == GrantKind::OneShot {
        next = next.transition(
            &AuthorizationEvent::ConsumeLease {
                lease_id: lease.lease_id,
            },
            &FixedClock(now),
        )?;
    }
    Ok((next, spent))
}

/// A one-event [`Clock`] view of an explicit instant, so the lease helpers
/// can run the state machine without a caller-supplied clock.
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// Maps a legacy transport-era session event onto the authorization
/// lifecycle, for the compatibility path in the daemon's IPC handlers.
///
/// The transport-era events deliberately have **no** mapping: `Pair`,
/// `TransportConnected`, `TransportDisconnected`, and `RequestAccess` are
/// facts about a pipe, and no authorization event can be derived from them.
pub fn authorization_event_for(
    event: &crate::state_machine::SessionEvent,
) -> Option<AuthorizationEvent> {
    use crate::state_machine::SessionEvent;
    match event {
        SessionEvent::Approve => Some(AuthorizationEvent::Approve),
        SessionEvent::Deny { reason } => Some(AuthorizationEvent::Deny {
            reason: reason.clone(),
        }),
        SessionEvent::Pause => Some(AuthorizationEvent::Suspend),
        SessionEvent::Resume => Some(AuthorizationEvent::Resume),
        SessionEvent::Revoke => Some(AuthorizationEvent::Revoke { reason: None }),
        SessionEvent::Pair
        | SessionEvent::TransportConnected
        | SessionEvent::TransportDisconnected
        | SessionEvent::RequestAccess
        | SessionEvent::CheckExpiry => None,
    }
}

/// Whether a grant's own clock says it is inside its lifetime, and that
/// lifetime is a real one rather than a zero-width artifact. Used by
/// persistence/callers that need the check without a full transition.
pub fn within_lifetime(grant: &AccessGrant, now: OffsetDateTime) -> bool {
    now < grant.expires_at && grant.expires_at - grant.issued_at > Duration::ZERO
}

/// The transport-era subject a grant answers, for compatibility code that
/// has to correlate an operation/audit row with its authority. Purely a
/// getter: it can never create or change a grant.
pub fn subject_of(grant: &AccessGrant) -> SessionId {
    grant.subject_session_id
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use companion_core::{
        AuthorizationPrincipal, CapabilityProfile, DeviceId, FakeClock, GrantRequest, WorkspaceId,
    };

    use super::*;

    fn pending_grant(clock: &FakeClock) -> AccessGrant {
        AccessGrant::requested(
            GrantRequest {
                subject_session_id: SessionId::new(),
                device_id: DeviceId::new(),
                principal: AuthorizationPrincipal::unverified("agent:test"),
                workspace_ids: BTreeSet::from([WorkspaceId::new()]),
                capability_profile: CapabilityProfile::Inspect,
                task_scope: "test task".into(),
                kind: GrantKind::Standing,
                lifetime: Duration::hours(1),
            },
            clock.now(),
        )
    }

    fn active_grant(clock: &FakeClock) -> AccessGrant {
        pending_grant(clock)
            .transition(&AuthorizationEvent::Approve, clock)
            .unwrap()
    }

    fn lease_request(grant: &AccessGrant) -> LeaseRequest {
        LeaseRequest {
            workspace_ids: grant.workspace_ids.clone(),
            capabilities: grant.effective_capabilities.clone(),
            lifetime: Duration::minutes(10),
        }
    }

    #[test]
    fn a_requested_grant_becomes_usable_only_after_local_approval() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = pending_grant(&clock);
        assert_eq!(grant.status, AuthorizationStatus::PendingApproval);
        assert!(!grant.is_usable_at(clock.now()));

        let approved = grant
            .transition(&AuthorizationEvent::Approve, &clock)
            .unwrap();
        assert_eq!(approved.status, AuthorizationStatus::Active);
        assert_eq!(approved.approved_at, Some(clock.now()));
        assert!(approved.is_usable_at(clock.now()));
    }

    #[test]
    fn denial_is_terminal_for_that_grant_id() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = pending_grant(&clock);
        let denied = grant
            .transition(
                &AuthorizationEvent::Deny {
                    reason: "not this machine's job".into(),
                },
                &clock,
            )
            .unwrap();
        assert_eq!(denied.status, AuthorizationStatus::Revoked);
        assert_eq!(denied.revoked_at, Some(clock.now()));
        assert_eq!(
            denied.revocation_reason.as_deref(),
            Some("not this machine's job")
        );
        assert!(!denied.is_usable_at(clock.now()));
    }

    #[test]
    fn suspend_and_resume_are_explicit_local_actions_that_never_reschedule() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = active_grant(&clock);
        let expires_at = grant.expires_at;

        let suspended = grant
            .transition(&AuthorizationEvent::Suspend, &clock)
            .unwrap();
        assert_eq!(suspended.status, AuthorizationStatus::Suspended);
        assert!(!suspended.is_usable_at(clock.now()));
        assert_eq!(
            suspended.expires_at, expires_at,
            "suspension must not extend the grant's lifetime"
        );

        let resumed = suspended
            .transition(&AuthorizationEvent::Resume, &clock)
            .unwrap();
        assert_eq!(resumed.status, AuthorizationStatus::Active);
        assert_eq!(resumed.expires_at, expires_at);
    }

    #[test]
    fn check_expiry_expires_a_grant_that_outlived_its_own_ttl_and_never_extends_it() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = active_grant(&clock);
        let expires_at = grant.expires_at;

        let still_live = grant
            .transition(&AuthorizationEvent::CheckExpiry, &clock)
            .unwrap();
        assert_eq!(still_live.status, AuthorizationStatus::Active);

        clock.advance(Duration::hours(2));
        let expired = still_live
            .transition(&AuthorizationEvent::CheckExpiry, &clock)
            .unwrap();
        assert_eq!(expired.status, AuthorizationStatus::Expired);
        assert_eq!(
            expired.expires_at, expires_at,
            "an expiry check must never move the deadline"
        );
        assert!(!expired.is_usable_at(clock.now()));
    }

    #[test]
    fn check_expiry_also_expires_an_unapproved_request_that_sat_past_its_ttl() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = pending_grant(&clock);
        clock.advance(Duration::hours(2));
        let expired = grant
            .transition(&AuthorizationEvent::CheckExpiry, &clock)
            .unwrap();
        assert_eq!(expired.status, AuthorizationStatus::Expired);
        assert!(
            expired
                .transition(&AuthorizationEvent::Approve, &clock)
                .is_err(),
            "an expired request must never be approvable afterwards"
        );
    }

    #[test]
    fn revoke_is_accepted_from_every_non_terminal_state() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        for status in [
            AuthorizationStatus::PendingApproval,
            AuthorizationStatus::Active,
            AuthorizationStatus::Suspended,
        ] {
            let mut grant = pending_grant(&clock);
            grant.status = status;
            let revoked = grant
                .transition(
                    &AuthorizationEvent::Revoke {
                        reason: Some("operator asked".into()),
                    },
                    &clock,
                )
                .unwrap();
            assert_eq!(
                revoked.status,
                AuthorizationStatus::Revoked,
                "from {status:?}"
            );
            assert_eq!(revoked.revoked_at, Some(clock.now()));
            assert!(revoked.is_terminal());
        }
    }

    #[test]
    fn terminal_grants_reject_every_further_event() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        for status in [
            AuthorizationStatus::Revoked,
            AuthorizationStatus::Expired,
            AuthorizationStatus::Consumed,
        ] {
            let mut grant = pending_grant(&clock);
            grant.status = status;
            for event in [
                AuthorizationEvent::Approve,
                AuthorizationEvent::Suspend,
                AuthorizationEvent::Resume,
                AuthorizationEvent::CheckExpiry,
                AuthorizationEvent::Revoke { reason: None },
            ] {
                let result = grant.transition(&event, &clock);
                assert!(
                    matches!(
                        result,
                        Err(GrantError::TerminalState { current }) if current == status
                    ),
                    "{status:?} must reject {event:?}, got {result:?}"
                );
            }
        }
    }

    #[test]
    fn a_one_shot_grant_is_consumed_exactly_once_by_its_single_lease() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let mut grant = pending_grant(&clock);
        grant.kind = GrantKind::OneShot;
        let grant = grant
            .transition(&AuthorizationEvent::Approve, &clock)
            .unwrap();

        let (grant, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
        assert_eq!(grant.issued_lease_id, Some(lease.lease_id));
        assert!(
            matches!(
                issue_lease(&grant, lease_request(&grant), clock.now()),
                Err(GrantError::Authorization(
                    AuthorizationError::OneShotLeaseAlreadyIssued { .. }
                ))
            ),
            "a one-shot grant cannot cut a second lease"
        );

        let (consumed, spent) =
            consume_lease(&grant, &lease, OperationId::new(), clock.now()).unwrap();
        assert_eq!(consumed.status, AuthorizationStatus::Consumed);
        assert_eq!(consumed.consumed_at, Some(clock.now()));
        assert_eq!(spent.consumed_at, Some(clock.now()));
        assert!(!consumed.is_usable_at(clock.now()));
        assert!(matches!(
            consumed.transition(&AuthorizationEvent::Resume, &clock),
            Err(GrantError::TerminalState { .. })
        ));
    }

    #[test]
    fn a_standing_grant_stays_standing_when_one_of_its_leases_is_spent() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = active_grant(&clock);
        let (grant, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
        let (still_active, spent) =
            consume_lease(&grant, &lease, OperationId::new(), clock.now()).unwrap();
        assert_eq!(still_active.status, AuthorizationStatus::Active);
        assert!(still_active.is_usable_at(clock.now()));
        assert!(spent.consumed_at.is_some());

        let (_, second) = issue_lease(&still_active, lease_request(&still_active), clock.now())
            .expect("a standing grant may cut another lease");
        assert_ne!(second.lease_id, lease.lease_id);
    }

    #[test]
    fn a_standing_grant_cannot_be_consumed_by_a_lease() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = active_grant(&clock);
        let (grant, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
        assert!(matches!(
            grant.transition(
                &AuthorizationEvent::ConsumeLease {
                    lease_id: lease.lease_id
                },
                &clock,
            ),
            Err(GrantError::InvalidTransition {
                from: AuthorizationStatus::Active,
                ..
            })
        ));
    }

    #[test]
    fn revoking_a_grant_invalidates_a_live_lease_of_it() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = active_grant(&clock);
        let (grant, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
        assert!(lease.validate_against(&grant, clock.now()).is_ok());

        let revoked = grant
            .transition(
                &AuthorizationEvent::Revoke {
                    reason: Some("operator asked".into()),
                },
                &clock,
            )
            .unwrap();
        assert_eq!(
            lease.validate_against(&revoked, clock.now()),
            Err(AuthorizationError::GrantRevoked)
        );
        assert!(matches!(
            consume_lease(&revoked, &lease, OperationId::new(), clock.now()),
            Err(GrantError::Authorization(AuthorizationError::GrantRevoked))
        ));
    }

    #[test]
    fn a_lease_of_another_grant_is_refused() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = active_grant(&clock);
        let (_, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
        let other = active_grant(&clock);
        assert_eq!(
            lease.validate_against(&other, clock.now()),
            Err(AuthorizationError::ForeignGrant)
        );
    }

    #[test]
    fn consuming_a_lease_that_was_never_issued_by_a_one_shot_grant_is_refused() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let mut grant = pending_grant(&clock);
        grant.kind = GrantKind::OneShot;
        let grant = grant
            .transition(&AuthorizationEvent::Approve, &clock)
            .unwrap();
        assert!(matches!(
            grant.transition(
                &AuthorizationEvent::ConsumeLease {
                    lease_id: LeaseId::new()
                },
                &clock,
            ),
            Err(GrantError::LeaseNotIssuedByGrant { .. })
        ));
    }

    #[test]
    fn transport_era_session_events_never_map_to_an_authorization_event() {
        use crate::state_machine::SessionEvent;
        for event in [
            SessionEvent::Pair,
            SessionEvent::TransportConnected,
            SessionEvent::TransportDisconnected,
            SessionEvent::RequestAccess,
            SessionEvent::CheckExpiry,
        ] {
            assert_eq!(
                authorization_event_for(&event),
                None,
                "{event:?} is a transport/lifecycle fact, not an authorization decision"
            );
        }
        assert_eq!(
            authorization_event_for(&SessionEvent::Approve),
            Some(AuthorizationEvent::Approve)
        );
        assert_eq!(
            authorization_event_for(&SessionEvent::Pause),
            Some(AuthorizationEvent::Suspend)
        );
        assert_eq!(
            authorization_event_for(&SessionEvent::Revoke),
            Some(AuthorizationEvent::Revoke { reason: None })
        );
        assert_eq!(
            authorization_event_for(&SessionEvent::Deny {
                reason: "no".into()
            }),
            Some(AuthorizationEvent::Deny {
                reason: "no".into()
            })
        );
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = pending_grant(&clock);
        for event in [
            AuthorizationEvent::Suspend,
            AuthorizationEvent::Resume,
            AuthorizationEvent::ConsumeLease {
                lease_id: LeaseId::new(),
            },
        ] {
            let result = grant.transition(&event, &clock);
            assert!(
                matches!(
                    result,
                    Err(GrantError::InvalidTransition {
                        from: AuthorizationStatus::PendingApproval,
                        ..
                    })
                ),
                "{event:?} must be rejected from PendingApproval, got {result:?}"
            );
        }
    }

    #[test]
    fn lifetime_helper_rejects_a_non_positive_or_lapsed_window() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = active_grant(&clock);
        assert!(within_lifetime(&grant, clock.now()));
        assert!(!within_lifetime(&grant, grant.expires_at));
        let degenerate = AccessGrant {
            issued_at: grant.issued_at,
            expires_at: grant.issued_at,
            ..grant
        };
        assert!(!within_lifetime(&degenerate, clock.now()));
    }
}
