//! The transport/authorization boundary, proven at the crate that owns both
//! models. Every test here drives real transport events through
//! [`companion_sessions::fold_transport_events`] and real authorization
//! events through the grant state machine, then asserts the two never
//! influence each other.

use std::collections::BTreeSet;
use std::sync::Arc;

use companion_core::{
    AccessGrant, AuthorizationPrincipal, AuthorizationStatus, CapabilityProfile, Clock, DeviceId,
    FakeClock, GrantKind, GrantRequest, LeaseRequest, SessionId, TransportState, WorkspaceId,
};
use companion_sessions::{
    consume_lease, fold_transport_events, is_pipe_usable, issue_lease, AuthorizationEvent,
    AuthorizationRepository, GrantTransition, TransportConnectivityEvent,
};
use companion_storage::Storage;
use time::{Duration, OffsetDateTime};

fn requested(kind: GrantKind) -> AccessGrant {
    AccessGrant::requested(
        GrantRequest {
            subject_session_id: SessionId::new(),
            device_id: DeviceId::new(),
            principal: AuthorizationPrincipal::unverified("agent:test"),
            workspace_ids: BTreeSet::from([WorkspaceId::new()]),
            capability_profile: CapabilityProfile::Inspect,
            task_scope: "boundary test".into(),
            kind,
            lifetime: Duration::hours(1),
        },
        OffsetDateTime::UNIX_EPOCH,
    )
}

fn lease_request(grant: &AccessGrant) -> LeaseRequest {
    LeaseRequest {
        workspace_ids: grant.workspace_ids.clone(),
        capabilities: grant.effective_capabilities.clone(),
        lifetime: Duration::minutes(15),
    }
}

/// Everything a relay pipe can do to itself, in one list.
fn reconnect_storm() -> [TransportConnectivityEvent; 8] {
    [
        TransportConnectivityEvent::Connected,
        TransportConnectivityEvent::Disconnected,
        TransportConnectivityEvent::Reconnecting,
        TransportConnectivityEvent::Connected,
        TransportConnectivityEvent::Disconnected,
        TransportConnectivityEvent::ConnectFailed,
        TransportConnectivityEvent::Connecting,
        TransportConnectivityEvent::Connected,
    ]
}

#[test]
fn a_reconnect_storm_never_revives_a_revoked_grant() {
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let grant = requested(GrantKind::Standing)
        .transition(&AuthorizationEvent::Approve, &clock)
        .unwrap();
    let (_, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
    let revoked = grant
        .transition(
            &AuthorizationEvent::Revoke {
                reason: Some("operator revoked it".into()),
            },
            &clock,
        )
        .unwrap();
    assert!(!revoked.is_usable_at(clock.now()));

    let after_storm = fold_transport_events(TransportState::Disconnected, reconnect_storm());
    assert_eq!(
        after_storm,
        TransportState::Connected,
        "the pipe really did come back up"
    );
    assert!(is_pipe_usable(after_storm));
    assert!(
        !revoked.is_usable_at(clock.now()),
        "authority is still revoked"
    );
    assert!(revoked.is_terminal());
    assert_eq!(
        lease.validate_against(&revoked, clock.now()),
        Err(companion_core::AuthorizationError::GrantRevoked)
    );
    assert!(
        consume_lease(
            &revoked,
            &lease,
            companion_core::OperationId::new(),
            clock.now()
        )
        .is_err(),
        "a live pipe must not let a revoked grant's lease be spent"
    );
}

#[test]
fn a_reconnect_storm_never_revives_or_extends_an_expired_grant() {
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let grant = requested(GrantKind::Standing)
        .transition(&AuthorizationEvent::Approve, &clock)
        .unwrap();
    let expires_at = grant.expires_at;
    let (_, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();

    clock.advance(Duration::hours(2));
    assert!(!grant.is_usable_at(clock.now()));

    fold_transport_events(TransportState::Disconnected, reconnect_storm());
    assert!(!grant.is_usable_at(clock.now()));
    assert_eq!(
        grant.expires_at, expires_at,
        "connectivity must never reschedule a TTL"
    );
    assert!(lease.validate_against(&grant, clock.now()).is_err());
}

#[test]
fn a_still_valid_grant_survives_transport_replacement_on_its_own_terms_only() {
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let grant = requested(GrantKind::Standing)
        .transition(&AuthorizationEvent::Approve, &clock)
        .unwrap();
    assert!(grant.is_usable_at(clock.now()));

    // Transport replacement: a brand-new pipe, from scratch.
    let fresh_pipe = fold_transport_events(TransportState::Disconnected, [reconnect_storm()[0]]);
    assert_eq!(fresh_pipe, TransportState::Connected);
    assert!(grant.is_usable_at(clock.now()));

    // A different device cannot spend the same authority.
    let impostor = companion_core::AccessGrant {
        device_id: DeviceId::new(),
        ..grant.clone()
    };
    let (_, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
    assert!(lease.validate_against(&impostor, clock.now()).is_err());

    // Revocation through the authorization machine, with the pipe up, ends
    // the authority without touching the pipe.
    let revoked = grant
        .transition(
            &AuthorizationEvent::Revoke {
                reason: Some("operator revoked it".into()),
            },
            &clock,
        )
        .unwrap();
    assert_eq!(
        fold_transport_events(fresh_pipe, reconnect_storm()),
        TransportState::Connected,
        "revocation is not a disconnect"
    );
    assert!(!revoked.is_usable_at(clock.now()));
}

#[test]
fn revoking_authority_leaves_the_persisted_grant_and_transport_state_independent() {
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let dir = tempfile::tempdir().unwrap().keep();
    let storage = Arc::new(Storage::open(&dir).unwrap());
    let repository = AuthorizationRepository::new(Arc::clone(&storage));

    let grant = requested(GrantKind::Standing)
        .transition(&AuthorizationEvent::Approve, &clock)
        .unwrap();
    repository.save_grant(&grant).unwrap();
    let revoked = grant
        .transition(
            &AuthorizationEvent::Revoke {
                reason: Some("operator revoked it".into()),
            },
            &clock,
        )
        .unwrap();
    repository.save_grant(&revoked).unwrap();

    // A restart plus a full reconnect storm: the durable authority is still
    // revoked, and the pipe state is a separate fact entirely.
    drop(repository);
    drop(storage);
    let restarted = Arc::new(Storage::open(&dir).unwrap());
    let repository = AuthorizationRepository::new(restarted);
    let pipe = fold_transport_events(TransportState::Disconnected, reconnect_storm());

    let reloaded = repository.load_grant(grant.grant_id).unwrap().unwrap();
    assert_eq!(reloaded.status, AuthorizationStatus::Revoked);
    assert!(!reloaded.is_usable_at(OffsetDateTime::UNIX_EPOCH));
    assert_eq!(pipe, TransportState::Connected);
}

#[test]
fn a_one_shot_grant_is_not_extended_by_repeated_transport_input() {
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let grant = requested(GrantKind::OneShot)
        .transition(&AuthorizationEvent::Approve, &clock)
        .unwrap();
    let (grant, lease) = issue_lease(&grant, lease_request(&grant), clock.now()).unwrap();
    let (consumed, _) = consume_lease(
        &grant,
        &lease,
        companion_core::OperationId::new(),
        clock.now(),
    )
    .unwrap();

    // Replaying the same connect/disconnect burst many times, and asking for
    // a fresh lease each time, never yields authority again.
    for _ in 0..5 {
        fold_transport_events(TransportState::Disconnected, reconnect_storm());
        assert!(issue_lease(&consumed, lease_request(&consumed), clock.now()).is_err());
        assert!(!consumed.is_usable_at(clock.now()));
    }
    assert_eq!(consumed.status, AuthorizationStatus::Consumed);
}
