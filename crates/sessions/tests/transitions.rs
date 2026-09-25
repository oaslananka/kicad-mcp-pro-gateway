//! Full state-table coverage plus the cross-crate regression the product
//! spec calls out explicitly: revoking a session, then "reconnecting" (in
//! this pure-state test: simply re-evaluating a new operation against the
//! now-revoked session record) must still deny the operation. Revocation
//! is not something a transport reconnect can undo.

use std::collections::BTreeSet;

use companion_core::{
    CapabilityProfile, Clock, DeviceId, FakeClock, OperationId, OperationRequest, SessionStatus,
};
use companion_policy::{DenyReason, PolicyDecision, PolicyEngine, TomlToolRegistry};
use companion_sessions::{new_unpaired_session, SessionEvent, SessionTransition};
use companion_workspace::WorkspaceAuthorization;
use time::OffsetDateTime;

fn registry() -> TomlToolRegistry {
    TomlToolRegistry::from_toml_str(
        r#"
        contract_version = 1
        source_repository = "oaslananka/kicad-mcp-pro"
        source_ref = "main"
        source_sha = "f641a92596ab7adc1e134287578b1ae5ff9580ad"

        [[tool]]
        name = "schematic.read"
        capability = "schematic.read"
        risk = "low"
        arguments = []
        effects = ["read"]
        "#,
    )
    .unwrap()
}

#[test]
fn full_lifecycle_then_revoke_then_operation_is_still_denied() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);

    // 1. Fresh session, walk the full happy path to Active.
    let session = new_unpaired_session(
        DeviceId::new(),
        "agent:test".into(),
        BTreeSet::from([workspace.workspace_id]),
        CapabilityProfile::Inspect,
        "read schematic".into(),
        time::Duration::hours(1),
        &clock,
    );
    let session = session.transition(SessionEvent::Pair, &clock).unwrap();
    let session = session
        .transition(SessionEvent::TransportConnected, &clock)
        .unwrap();
    let session = session
        .transition(SessionEvent::RequestAccess, &clock)
        .unwrap();
    let session = session.transition(SessionEvent::Approve, &clock).unwrap();
    assert_eq!(session.status, SessionStatus::Active);

    // 2. While active, a legitimate operation is allowed.
    let engine = PolicyEngine::new(registry());
    let op = OperationRequest {
        operation_id: OperationId::new(),
        session_id: session.session_id,
        workspace_id: workspace.workspace_id,
        tool_name: "schematic.read".into(),
        arguments: Default::default(),
        target_path: None,
        requested_at: clock.now(),
    };
    let decision = engine.evaluate(&op, &session, &workspace, &clock);
    assert!(
        matches!(decision, PolicyDecision::Allow { .. }),
        "{decision:?}"
    );

    // 3. User revokes the session locally.
    let session = session.transition(SessionEvent::Revoke, &clock).unwrap();
    assert_eq!(session.status, SessionStatus::Revoked);

    // 4. "Reconnect" is simulated by simply re-issuing the same kind of
    //    operation against the (unchanged, still-Revoked) session record —
    //    a transport reconnect never mutates session status, so this is
    //    exactly what a reconnect-then-retry looks like from the policy
    //    engine's point of view.
    let retry = OperationRequest {
        operation_id: OperationId::new(),
        requested_at: clock.now(),
        ..op
    };
    let decision = engine.evaluate(&retry, &session, &workspace, &clock);
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::SessionRevoked
        }
    );

    // 5. The revoked session cannot be resurrected by any further event.
    let resurrect_attempt = session.transition(SessionEvent::TransportConnected, &clock);
    assert!(resurrect_attempt.is_err());
}

#[test]
fn expiration_then_clock_advance_then_operation_denied() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);

    let session = new_unpaired_session(
        DeviceId::new(),
        "agent:test".into(),
        BTreeSet::from([workspace.workspace_id]),
        CapabilityProfile::Inspect,
        "read schematic".into(),
        time::Duration::minutes(30),
        &clock,
    );
    let session = session.transition(SessionEvent::Pair, &clock).unwrap();
    let session = session
        .transition(SessionEvent::TransportConnected, &clock)
        .unwrap();
    let session = session
        .transition(SessionEvent::RequestAccess, &clock)
        .unwrap();
    let session = session.transition(SessionEvent::Approve, &clock).unwrap();

    let engine = PolicyEngine::new(registry());
    let op = OperationRequest {
        operation_id: OperationId::new(),
        session_id: session.session_id,
        workspace_id: workspace.workspace_id,
        tool_name: "schematic.read".into(),
        arguments: Default::default(),
        target_path: None,
        requested_at: clock.now(),
    };
    assert!(matches!(
        engine.evaluate(&op, &session, &workspace, &clock),
        PolicyDecision::Allow { .. }
    ));

    clock.advance(time::Duration::hours(1));

    let decision = engine.evaluate(&op, &session, &workspace, &clock);
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::SessionExpired
        }
    );
}
