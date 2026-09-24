use std::collections::BTreeSet;
use std::path::Path;

use companion_core::{
    ApprovalPolicy, Capability, CapabilityProfile, Clock, DeviceId, FakeClock, OperationId,
    OperationRequest, RiskLevel, Session, SessionId, SessionStatus, WorkspaceId,
};
use companion_policy::{
    ApprovalReason, DenyReason, PolicyDecision, PolicyEngine, TomlToolRegistry,
};
use companion_workspace::WorkspaceAuthorization;
use time::OffsetDateTime;

fn registry() -> TomlToolRegistry {
    TomlToolRegistry::from_toml_str(
        r#"
        [[tool]]
        name = "schematic.read"
        capability = "schematic.read"
        risk = "low"

        [[tool]]
        name = "schematic.add_symbol"
        capability = "schematic.write"
        risk = "normal"

        [[tool]]
        name = "manufacturing.export_gerber"
        capability = "manufacturing.export"
        risk = "high"
        "#,
    )
    .unwrap()
}

fn workspace(dir: &Path) -> WorkspaceAuthorization {
    WorkspaceAuthorization::new("proj".into(), dir).unwrap()
}

fn active_session(
    workspace_id: WorkspaceId,
    profile: CapabilityProfile,
    clock: &FakeClock,
) -> Session {
    let mut workspace_ids = BTreeSet::new();
    workspace_ids.insert(workspace_id);
    Session {
        session_id: SessionId::new(),
        device_id: DeviceId::new(),
        remote_principal: "agent:test".into(),
        workspace_ids,
        effective_capabilities: profile.effective_capabilities(),
        capability_profile: profile,
        task_scope: "test task".into(),
        issued_at: clock.now(),
        approved_at: Some(clock.now()),
        expires_at: clock.now() + time::Duration::hours(1),
        risk_policy_version: 1,
        approval_policy: ApprovalPolicy::Standard,
        status: SessionStatus::Active,
    }
}

fn request(workspace_id: WorkspaceId, tool_name: &str) -> OperationRequest {
    OperationRequest {
        operation_id: OperationId::new(),
        session_id: SessionId::new(),
        workspace_id,
        tool_name: tool_name.to_string(),
        arguments: Default::default(),
        target_path: None,
        requested_at: OffsetDateTime::UNIX_EPOCH,
    }
}

#[test]
fn denies_when_session_not_active() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let mut session = active_session(ws.workspace_id, CapabilityProfile::Inspect, &clock);
    session.status = SessionStatus::Connected;
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "schematic.read"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::SessionNotActive
        }
    );
}

#[test]
fn denies_when_session_expired() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Inspect, &clock);
    clock.advance(time::Duration::hours(2)); // past expires_at
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "schematic.read"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::SessionExpired
        }
    );
}

#[test]
fn denies_when_session_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let mut session = active_session(ws.workspace_id, CapabilityProfile::Inspect, &clock);
    session.status = SessionStatus::Revoked;
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "schematic.read"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::SessionRevoked
        }
    );
}

#[test]
fn denies_when_workspace_not_in_session_workspace_ids() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let mut session = active_session(ws.workspace_id, CapabilityProfile::Inspect, &clock);
    session.workspace_ids = BTreeSet::from([WorkspaceId::new()]); // a different workspace
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "schematic.read"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::WorkspaceNotAuthorized
        }
    );
}

#[test]
fn denies_when_path_escapes_workspace() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("project");
    let evil = parent.path().join("project-evil");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evil).unwrap();
    let ws = workspace(&root);
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Inspect, &clock);
    let mut req = request(ws.workspace_id, "schematic.read");
    req.target_path = Some(evil.join("file.kicad_sch"));
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(&req, &session, &ws, &clock);
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::PathEscapesWorkspace
        }
    );
}

#[test]
fn denies_unknown_tool_with_no_fallback_allow() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Manufacturing, &clock);
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "shell.exec"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::UnknownTool
        }
    );
}

#[test]
fn denies_when_capability_not_in_effective_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Inspect, &clock);
    let engine = PolicyEngine::new(registry());

    // Inspect does not include schematic.write.
    let decision = engine.evaluate(
        &request(ws.workspace_id, "schematic.add_symbol"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::CapabilityNotGranted
        }
    );
}

#[test]
fn requires_approval_for_high_risk_operation_even_with_capability_granted() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Manufacturing, &clock);
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "manufacturing.export_gerber"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::RequireApproval {
            reason: ApprovalReason::HighRiskOperation,
            risk: RiskLevel::High,
            capability: Capability::MANUFACTURING_EXPORT,
        }
    );
}

#[test]
fn allows_low_risk_known_tool_within_authorized_workspace_with_capability() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Inspect, &clock);
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "schematic.read"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Allow {
            capability: Capability::SCHEMATIC_READ,
            risk: RiskLevel::Low
        }
    );
}

#[test]
fn manufacturing_capability_is_never_implied_by_design_profile() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Design, &clock);
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(
        &request(ws.workspace_id, "manufacturing.export_gerber"),
        &session,
        &ws,
        &clock,
    );
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::CapabilityNotGranted
        }
    );
}

#[test]
fn malformed_request_with_empty_tool_name_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let ws = workspace(dir.path());
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(ws.workspace_id, CapabilityProfile::Manufacturing, &clock);
    let engine = PolicyEngine::new(registry());

    let decision = engine.evaluate(&request(ws.workspace_id, "   "), &session, &ws, &clock);
    assert_eq!(
        decision,
        PolicyDecision::Deny {
            reason: DenyReason::MalformedRequest
        }
    );
}
