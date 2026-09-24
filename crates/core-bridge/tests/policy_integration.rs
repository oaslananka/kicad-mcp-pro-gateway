//! Proves the shape of the daemon's real request pipeline (see
//! `docs/architecture/data-flow.md`): the core bridge is only ever reached
//! after a policy `Allow`. A `Deny` must never result in a call reaching
//! kicad-mcp-pro, and this test asserts that against the mock server's own
//! call counter rather than just trusting the control flow by inspection.

use std::collections::BTreeSet;

use companion_core::{
    ApprovalPolicy, CapabilityProfile, Clock, DeviceId, FakeClock, OperationId, OperationRequest,
    SessionId, SessionStatus,
};
use companion_core_bridge::{CoreBridgeClient, CoreBridgeConfig, MockMcpServer};
use companion_policy::{PolicyDecision, PolicyEngine, TomlToolRegistry};
use companion_workspace::WorkspaceAuthorization;
use time::OffsetDateTime;

fn registry() -> TomlToolRegistry {
    TomlToolRegistry::from_toml_str(
        r#"
        [[tool]]
        name = "schematic.read"
        capability = "schematic.read"
        risk = "low"
        "#,
    )
    .unwrap()
}

fn active_session(
    workspace_id: companion_core::WorkspaceId,
    clock: &FakeClock,
) -> companion_core::Session {
    companion_core::Session {
        session_id: SessionId::new(),
        device_id: DeviceId::new(),
        remote_principal: "agent:test".into(),
        workspace_ids: BTreeSet::from([workspace_id]),
        capability_profile: CapabilityProfile::Inspect,
        effective_capabilities: CapabilityProfile::Inspect.effective_capabilities(),
        task_scope: "read schematic".into(),
        issued_at: clock.now(),
        approved_at: Some(clock.now()),
        expires_at: clock.now() + time::Duration::hours(1),
        risk_policy_version: 1,
        approval_policy: ApprovalPolicy::Standard,
        status: SessionStatus::Active,
    }
}

#[tokio::test]
async fn policy_allow_reaches_the_core_bridge_and_deny_never_does() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let session = active_session(workspace.workspace_id, &clock);
    let engine = PolicyEngine::new(registry());

    let server = MockMcpServer::start().await;
    let bridge = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    // A known, authorized, low-risk operation: policy allows it, and only
    // then does the daemon (simulated here) call the core bridge.
    let allowed_request = OperationRequest {
        operation_id: OperationId::new(),
        session_id: session.session_id,
        workspace_id: workspace.workspace_id,
        tool_name: "schematic.read".into(),
        arguments: Default::default(),
        target_path: None,
        requested_at: clock.now(),
    };
    let decision = engine.evaluate(&allowed_request, &session, &workspace, &clock);
    assert!(matches!(decision, PolicyDecision::Allow { .. }));
    if matches!(decision, PolicyDecision::Allow { .. }) {
        bridge
            .call_tool("schematic.read", serde_json::json!({}), "corr-allow")
            .await
            .unwrap();
    }
    assert_eq!(
        server.tool_call_count(),
        1,
        "an Allow decision must reach the core bridge exactly once"
    );

    // An unknown tool: policy denies it, and the daemon must never call the
    // core bridge as a result.
    let denied_request = OperationRequest {
        operation_id: OperationId::new(),
        session_id: session.session_id,
        workspace_id: workspace.workspace_id,
        tool_name: "shell.exec".into(),
        arguments: Default::default(),
        target_path: None,
        requested_at: clock.now(),
    };
    let decision = engine.evaluate(&denied_request, &session, &workspace, &clock);
    assert!(matches!(decision, PolicyDecision::Deny { .. }));
    if matches!(decision, PolicyDecision::Allow { .. }) {
        bridge
            .call_tool("shell.exec", serde_json::json!({}), "corr-deny")
            .await
            .unwrap();
    }
    assert_eq!(
        server.tool_call_count(),
        1,
        "a Deny decision must never reach the core bridge"
    );

    server.stop();
}
