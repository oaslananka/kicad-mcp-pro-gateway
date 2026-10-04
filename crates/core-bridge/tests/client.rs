use companion_core_bridge::{
    CoreBridgeClient, CoreBridgeConfig, CoreBridgeError, MockMcpServer, ProtocolLane,
    ToolCallBehavior, FINAL_MCP_PROTOCOL_VERSION, LEGACY_MCP_PROTOCOL_VERSION,
};
use serde_json::json;

#[tokio::test]
async fn final_lane_connects_with_stateless_discovery_and_per_request_metadata() {
    let server = MockMcpServer::start().await;
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    let discovered = client.connect("corr-discover").await.unwrap();
    assert_eq!(
        discovered["supportedVersions"][0],
        FINAL_MCP_PROTOCOL_VERSION
    );

    let tools = client.list_tools("corr-list").await.unwrap();
    assert!(tools.iter().any(|t| t.name == "schematic.read"));

    client
        .call_tool("schematic.read", json!({}), "corr-call")
        .await
        .unwrap();

    let requests = server.requests();
    assert_eq!(requests.len(), 3);

    let discovery = &requests[0];
    assert_eq!(discovery.body["method"], "server/discover");
    assert_eq!(
        discovery
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str),
        Some(FINAL_MCP_PROTOCOL_VERSION)
    );
    assert_eq!(
        discovery.headers.get("mcp-method").map(String::as_str),
        Some("server/discover")
    );
    assert!(!discovery.headers.contains_key("mcp-session-id"));
    assert_eq!(
        discovery.body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        FINAL_MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        discovery.body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
        "kicad-mcp-pro-gateway"
    );
    assert_eq!(
        discovery.body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );

    let listed = &requests[1];
    assert_eq!(listed.body["method"], "tools/list");
    assert_eq!(
        listed.headers.get("mcp-method").map(String::as_str),
        Some("tools/list")
    );
    assert!(!listed.headers.contains_key("mcp-name"));
    assert!(
        !listed.headers.contains_key("mcp-session-id"),
        "final lane must ignore an unexpected session header from discovery"
    );
    assert_eq!(
        listed.body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        FINAL_MCP_PROTOCOL_VERSION
    );

    let called = &requests[2];
    assert_eq!(called.body["method"], "tools/call");
    assert_eq!(
        called.headers.get("mcp-method").map(String::as_str),
        Some("tools/call")
    );
    assert_eq!(
        called.headers.get("mcp-name").map(String::as_str),
        Some("schematic.read")
    );
    assert!(!called.headers.contains_key("mcp-session-id"));
    assert_eq!(
        called.body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        FINAL_MCP_PROTOCOL_VERSION
    );

    server.stop();
}

#[tokio::test]
async fn legacy_lane_is_explicit_and_preserves_initialize_session_semantics() {
    let server = MockMcpServer::start().await;
    let config =
        CoreBridgeConfig::new(server.endpoint()).with_protocol_lane(ProtocolLane::Legacy2025);
    let client = CoreBridgeClient::new(config).unwrap();

    let initialized = client.connect("corr-legacy-init").await.unwrap();
    assert_eq!(initialized["protocolVersion"], LEGACY_MCP_PROTOCOL_VERSION);

    client.list_tools("corr-legacy-list").await.unwrap();

    let requests = server.requests();
    assert_eq!(requests.len(), 2);

    let initialize = &requests[0];
    assert_eq!(initialize.body["method"], "initialize");
    assert_eq!(
        initialize.body["params"]["protocolVersion"],
        LEGACY_MCP_PROTOCOL_VERSION
    );
    assert!(initialize.body["params"].get("_meta").is_none());
    assert_eq!(
        initialize
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str),
        Some(LEGACY_MCP_PROTOCOL_VERSION)
    );
    assert!(!initialize.headers.contains_key("mcp-method"));
    assert!(!initialize.headers.contains_key("mcp-session-id"));

    let listed = &requests[1];
    assert_eq!(listed.body["method"], "tools/list");
    assert_eq!(
        listed.headers.get("mcp-session-id").map(String::as_str),
        Some("mock-session")
    );
    assert!(listed.body["params"].get("_meta").is_none());

    server.stop();
}

#[tokio::test]
async fn initialize_is_rejected_on_the_final_lane_before_network_io() {
    let server = MockMcpServer::start().await;
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    let result = client.initialize("corr-invalid-init").await;
    assert!(
        matches!(result, Err(CoreBridgeError::ProtocolError(_))),
        "{result:?}"
    );
    assert!(server.requests().is_empty());

    server.stop();
}

#[tokio::test]
async fn list_tools_returns_the_mock_servers_tool_list() {
    let server = MockMcpServer::start().await;
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    let tools = client.list_tools("corr-2").await.unwrap();
    assert!(tools.iter().any(|t| t.name == "schematic.read"));

    server.stop();
}

#[tokio::test]
async fn call_tool_returns_the_configured_success_result() {
    let server = MockMcpServer::start().await;
    server.set_tool_call_behavior(ToolCallBehavior::Success(
        json!({ "content": [{ "type": "text", "text": "ok" }] }),
    ));
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    let result = client
        .call_tool("schematic.read", json!({}), "corr-3")
        .await
        .unwrap();
    assert_eq!(result["content"][0]["text"], "ok");
    assert_eq!(server.tool_call_count(), 1);

    server.stop();
}

#[tokio::test]
async fn call_tool_maps_a_json_rpc_error_to_a_typed_tool_error() {
    let server = MockMcpServer::start().await;
    server.set_tool_call_behavior(ToolCallBehavior::Error {
        code: -32000,
        message: "workspace locked".into(),
    });
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    let result = client
        .call_tool("schematic.add_symbol", json!({}), "corr-4")
        .await;
    match result {
        Err(CoreBridgeError::ToolError { code, message }) => {
            assert_eq!(code, Some(-32000));
            assert_eq!(message, "workspace locked");
        }
        other => panic!("expected ToolError, got {other:?}"),
    }

    server.stop();
}

#[tokio::test]
async fn call_tool_times_out_against_a_hanging_server_rather_than_blocking_forever() {
    let server = MockMcpServer::start().await;
    server.set_tool_call_behavior(ToolCallBehavior::Hang);
    let mut config = CoreBridgeConfig::new(server.endpoint());
    config.timeout = std::time::Duration::from_millis(200);
    let client = CoreBridgeClient::new(config).unwrap();

    let result = client
        .call_tool("schematic.read", json!({}), "corr-5")
        .await;
    assert!(
        matches!(result, Err(CoreBridgeError::Timeout)),
        "{result:?}"
    );

    server.stop();
}

#[tokio::test]
async fn unreachable_endpoint_is_a_typed_error_not_a_hang() {
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(
        url::Url::parse("http://127.0.0.1:1").unwrap(),
    ))
    .unwrap();

    let result = client.connect("corr-6").await;
    assert!(
        matches!(result, Err(CoreBridgeError::Unreachable(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn non_loopback_endpoint_is_rejected_before_any_network_call() {
    let result = CoreBridgeClient::new(CoreBridgeConfig::new(
        url::Url::parse("http://example.com/mcp").unwrap(),
    ));
    assert!(matches!(
        result,
        Err(CoreBridgeError::EndpointNotAllowed { .. })
    ));
}
