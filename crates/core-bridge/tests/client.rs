use companion_core_bridge::{
    CoreBridgeClient, CoreBridgeConfig, CoreBridgeError, McpProtocolLane, MockMcpServer,
    ToolCallBehavior, MCP_LEGACY_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION,
};
use serde_json::json;

#[tokio::test]
async fn final_lane_uses_direct_stateless_discovery_and_request_metadata() {
    let server = MockMcpServer::start().await;
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    let discovery = client.bootstrap("corr-discover").await.unwrap();
    assert_eq!(discovery["supportedVersions"], json!([MCP_PROTOCOL_VERSION]));
    assert_eq!(
        discovery["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "mock-kicad-mcp-pro"
    );

    let tools = client.list_tools("corr-list").await.unwrap();
    assert!(tools.iter().any(|t| t.name == "schematic.read"));
    client
        .call_tool("schematic.read", json!({}), "corr-call")
        .await
        .unwrap();

    let requests = server.requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>(),
        vec!["server/discover", "tools/list", "tools/call"]
    );
    for request in &requests {
        assert_eq!(
            request.header("MCP-Protocol-Version"),
            Some(MCP_PROTOCOL_VERSION)
        );
        assert_eq!(request.header("Mcp-Method"), Some(request.method.as_str()));
        assert_eq!(request.header("MCP-Session-Id"), None);
        assert_eq!(
            request.params["_meta"]["io.modelcontextprotocol/protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        assert_eq!(
            request.params["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
            "kicad-mcp-pro-gateway"
        );
        assert_eq!(
            request.params["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            json!({})
        );
    }
    assert_eq!(requests[0].header("Mcp-Name"), None);
    assert_eq!(requests[1].header("Mcp-Name"), None);
    assert_eq!(requests[2].header("Mcp-Name"), Some("schematic.read"));

    server.stop();
}

#[tokio::test]
async fn legacy_lane_is_explicit_and_echoes_the_legacy_session_id() {
    let server = MockMcpServer::start().await;
    let config =
        CoreBridgeConfig::new(server.endpoint()).with_protocol_lane(McpProtocolLane::Legacy2025);
    let client = CoreBridgeClient::new(config).unwrap();

    let result = client.bootstrap("corr-legacy-init").await.unwrap();
    assert_eq!(result["protocolVersion"], MCP_LEGACY_PROTOCOL_VERSION);
    client.list_tools("corr-legacy-list").await.unwrap();

    let requests = server.requests();
    assert_eq!(requests[0].method, "initialize");
    assert_eq!(
        requests[0].header("MCP-Protocol-Version"),
        Some(MCP_LEGACY_PROTOCOL_VERSION)
    );
    assert_eq!(requests[0].header("Mcp-Method"), None);
    assert_eq!(
        requests[0].params["protocolVersion"],
        MCP_LEGACY_PROTOCOL_VERSION
    );
    assert!(requests[0].params.get("_meta").is_none());

    assert_eq!(requests[1].method, "tools/list");
    assert_eq!(
        requests[1].header("MCP-Session-Id"),
        Some("mock-legacy-session")
    );
    assert_eq!(requests[1].header("Mcp-Method"), None);
    assert!(requests[1].params.get("_meta").is_none());

    server.stop();
}

#[tokio::test]
async fn initialize_api_does_not_put_legacy_initialize_on_the_final_wire() {
    let server = MockMcpServer::start().await;
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    client.initialize("corr-api-compat").await.unwrap();
    assert_eq!(server.requests()[0].method, "server/discover");

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

    let result = client.bootstrap("corr-6").await;
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
