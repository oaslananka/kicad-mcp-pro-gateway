use companion_core_bridge::{
    CoreBridgeClient, CoreBridgeConfig, CoreBridgeError, MockMcpServer, ToolCallBehavior,
};
use serde_json::json;

#[tokio::test]
async fn initialize_succeeds_against_the_mock_server() {
    let server = MockMcpServer::start().await;
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();

    let result = client.initialize("corr-1").await.unwrap();
    assert_eq!(result["serverInfo"]["name"], "mock-kicad-mcp-pro");

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
    // Loopback but nothing listening: connection should be refused quickly.
    let client = CoreBridgeClient::new(CoreBridgeConfig::new(
        url::Url::parse("http://127.0.0.1:1").unwrap(),
    ))
    .unwrap();

    let result = client.initialize("corr-6").await;
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
