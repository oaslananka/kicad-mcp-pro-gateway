use companion_core_bridge::{CoreBridgeClient, CoreBridgeConfig, MockMcpServer};
use companion_policy::{TomlToolRegistry, ToolCapabilityResolver, ToolCatalogSnapshot};
use kicad_mcp_gateway_daemon::tool_reconciliation::reconcile_live_tool_registry;

#[tokio::test]
async fn live_reconciliation_reports_unclassified_tools_without_authorizing_them() {
    let server = MockMcpServer::start().await;
    let bridge = CoreBridgeClient::new(CoreBridgeConfig::new(server.endpoint())).unwrap();
    let registry = TomlToolRegistry::from_toml_str(
        r#"
        [[tool]]
        name = "schematic.read"
        capability = "schematic.read"
        risk = "low"
        "#,
    )
    .unwrap();

    let snapshot = ToolCatalogSnapshot::from_tool_names(
        "oaslananka/kicad-mcp-pro",
        "main",
        "deadbeef",
        ["schematic.read", "snapshot_only"],
    );
    let report = reconcile_live_tool_registry(&bridge, &registry, &snapshot)
        .await
        .expect("mock MCP reconciliation succeeds");

    assert_eq!(report.registry_coverage.classified, vec!["schematic.read"]);
    assert_eq!(
        report.registry_coverage.unclassified,
        vec!["schematic.add_symbol"]
    );
    assert!(report.registry_coverage.stale.is_empty());
    assert_eq!(report.live_not_in_snapshot, vec!["schematic.add_symbol"]);
    assert_eq!(report.snapshot_not_live, vec!["snapshot_only"]);
    assert_eq!(registry.resolve("schematic.add_symbol"), None);
    server.stop();
}

#[tokio::test]
#[ignore = "requires a real kicad-mcp-pro HTTP server"]
async fn live_core_can_be_reconciled_without_granting_unknown_tools() {
    let endpoint = std::env::var("KICAD_MCP_LIVE_ENDPOINT")
        .expect("set KICAD_MCP_LIVE_ENDPOINT for the manual live probe");
    let bridge = CoreBridgeClient::new(CoreBridgeConfig::new(endpoint.parse().unwrap())).unwrap();
    let registry = TomlToolRegistry::embedded();

    let snapshot = ToolCatalogSnapshot::embedded();
    let report = reconcile_live_tool_registry(&bridge, &registry, &snapshot)
        .await
        .expect("live MCP reconciliation succeeds");

    println!(
        "live={} classified={} unclassified={} registry_not_live={} live_not_snapshot={} snapshot_not_live={}",
        report.registry_coverage.catalog_total,
        report.registry_coverage.classified.len(),
        report.registry_coverage.unclassified.len(),
        report.registry_coverage.stale.len(),
        report.live_not_in_snapshot.len(),
        report.snapshot_not_live.len()
    );
    assert_eq!(
        report.registry_coverage.classified.len() + report.registry_coverage.unclassified.len(),
        report.registry_coverage.catalog_total
    );
    for tool in &report.registry_coverage.unclassified {
        assert_eq!(
            registry.resolve(tool),
            None,
            "{tool} must remain fail-closed"
        );
    }
}
