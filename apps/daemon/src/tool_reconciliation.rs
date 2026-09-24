use std::collections::BTreeSet;

use companion_core_bridge::{CoreBridgeClient, CoreBridgeError};
use companion_policy::{TomlToolRegistry, ToolCatalogSnapshot, ToolRegistryCoverage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveToolReconciliation {
    pub registry_coverage: ToolRegistryCoverage,
    pub live_not_in_snapshot: Vec<String>,
    pub snapshot_not_live: Vec<String>,
}

/// Compares the live MCP `tools/list` surface with both the curated policy
/// allowlist and the SHA-pinned upstream snapshot. Discovery is observational
/// only: unknown tools remain denied by `TomlToolRegistry`.
pub async fn reconcile_live_tool_registry(
    core_bridge: &CoreBridgeClient,
    registry: &TomlToolRegistry,
    snapshot: &ToolCatalogSnapshot,
) -> Result<LiveToolReconciliation, CoreBridgeError> {
    core_bridge.initialize("registry-reconcile-init").await?;
    let tools = core_bridge.list_tools("registry-reconcile-list").await?;
    let live = tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<BTreeSet<_>>();
    let snapshot_tools = snapshot
        .tool_names()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let registry_coverage = registry.coverage_against_tool_names(live.iter());
    let live_not_in_snapshot = live.difference(&snapshot_tools).cloned().collect();
    let snapshot_not_live = snapshot_tools.difference(&live).cloned().collect();

    Ok(LiveToolReconciliation {
        registry_coverage,
        live_not_in_snapshot,
        snapshot_not_live,
    })
}
