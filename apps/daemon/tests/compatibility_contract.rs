use companion_core_bridge::MCP_PROTOCOL_VERSION;
use companion_policy::ToolCatalogSnapshot;
use companion_protocol::PROTOCOL_VERSION;

const COMPATIBILITY_MATRIX: &str =
    include_str!("../../../docs/architecture/compatibility-matrix.md");

#[test]
fn canonical_compatibility_matrix_matches_runtime_and_policy_contracts() {
    let snapshot = ToolCatalogSnapshot::embedded();

    assert!(COMPATIBILITY_MATRIX.contains(&format!(
        "| **MCP core-bridge protocol** | `{MCP_PROTOCOL_VERSION}` |"
    )));
    assert!(COMPATIBILITY_MATRIX.contains(&format!(
        "| **Gateway transport protocol** | `{PROTOCOL_VERSION}` |"
    )));
    assert!(COMPATIBILITY_MATRIX.contains(&snapshot.source_sha));
    assert!(COMPATIBILITY_MATRIX.contains(&format!("{} tools", snapshot.len())));
}
