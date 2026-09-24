use companion_policy::ToolCatalogSnapshot;

#[test]
fn generated_tools_reference_parser_extracts_public_tool_names_only() {
    let markdown = r#"
Machine-maintained catalog.

Total public tools: 2.

| Tool | Profile(s) | Read-Only |
|---|---|---:|
| `zeta_tool` | full | yes |
| `alpha_tool` | default, full | no |

Other text with `not_a_table_tool` must be ignored.
"#;

    let snapshot = ToolCatalogSnapshot::from_tools_reference_markdown(
        "oaslananka/kicad-mcp-pro",
        "main",
        "abc123",
        markdown,
    )
    .unwrap();

    assert_eq!(snapshot.tool_names(), &["alpha_tool", "zeta_tool"]);
    assert_eq!(snapshot.source_sha, "abc123");
}

#[test]
fn duplicate_tool_in_snapshot_is_rejected() {
    let result = ToolCatalogSnapshot::from_toml_str(
        r#"
source_repository = "oaslananka/kicad-mcp-pro"
source_ref = "main"
source_sha = "abc123"
tools = ["same_tool", "same_tool"]
"#,
    );

    assert!(result.is_err());
}

#[test]
fn duplicate_tool_in_generated_reference_is_rejected() {
    let markdown = r#"
| Tool | Profile(s) |
|---|---|
| `same_tool` | full |
| `same_tool` | default |
"#;

    let result = ToolCatalogSnapshot::from_tools_reference_markdown(
        "oaslananka/kicad-mcp-pro",
        "main",
        "abc123",
        markdown,
    );

    assert!(result.is_err());
}

#[test]
fn generated_reference_declared_count_must_match_parsed_rows() {
    let markdown = r#"
Total public tools: 2.

| Tool | Profile(s) |
|---|---|
| `only_one_tool` | full |
"#;

    let result = ToolCatalogSnapshot::from_tools_reference_markdown(
        "oaslananka/kicad-mcp-pro",
        "main",
        "abc123",
        markdown,
    );

    assert!(result.is_err());
}
