use std::process::Command;

use companion_policy::ToolCatalogSnapshot;

#[test]
fn reconcile_command_writes_snapshot_and_reports_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("tools-reference.generated.md");
    let output = dir.path().join("snapshot.toml");
    std::fs::write(
        &source,
        r#"Total public tools: 2.

| Tool | Profile(s) |
|---|---|
| `sch_add_symbol` | full |
| `new_upstream_tool` | full |
"#,
    )
    .unwrap();

    let result = Command::new(
        std::env::var("CARGO_BIN_EXE_reconcile-tool-registry")
            .expect("reconcile binary path is available"),
    )
    .arg(&source)
    .arg("abc123")
    .arg(&output)
    .output()
    .unwrap();

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("catalog=2"));
    assert!(stdout.contains("classified=1"));
    assert!(stdout.contains("unclassified=1"));
    let snapshot_text = std::fs::read_to_string(&output).unwrap();
    let snapshot = ToolCatalogSnapshot::from_toml_str(&snapshot_text).unwrap();
    assert_eq!(snapshot.source_repository, "oaslananka/kicad-mcp-pro");
    assert_eq!(snapshot.source_ref, "main");
    assert_eq!(snapshot.source_sha, "abc123");
    assert_eq!(
        snapshot.tool_names(),
        &["new_upstream_tool", "sch_add_symbol"]
    );
}
