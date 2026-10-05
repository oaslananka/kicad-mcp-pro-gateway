use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("daemon crate must live under apps/daemon")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    fs::read_to_string(repository_root().join(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

#[test]
fn root_router_declares_all_agent_boundaries() {
    let root = read("AGENTS.md");

    for path in [
        "apps/daemon/AGENTS.md",
        "apps/desktop/AGENTS.md",
        "crates/AGENTS.md",
        "crates/policy/AGENTS.md",
        "crates/core-bridge/AGENTS.md",
        ".github/AGENTS.md",
    ] {
        assert!(root.contains(path), "root router must declare {path}");
        assert!(
            repository_root().join(path).is_file(),
            "nested instruction file must exist: {path}"
        );
    }

    for marker in [
        "Transport is not authorization",
        "OperationRequest.target_path",
        "durable pre-execution audit",
        "loopback-only",
        "green workflow",
    ] {
        assert!(
            root.contains(marker),
            "root router is missing critical marker: {marker}"
        );
    }
}

#[test]
fn security_boundaries_keep_their_core_invariants() {
    let daemon = read("apps/daemon/AGENTS.md");
    for marker in [
        "single authoritative local runtime",
        "Transport connectivity is not authority",
        "access_grants",
        "Audit is a gate",
        "replay",
    ] {
        assert!(\n            daemon.contains(marker),\n            "daemon instructions missing: {marker}"\n        );
    }

    let crates = read("crates/AGENTS.md");
    for marker in [
        "SecretStore",
        "plaintext files",
        "SQLite",
        "transport",
        "core-bridge",
    ] {
        assert!(\n            crates.contains(marker),\n            "crate instructions missing: {marker}"\n        );
    }

    let policy = read("crates/policy/AGENTS.md");
    for marker in [
        "authorization grant",
        "target_path",
        "NormalizedOperationEffects",
        "Static reviewed risk is a floor",
        "fail closed",
    ] {
        assert!(\n            policy.contains(marker),\n            "policy instructions missing: {marker}"\n        );
    }

    let bridge = read("crates/core-bridge/AGENTS.md");
    for marker in [
        "loopback-only",
        "general HTTP/MCP proxy",
        "2026-07-28",
        "2025-11-25",
        "Tasks/Apps",
    ] {
        assert!(\n            bridge.contains(marker),\n            "bridge instructions missing: {marker}"\n        );
    }
}

#[test]
fn desktop_and_ci_instructions_preserve_packaging_and_evidence_rules() {
    let desktop = read("apps/desktop/AGENTS.md");
    for marker in [
        "packaged sidecar",
        "Do not search `PATH`",
        "vendor/compat",
        "glib 0.18",
        "Secure=true",
    ] {
        assert!(
            desktop.contains(marker),
            "desktop instructions missing: {marker}"
        );
    }

    let github = read(".github/AGENTS.md");
    for marker in [
        "full commit SHAs",
        "false-green",
        "zero live tests",
        "SPDX SBOM",
        "human release-owner promotion",
    ] {
        assert!(
            github.contains(marker),
            "GitHub instructions missing: {marker}"
        );
    }
}
