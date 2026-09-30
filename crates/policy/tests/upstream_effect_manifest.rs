use companion_policy::{
    EffectVerificationRequirement, OperationEffect, TomlToolRegistry, ToolCapabilityResolver,
    ToolCatalogSnapshot, UpstreamEffectManifest, UpstreamEffectManifestError,
};

const FIXTURE: &str = include_str!("fixtures/tool-effect-manifest-v1.json");

fn fixture_value() -> serde_json::Value {
    serde_json::from_str(FIXTURE).unwrap()
}

#[test]
fn upstream_fixture_parses_strictly() {
    let manifest = UpstreamEffectManifest::from_json_str(FIXTURE).unwrap();

    assert_eq!(manifest.schema_version(), "1.0.0");
    assert_eq!(manifest.source().version, "3.35.2");
    assert_eq!(
        manifest.source().reviewed_source_sha,
        "e460e28a4dd0f2c105a1d2db3e26eb731769c543"
    );
    assert_eq!(manifest.tool_names().count(), 6);

    let read = manifest.tool("sch_get_symbols").unwrap();
    assert_eq!(
        read.contract().effects(),
        &std::collections::BTreeSet::from([OperationEffect::Read])
    );
    assert!(!read.destructive());
    assert!(read.idempotent());
    assert!(read
        .verification_requirements()
        .contains(&EffectVerificationRequirement::SourceReview));
}

#[test]
fn current_upstream_fixture_is_detected_as_stale_against_the_embedded_fallback_snapshot() {
    let manifest = UpstreamEffectManifest::from_json_str(FIXTURE).unwrap();
    let snapshot = ToolCatalogSnapshot::embedded();

    let error = manifest.validate_source(&snapshot).unwrap_err();
    assert!(matches!(
        error,
        UpstreamEffectManifestError::StaleSource {
            field: "reviewed_source_sha",
            ..
        }
    ));
}

#[test]
fn reconciliation_exposes_the_real_export_gerber_argument_drift() {
    let manifest = UpstreamEffectManifest::from_json_str(FIXTURE).unwrap();
    let registry = TomlToolRegistry::try_embedded().unwrap();

    let report = manifest.reconcile_with_fallback(&registry).unwrap();
    assert!(report.fallback_only_reviewed.is_empty());
    assert!(report.upstream_only_reviewed.is_empty());
    assert_eq!(report.contract_mismatches, vec!["export_gerber"]);

    let upstream = manifest.tool("export_gerber").unwrap().contract();
    let fallback = registry.effect_contract("export_gerber").unwrap();
    assert!(!upstream.arguments().contains("variant_name"));
    assert!(fallback.arguments().contains("variant_name"));
}

#[test]
fn unknown_schema_major_fails_closed() {
    let mut value = fixture_value();
    value["schemaVersion"] = serde_json::json!("2.0.0");

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::UnsupportedSchemaVersion(_))
    ));
}

#[test]
fn unknown_manifest_field_fails_closed() {
    let mut value = fixture_value();
    value["caller_policy"] = serde_json::json!({"allow": true});

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::MalformedJson(_))
    ));
}

#[test]
fn unknown_effect_fails_closed() {
    let mut value = fixture_value();
    value["tools"][0]["effects"] = serde_json::json!(["read", "chown"]);

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::MalformedJson(_))
    ));
}

#[test]
fn duplicate_tool_fails_closed() {
    let mut value = fixture_value();
    let duplicate = value["tools"][0].clone();
    value["tools"].as_array_mut().unwrap().push(duplicate);

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::DuplicateTool(_))
    ));
}

#[test]
fn malformed_path_dependency_fails_closed() {
    let mut value = fixture_value();
    let project = value["tools"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|tool| tool["name"] == "kicad_create_new_project")
        .unwrap();
    project["path_arguments"][1]["base_argument"] = serde_json::json!("missing");

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::InvalidEffectContract { .. })
    ));
}

#[test]
fn duplicate_effect_fact_fails_closed() {
    let mut value = fixture_value();
    value["tools"][0]["effects"] = serde_json::json!(["read", "read"]);

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::DuplicateFact {
            field: "effects",
            ..
        })
    ));
}

#[test]
fn unclassified_manifest_tool_cannot_be_promoted_by_reconciliation() {
    let mut value = fixture_value();
    let mut injected = value["tools"][0].clone();
    injected["name"] = serde_json::json!("shell_exec");
    injected["reviewed_source_paths"] = serde_json::json!(["src/kicad_mcp/tools/fake.py"]);
    value["tools"].as_array_mut().unwrap().push(injected);

    let manifest =
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()).unwrap();
    let registry = TomlToolRegistry::try_embedded().unwrap();

    assert_eq!(registry.resolve("shell_exec"), None);
    assert!(matches!(
        manifest.reconcile_with_fallback(&registry),
        Err(UpstreamEffectManifestError::UnclassifiedTool(tool)) if tool == "shell_exec"
    ));
}

#[test]
fn unsafe_review_source_path_fails_closed() {
    for path in [
        "../../outside/review.py",
        r"..\outside\review.py",
        "/tmp/review.py",
    ] {
        let mut value = fixture_value();
        value["tools"][0]["reviewed_source_paths"] = serde_json::json!([path]);

        assert!(matches!(
            UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
            Err(UpstreamEffectManifestError::InvalidReviewedSourcePath { .. })
        ));
    }
}
