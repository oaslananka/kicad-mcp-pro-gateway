use companion_policy::{
    ArgumentValueKind, BreadthDimension, CollectionItemKind, EffectVerificationRequirement,
    OperationEffect, TomlToolRegistry, ToolCapabilityResolver, ToolCatalogSnapshot,
    UpstreamEffectManifest, UpstreamEffectManifestError,
};

const FIXTURE: &str = include_str!("fixtures/tool-effect-manifest-v2.json");

fn fixture_value() -> serde_json::Value {
    serde_json::from_str(FIXTURE).unwrap()
}

fn tool_mut<'a>(value: &'a mut serde_json::Value, name: &str) -> &'a mut serde_json::Value {
    value["tools"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|tool| tool["name"] == name)
        .unwrap()
}

#[test]
fn released_upstream_fixture_parses_strictly() {
    let manifest = UpstreamEffectManifest::from_json_str(FIXTURE).unwrap();

    assert_eq!(manifest.schema_version(), "2.0.0");
    assert_eq!(manifest.source().version, "4.0.0");
    assert_eq!(
        manifest.source().reviewed_source_sha,
        "66c0cd2750b8d79d717ece5299ec8da995f775cd"
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

    let delete = manifest.tool("pcb_delete_items").unwrap();
    let item_ids = delete.argument_shape("item_ids").unwrap();
    assert_eq!(item_ids.argument(), "item_ids");
    assert_eq!(item_ids.value_kind(), ArgumentValueKind::Collection);
    assert_eq!(item_ids.item_kind(), Some(CollectionItemKind::String));
    assert_eq!(
        item_ids.breadth_dimension(),
        Some(BreadthDimension::ItemCount)
    );

    let project = manifest.tool("kicad_create_new_project").unwrap();
    let overwrite = project.argument_shape("confirm_overwrite").unwrap();
    assert_eq!(overwrite.value_kind(), ArgumentValueKind::Boolean);
    assert_eq!(overwrite.item_kind(), None);
    assert_eq!(overwrite.breadth_dimension(), None);
}

#[test]
fn released_manifest_source_matches_the_embedded_reviewed_snapshot() {
    let manifest = UpstreamEffectManifest::from_json_str(FIXTURE).unwrap();
    let snapshot = ToolCatalogSnapshot::embedded();

    manifest.validate_source(&snapshot).unwrap();
    assert_eq!(
        snapshot.source_sha,
        "66c0cd2750b8d79d717ece5299ec8da995f775cd"
    );
    assert_eq!(snapshot.len(), 387);
}

#[test]
fn stale_manifest_source_still_fails_closed() {
    let mut value = fixture_value();
    value["source"]["reviewed_source_sha"] =
        serde_json::json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let manifest =
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()).unwrap();
    let snapshot = ToolCatalogSnapshot::embedded();

    assert!(matches!(
        manifest.validate_source(&snapshot),
        Err(UpstreamEffectManifestError::StaleSource {
            field: "reviewed_source_sha",
            ..
        })
    ));
}

#[test]
fn released_manifest_reconciles_exactly_with_the_reviewed_fallback_and_risk_facts() {
    let manifest = UpstreamEffectManifest::from_json_str(FIXTURE).unwrap();
    let registry = TomlToolRegistry::try_embedded().unwrap();

    let report = manifest.reconcile_with_fallback(&registry).unwrap();
    assert!(report.is_exact_match(), "{report:?}");
    assert!(report.risk_fact_mismatches.is_empty());

    let upstream = manifest.tool("export_gerber").unwrap().contract();
    let fallback = registry.effect_contract("export_gerber").unwrap();
    assert_eq!(upstream, fallback);
    assert!(!fallback.arguments().contains("variant_name"));
}

#[test]
fn legacy_v1_and_unknown_future_schema_majors_fail_closed() {
    for version in ["1.0.0", "3.0.0"] {
        let mut value = fixture_value();
        value["schemaVersion"] = serde_json::json!(version);

        assert!(matches!(
            UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
            Err(UpstreamEffectManifestError::UnsupportedSchemaVersion(actual)) if actual == version
        ));
    }
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
    let project = tool_mut(&mut value, "kicad_create_new_project");
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
fn malformed_collection_shape_fails_closed() {
    let mut value = fixture_value();
    let delete = tool_mut(&mut value, "pcb_delete_items");
    delete["argument_shapes"][0]
        .as_object_mut()
        .unwrap()
        .remove("item_kind");

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::InvalidArgumentShape { .. })
    ));
}

#[test]
fn scalar_shape_cannot_smuggle_collection_only_metadata() {
    let mut value = fixture_value();
    let project = tool_mut(&mut value, "kicad_create_new_project");
    project["argument_shapes"][0]["breadth_dimension"] = serde_json::json!("item_count");

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::InvalidArgumentShape { .. })
    ));
}

#[test]
fn duplicate_argument_shape_fails_closed() {
    let mut value = fixture_value();
    let delete = tool_mut(&mut value, "pcb_delete_items");
    let duplicate = delete["argument_shapes"][0].clone();
    delete["argument_shapes"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);

    assert!(matches!(
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()),
        Err(UpstreamEffectManifestError::DuplicateFact {
            field: "argument shapes",
            ..
        })
    ));
}

#[test]
fn breadth_dimension_drift_is_visible_in_reconciliation() {
    let mut value = fixture_value();
    let delete = tool_mut(&mut value, "pcb_delete_items");
    delete["argument_shapes"][0]["breadth_dimension"] = serde_json::json!("path_count");

    let manifest =
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()).unwrap();
    let registry = TomlToolRegistry::try_embedded().unwrap();
    let report = manifest.reconcile_with_fallback(&registry).unwrap();

    assert!(!report.is_exact_match());
    assert_eq!(
        report.risk_fact_mismatches,
        vec!["pcb_delete_items.item_ids".to_string()]
    );
}

#[test]
fn boolean_shape_drift_is_visible_in_reconciliation() {
    let mut value = fixture_value();
    let project = tool_mut(&mut value, "kicad_create_new_project");
    project["argument_shapes"][0]["value_kind"] = serde_json::json!("string");

    let manifest =
        UpstreamEffectManifest::from_json_str(&serde_json::to_string(&value).unwrap()).unwrap();
    let registry = TomlToolRegistry::try_embedded().unwrap();
    let report = manifest.reconcile_with_fallback(&registry).unwrap();

    assert!(!report.is_exact_match());
    assert_eq!(
        report.risk_fact_mismatches,
        vec!["kicad_create_new_project.confirm_overwrite".to_string()]
    );
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
