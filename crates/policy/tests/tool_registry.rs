use companion_policy::{TomlToolRegistry, ToolCapabilityResolver, ToolCatalogSnapshot};

#[test]
fn embedded_tool_registry_is_valid() {
    let _registry = TomlToolRegistry::embedded();
}

#[test]
fn embedded_tool_registry_resolves_a_known_seed_entry() {
    let registry = TomlToolRegistry::embedded();
    assert!(registry.resolve("sch_add_symbol").is_some());
}

#[test]
fn embedded_tool_registry_classifies_manufacturing_export_as_high_risk() {
    let registry = TomlToolRegistry::embedded();
    let (capability, risk) = registry
        .resolve("export_gerber")
        .expect("export_gerber is a known tool");
    assert_eq!(capability, companion_core::Capability::MANUFACTURING_EXPORT);
    assert_eq!(risk, companion_core::RiskLevel::High);
}

#[test]
fn embedded_tool_registry_denies_unknown_tool() {
    let registry = TomlToolRegistry::embedded();
    assert_eq!(registry.resolve("shell.exec"), None);
}

#[test]
fn embedded_registry_classifies_conservative_read_only_batch() {
    use companion_core::{Capability, RiskLevel};

    let registry = TomlToolRegistry::embedded();
    let cases = [
        ("kicad_get_server_info", Capability::PROJECT_READ),
        ("kicad_get_tools_in_category", Capability::PROJECT_READ),
        ("kicad_get_version", Capability::PROJECT_READ),
        ("kicad_help", Capability::PROJECT_READ),
        ("kicad_list_tool_categories", Capability::PROJECT_READ),
        ("get_board_stats", Capability::PCB_READ),
        ("pcb_get_board_summary", Capability::PCB_READ),
        ("pcb_get_layers", Capability::PCB_READ),
        ("pcb_get_net_statistics", Capability::PCB_READ),
        ("pcb_get_pads", Capability::PCB_READ),
        ("pcb_get_stackup", Capability::PCB_READ),
        ("pcb_get_tracks", Capability::PCB_READ),
        ("pcb_get_vias", Capability::PCB_READ),
        ("pcb_get_zones", Capability::PCB_READ),
        ("sch_get_bounding_boxes", Capability::SCHEMATIC_READ),
        ("sch_get_connectivity_graph", Capability::SCHEMATIC_READ),
        ("sch_get_labels", Capability::SCHEMATIC_READ),
        ("sch_get_net_names", Capability::SCHEMATIC_READ),
        ("sch_get_population_status", Capability::SCHEMATIC_READ),
        ("sch_get_wires", Capability::SCHEMATIC_READ),
        ("drc_list_exclusions", Capability::VALIDATION_RUN),
        ("get_courtyard_violations", Capability::VALIDATION_RUN),
        ("get_silk_to_pad_violations", Capability::VALIDATION_RUN),
        ("get_unconnected_nets", Capability::VALIDATION_RUN),
        (
            "validate_footprints_vs_schematic",
            Capability::VALIDATION_RUN,
        ),
    ];

    for (tool, capability) in cases {
        assert_eq!(
            registry.resolve(tool),
            Some((capability, RiskLevel::Low)),
            "unexpected classification for {tool}"
        );
    }
}

#[test]
fn coverage_report_separates_classified_unclassified_and_stale_tools() {
    let registry = TomlToolRegistry::from_toml_str(
        r#"
        [[tool]]
        name = "known_tool"
        capability = "schematic.read"
        risk = "low"

        [[tool]]
        name = "stale_tool"
        capability = "schematic.read"
        risk = "low"
        "#,
    )
    .unwrap();
    let snapshot = ToolCatalogSnapshot::from_tool_names(
        "oaslananka/kicad-mcp-pro",
        "main",
        "deadbeef",
        ["known_tool", "new_tool"],
    );

    let report = registry.coverage_against(&snapshot);
    assert_eq!(report.classified, vec!["known_tool"]);
    assert_eq!(report.unclassified, vec!["new_tool"]);
    assert_eq!(report.stale, vec!["stale_tool"]);
    assert_eq!(report.catalog_total, 2);
    assert_eq!(report.registry_total, 2);
}

#[test]
fn embedded_registry_has_no_entries_missing_from_upstream_snapshot() {
    let registry = TomlToolRegistry::embedded();
    let snapshot = ToolCatalogSnapshot::embedded();
    let report = registry.coverage_against(&snapshot);
    assert!(
        report.stale.is_empty(),
        "stale registry entries: {:?}",
        report.stale
    );
}

#[test]
fn deliberately_excluded_discovery_tools_remain_fail_closed() {
    let registry = TomlToolRegistry::embedded();
    let snapshot = ToolCatalogSnapshot::embedded();

    for tool in [
        "kicad_list_recent_projects",
        "kicad_scan_directory",
        "lib_list_libraries",
        "lib_search_3d_models",
    ] {
        assert!(snapshot.contains(tool), "snapshot should contain {tool}");
        assert_eq!(registry.resolve(tool), None, "{tool} must remain denied");
    }
}

#[test]
fn complete_upstream_snapshot_disposition_policy_enforced() {
    let registry = TomlToolRegistry::embedded();
    let snapshot = ToolCatalogSnapshot::embedded();
    let report = registry.coverage_against(&snapshot);

    // Explicitly denied/deferred tools that must stay unclassified & fail-closed
    let expected_denied_deferred = [
        "jobset_run",
        "kicad_list_recent_projects",
        "kicad_scan_directory",
        "lib_list_libraries",
        "lib_search_3d_models",
        "mfg_import_allegro",
        "mfg_import_geda",
        "mfg_import_pads",
        "mfg_import_specctra",
        "pcb_import_board",
        "project_embed_file",
        "project_extract_embedded_file",
        "project_remove_embedded_file",
        "route_export_dsn",
        "route_import_ses",
    ];

    assert_eq!(
        report.unclassified,
        expected_denied_deferred,
        "Every unclassified tool in the upstream snapshot must match the explicit DENY/DEFER review list"
    );

    // Verify fail-closed behavior for all denied/deferred tools
    for tool in expected_denied_deferred {
        assert_eq!(
            registry.resolve(tool),
            None,
            "Tool {tool} must remain denied/unclassified"
        );
    }

    // Verify 100% snapshot disposition coverage (classified + explicitly denied)
    assert_eq!(
        report.classified.len() + expected_denied_deferred.len(),
        report.catalog_total,
        "100% of snapshot tools must have an explicit disposition"
    );

    // Verify stale registry entries count is zero
    assert!(
        report.stale.is_empty(),
        "Stale entries must be 0: {:?}",
        report.stale
    );
}
