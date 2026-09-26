//! Property/fuzz coverage for the tool-registry and effect-manifest parsers
//! in `companion-policy` (T6 in the threat model).
//!
//! These parsers are the authorization allowlist: whatever they hand back is
//! what the policy engine is allowed to grant. Every target below is therefore
//! written as a fail-closed property — an input that is not exactly a reviewed
//! declaration has to produce a load error, never a classification, and a
//! classification may only ever be one the source text actually declared.
//!
//! See `docs/development/testing.md` for the bounded CI lane and the longer
//! local fuzz lane.

use std::collections::BTreeSet;

use companion_core::{Capability, RiskLevel};
use companion_policy::{
    OperationEffect, TomlToolRegistry, ToolCapabilityResolver, ToolCatalogSnapshot,
    TOOL_EFFECT_CONTRACT_VERSION,
};
use proptest::prelude::*;

const REVIEWED_REGISTRY: &str = include_str!("../assets/tool_registry.toml");
const PINNED_CATALOG: &str = include_str!("../assets/upstream_tool_snapshot.toml");

/// The closed capability set, as it is written in a manifest.
fn capability_names() -> Vec<String> {
    Capability::ALL
        .iter()
        .map(|capability| capability.as_str().to_string())
        .collect()
}

/// The closed risk set, as it is written in a manifest.
fn risk_names() -> Vec<String> {
    vec![
        "low".to_string(),
        "normal".to_string(),
        "high".to_string(),
        "critical".to_string(),
    ]
}

/// The closed effect set, as it is written in a manifest.
const EFFECT_NAMES: [&str; 4] = ["read", "write", "create", "delete"];

/// Capability, risk, and effect spellings that have been tried against these
/// parsers, including near-misses that must not fuzzy-match a real one.
fn historical_classification_names() -> Vec<String> {
    [
        // Real spellings.
        "project.read",
        "schematic.write",
        "manufacturing.export",
        "workspace.read",
        "low",
        "normal",
        "high",
        "critical",
        "read",
        "write",
        "create",
        "delete",
        // Case, whitespace, and separator near-misses.
        "Project.Read",
        "PROJECT.READ",
        " project.read",
        "project.read ",
        "project..read",
        "project-read",
        "project.read.extra",
        "Low",
        "HIGH",
        "Read",
        "readwrite",
        "delete ",
        // Capabilities that are deliberately not modeled at all.
        "shell.exec",
        "filesystem.write",
        "manufacturing.write",
        "manufacturing.readwrite",
        "project.readwrite",
        "unknown.capability",
        "",
    ]
    .iter()
    .map(|name| (*name).to_string())
    .collect()
}

/// Manifest fragments that have shown up at this boundary: TOML that is not a
/// manifest, manifests with the wrong shape, and near-miss tool names.
fn historical_manifest_fragments() -> Vec<String> {
    [
        "",
        "\n",
        "[[tool]]",
        "[tool]",
        "tool = []",
        "contract_version = 1",
        "contract_version = 2",
        "source_repository = \"kicad-mcp-pro\"",
        "[[tool]]\nname = \"probe\"\ncapability = \"project.read\"\nrisk = \"low\"\n",
        // A capability that is not in the closed set.
        "[[tool]]\nname = \"probe\"\ncapability = \"shell.exec\"\nrisk = \"critical\"\n",
        // Required fields quietly defaulted.
        "[[tool]]\nname = \"probe\"\nrisk = \"low\"\n",
        "[[tool]]\nname = \"probe\"\ncapability = \"project.read\"\n",
        "[[tool]]\ncapability = \"project.read\"\nrisk = \"low\"\n",
        // The same tool twice.
        "[[tool]]\nname = \"probe\"\ncapability = \"project.read\"\nrisk = \"low\"\n\n[[tool]]\nname = \"probe\"\ncapability = \"project.write\"\nrisk = \"high\"\n",
        // Effects without the pinned source, and an effect name that is not in
        // the closed set.
        "[[tool]]\nname = \"probe\"\ncapability = \"project.write\"\nrisk = \"high\"\neffects = [\"write\"]\narguments = [\"paths\"]\n",
        "[[tool]]\nname = \"probe\"\ncapability = \"project.write\"\nrisk = \"high\"\neffects = [\"chown\"]\narguments = [\"paths\"]\n",
        // Effects declared with no arguments.
        "[[tool]]\nname = \"probe\"\ncapability = \"project.write\"\nrisk = \"high\"\neffects = [\"write\"]\n",
        // A misspelled field name, which `deny_unknown_fields` must reject
        // rather than ignore.
        "[[tool]]\nname = \"probe\"\ncapability = \"project.write\"\nrisk = \"high\"\neffects = [\"write\"]\narguments = [\"paths\"]\npath_argument = [{ \"argument\": \"paths\", \"effects\": [\"write\"] }]\n",
        // A tool name that only looks like a real one.
        "[[tool]]\nname = \"shell_exec\"\ncapability = \"project.read\"\nrisk = \"low\"\n",
        "[[tool]]\nname = \"export gerber\"\ncapability = \"project.read\"\nrisk = \"low\"\n",
        "[[tool]]\nname = \"\"\ncapability = \"project.read\"\nrisk = \"low\"\n",
    ]
    .iter()
    .map(|fragment| (*fragment).to_string())
    .collect()
}

/// A contract-source block that matches the pinned upstream snapshot, so the
/// source-pinning rules can be exercised without inventing a second upstream.
fn pinned_source_block() -> String {
    let snapshot = ToolCatalogSnapshot::embedded();
    format!(
        "contract_version = {TOOL_EFFECT_CONTRACT_VERSION}\n\
         source_repository = \"{}\"\n\
         source_ref = \"{}\"\n\
         source_sha = \"{}\"\n",
        snapshot.source_repository, snapshot.source_ref, snapshot.source_sha,
    )
}

/// Every tool a registry classifies, whether or not it is in the pinned
/// catalog. The registry has no "all names" accessor, and
/// `classified ∪ stale` is exactly that set.
fn classified_tool_names(
    registry: &TomlToolRegistry,
    snapshot: &ToolCatalogSnapshot,
) -> Vec<String> {
    let coverage = registry.coverage_against(snapshot);
    coverage
        .classified
        .into_iter()
        .chain(coverage.stale)
        .collect()
}

fn any_text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..2048)
            .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        prop::sample::select(historical_manifest_fragments()),
        "[ -~\n\t]{0,512}",
    ]
}

fn classification_name() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(historical_classification_names()),
        "[A-Za-z0-9._ -]{0,32}",
    ]
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics_a_manifest_parser(
        text in any_text(),
    ) {
        // Either answer is acceptable; a panic, a hang, or an unbounded
        // allocation is not. Whatever the answer, it has to be the same answer
        // every time: an allowlist load that depends on hash order or hidden
        // state would not be reviewable.
        prop_assert_eq!(
            TomlToolRegistry::from_toml_str(&text).is_ok(),
            TomlToolRegistry::from_toml_str(&text).is_ok(),
            "the same manifest text loaded differently on a second pass"
        );
        prop_assert_eq!(
            ToolCatalogSnapshot::from_toml_str(&text).is_ok(),
            ToolCatalogSnapshot::from_toml_str(&text).is_ok(),
            "the same catalog text loaded differently on a second pass"
        );
    }

    #[test]
    fn a_loaded_registry_only_ever_hands_out_a_classification_the_source_declared(
        text in any_text(),
    ) {
        let snapshot = ToolCatalogSnapshot::from_toml_str(PINNED_CATALOG)
            .expect("the pinned catalog is valid");

        let Ok(registry) = TomlToolRegistry::from_toml_str(&text) else {
            return Ok(());
        };

        for name in classified_tool_names(&registry, &snapshot) {
            let (capability, risk) = registry
                .resolve(&name)
                .expect("a classified tool resolves");
            prop_assert!(
                text.contains(capability.as_str()),
                "{name} resolved to capability {} that the source never declares",
                capability.as_str()
            );
            prop_assert!(
                text.contains(&risk_name(risk)),
                "{name} resolved to risk {} that the source never declares",
                risk_name(risk)
            );
        }
    }

    #[test]
    fn a_loaded_catalog_agrees_with_its_own_tool_list(
        text in any_text(),
    ) {
        let Ok(snapshot) = ToolCatalogSnapshot::from_toml_str(&text) else {
            return Ok(());
        };

        // `contains` is a binary search over a sorted list, so a sort or
        // ordering regression would silently start denying known tools (or
        // admitting unknown ones) for the wrong reason.
        let names = snapshot.tool_names();
        prop_assert!(
            names.windows(2).all(|pair| pair[0] < pair[1]),
            "the tool list must stay sorted and duplicate-free for contains() to be correct"
        );
        for name in names {
            prop_assert!(snapshot.contains(name));
        }
    }

    #[test]
    fn a_capability_outside_the_closed_set_is_always_a_load_error(
        capability in classification_name(),
        risk in prop::sample::select(risk_names()),
    ) {
        if Capability::parse(&capability).is_some() {
            return Ok(());
        }

        let source = format!(
            "[[tool]]\nname = \"probe.tool\"\ncapability = \"{capability}\"\nrisk = \"{risk}\"\n"
        );
        prop_assert!(
            TomlToolRegistry::from_toml_str(&source).is_err(),
            "capability {capability:?} is not in the closed set but loaded"
        );
    }

    #[test]
    fn every_capability_and_risk_in_the_closed_set_loads_exactly_as_written(
        capability in prop::sample::select(capability_names()),
        risk in prop::sample::select(risk_names()),
    ) {
        let source = format!(
            "[[tool]]\nname = \"probe.tool\"\ncapability = \"{capability}\"\nrisk = \"{risk}\"\n"
        );
        let registry = TomlToolRegistry::from_toml_str(&source)
            .expect("a closed-set capability and risk load");

        prop_assert_eq!(
            registry.resolve("probe.tool"),
            Some((Capability::parse(&capability).unwrap(), RiskLevel::parse(&risk).unwrap()))
        );
        prop_assert!(registry.effect_contract("probe.tool").is_none());
    }

    #[test]
    fn an_effect_outside_the_closed_set_is_always_a_load_error(
        effect in classification_name(),
    ) {
        if EFFECT_NAMES.contains(&effect.as_str()) {
            return Ok(());
        }

        let source = format!(
            "{source}\
             [[tool]]\n\
             name = \"probe.tool\"\n\
             capability = \"project.write\"\n\
             risk = \"high\"\n\
             effects = [\"{effect}\"]\n\
             arguments = [\"paths\"]\n",
            source = pinned_source_block()
        );
        prop_assert!(
            TomlToolRegistry::from_toml_str(&source).is_err(),
            "effect {effect:?} is not in the closed set but loaded"
        );
    }

    #[test]
    fn an_effect_contract_is_accepted_only_when_it_is_completely_declared(
        declare_source in any::<bool>(),
        declare_arguments in any::<bool>(),
        declare_effects in any::<bool>(),
        declare_path_argument in any::<bool>(),
        path_argument_declared in any::<bool>(),
    ) {
        let mut source = String::new();
        if declare_source {
            source.push_str(&pinned_source_block());
        }
        source.push_str("[[tool]]\nname = \"probe.tool\"\ncapability = \"project.write\"\nrisk = \"high\"\n");
        if declare_arguments {
            source.push_str("arguments = [\"paths\"]\n");
        }
        if declare_effects {
            source.push_str("effects = [\"write\"]\n");
        }
        if declare_path_argument {
            let argument = if path_argument_declared { "paths" } else { "undeclared" };
            source.push_str(&format!(
                "[[tool.path_arguments]]\nargument = \"{argument}\"\neffects = [\"write\"]\n"
            ));
        }

        let result = TomlToolRegistry::from_toml_str(&source);
        // A contract is loadable only with a pinned source, an argument list,
        // effects, and path arguments that are themselves declared.
        let contract_is_complete = declare_source
            && declare_arguments
            && declare_effects
            && (!declare_path_argument || path_argument_declared);

        match result {
            Ok(registry) if contract_is_complete => {
                // A complete declaration is the only way to get a contract,
                // and it is built exactly as declared.
                let contract = registry
                    .effect_contract("probe.tool")
                    .expect("a completely declared effect contract loads");
                prop_assert!(contract.effects().contains(&OperationEffect::Write));
                prop_assert!(contract.arguments().contains("paths"));
                if declare_path_argument {
                    prop_assert!(contract.path_arguments().contains_key("paths"));
                }
            }
            Ok(registry) => {
                // Anything short of a complete declaration is a classified
                // tool with no contract at all, which the policy engine denies
                // until the effects are reviewed — never a partial contract.
                prop_assert!(registry.effect_contract("probe.tool").is_none());
            }
            Err(error) => {
                prop_assert!(
                    !contract_is_complete,
                    "a completely declared effect contract failed to load: {error}"
                );
            }
        }
    }

    #[test]
    fn a_mutated_reviewed_manifest_never_panics_and_never_invents_a_classification(
        index in 0..REVIEWED_REGISTRY.len(),
        byte in any::<u8>(),
    ) {
        let mut mutated = REVIEWED_REGISTRY.as_bytes().to_vec();
        mutated[index] = byte;
        let mutated = String::from_utf8_lossy(&mutated).into_owned();

        let Ok(registry) = TomlToolRegistry::from_toml_str(&mutated) else {
            return Ok(());
        };

        let snapshot = ToolCatalogSnapshot::from_toml_str(PINNED_CATALOG)
            .expect("the pinned catalog is valid");
        for name in classified_tool_names(&registry, &snapshot) {
            let (capability, _) = registry
                .resolve(&name)
                .expect("a classified tool resolves");
            prop_assert!(
                mutated.contains(capability.as_str()),
                "a single-byte change to the reviewed manifest produced capability {} \
                 for {name}, which it does not declare",
                capability.as_str()
            );
        }
    }
}

/// `RiskLevel` serializes as a variant name; a manifest spells it lowercase.
fn risk_name(risk: RiskLevel) -> String {
    serde_json::to_value(risk)
        .expect("risk serializes")
        .as_str()
        .expect("risk serializes as a string")
        .to_lowercase()
}

/// Risk gates the extra approval step for a high-risk operation, so a tool
/// whose reviewed contract can mutate a project may never be classified as
/// low risk. This is a property of the reviewed asset, so it is asserted
/// exhaustively rather than sampled.
#[test]
fn a_tool_that_can_mutate_a_project_is_never_classified_low_risk() {
    let registry = TomlToolRegistry::try_embedded().expect("the reviewed manifest is valid");
    let snapshot = ToolCatalogSnapshot::embedded();
    let mutating = [
        OperationEffect::Write,
        OperationEffect::Create,
        OperationEffect::Delete,
    ];

    for name in classified_tool_names(&registry, &snapshot) {
        let Some(contract) = registry.effect_contract(&name) else {
            continue;
        };
        let mutates = contract
            .effects()
            .iter()
            .any(|effect| mutating.contains(effect))
            || contract.path_arguments().values().any(|argument| {
                argument
                    .effects()
                    .iter()
                    .any(|effect| mutating.contains(effect))
            });
        if mutates {
            let (_, risk) = registry.resolve(&name).expect("a classified tool resolves");
            assert_ne!(
                risk,
                RiskLevel::Low,
                "{name} can write, create, or delete but is classified low risk"
            );
        }
    }
}

/// The same review from the other direction: a tool whose reviewed effects are
/// read-only may not hold a capability that grants mutation, so an effect
/// contract and a capability can never drift apart in opposite directions.
#[test]
fn a_read_only_effect_contract_never_carries_a_mutating_capability() {
    let registry = TomlToolRegistry::try_embedded().expect("the reviewed manifest is valid");
    let snapshot = ToolCatalogSnapshot::embedded();
    let mutating = [
        OperationEffect::Write,
        OperationEffect::Create,
        OperationEffect::Delete,
    ];

    for name in classified_tool_names(&registry, &snapshot) {
        let Some(contract) = registry.effect_contract(&name) else {
            continue;
        };
        let effects: BTreeSet<&OperationEffect> = contract
            .effects()
            .iter()
            .chain(
                contract
                    .path_arguments()
                    .values()
                    .flat_map(|argument| argument.effects()),
            )
            .collect();
        let mutates = effects.iter().any(|effect| mutating.contains(effect));
        if !mutates {
            let (capability, _) = registry.resolve(&name).expect("a classified tool resolves");
            assert!(
                capability.as_str().ends_with(".read"),
                "{name} models read-only effects but holds {capability}"
            );
        }
    }
}
