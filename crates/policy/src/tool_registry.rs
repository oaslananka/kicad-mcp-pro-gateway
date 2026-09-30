//! Versioned, reviewed tool contracts.
//!
//! Each entry maps a tool name to its required capability/risk and, when the
//! tool has been reviewed, to a fail-closed [`ToolEffectContract`]. Unknown
//! tools resolve to `None`; known tools without an effect contract remain
//! classified but are denied by policy before authorization.

use std::collections::{BTreeSet, HashMap};

use companion_core::{Capability, RiskLevel};
use serde::Deserialize;

use crate::operation_effects::{OperationEffect, ToolEffectContract};
use crate::tool_catalog::ToolCatalogSnapshot;

pub const TOOL_EFFECT_CONTRACT_VERSION: u32 = 1;
pub const OPERATION_RISK_POLICY_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskRule {
    ArgumentCardinality {
        argument: String,
        minimum_count: u64,
        requires_effect: OperationEffect,
        escalate_to: RiskLevel,
    },
}

pub trait ToolCapabilityResolver: Send + Sync {
    fn resolve(&self, tool_name: &str) -> Option<(Capability, RiskLevel)>;

    /// Returns only a reviewed, source-pinned effect contract. The default
    /// keeps third-party resolvers source-compatible while making them fail
    /// closed until they explicitly implement effect normalization.
    fn effect_contract(&self, _tool_name: &str) -> Option<&ToolEffectContract> {
        None
    }

    fn risk_rules(&self, _tool_name: &str) -> &[RiskRule] {
        &[]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToolRegistryError {
    #[error("tool registry asset is malformed toml: {0}")]
    Malformed(String),
    #[error("tool registry entry '{tool}' references unknown capability '{capability}'")]
    UnknownCapability { tool: String, capability: String },
    #[error("tool registry entry '{tool}' references unknown risk level '{risk}'")]
    UnknownRisk { tool: String, risk: String },
    #[error("tool registry has a duplicate entry for tool '{0}'")]
    DuplicateTool(String),
    #[error("tool effect contract source is missing")]
    MissingContractSource,
    #[error("unsupported tool effect contract version {0}")]
    UnsupportedContractVersion(u32),
    #[error("tool effect contract source {field} is '{actual}', expected pinned '{expected}'")]
    ContractSourceMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("tool effect contract for '{tool}' is incomplete: {message}")]
    IncompleteEffectContract { tool: String, message: String },
    #[error("tool effect contract for '{tool}' is invalid: {message}")]
    InvalidEffectContract { tool: String, message: String },
    #[error("risk rule for '{tool}' is invalid: {message}")]
    InvalidRiskRule { tool: String, message: String },
    #[error("embedded tool registry contains stale entry '{0}'")]
    StaleTool(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolRegistryFile {
    #[serde(default)]
    contract_version: Option<u32>,
    #[serde(default)]
    source_repository: Option<String>,
    #[serde(default)]
    source_ref: Option<String>,
    #[serde(default)]
    source_sha: Option<String>,
    #[serde(default)]
    tool: Vec<ToolEntryRaw>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolEntryRaw {
    name: String,
    capability: String,
    risk: String,
    #[serde(default)]
    arguments: Option<Vec<String>>,
    #[serde(default)]
    effects: Option<Vec<String>>,
    #[serde(default)]
    path_arguments: Vec<PathArgumentRaw>,
    #[serde(default)]
    risk_rules: Vec<RiskRuleRaw>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RiskRuleKindRaw {
    ArgumentCardinality,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskRuleRaw {
    kind: RiskRuleKindRaw,
    argument: String,
    minimum_count: u64,
    requires_effect: String,
    escalate_to: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathArgumentRaw {
    argument: String,
    #[serde(default)]
    base_argument: Option<String>,
    #[serde(default)]
    effects: Vec<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    default: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolContractSource {
    pub contract_version: u32,
    pub source_repository: String,
    pub source_ref: String,
    pub source_sha: String,
}

#[derive(Debug)]
struct ToolEntry {
    capability: Capability,
    risk: RiskLevel,
    effect_contract: Option<ToolEffectContract>,
    risk_rules: Vec<RiskRule>,
}

pub struct TomlToolRegistry {
    entries: HashMap<String, ToolEntry>,
    source: Option<ToolContractSource>,
}

impl TomlToolRegistry {
    pub fn from_toml_str(source: &str) -> Result<Self, ToolRegistryError> {
        let file: ToolRegistryFile =
            toml::from_str(source).map_err(|e| ToolRegistryError::Malformed(e.to_string()))?;
        let contract_source = parse_contract_source(&file)?;

        let mut entries = HashMap::new();
        for raw in file.tool {
            let capability = Capability::parse(&raw.capability).ok_or_else(|| {
                ToolRegistryError::UnknownCapability {
                    tool: raw.name.clone(),
                    capability: raw.capability.clone(),
                }
            })?;
            let risk =
                RiskLevel::parse(&raw.risk).ok_or_else(|| ToolRegistryError::UnknownRisk {
                    tool: raw.name.clone(),
                    risk: raw.risk.clone(),
                })?;
            let effect_contract = parse_effect_contract(&raw, contract_source.as_ref())?;
            let risk_rules = parse_risk_rules(&raw, risk, effect_contract.as_ref())?;

            if entries
                .insert(
                    raw.name.clone(),
                    ToolEntry {
                        capability,
                        risk,
                        effect_contract,
                        risk_rules,
                    },
                )
                .is_some()
            {
                return Err(ToolRegistryError::DuplicateTool(raw.name));
            }
        }

        let registry = Self {
            entries,
            source: contract_source,
        };
        if registry.source.is_some() {
            registry.validate_source(&ToolCatalogSnapshot::embedded())?;
        }
        Ok(registry)
    }

    /// Loads and validates the registry and effect contracts embedded at
    /// compile time. Daemon startup uses this fallible form so stale or
    /// incomplete trusted source prevents startup instead of granting access.
    pub fn try_embedded() -> Result<Self, ToolRegistryError> {
        let registry = Self::from_toml_str(include_str!("../assets/tool_registry.toml"))?;
        if registry.source.is_none() {
            return Err(ToolRegistryError::MissingContractSource);
        }
        if let Some(stale) = registry
            .coverage_against(&ToolCatalogSnapshot::embedded())
            .stale
            .into_iter()
            .next()
        {
            return Err(ToolRegistryError::StaleTool(stale));
        }
        Ok(registry)
    }

    /// Compatibility helper for tests and tooling. Production startup uses
    /// [`Self::try_embedded`] so source drift is surfaced as a typed error.
    pub fn embedded() -> Self {
        Self::try_embedded().expect(
            "assets/tool_registry.toml must match the pinned upstream snapshot and remain valid",
        )
    }

    pub fn validate_source(&self, snapshot: &ToolCatalogSnapshot) -> Result<(), ToolRegistryError> {
        let source = self
            .source
            .as_ref()
            .ok_or(ToolRegistryError::MissingContractSource)?;
        validate_source_fields(source, snapshot)
    }

    pub fn contract_source(&self) -> Option<&ToolContractSource> {
        self.source.as_ref()
    }

    pub fn effect_contract_names(&self) -> Vec<String> {
        let mut names = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.effect_contract.is_some())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names
    }
}

fn parse_contract_source(
    file: &ToolRegistryFile,
) -> Result<Option<ToolContractSource>, ToolRegistryError> {
    let field_count = usize::from(file.contract_version.is_some())
        + usize::from(file.source_repository.is_some())
        + usize::from(file.source_ref.is_some())
        + usize::from(file.source_sha.is_some());
    if field_count == 0 {
        return Ok(None);
    }
    if field_count != 4 {
        return Err(ToolRegistryError::MissingContractSource);
    }

    let version = file.contract_version.unwrap_or_default();
    if version != TOOL_EFFECT_CONTRACT_VERSION {
        return Err(ToolRegistryError::UnsupportedContractVersion(version));
    }

    Ok(Some(ToolContractSource {
        contract_version: version,
        source_repository: file
            .source_repository
            .clone()
            .ok_or(ToolRegistryError::MissingContractSource)?,
        source_ref: file
            .source_ref
            .clone()
            .ok_or(ToolRegistryError::MissingContractSource)?,
        source_sha: file
            .source_sha
            .clone()
            .ok_or(ToolRegistryError::MissingContractSource)?,
    }))
}

fn validate_source_fields(
    source: &ToolContractSource,
    snapshot: &ToolCatalogSnapshot,
) -> Result<(), ToolRegistryError> {
    let checks = [
        (
            "source_repository",
            snapshot.source_repository.as_str(),
            source.source_repository.as_str(),
        ),
        (
            "source_ref",
            snapshot.source_ref.as_str(),
            source.source_ref.as_str(),
        ),
        (
            "source_sha",
            snapshot.source_sha.as_str(),
            source.source_sha.as_str(),
        ),
    ];
    for (field, expected, actual) in checks {
        if expected != actual {
            return Err(ToolRegistryError::ContractSourceMismatch {
                field,
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
        }
    }
    Ok(())
}

fn parse_effect_contract(
    raw: &ToolEntryRaw,
    source: Option<&ToolContractSource>,
) -> Result<Option<ToolEffectContract>, ToolRegistryError> {
    let has_partial_contract = raw.arguments.is_some() || !raw.path_arguments.is_empty();
    if raw.effects.is_none() {
        if has_partial_contract {
            return Err(ToolRegistryError::IncompleteEffectContract {
                tool: raw.name.clone(),
                message:
                    "effects must be declared whenever arguments or path arguments are present"
                        .into(),
            });
        }
        return Ok(None);
    }

    if source.is_none() {
        return Err(ToolRegistryError::MissingContractSource);
    }
    let arguments =
        raw.arguments
            .clone()
            .ok_or_else(|| ToolRegistryError::IncompleteEffectContract {
                tool: raw.name.clone(),
                message: "arguments must be declared for an effectful tool".into(),
            })?;
    let effects = parse_effects(&raw.name, &raw.effects.clone().unwrap_or_default())?;
    let path_arguments = raw
        .path_arguments
        .iter()
        .map(|path| {
            let effects = parse_effects(&raw.name, &path.effects)?;
            crate::operation_effects::PathArgumentContract::new(
                path.argument.clone(),
                effects,
                path.required,
                path.default.clone(),
                path.base_argument.clone(),
            )
            .map_err(|error| ToolRegistryError::InvalidEffectContract {
                tool: raw.name.clone(),
                message: error.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    ToolEffectContract::new(arguments, effects, path_arguments)
        .map(Some)
        .map_err(|error| ToolRegistryError::InvalidEffectContract {
            tool: raw.name.clone(),
            message: error.to_string(),
        })
}

fn parse_risk_rules(
    raw: &ToolEntryRaw,
    base_risk: RiskLevel,
    effect_contract: Option<&ToolEffectContract>,
) -> Result<Vec<RiskRule>, ToolRegistryError> {
    if raw.risk_rules.is_empty() {
        return Ok(Vec::new());
    }
    let contract = effect_contract.ok_or_else(|| ToolRegistryError::InvalidRiskRule {
        tool: raw.name.clone(),
        message: "risk rules require a reviewed effect contract".into(),
    })?;

    let mut rules = Vec::with_capacity(raw.risk_rules.len());
    for raw_rule in &raw.risk_rules {
        let rule = match raw_rule.kind {
            RiskRuleKindRaw::ArgumentCardinality => {
                if !contract.arguments().contains(&raw_rule.argument) {
                    return Err(ToolRegistryError::InvalidRiskRule {
                        tool: raw.name.clone(),
                        message: format!(
                            "argument '{}' is absent from the reviewed contract",
                            raw_rule.argument
                        ),
                    });
                }
                if raw_rule.minimum_count < 2 {
                    return Err(ToolRegistryError::InvalidRiskRule {
                        tool: raw.name.clone(),
                        message: "argument_cardinality minimum_count must be at least 2".into(),
                    });
                }
                let requires_effect =
                    parse_effects(&raw.name, std::slice::from_ref(&raw_rule.requires_effect))?
                        .into_iter()
                        .next()
                        .expect("one effect string yields one parsed effect");
                let has_effect = contract.effects().contains(&requires_effect)
                    || contract
                        .path_arguments()
                        .values()
                        .any(|path| path.effects().contains(&requires_effect));
                if !has_effect {
                    return Err(ToolRegistryError::InvalidRiskRule {
                        tool: raw.name.clone(),
                        message: format!(
                            "required effect '{}' is absent from the reviewed contract",
                            raw_rule.requires_effect
                        ),
                    });
                }
                let escalate_to = RiskLevel::parse(&raw_rule.escalate_to).ok_or_else(|| {
                    ToolRegistryError::InvalidRiskRule {
                        tool: raw.name.clone(),
                        message: format!(
                            "unknown escalation risk level '{}'",
                            raw_rule.escalate_to
                        ),
                    }
                })?;
                if escalate_to <= base_risk {
                    return Err(ToolRegistryError::InvalidRiskRule {
                        tool: raw.name.clone(),
                        message: "risk rule must strictly raise the tool's base risk".into(),
                    });
                }
                RiskRule::ArgumentCardinality {
                    argument: raw_rule.argument.clone(),
                    minimum_count: raw_rule.minimum_count,
                    requires_effect,
                    escalate_to,
                }
            }
        };
        if rules.contains(&rule) {
            return Err(ToolRegistryError::InvalidRiskRule {
                tool: raw.name.clone(),
                message: "duplicate equivalent risk rule".into(),
            });
        }
        rules.push(rule);
    }
    Ok(rules)
}

fn parse_effects(
    tool: &str,
    effects: &[String],
) -> Result<Vec<OperationEffect>, ToolRegistryError> {
    effects
        .iter()
        .map(|effect| match effect.as_str() {
            "read" => Ok(OperationEffect::Read),
            "write" => Ok(OperationEffect::Write),
            "create" => Ok(OperationEffect::Create),
            "delete" => Ok(OperationEffect::Delete),
            _ => Err(ToolRegistryError::InvalidEffectContract {
                tool: tool.to_string(),
                message: format!("unknown operation effect '{effect}'"),
            }),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRegistryCoverage {
    pub classified: Vec<String>,
    pub unclassified: Vec<String>,
    pub stale: Vec<String>,
    pub effect_modelled: Vec<String>,
    pub effect_unmodelled: Vec<String>,
    pub catalog_total: usize,
    pub registry_total: usize,
}

impl TomlToolRegistry {
    pub fn coverage_against(&self, snapshot: &ToolCatalogSnapshot) -> ToolRegistryCoverage {
        self.coverage_against_tool_names(snapshot.tool_names())
    }

    pub fn coverage_against_tool_names<I, S>(&self, tool_names: I) -> ToolRegistryCoverage
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let catalog = tool_names
            .into_iter()
            .map(|name| name.as_ref().to_string())
            .collect::<BTreeSet<_>>();
        let registry = self.entries.keys().cloned().collect::<BTreeSet<_>>();
        let classified = catalog.intersection(&registry).cloned().collect();
        let unclassified = catalog.difference(&registry).cloned().collect();
        let stale = registry.difference(&catalog).cloned().collect();
        let effect_modelled = self.effect_contract_names();
        let modelled = effect_modelled.iter().cloned().collect::<BTreeSet<_>>();
        let effect_unmodelled = registry.difference(&modelled).cloned().collect();
        ToolRegistryCoverage {
            classified,
            unclassified,
            stale,
            effect_modelled,
            effect_unmodelled,
            catalog_total: catalog.len(),
            registry_total: registry.len(),
        }
    }
}

impl ToolCapabilityResolver for TomlToolRegistry {
    fn resolve(&self, tool_name: &str) -> Option<(Capability, RiskLevel)> {
        self.entries
            .get(tool_name)
            .map(|entry| (entry.capability, entry.risk))
    }

    fn effect_contract(&self, tool_name: &str) -> Option<&ToolEffectContract> {
        self.entries
            .get(tool_name)
            .and_then(|entry| entry.effect_contract.as_ref())
    }

    fn risk_rules(&self, tool_name: &str) -> &[RiskRule] {
        self.entries
            .get(tool_name)
            .map(|entry| entry.risk_rules.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_registry() -> TomlToolRegistry {
        TomlToolRegistry::from_toml_str(
            r#"
            [[tool]]
            name = "schematic.add_symbol"
            capability = "schematic.write"
            risk = "normal"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn resolves_known_tool_to_capability_and_risk() {
        let registry = sample_registry();
        let (capability, risk) = registry
            .resolve("schematic.add_symbol")
            .expect("known tool resolves");
        assert_eq!(capability, Capability::SCHEMATIC_WRITE);
        assert_eq!(risk, RiskLevel::Normal);
        assert!(registry.effect_contract("schematic.add_symbol").is_none());
    }

    #[test]
    fn unknown_tool_resolves_to_none() {
        let registry = sample_registry();
        assert_eq!(registry.resolve("totally_unknown_tool"), None);
        assert!(registry.effect_contract("totally_unknown_tool").is_none());
    }

    #[test]
    fn unknown_capability_in_asset_is_a_load_error_not_a_panic() {
        let result = TomlToolRegistry::from_toml_str(
            r#"
            [[tool]]
            name = "shell.exec"
            capability = "shell.exec"
            risk = "critical"
            "#,
        );
        assert!(matches!(
            result,
            Err(ToolRegistryError::UnknownCapability { .. })
        ));
    }

    #[test]
    fn duplicate_tool_entry_is_a_load_error() {
        let result = TomlToolRegistry::from_toml_str(
            r#"
            [[tool]]
            name = "schematic.read"
            capability = "schematic.read"
            risk = "low"

            [[tool]]
            name = "schematic.read"
            capability = "schematic.write"
            risk = "normal"
            "#,
        );
        assert!(matches!(result, Err(ToolRegistryError::DuplicateTool(_))));
    }

    fn pinned_effectful_tool(rule: &str, arguments: &str, effects: &str, risk: &str) -> String {
        let snapshot = ToolCatalogSnapshot::embedded();
        format!(
            "contract_version = {TOOL_EFFECT_CONTRACT_VERSION}\n\
             source_repository = \"{}\"\n\
             source_ref = \"{}\"\n\
             source_sha = \"{}\"\n\n\
             [[tool]]\n\
             name = \"pcb_delete_items\"\n\
             capability = \"pcb.write\"\n\
             risk = \"{risk}\"\n\
             arguments = {arguments}\n\
             effects = {effects}\n\
             {rule}",
            snapshot.source_repository, snapshot.source_ref, snapshot.source_sha,
        )
    }

    const CARDINALITY_RULE: &str = "[[tool.risk_rules]]\n\
        kind = \"argument_cardinality\"\n\
        argument = \"item_ids\"\n\
        minimum_count = 2\n\
        requires_effect = \"delete\"\n\
        escalate_to = \"high\"\n";

    #[test]
    fn parses_reviewed_argument_cardinality_risk_rule() {
        let source = pinned_effectful_tool(
            CARDINALITY_RULE,
            "[\"item_ids\"]",
            "[\"read\", \"delete\"]",
            "normal",
        );
        let registry = TomlToolRegistry::from_toml_str(&source).unwrap();

        assert_eq!(
            registry.risk_rules("pcb_delete_items"),
            &[RiskRule::ArgumentCardinality {
                argument: "item_ids".into(),
                minimum_count: 2,
                requires_effect: OperationEffect::Delete,
                escalate_to: RiskLevel::High,
            }]
        );
    }

    #[test]
    fn risk_rule_with_unknown_field_is_rejected() {
        let source = pinned_effectful_tool(
            &format!("{CARDINALITY_RULE}unexpected = true\n"),
            "[\"item_ids\"]",
            "[\"read\", \"delete\"]",
            "normal",
        );
        assert!(TomlToolRegistry::from_toml_str(&source).is_err());
    }

    #[test]
    fn risk_rule_with_unknown_kind_is_rejected() {
        let rule = CARDINALITY_RULE.replace("argument_cardinality", "argument_volume");
        let source =
            pinned_effectful_tool(&rule, "[\"item_ids\"]", "[\"read\", \"delete\"]", "normal");
        assert!(TomlToolRegistry::from_toml_str(&source).is_err());
    }

    #[test]
    fn risk_rule_cannot_reference_an_unknown_argument() {
        let rule = CARDINALITY_RULE.replace("item_ids", "missing_ids");
        let source =
            pinned_effectful_tool(&rule, "[\"item_ids\"]", "[\"read\", \"delete\"]", "normal");
        assert!(matches!(
            TomlToolRegistry::from_toml_str(&source),
            Err(ToolRegistryError::InvalidRiskRule { .. })
        ));
    }

    #[test]
    fn risk_rule_requires_its_reviewed_effect() {
        let source =
            pinned_effectful_tool(CARDINALITY_RULE, "[\"item_ids\"]", "[\"read\"]", "normal");
        assert!(matches!(
            TomlToolRegistry::from_toml_str(&source),
            Err(ToolRegistryError::InvalidRiskRule { .. })
        ));
    }

    #[test]
    fn argument_cardinality_threshold_must_be_at_least_two() {
        let rule = CARDINALITY_RULE.replace("minimum_count = 2", "minimum_count = 1");
        let source =
            pinned_effectful_tool(&rule, "[\"item_ids\"]", "[\"read\", \"delete\"]", "normal");
        assert!(matches!(
            TomlToolRegistry::from_toml_str(&source),
            Err(ToolRegistryError::InvalidRiskRule { .. })
        ));
    }

    #[test]
    fn risk_rule_must_strictly_raise_base_risk() {
        let rule = CARDINALITY_RULE.replace("escalate_to = \"high\"", "escalate_to = \"normal\"");
        let source =
            pinned_effectful_tool(&rule, "[\"item_ids\"]", "[\"read\", \"delete\"]", "normal");
        assert!(matches!(
            TomlToolRegistry::from_toml_str(&source),
            Err(ToolRegistryError::InvalidRiskRule { .. })
        ));
    }

    #[test]
    fn duplicate_equivalent_risk_rules_are_rejected() {
        let source = pinned_effectful_tool(
            &format!("{CARDINALITY_RULE}{CARDINALITY_RULE}"),
            "[\"item_ids\"]",
            "[\"read\", \"delete\"]",
            "normal",
        );
        assert!(matches!(
            TomlToolRegistry::from_toml_str(&source),
            Err(ToolRegistryError::InvalidRiskRule { .. })
        ));
    }

    #[test]
    fn risk_rule_requires_a_reviewed_effect_contract() {
        let snapshot = ToolCatalogSnapshot::embedded();
        let source = format!(
            "contract_version = {TOOL_EFFECT_CONTRACT_VERSION}\n\
             source_repository = \"{}\"\n\
             source_ref = \"{}\"\n\
             source_sha = \"{}\"\n\n\
             [[tool]]\n\
             name = \"pcb_delete_items\"\n\
             capability = \"pcb.write\"\n\
             risk = \"normal\"\n\
             {CARDINALITY_RULE}",
            snapshot.source_repository, snapshot.source_ref, snapshot.source_sha,
        );
        assert!(matches!(
            TomlToolRegistry::from_toml_str(&source),
            Err(ToolRegistryError::InvalidRiskRule { .. })
        ));
    }
}
