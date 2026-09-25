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

pub trait ToolCapabilityResolver: Send + Sync {
    fn resolve(&self, tool_name: &str) -> Option<(Capability, RiskLevel)>;

    /// Returns only a reviewed, source-pinned effect contract. The default
    /// keeps third-party resolvers source-compatible while making them fail
    /// closed until they explicitly implement effect normalization.
    fn effect_contract(&self, _tool_name: &str) -> Option<&ToolEffectContract> {
        None
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

            if entries
                .insert(
                    raw.name.clone(),
                    ToolEntry {
                        capability,
                        risk,
                        effect_contract,
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
}
