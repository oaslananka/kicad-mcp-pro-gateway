//! Data-driven tool name -> (capability, risk) mapping.
//!
//! An unknown tool name resolves to `None`. Callers (the policy engine)
//! treat `None` as a hard deny with no fallback — see
//! `docs/security/threat-model.md` (T6).

use std::collections::{BTreeSet, HashMap};

use crate::tool_catalog::ToolCatalogSnapshot;

use companion_core::{Capability, RiskLevel};
use serde::Deserialize;

pub trait ToolCapabilityResolver: Send + Sync {
    fn resolve(&self, tool_name: &str) -> Option<(Capability, RiskLevel)>;
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
}

#[derive(Debug, Deserialize)]
struct ToolRegistryFile {
    tool: Vec<ToolEntryRaw>,
}

#[derive(Debug, Deserialize)]
struct ToolEntryRaw {
    name: String,
    capability: String,
    risk: String,
}

pub struct TomlToolRegistry {
    entries: HashMap<String, (Capability, RiskLevel)>,
}

impl TomlToolRegistry {
    pub fn from_toml_str(source: &str) -> Result<Self, ToolRegistryError> {
        let file: ToolRegistryFile =
            toml::from_str(source).map_err(|e| ToolRegistryError::Malformed(e.to_string()))?;

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

            if entries
                .insert(raw.name.clone(), (capability, risk))
                .is_some()
            {
                return Err(ToolRegistryError::DuplicateTool(raw.name));
            }
        }

        Ok(Self { entries })
    }

    /// Loads the registry embedded at compile time from
    /// `assets/tool_registry.toml`. The `embedded_tool_registry_is_valid`
    /// test in `tests/tool_registry.rs` validates this asset on every CI
    /// run, so a malformed committed asset fails the build rather than
    /// panicking at runtime for a real user.
    pub fn embedded() -> Self {
        Self::from_toml_str(include_str!("../assets/tool_registry.toml")).expect(
            "assets/tool_registry.toml is validated by tests/tool_registry.rs on every CI run",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRegistryCoverage {
    pub classified: Vec<String>,
    pub unclassified: Vec<String>,
    pub stale: Vec<String>,
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
        ToolRegistryCoverage {
            classified,
            unclassified,
            stale,
            catalog_total: catalog.len(),
            registry_total: registry.len(),
        }
    }
}

impl ToolCapabilityResolver for TomlToolRegistry {
    fn resolve(&self, tool_name: &str) -> Option<(Capability, RiskLevel)> {
        self.entries.get(tool_name).copied()
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
    }

    #[test]
    fn unknown_tool_resolves_to_none() {
        let registry = sample_registry();
        assert_eq!(registry.resolve("totally_unknown_tool"), None);
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
