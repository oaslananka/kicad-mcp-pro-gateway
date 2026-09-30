//! Strict consumer for the upstream reviewed tool-effect manifest.
//!
//! This module deliberately does not replace the embedded TOML policy source.
//! It parses factual upstream effect metadata and can reconcile it against the
//! locally reviewed fallback. Authorization remains owned by Gateway.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde::Deserialize;

use crate::operation_effects::{OperationEffect, PathArgumentContract, ToolEffectContract};
use crate::tool_catalog::ToolCatalogSnapshot;
use crate::tool_registry::{TomlToolRegistry, ToolCapabilityResolver};

pub const UPSTREAM_EFFECT_MANIFEST_SCHEMA_MAJOR: u64 = 1;
pub const UPSTREAM_EFFECT_MANIFEST_REPOSITORY: &str = "oaslananka/kicad-mcp-pro";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamEffectManifestSource {
    pub repository: String,
    pub version: String,
    pub reviewed_source_sha: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectVerificationRequirement {
    SourceReview,
    InputSchemaMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionSupport {
    None,
    InternalGuarded,
    ExternalLifecycle,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedToolEffectFacts {
    contract: ToolEffectContract,
    destructive: bool,
    idempotent: bool,
    supports_dry_run: bool,
    supports_rollback: bool,
    transaction_support: TransactionSupport,
    verification_requirements: BTreeSet<EffectVerificationRequirement>,
    reviewed_source_paths: Vec<String>,
}

impl ReviewedToolEffectFacts {
    pub fn contract(&self) -> &ToolEffectContract {
        &self.contract
    }

    pub fn destructive(&self) -> bool {
        self.destructive
    }

    pub fn idempotent(&self) -> bool {
        self.idempotent
    }

    pub fn supports_dry_run(&self) -> bool {
        self.supports_dry_run
    }

    pub fn supports_rollback(&self) -> bool {
        self.supports_rollback
    }

    pub fn transaction_support(&self) -> TransactionSupport {
        self.transaction_support
    }

    pub fn verification_requirements(&self) -> &BTreeSet<EffectVerificationRequirement> {
        &self.verification_requirements
    }

    pub fn reviewed_source_paths(&self) -> &[String] {
        &self.reviewed_source_paths
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamEffectManifest {
    schema_version: String,
    source: UpstreamEffectManifestSource,
    tools: BTreeMap<String, ReviewedToolEffectFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectManifestReconciliation {
    pub fallback_only_reviewed: Vec<String>,
    pub upstream_only_reviewed: Vec<String>,
    pub contract_mismatches: Vec<String>,
}

impl EffectManifestReconciliation {
    pub fn is_exact_match(&self) -> bool {
        self.fallback_only_reviewed.is_empty()
            && self.upstream_only_reviewed.is_empty()
            && self.contract_mismatches.is_empty()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpstreamEffectManifestError {
    #[error("upstream tool-effect manifest is malformed JSON: {0}")]
    MalformedJson(String),
    #[error("unsupported upstream tool-effect manifest schema version '{0}'")]
    UnsupportedSchemaVersion(String),
    #[error(
        "upstream tool-effect manifest source repository is '{actual}', expected '{expected}'"
    )]
    SourceRepositoryMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("upstream tool-effect manifest source version is not strict semver: '{0}'")]
    InvalidSourceVersion(String),
    #[error("upstream tool-effect manifest reviewed source SHA is invalid: '{0}'")]
    InvalidSourceSha(String),
    #[error("upstream tool-effect manifest must contain at least one reviewed tool")]
    EmptyManifest,
    #[error("upstream tool-effect manifest contains duplicate tool '{0}'")]
    DuplicateTool(String),
    #[error("upstream tool-effect manifest has invalid tool name '{0}'")]
    InvalidToolName(String),
    #[error("upstream tool-effect manifest tool '{tool}' has duplicate {field}")]
    DuplicateFact { tool: String, field: &'static str },
    #[error("upstream tool-effect manifest tool '{tool}' is missing required review evidence")]
    MissingReviewEvidence { tool: String },
    #[error(
        "upstream tool-effect manifest tool '{tool}' has invalid reviewed source path '{path}'"
    )]
    InvalidReviewedSourcePath { tool: String, path: String },
    #[error("upstream tool-effect manifest tool '{tool}' has inconsistent destructive annotation")]
    InconsistentDestructive { tool: String },
    #[error("upstream tool-effect manifest tool '{tool}' has invalid path contract: {message}")]
    InvalidPathContract { tool: String, message: String },
    #[error("upstream tool-effect manifest tool '{tool}' has invalid effect contract: {message}")]
    InvalidEffectContract { tool: String, message: String },
    #[error("upstream tool-effect manifest source {field} is '{actual}', expected '{expected}'")]
    StaleSource {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("upstream tool-effect manifest contains locally unclassified tool '{0}'")]
    UnclassifiedTool(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    source: RawSource,
    tools: Vec<RawTool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    repository: String,
    version: String,
    reviewed_source_sha: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    name: String,
    arguments: Vec<String>,
    effects: Vec<OperationEffect>,
    path_arguments: Vec<RawPathArgument>,
    destructive: bool,
    idempotent: bool,
    supports_dry_run: bool,
    supports_rollback: bool,
    transaction_support: TransactionSupport,
    verification_requirements: Vec<EffectVerificationRequirement>,
    reviewed_source_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPathArgument {
    argument: String,
    effects: Vec<OperationEffect>,
    required: bool,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    base_argument: Option<String>,
}

impl UpstreamEffectManifest {
    pub fn from_json_str(source: &str) -> Result<Self, UpstreamEffectManifestError> {
        let raw: RawManifest = serde_json::from_str(source)
            .map_err(|error| UpstreamEffectManifestError::MalformedJson(error.to_string()))?;

        validate_schema_version(&raw.schema_version)?;
        let source = parse_source(raw.source)?;
        let tools = parse_tools(raw.tools)?;

        Ok(Self {
            schema_version: raw.schema_version,
            source,
            tools,
        })
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn source(&self) -> &UpstreamEffectManifestSource {
        &self.source
    }

    pub fn tool(&self, name: &str) -> Option<&ReviewedToolEffectFacts> {
        self.tools.get(name)
    }

    pub fn tool_names(&self) -> impl Iterator<Item = &str> {
        self.tools.keys().map(String::as_str)
    }

    pub fn validate_source(
        &self,
        snapshot: &ToolCatalogSnapshot,
    ) -> Result<(), UpstreamEffectManifestError> {
        if self.source.repository != snapshot.source_repository {
            return Err(UpstreamEffectManifestError::StaleSource {
                field: "repository",
                expected: snapshot.source_repository.clone(),
                actual: self.source.repository.clone(),
            });
        }
        if self.source.reviewed_source_sha != snapshot.source_sha {
            return Err(UpstreamEffectManifestError::StaleSource {
                field: "reviewed_source_sha",
                expected: snapshot.source_sha.clone(),
                actual: self.source.reviewed_source_sha.clone(),
            });
        }
        Ok(())
    }

    pub fn reconcile_with_fallback(
        &self,
        registry: &TomlToolRegistry,
    ) -> Result<EffectManifestReconciliation, UpstreamEffectManifestError> {
        for name in self.tools.keys() {
            if registry.resolve(name).is_none() {
                return Err(UpstreamEffectManifestError::UnclassifiedTool(name.clone()));
            }
        }

        let upstream_names = self.tools.keys().cloned().collect::<BTreeSet<_>>();
        let fallback_names = registry
            .effect_contract_names()
            .into_iter()
            .collect::<BTreeSet<_>>();

        let fallback_only_reviewed = fallback_names
            .difference(&upstream_names)
            .cloned()
            .collect::<Vec<_>>();
        let upstream_only_reviewed = upstream_names
            .difference(&fallback_names)
            .cloned()
            .collect::<Vec<_>>();
        let contract_mismatches = upstream_names
            .intersection(&fallback_names)
            .filter(|name| {
                self.tools
                    .get(*name)
                    .zip(registry.effect_contract(name))
                    .is_some_and(|(upstream, fallback)| upstream.contract() != fallback)
            })
            .cloned()
            .collect::<Vec<_>>();

        Ok(EffectManifestReconciliation {
            fallback_only_reviewed,
            upstream_only_reviewed,
            contract_mismatches,
        })
    }
}

fn validate_schema_version(version: &str) -> Result<(), UpstreamEffectManifestError> {
    if strict_semver_major(version) == Some(UPSTREAM_EFFECT_MANIFEST_SCHEMA_MAJOR) {
        Ok(())
    } else {
        Err(UpstreamEffectManifestError::UnsupportedSchemaVersion(
            version.to_string(),
        ))
    }
}

fn parse_source(
    source: RawSource,
) -> Result<UpstreamEffectManifestSource, UpstreamEffectManifestError> {
    if source.repository != UPSTREAM_EFFECT_MANIFEST_REPOSITORY {
        return Err(UpstreamEffectManifestError::SourceRepositoryMismatch {
            expected: UPSTREAM_EFFECT_MANIFEST_REPOSITORY,
            actual: source.repository,
        });
    }
    if strict_semver_major(&source.version).is_none() {
        return Err(UpstreamEffectManifestError::InvalidSourceVersion(
            source.version,
        ));
    }
    if !is_lower_hex_sha(&source.reviewed_source_sha) {
        return Err(UpstreamEffectManifestError::InvalidSourceSha(
            source.reviewed_source_sha,
        ));
    }

    Ok(UpstreamEffectManifestSource {
        repository: source.repository,
        version: source.version,
        reviewed_source_sha: source.reviewed_source_sha,
    })
}

fn parse_tools(
    raw_tools: Vec<RawTool>,
) -> Result<BTreeMap<String, ReviewedToolEffectFacts>, UpstreamEffectManifestError> {
    if raw_tools.is_empty() {
        return Err(UpstreamEffectManifestError::EmptyManifest);
    }

    let mut tools = BTreeMap::new();
    for raw_tool in raw_tools {
        let (name, facts) = parse_tool(raw_tool)?;
        if tools.insert(name.clone(), facts).is_some() {
            return Err(UpstreamEffectManifestError::DuplicateTool(name));
        }
    }
    Ok(tools)
}

fn parse_tool(
    raw_tool: RawTool,
) -> Result<(String, ReviewedToolEffectFacts), UpstreamEffectManifestError> {
    let RawTool {
        name,
        arguments,
        effects,
        path_arguments,
        destructive,
        idempotent,
        supports_dry_run,
        supports_rollback,
        transaction_support,
        verification_requirements,
        reviewed_source_paths,
    } = raw_tool;

    validate_tool_name(&name)?;
    reject_duplicates(&name, "arguments", &arguments)?;
    reject_duplicates(&name, "effects", &effects)?;

    let (verification_requirements, reviewed_source_paths) =
        parse_review_evidence(&name, verification_requirements, reviewed_source_paths)?;
    let (path_arguments, path_changes_state) = parse_path_arguments(&name, path_arguments)?;
    let changes_state = effects.iter().any(is_mutating_effect) || path_changes_state;
    if destructive != changes_state {
        return Err(UpstreamEffectManifestError::InconsistentDestructive { tool: name });
    }

    let contract =
        ToolEffectContract::new(arguments, effects, path_arguments).map_err(|error| {
            UpstreamEffectManifestError::InvalidEffectContract {
                tool: name.clone(),
                message: error.to_string(),
            }
        })?;

    let facts = ReviewedToolEffectFacts {
        contract,
        destructive,
        idempotent,
        supports_dry_run,
        supports_rollback,
        transaction_support,
        verification_requirements,
        reviewed_source_paths,
    };
    Ok((name, facts))
}

fn parse_review_evidence(
    tool: &str,
    requirements: Vec<EffectVerificationRequirement>,
    source_paths: Vec<String>,
) -> Result<(BTreeSet<EffectVerificationRequirement>, Vec<String>), UpstreamEffectManifestError> {
    reject_duplicates(tool, "verification requirements", &requirements)?;
    reject_duplicates(tool, "reviewed source paths", &source_paths)?;

    let requirements = requirements.into_iter().collect::<BTreeSet<_>>();
    if !requirements.contains(&EffectVerificationRequirement::SourceReview)
        || !requirements.contains(&EffectVerificationRequirement::InputSchemaMatch)
        || source_paths.is_empty()
    {
        return Err(UpstreamEffectManifestError::MissingReviewEvidence {
            tool: tool.to_string(),
        });
    }

    for source_path in &source_paths {
        if !is_safe_source_path(source_path) {
            return Err(UpstreamEffectManifestError::InvalidReviewedSourcePath {
                tool: tool.to_string(),
                path: source_path.clone(),
            });
        }
    }
    Ok((requirements, source_paths))
}

fn parse_path_arguments(
    tool: &str,
    raw_paths: Vec<RawPathArgument>,
) -> Result<(Vec<PathArgumentContract>, bool), UpstreamEffectManifestError> {
    let mut path_arguments = Vec::with_capacity(raw_paths.len());
    let mut path_names = BTreeSet::new();
    let mut changes_state = false;

    for path in raw_paths {
        if !path_names.insert(path.argument.clone()) {
            return Err(UpstreamEffectManifestError::DuplicateFact {
                tool: tool.to_string(),
                field: "path arguments",
            });
        }
        reject_duplicates(tool, "path effects", &path.effects)?;
        if path.required && path.default.is_some() {
            return Err(UpstreamEffectManifestError::InvalidPathContract {
                tool: tool.to_string(),
                message: format!(
                    "required path argument '{}' must not declare a default",
                    path.argument
                ),
            });
        }

        changes_state |= path.effects.iter().any(is_mutating_effect);
        let contract = PathArgumentContract::new(
            path.argument,
            path.effects,
            path.required,
            path.default,
            path.base_argument,
        )
        .map_err(|error| UpstreamEffectManifestError::InvalidPathContract {
            tool: tool.to_string(),
            message: error.to_string(),
        })?;
        path_arguments.push(contract);
    }

    Ok((path_arguments, changes_state))
}

fn strict_semver_major(value: &str) -> Option<u64> {
    let mut parts = value.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some()
        || major.is_empty()
        || minor.is_empty()
        || patch.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
        || !patch.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    major.parse().ok()
}

fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_tool_name(name: &str) -> Result<(), UpstreamEffectManifestError> {
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        });
    if valid {
        Ok(())
    } else {
        Err(UpstreamEffectManifestError::InvalidToolName(
            name.to_string(),
        ))
    }
}

fn reject_duplicates<T>(
    tool: &str,
    field: &'static str,
    values: &[T],
) -> Result<(), UpstreamEffectManifestError>
where
    T: Ord + Clone,
{
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(UpstreamEffectManifestError::DuplicateFact {
            tool: tool.to_string(),
            field,
        })
    }
}

fn is_mutating_effect(effect: &OperationEffect) -> bool {
    matches!(
        effect,
        OperationEffect::Write | OperationEffect::Create | OperationEffect::Delete
    )
}

fn is_safe_source_path(value: &str) -> bool {
    if value.trim().is_empty() || value.contains('\\') {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}
