//! Trusted tool-effect contracts and normalized operation effects.
//!
//! `OperationRequest::target_path` is caller-controlled metadata and is never
//! read here. Path authority comes only from the reviewed argument selectors in
//! a [`ToolEffectContract`]. This module performs no containment or symlink
//! checks; the policy engine applies those checks to every path in the
//! resulting [`NormalizedOperationEffects`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationEffect {
    Read,
    Write,
    Create,
    Delete,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ToolEffectContractError {
    #[error("tool effect contract must model at least one operation effect")]
    NoEffects,
    #[error("tool effect contract has an empty argument name")]
    EmptyArgument,
    #[error("tool effect contract declares duplicate argument '{0}'")]
    DuplicateArgument(String),
    #[error("path argument '{argument}' is not present in the reviewed argument list")]
    UndeclaredPathArgument { argument: String },
    #[error("tool effect contract declares path argument '{0}' more than once")]
    DuplicatePathArgument(String),
    #[error("path argument '{argument}' has an invalid reviewed default path")]
    InvalidDefaultPath { argument: String },
    #[error("path argument has an empty base argument")]
    EmptyBaseArgument,
    #[error(
        "path argument '{argument}' references undeclared base path argument '{base_argument}'"
    )]
    UndeclaredBasePathArgument {
        argument: String,
        base_argument: String,
    },
    #[error("path argument '{argument}' has a cyclic base path dependency")]
    CyclicPathDependency { argument: String },
    #[error("path argument '{argument}' depends on optional base path '{base_argument}' without a default")]
    IndeterminateBasePath {
        argument: String,
        base_argument: String,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationEffectNormalizationError {
    #[error(
        "operation includes argument '{argument}' that is absent from the reviewed tool contract"
    )]
    UnknownArgument { argument: String },
    #[error("required path argument '{argument}' is missing")]
    MissingRequiredPathArgument { argument: String },
    #[error("path argument '{argument}' must be a string or an array of strings")]
    InvalidPathValue { argument: String },
    #[error("path argument '{argument}' uses unsupported alternate-path syntax")]
    UnsupportedPathSyntax { argument: String },
    #[error("reviewed tool contract produced no operation effects for the supplied arguments")]
    NoEffects,
    #[error("reviewed path argument '{argument}' has an invalid base dependency")]
    InvalidPathDependency { argument: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathArgumentContract {
    argument: String,
    effects: BTreeSet<OperationEffect>,
    required: bool,
    default: Option<String>,
    base_argument: Option<String>,
}

impl PathArgumentContract {
    pub fn new(
        argument: impl Into<String>,
        effects: impl IntoIterator<Item = OperationEffect>,
        required: bool,
        default: Option<String>,
        base_argument: Option<String>,
    ) -> Result<Self, ToolEffectContractError> {
        let argument = argument.into();
        if argument.trim().is_empty() {
            return Err(ToolEffectContractError::EmptyArgument);
        }

        let effects = effects.into_iter().collect::<BTreeSet<_>>();
        if effects.is_empty() {
            return Err(ToolEffectContractError::NoEffects);
        }
        if let Some(default) = default.as_deref() {
            normalize_argument_path(default, Path::new("")).map_err(|()| {
                ToolEffectContractError::InvalidDefaultPath {
                    argument: argument.clone(),
                }
            })?;
        }
        if base_argument
            .as_deref()
            .is_some_and(|base_argument| base_argument.trim().is_empty())
        {
            return Err(ToolEffectContractError::EmptyBaseArgument);
        }

        Ok(Self {
            argument,
            effects,
            required,
            default,
            base_argument,
        })
    }

    pub fn argument(&self) -> &str {
        &self.argument
    }

    pub fn effects(&self) -> &BTreeSet<OperationEffect> {
        &self.effects
    }

    pub fn is_required(&self) -> bool {
        self.required
    }

    pub fn default_path(&self) -> Option<&str> {
        self.default.as_deref()
    }

    pub fn base_argument(&self) -> Option<&str> {
        self.base_argument.as_deref()
    }
}

fn validate_path_dependencies(
    contracts: &BTreeMap<String, PathArgumentContract>,
) -> Result<(), ToolEffectContractError> {
    for (argument, contract) in contracts {
        let Some(base_argument) = contract.base_argument() else {
            continue;
        };
        let Some(base) = contracts.get(base_argument) else {
            return Err(ToolEffectContractError::UndeclaredBasePathArgument {
                argument: argument.clone(),
                base_argument: base_argument.to_string(),
            });
        };
        if !base.is_required() && base.default_path().is_none() {
            return Err(ToolEffectContractError::IndeterminateBasePath {
                argument: argument.clone(),
                base_argument: base_argument.to_string(),
            });
        }
    }

    let mut visiting = BTreeSet::new();
    for argument in contracts.keys() {
        visit_path_dependencies(argument, contracts, &mut visiting)?;
    }
    Ok(())
}

fn visit_path_dependencies(
    argument: &str,
    contracts: &BTreeMap<String, PathArgumentContract>,
    visiting: &mut BTreeSet<String>,
) -> Result<(), ToolEffectContractError> {
    if !visiting.insert(argument.to_string()) {
        return Err(ToolEffectContractError::CyclicPathDependency {
            argument: argument.to_string(),
        });
    }
    if let Some(base_argument) = contracts
        .get(argument)
        .and_then(PathArgumentContract::base_argument)
    {
        visit_path_dependencies(base_argument, contracts, visiting)?;
    }
    visiting.remove(argument);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEffectContract {
    arguments: BTreeSet<String>,
    effects: BTreeSet<OperationEffect>,
    path_arguments: BTreeMap<String, PathArgumentContract>,
}

impl ToolEffectContract {
    pub fn new(
        arguments: impl IntoIterator<Item = String>,
        effects: impl IntoIterator<Item = OperationEffect>,
        path_arguments: impl IntoIterator<Item = PathArgumentContract>,
    ) -> Result<Self, ToolEffectContractError> {
        let mut argument_set = BTreeSet::new();
        for argument in arguments {
            if argument.trim().is_empty() {
                return Err(ToolEffectContractError::EmptyArgument);
            }
            if !argument_set.insert(argument.clone()) {
                return Err(ToolEffectContractError::DuplicateArgument(argument));
            }
        }

        let effects = effects.into_iter().collect::<BTreeSet<_>>();
        let mut path_argument_map = BTreeMap::new();
        for path_argument in path_arguments {
            let name = path_argument.argument().to_string();
            if !argument_set.contains(&name) {
                return Err(ToolEffectContractError::UndeclaredPathArgument { argument: name });
            }
            if path_argument_map
                .insert(name.clone(), path_argument)
                .is_some()
            {
                return Err(ToolEffectContractError::DuplicatePathArgument(name));
            }
        }

        validate_path_dependencies(&path_argument_map)?;

        if effects.is_empty() && path_argument_map.is_empty() {
            return Err(ToolEffectContractError::NoEffects);
        }

        Ok(Self {
            arguments: argument_set,
            effects,
            path_arguments: path_argument_map,
        })
    }

    pub fn arguments(&self) -> &BTreeSet<String> {
        &self.arguments
    }

    pub fn effects(&self) -> &BTreeSet<OperationEffect> {
        &self.effects
    }

    pub fn path_arguments(&self) -> &BTreeMap<String, PathArgumentContract> {
        &self.path_arguments
    }

    pub fn normalize(
        &self,
        arguments: &serde_json::Map<String, serde_json::Value>,
        workspace_root: &Path,
    ) -> Result<NormalizedOperationEffects, OperationEffectNormalizationError> {
        for argument in arguments.keys() {
            if !self.arguments.contains(argument) {
                return Err(OperationEffectNormalizationError::UnknownArgument {
                    argument: argument.clone(),
                });
            }
        }

        let mut normalized = NormalizedOperationEffects::default();
        for effect in &self.effects {
            normalized.insert(*effect, workspace_root.to_path_buf());
        }

        let mut resolving = BTreeSet::new();
        for contract in self.path_arguments.values() {
            self.resolve_path_argument(
                contract,
                arguments,
                workspace_root,
                &mut normalized,
                &mut resolving,
            )?;
        }

        if normalized.is_empty() {
            Err(OperationEffectNormalizationError::NoEffects)
        } else {
            Ok(normalized)
        }
    }

    fn resolve_path_argument(
        &self,
        contract: &PathArgumentContract,
        arguments: &serde_json::Map<String, serde_json::Value>,
        workspace_root: &Path,
        normalized: &mut NormalizedOperationEffects,
        resolving: &mut BTreeSet<String>,
    ) -> Result<Vec<PathBuf>, OperationEffectNormalizationError> {
        if !resolving.insert(contract.argument.clone()) {
            return Err(OperationEffectNormalizationError::InvalidPathDependency {
                argument: contract.argument.clone(),
            });
        }

        let raw_paths = match arguments.get(&contract.argument) {
            None | Some(serde_json::Value::Null) => {
                if let Some(default) = &contract.default {
                    vec![default.as_str()]
                } else if contract.required {
                    resolving.remove(&contract.argument);
                    return Err(
                        OperationEffectNormalizationError::MissingRequiredPathArgument {
                            argument: contract.argument.clone(),
                        },
                    );
                } else {
                    Vec::new()
                }
            }
            Some(serde_json::Value::String(path)) => vec![path.as_str()],
            Some(serde_json::Value::Array(paths)) => {
                let mut raw_paths = Vec::with_capacity(paths.len());
                for path in paths {
                    let serde_json::Value::String(path) = path else {
                        resolving.remove(&contract.argument);
                        return Err(OperationEffectNormalizationError::InvalidPathValue {
                            argument: contract.argument.clone(),
                        });
                    };
                    raw_paths.push(path.as_str());
                }
                raw_paths
            }
            Some(_) => {
                resolving.remove(&contract.argument);
                return Err(OperationEffectNormalizationError::InvalidPathValue {
                    argument: contract.argument.clone(),
                });
            }
        };

        if raw_paths.is_empty() {
            resolving.remove(&contract.argument);
            return Ok(Vec::new());
        }

        let base_paths = if let Some(base_argument) = &contract.base_argument {
            let base_contract = self.path_arguments.get(base_argument).ok_or_else(|| {
                OperationEffectNormalizationError::InvalidPathDependency {
                    argument: contract.argument.clone(),
                }
            })?;
            self.resolve_path_argument(
                base_contract,
                arguments,
                workspace_root,
                normalized,
                resolving,
            )?
        } else {
            vec![workspace_root.to_path_buf()]
        };

        if base_paths.is_empty() {
            return Err(OperationEffectNormalizationError::InvalidPathDependency {
                argument: contract.argument.clone(),
            });
        }

        let mut paths = Vec::with_capacity(raw_paths.len() * base_paths.len());
        for raw in raw_paths {
            for base in &base_paths {
                let path = normalize_argument_path(raw, base).map_err(|()| {
                    OperationEffectNormalizationError::UnsupportedPathSyntax {
                        argument: contract.argument.clone(),
                    }
                })?;
                for effect in &contract.effects {
                    normalized.insert(*effect, path.clone());
                }
                paths.push(path);
            }
        }
        resolving.remove(&contract.argument);
        Ok(paths)
    }
}

fn normalize_argument_path(raw: &str, workspace_root: &Path) -> Result<PathBuf, ()> {
    validate_path_text(raw)?;
    let portable = raw.replace('\\', "/");

    // On non-Windows platforms, reject Windows drive prefixes (e.g., C:/) as foreign syntax.
    // On Windows, allow native drive-absolute paths and let WorkspaceBoundary classify in/out-of-workspace.
    #[cfg(not(target_os = "windows"))]
    {
        if has_windows_drive_prefix(&portable) {
            return Err(());
        }
    }

    let path = PathBuf::from(portable);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(workspace_root.join(path))
    }
}

fn validate_path_text(path: &str) -> Result<(), ()> {
    if path.trim().is_empty()
        || path.contains('\0')
        || path.starts_with('~')
        || path.starts_with('$')
        || path.starts_with('%')
    {
        return Err(());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NormalizedOperationEffects {
    paths: BTreeMap<OperationEffect, BTreeSet<PathBuf>>,
}

impl NormalizedOperationEffects {
    fn insert(&mut self, effect: OperationEffect, path: PathBuf) {
        self.paths.entry(effect).or_default().insert(path);
    }

    pub fn paths_for(&self, effect: OperationEffect) -> impl Iterator<Item = &Path> {
        self.paths
            .get(&effect)
            .into_iter()
            .flat_map(|paths| paths.iter().map(PathBuf::as_path))
    }

    pub fn iter(&self) -> impl Iterator<Item = (OperationEffect, &Path)> {
        self.paths
            .iter()
            .flat_map(|(effect, paths)| paths.iter().map(move |path| (*effect, path.as_path())))
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn contract() -> ToolEffectContract {
        ToolEffectContract::new(
            ["read".into(), "write".into(), "paths".into()],
            [OperationEffect::Read],
            [
                PathArgumentContract::new("paths", [OperationEffect::Read], false, None, None)
                    .unwrap(),
                PathArgumentContract::new(
                    "read",
                    [OperationEffect::Read],
                    false,
                    Some("read.kicad_sch".into()),
                    None,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn normalizes_path_relative_to_reviewed_base_argument() {
        let contract = ToolEffectContract::new(
            ["base".into(), "child".into()],
            [],
            [
                PathArgumentContract::new("base", [OperationEffect::Read], true, None, None)
                    .unwrap(),
                PathArgumentContract::new(
                    "child",
                    [OperationEffect::Write],
                    true,
                    None,
                    Some("base".into()),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let arguments = json!({ "base": "nested", "child": "child.kicad_pro" })
            .as_object()
            .unwrap()
            .clone();

        let effects = contract
            .normalize(&arguments, Path::new("/workspace/project"))
            .unwrap();

        assert!(effects
            .paths_for(OperationEffect::Write)
            .any(|path| path == Path::new("/workspace/project/nested/child.kicad_pro")));
    }

    #[test]
    fn rejects_invalid_base_argument_dependencies() {
        let undeclared = ToolEffectContract::new(
            ["child".into()],
            [],
            [PathArgumentContract::new(
                "child",
                [OperationEffect::Write],
                true,
                None,
                Some("missing".into()),
            )
            .unwrap()],
        );
        assert!(matches!(
            undeclared,
            Err(ToolEffectContractError::UndeclaredBasePathArgument { .. })
        ));

        let cyclic = ToolEffectContract::new(
            ["a".into(), "b".into()],
            [],
            [
                PathArgumentContract::new(
                    "a",
                    [OperationEffect::Write],
                    true,
                    None,
                    Some("b".into()),
                )
                .unwrap(),
                PathArgumentContract::new(
                    "b",
                    [OperationEffect::Write],
                    true,
                    None,
                    Some("a".into()),
                )
                .unwrap(),
            ],
        );
        assert!(matches!(
            cyclic,
            Err(ToolEffectContractError::CyclicPathDependency { .. })
        ));

        let empty_base = ToolEffectContract::new(
            ["base".into(), "child".into()],
            [OperationEffect::Read],
            [
                PathArgumentContract::new(
                    "base",
                    [OperationEffect::Read],
                    false,
                    Some("nested".into()),
                    None,
                )
                .unwrap(),
                PathArgumentContract::new(
                    "child",
                    [OperationEffect::Write],
                    true,
                    None,
                    Some("base".into()),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let arguments = json!({ "base": [], "child": "child.kicad_pro" });
        assert!(matches!(
            empty_base.normalize(
                arguments.as_object().unwrap(),
                Path::new("/workspace/project")
            ),
            Err(OperationEffectNormalizationError::InvalidPathDependency { .. })
        ));
    }

    #[test]
    fn normalizes_implicit_default_and_multi_path_effects() {
        let root = Path::new("/workspace/project");
        let arguments = json!({
            "paths": ["child/one.kicad_sch", "child/two.kicad_sch"]
        })
        .as_object()
        .unwrap()
        .clone();

        let effects = contract().normalize(&arguments, root).unwrap();

        assert!(effects
            .paths_for(OperationEffect::Read)
            .any(|path| path == root));
        assert!(effects
            .paths_for(OperationEffect::Read)
            .any(|path| { path == root.join("read.kicad_sch") }));
        assert!(effects
            .paths_for(OperationEffect::Read)
            .any(|path| { path == root.join("child/one.kicad_sch") }));
        assert!(effects
            .paths_for(OperationEffect::Read)
            .any(|path| { path == root.join("child/two.kicad_sch") }));
    }

    #[test]
    fn rejects_unknown_and_non_string_path_arguments() {
        let root = Path::new("/workspace/project");
        let unknown = json!({ "paths": [], "undeclared": "value" });
        assert!(matches!(
            contract().normalize(unknown.as_object().unwrap(), root),
            Err(OperationEffectNormalizationError::UnknownArgument { .. })
        ));

        let non_string = json!({ "paths": [42] });
        assert!(matches!(
            contract().normalize(non_string.as_object().unwrap(), root),
            Err(OperationEffectNormalizationError::InvalidPathValue { .. })
        ));
    }

    #[test]
    fn rejects_nested_path_arrays() {
        let root = Path::new("/workspace/project");
        let argument = json!({ "paths": [["nested.kicad_sch"]] });
        assert!(matches!(
            contract().normalize(argument.as_object().unwrap(), root),
            Err(OperationEffectNormalizationError::InvalidPathValue { argument: _ })
        ));
    }

    #[test]
    fn rejects_alternate_path_syntax_without_echoing_the_value() {
        let root = Path::new("/workspace/project");
        for raw in [
            "~/.ssh/authorized_keys",
            "$HOME/authorized_keys",
            "%USERPROFILE%/authorized_keys",
            r"C:\Users\example\authorized_keys",
        ] {
            let argument = json!({ "paths": [raw] });
            let error = contract()
                .normalize(argument.as_object().unwrap(), root)
                .unwrap_err();
            assert_eq!(
                error,
                OperationEffectNormalizationError::UnsupportedPathSyntax {
                    argument: "paths".into()
                }
            );
            assert!(!error.to_string().contains("authorized_keys"));
        }
    }
}
