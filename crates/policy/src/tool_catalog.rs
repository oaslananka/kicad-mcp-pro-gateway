use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ToolCatalogError {
    #[error("tool catalog snapshot is malformed toml: {0}")]
    Malformed(String),
    #[error("tool catalog snapshot has a duplicate tool '{0}'")]
    DuplicateTool(String),
    #[error("tool catalog snapshot contains an empty tool name")]
    EmptyToolName,
    #[error("generated tools reference does not declare 'Total public tools'")]
    MissingDeclaredCount,
    #[error("generated tools reference declares {declared} public tools but parsed {parsed}")]
    DeclaredCountMismatch { declared: usize, parsed: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCatalogSnapshot {
    pub source_repository: String,
    pub source_ref: String,
    pub source_sha: String,
    tools: Vec<String>,
}

impl ToolCatalogSnapshot {
    pub fn from_toml_str(source: &str) -> Result<Self, ToolCatalogError> {
        let mut snapshot: Self =
            toml::from_str(source).map_err(|e| ToolCatalogError::Malformed(e.to_string()))?;
        snapshot.validate()?;
        snapshot.tools.sort();
        Ok(snapshot)
    }
    pub fn from_tool_names<I, S>(
        source_repository: impl Into<String>,
        source_ref: impl Into<String>,
        source_sha: impl Into<String>,
        tool_names: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let tools = tool_names
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            source_repository: source_repository.into(),
            source_ref: source_ref.into(),
            source_sha: source_sha.into(),
            tools,
        }
    }

    pub fn embedded() -> Self {
        Self::from_toml_str(include_str!("../assets/upstream_tool_snapshot.toml"))
            .expect("embedded upstream tool snapshot is validated by policy tests")
    }

    pub fn contains(&self, tool_name: &str) -> bool {
        self.tools
            .binary_search_by(|name| name.as_str().cmp(tool_name))
            .is_ok()
    }

    pub fn tool_names(&self) -> &[String] {
        &self.tools
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    fn validate(&self) -> Result<(), ToolCatalogError> {
        let mut seen = BTreeSet::new();
        for tool in &self.tools {
            if tool.trim().is_empty() {
                return Err(ToolCatalogError::EmptyToolName);
            }
            if !seen.insert(tool) {
                return Err(ToolCatalogError::DuplicateTool(tool.clone()));
            }
        }
        Ok(())
    }
}

impl ToolCatalogSnapshot {
    pub fn from_tools_reference_markdown(
        source_repository: impl Into<String>,
        source_ref: impl Into<String>,
        source_sha: impl Into<String>,
        markdown: &str,
    ) -> Result<Self, ToolCatalogError> {
        let declared_count = markdown
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("Total public tools: ")
                    .and_then(|value| value.strip_suffix('.'))
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .ok_or(ToolCatalogError::MissingDeclaredCount)?;

        let mut tools = BTreeSet::new();
        for line in markdown.lines() {
            let line = line.trim();
            if !line.starts_with("| `") {
                continue;
            }
            let Some(cell) = line.split('|').nth(1).map(str::trim) else {
                continue;
            };
            let Some(name) = cell
                .strip_prefix('`')
                .and_then(|value| value.strip_suffix('`'))
            else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if !tools.insert(name.to_string()) {
                return Err(ToolCatalogError::DuplicateTool(name.to_string()));
            }
        }

        if tools.is_empty() {
            return Err(ToolCatalogError::Malformed(
                "generated tools reference contained no public tool rows".into(),
            ));
        }
        if tools.len() != declared_count {
            return Err(ToolCatalogError::DeclaredCountMismatch {
                declared: declared_count,
                parsed: tools.len(),
            });
        }

        Ok(Self::from_tool_names(
            source_repository,
            source_ref,
            source_sha,
            tools,
        ))
    }

    pub fn to_toml_pretty(&self) -> Result<String, ToolCatalogError> {
        toml::to_string_pretty(self).map_err(|e| ToolCatalogError::Malformed(e.to_string()))
    }
}
