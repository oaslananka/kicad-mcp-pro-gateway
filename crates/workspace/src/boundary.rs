//! Canonical workspace path boundary enforcement.
//!
//! [`WorkspaceAuthorization::resolve_within`] is the only sanctioned way to
//! check whether a remote-requested path lands inside an authorized
//! workspace. It never uses string-prefix comparison
//! (`path.starts_with(root_string)`), which is vulnerable to sibling
//! directory collisions like `C:\project` vs `C:\project-evil`. Instead it
//! canonicalizes the longest existing ancestor of the requested path
//! (resolving any symlinks along the way) and compares path *components*
//! against the workspace's own canonicalized root.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use companion_core::{CompanionError, WorkspaceId};
use time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace root must be an absolute path")]
    RelativeRoot,
    #[error("workspace root does not exist or is not accessible: {0}")]
    RootNotFound(String),
    #[error("requested path escapes the authorized workspace root")]
    PathEscapesRoot,
    #[error(
        "requested path resolves through a symlink that escapes the authorized workspace root"
    )]
    SymlinkEscapesRoot,
}

impl CompanionError for WorkspaceError {
    fn code(&self) -> &'static str {
        match self {
            WorkspaceError::RelativeRoot => "WORKSPACE_RELATIVE_ROOT",
            WorkspaceError::RootNotFound(_) => "WORKSPACE_ROOT_NOT_FOUND",
            WorkspaceError::PathEscapesRoot => "WORKSPACE_PATH_ESCAPES_ROOT",
            WorkspaceError::SymlinkEscapesRoot => "WORKSPACE_SYMLINK_ESCAPES_ROOT",
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceAuthorization {
    pub workspace_id: WorkspaceId,
    pub display_name: String,
    pub canonical_root: PathBuf,
    pub created_at: OffsetDateTime,
    pub enabled: bool,
}

impl WorkspaceAuthorization {
    /// Authorizes `root` as a workspace. `root` must be an absolute,
    /// existing path; it is canonicalized immediately so every later
    /// containment check compares against the real, symlink-resolved root.
    pub fn new(display_name: String, root: &Path) -> Result<Self, WorkspaceError> {
        if root.is_relative() {
            return Err(WorkspaceError::RelativeRoot);
        }
        let canonical_root =
            dunce::canonicalize(root).map_err(|e| WorkspaceError::RootNotFound(e.to_string()))?;

        Ok(Self {
            workspace_id: WorkspaceId::new(),
            display_name,
            canonical_root,
            created_at: OffsetDateTime::now_utc(),
            enabled: true,
        })
    }
}

/// Resolves a remote-requested path against an authorized workspace root,
/// failing if it escapes the root by traversal, sibling-directory
/// collision, or symlink.
pub trait WorkspaceBoundary {
    fn resolve_within(&self, requested: &Path) -> Result<PathBuf, WorkspaceError>;
}

impl WorkspaceBoundary for WorkspaceAuthorization {
    fn resolve_within(&self, requested: &Path) -> Result<PathBuf, WorkspaceError> {
        let normalized = lexical_normalize(requested);
        let (existing_prefix, remaining) = split_existing_prefix(&normalized);

        let canonical_existing = if existing_prefix.as_os_str().is_empty() {
            self.canonical_root.clone()
        } else {
            dunce::canonicalize(&existing_prefix)
                .map_err(|e| WorkspaceError::RootNotFound(e.to_string()))?
        };

        let candidate = if remaining.as_os_str().is_empty() {
            canonical_existing
        } else {
            canonical_existing.join(&remaining)
        };

        if !is_contained(&self.canonical_root, &candidate) {
            return Err(
                if symlink_inside_workspace(&self.canonical_root, &existing_prefix) {
                    WorkspaceError::SymlinkEscapesRoot
                } else {
                    WorkspaceError::PathEscapesRoot
                },
            );
        }

        Ok(candidate)
    }
}

/// Resolves `.`/`..` components purely syntactically (no filesystem
/// access), so a not-yet-existing target path can still be checked for
/// traversal sequences before anything is created.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

/// Splits `path` into the longest existing ancestor and the remaining
/// (not-yet-existing) trailing components.
fn split_existing_prefix(path: &Path) -> (PathBuf, PathBuf) {
    let mut existing = path.to_path_buf();
    let mut remaining_parts: Vec<OsString> = Vec::new();

    loop {
        if existing.as_os_str().is_empty() || existing.exists() {
            break;
        }
        let Some(file_name) = existing.file_name().map(|s| s.to_os_string()) else {
            break;
        };
        if !existing.pop() {
            break;
        }
        remaining_parts.push(file_name);
    }

    remaining_parts.reverse();
    let mut remaining = PathBuf::new();
    for part in remaining_parts {
        remaining.push(part);
    }
    (existing, remaining)
}

/// Component-wise containment check — never a string-prefix check, which
/// would incorrectly accept `C:\project-evil` as being inside `C:\project`.
fn is_contained(root: &Path, candidate: &Path) -> bool {
    let root_components: Vec<Component> = root.components().collect();
    let candidate_components: Vec<Component> = candidate.components().collect();
    if candidate_components.len() < root_components.len() {
        return false;
    }
    candidate_components[..root_components.len()] == root_components[..]
}

fn symlink_inside_workspace(root: &Path, path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        let parent = current.clone();
        current.push(component.as_os_str());

        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            continue;
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }

        // Ignore aliases in ancestors outside the authorized workspace
        // (for example macOS /var -> /private/var). A symlink is relevant
        // to the security classification only when it is traversed from a
        // parent that already resolves inside the authorized root.
        let Ok(canonical_parent) = dunce::canonicalize(&parent) else {
            continue;
        };
        if is_contained(root, &canonical_parent) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_containment_is_byte_exact_for_unicode_segments() {
        let root = PathBuf::from("workspace").join("caf\u{00e9}");
        let visually_equivalent = PathBuf::from("workspace")
            .join("cafe\u{0301}")
            .join("file.kicad_pro");

        assert!(!is_contained(&root, &visually_equivalent));
    }
}
