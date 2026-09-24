//! Workspace persistence on top of `companion-storage`.

use std::path::PathBuf;
use std::sync::Arc;

use companion_core::WorkspaceId;
use companion_storage::Storage;
use time::OffsetDateTime;

use crate::boundary::{WorkspaceAuthorization, WorkspaceError};

pub struct WorkspaceRepository {
    storage: Arc<Storage>,
}

impl WorkspaceRepository {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub fn save(&self, workspace: &WorkspaceAuthorization) -> Result<(), WorkspaceError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| WorkspaceError::RootNotFound("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO workspaces (workspace_id, display_name, canonical_root, created_at, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(workspace_id) DO UPDATE SET
                display_name = excluded.display_name,
                enabled = excluded.enabled",
            rusqlite::params![
                workspace.workspace_id.to_string(),
                workspace.display_name,
                workspace.canonical_root.to_string_lossy(),
                format_rfc3339(workspace.created_at)?,
                workspace.enabled,
            ],
        )
        .map_err(|e| WorkspaceError::RootNotFound(e.to_string()))?;
        Ok(())
    }

    pub fn load(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceAuthorization>, WorkspaceError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| WorkspaceError::RootNotFound("mutex poisoned".into()))?;
        let result = conn.query_row(
            "SELECT workspace_id, display_name, canonical_root, created_at, enabled FROM workspaces WHERE workspace_id = ?1",
            rusqlite::params![workspace_id.to_string()],
            row_to_workspace,
        );
        match result {
            Ok(workspace) => Ok(Some(workspace?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WorkspaceError::RootNotFound(e.to_string())),
        }
    }

    pub fn list(&self) -> Result<Vec<WorkspaceAuthorization>, WorkspaceError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| WorkspaceError::RootNotFound("mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare("SELECT workspace_id, display_name, canonical_root, created_at, enabled FROM workspaces")
            .map_err(|e| WorkspaceError::RootNotFound(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_workspace)
            .map_err(|e| WorkspaceError::RootNotFound(e.to_string()))?;
        let mut workspaces = Vec::new();
        for row in rows {
            workspaces.push(row.map_err(|e| WorkspaceError::RootNotFound(e.to_string()))??);
        }
        Ok(workspaces)
    }

    pub fn remove(&self, workspace_id: WorkspaceId) -> Result<(), WorkspaceError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| WorkspaceError::RootNotFound("mutex poisoned".into()))?;
        conn.execute(
            "DELETE FROM workspaces WHERE workspace_id = ?1",
            rusqlite::params![workspace_id.to_string()],
        )
        .map_err(|e| WorkspaceError::RootNotFound(e.to_string()))?;
        Ok(())
    }
}

fn row_to_workspace(
    row: &rusqlite::Row,
) -> rusqlite::Result<Result<WorkspaceAuthorization, WorkspaceError>> {
    let workspace_id: String = row.get(0)?;
    let display_name: String = row.get(1)?;
    let canonical_root: String = row.get(2)?;
    let created_at: String = row.get(3)?;
    let enabled: bool = row.get(4)?;

    Ok((|| {
        Ok(WorkspaceAuthorization {
            workspace_id: workspace_id
                .parse()
                .map_err(|e| WorkspaceError::RootNotFound(format!("{e:?}")))?,
            display_name,
            canonical_root: PathBuf::from(canonical_root),
            created_at: parse_rfc3339(&created_at)?,
            enabled,
        })
    })())
}

fn format_rfc3339(t: OffsetDateTime) -> Result<String, WorkspaceError> {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| WorkspaceError::RootNotFound(e.to_string()))
}

fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, WorkspaceError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| WorkspaceError::RootNotFound(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> WorkspaceRepository {
        let dir = tempfile::tempdir().unwrap().keep();
        let storage = Arc::new(Storage::open(&dir).unwrap());
        WorkspaceRepository::new(storage)
    }

    fn sample_workspace() -> WorkspaceAuthorization {
        let dir = tempfile::tempdir().unwrap().keep();
        WorkspaceAuthorization::new("SensorBoard".into(), &dir).unwrap()
    }

    #[test]
    fn save_then_load_round_trips() {
        let repository = repo();
        let workspace = sample_workspace();
        repository.save(&workspace).unwrap();
        let loaded = repository
            .load(workspace.workspace_id)
            .unwrap()
            .expect("workspace present");
        assert_eq!(loaded, workspace);
    }

    #[test]
    fn load_unknown_workspace_returns_none() {
        let repository = repo();
        assert!(repository.load(WorkspaceId::new()).unwrap().is_none());
    }

    #[test]
    fn list_returns_all_saved_workspaces() {
        let repository = repo();
        let a = sample_workspace();
        let b = sample_workspace();
        repository.save(&a).unwrap();
        repository.save(&b).unwrap();
        let all = repository.list().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn remove_deletes_the_workspace() {
        let repository = repo();
        let workspace = sample_workspace();
        repository.save(&workspace).unwrap();
        repository.remove(workspace.workspace_id).unwrap();
        assert!(repository.load(workspace.workspace_id).unwrap().is_none());
    }
}
