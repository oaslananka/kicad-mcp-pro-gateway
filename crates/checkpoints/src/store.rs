//! Local safe-snapshot checkpoints. V1 strategy: copy the authorized
//! workspace root into `<checkpoints_root>/<workspace_id>/<checkpoint_id>/`.
//! This is a conservative, file-copy-based approach, not a revision graph
//! (see `docs/superpowers/specs/2026-09-16-companion-v1-design.md` §11).
//!
//! Disk space: each checkpoint is a full copy of the workspace at the time
//! it was taken. A workspace with N checkpoints uses roughly N times its
//! own size in `<checkpoints_root>`. There is no automatic pruning —
//! deleting a checkpoint is always an explicit [`FilesystemCheckpointStore::delete`]
//! call for exactly one checkpoint id; there is no "delete all" operation.

use std::path::PathBuf;
use std::sync::Arc;

use companion_core::{CheckpointId, SessionId, TaskId, WorkspaceId};
use companion_storage::Storage;
use companion_workspace::WorkspaceAuthorization;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::CheckpointError;
use crate::fs_ops::{clear_dir_excluding, copy_dir_recursive};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    pub checkpoint_id: CheckpointId,
    pub workspace_id: WorkspaceId,
    pub session_id: Option<SessionId>,
    pub task_id: Option<TaskId>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub root_snapshot_path: PathBuf,
}

pub struct FilesystemCheckpointStore {
    storage: Arc<Storage>,
    checkpoints_root: PathBuf,
}

impl FilesystemCheckpointStore {
    pub fn new(storage: Arc<Storage>, checkpoints_root: PathBuf) -> Self {
        Self {
            storage,
            checkpoints_root,
        }
    }

    /// Snapshots `workspace` now. Metadata is inserted via a single SQLite
    /// statement, which is atomic by construction — there is no
    /// partially-written metadata state a crash could leave behind.
    pub fn create(
        &self,
        workspace: &WorkspaceAuthorization,
        session_id: Option<SessionId>,
        task_id: Option<TaskId>,
    ) -> Result<CheckpointMetadata, CheckpointError> {
        std::fs::create_dir_all(&self.checkpoints_root)
            .map_err(|e| CheckpointError::Io(e.to_string()))?;

        let checkpoint_id = CheckpointId::new();
        let dest = self
            .checkpoints_root
            .join(workspace.workspace_id.to_string())
            .join(checkpoint_id.to_string());

        copy_dir_recursive(&workspace.canonical_root, &dest, &self.checkpoints_root)
            .map_err(|e| CheckpointError::Io(e.to_string()))?;

        let metadata = CheckpointMetadata {
            checkpoint_id,
            workspace_id: workspace.workspace_id,
            session_id,
            task_id,
            created_at: OffsetDateTime::now_utc(),
            root_snapshot_path: dest,
        };

        self.insert_row(&metadata)?;
        Ok(metadata)
    }

    pub fn list(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<CheckpointMetadata>, CheckpointError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| CheckpointError::Storage("mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT checkpoint_id, workspace_id, session_id, task_id, created_at, root_snapshot_path \
                 FROM checkpoints WHERE workspace_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| CheckpointError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![workspace_id.to_string()], row_to_raw)
            .map_err(|e| CheckpointError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(parse_raw(
                row.map_err(|e| CheckpointError::Storage(e.to_string()))?,
            )?);
        }
        Ok(out)
    }

    pub fn get(
        &self,
        checkpoint_id: CheckpointId,
    ) -> Result<Option<CheckpointMetadata>, CheckpointError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| CheckpointError::Storage("mutex poisoned".into()))?;
        let result = conn.query_row(
            "SELECT checkpoint_id, workspace_id, session_id, task_id, created_at, root_snapshot_path \
             FROM checkpoints WHERE checkpoint_id = ?1",
            rusqlite::params![checkpoint_id.to_string()],
            row_to_raw,
        );
        match result {
            Ok(raw) => parse_raw(raw).map(Some),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(CheckpointError::Storage(e.to_string())),
        }
    }

    /// Restores `workspace`'s contents from `checkpoint_id`'s snapshot.
    /// Fails explicitly — never silently no-ops — when the checkpoint
    /// belongs to a different workspace or its snapshot data is missing
    /// from disk.
    pub fn restore(
        &self,
        checkpoint_id: CheckpointId,
        workspace: &WorkspaceAuthorization,
    ) -> Result<(), CheckpointError> {
        let metadata = self.get(checkpoint_id)?.ok_or(CheckpointError::NotFound)?;
        if metadata.workspace_id != workspace.workspace_id {
            return Err(CheckpointError::WorkspaceMismatch);
        }
        if !metadata.root_snapshot_path.exists() {
            return Err(CheckpointError::SnapshotMissing);
        }

        clear_dir_excluding(&workspace.canonical_root, &self.checkpoints_root)
            .map_err(|e| CheckpointError::Io(e.to_string()))?;
        copy_dir_recursive(
            &metadata.root_snapshot_path,
            &workspace.canonical_root,
            &self.checkpoints_root,
        )
        .map_err(|e| CheckpointError::Io(e.to_string()))?;
        Ok(())
    }

    /// Deletes exactly one checkpoint's snapshot data and metadata. There
    /// is deliberately no bulk "delete all" — checkpoint history is never
    /// silently erased in aggregate.
    pub fn delete(&self, checkpoint_id: CheckpointId) -> Result<(), CheckpointError> {
        let metadata = self.get(checkpoint_id)?.ok_or(CheckpointError::NotFound)?;
        if metadata.root_snapshot_path.exists() {
            std::fs::remove_dir_all(&metadata.root_snapshot_path)
                .map_err(|e| CheckpointError::Io(e.to_string()))?;
        }
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| CheckpointError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "DELETE FROM checkpoints WHERE checkpoint_id = ?1",
            rusqlite::params![checkpoint_id.to_string()],
        )
        .map_err(|e| CheckpointError::Storage(e.to_string()))?;
        Ok(())
    }

    fn insert_row(&self, metadata: &CheckpointMetadata) -> Result<(), CheckpointError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| CheckpointError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO checkpoints (checkpoint_id, workspace_id, session_id, task_id, created_at, root_snapshot_path) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                metadata.checkpoint_id.to_string(),
                metadata.workspace_id.to_string(),
                metadata.session_id.map(|s| s.to_string()),
                metadata.task_id.map(|t| t.to_string()),
                format_rfc3339(metadata.created_at)?,
                metadata.root_snapshot_path.to_string_lossy(),
            ],
        )
        .map_err(|e| CheckpointError::Storage(e.to_string()))?;
        Ok(())
    }
}

struct RawRow {
    checkpoint_id: String,
    workspace_id: String,
    session_id: Option<String>,
    task_id: Option<String>,
    created_at: String,
    root_snapshot_path: String,
}

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawRow> {
    Ok(RawRow {
        checkpoint_id: row.get(0)?,
        workspace_id: row.get(1)?,
        session_id: row.get(2)?,
        task_id: row.get(3)?,
        created_at: row.get(4)?,
        root_snapshot_path: row.get(5)?,
    })
}

fn parse_raw(raw: RawRow) -> Result<CheckpointMetadata, CheckpointError> {
    Ok(CheckpointMetadata {
        checkpoint_id: raw
            .checkpoint_id
            .parse()
            .map_err(|e| CheckpointError::Storage(format!("{e:?}")))?,
        workspace_id: raw
            .workspace_id
            .parse()
            .map_err(|e| CheckpointError::Storage(format!("{e:?}")))?,
        session_id: raw
            .session_id
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| CheckpointError::Storage(format!("{e:?}")))?,
        task_id: raw
            .task_id
            .map(|s| s.parse())
            .transpose()
            .map_err(|e| CheckpointError::Storage(format!("{e:?}")))?,
        created_at: parse_rfc3339(&raw.created_at)?,
        root_snapshot_path: PathBuf::from(raw.root_snapshot_path),
    })
}

fn format_rfc3339(t: OffsetDateTime) -> Result<String, CheckpointError> {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| CheckpointError::Storage(e.to_string()))
}

fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, CheckpointError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| CheckpointError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (FilesystemCheckpointStore, tempfile::TempDir) {
        let data_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(data_dir.path()).unwrap());
        let checkpoints_root = data_dir.path().join("checkpoints");
        (
            FilesystemCheckpointStore::new(storage, checkpoints_root),
            data_dir,
        )
    }

    fn workspace_with_file(
        name: &str,
        contents: &str,
    ) -> (WorkspaceAuthorization, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(name), contents).unwrap();
        let workspace = WorkspaceAuthorization::new("proj".into(), dir.path()).unwrap();
        (workspace, dir)
    }

    #[test]
    fn create_copies_workspace_contents_into_the_snapshot() {
        let (store, _data_dir) = store();
        let (workspace, _ws_dir) = workspace_with_file("board.kicad_pcb", "v1");

        let metadata = store.create(&workspace, None, None).unwrap();

        let snapshot_file = metadata.root_snapshot_path.join("board.kicad_pcb");
        assert_eq!(std::fs::read_to_string(snapshot_file).unwrap(), "v1");
    }

    #[test]
    fn create_records_session_and_task_association() {
        let (store, _data_dir) = store();
        let (workspace, _ws_dir) = workspace_with_file("board.kicad_pcb", "v1");
        let session_id = SessionId::new();
        let task_id = TaskId::new();

        let metadata = store
            .create(&workspace, Some(session_id), Some(task_id))
            .unwrap();

        assert_eq!(metadata.session_id, Some(session_id));
        assert_eq!(metadata.task_id, Some(task_id));
    }

    #[test]
    fn each_checkpoint_gets_a_unique_id() {
        let (store, _data_dir) = store();
        let (workspace, _ws_dir) = workspace_with_file("board.kicad_pcb", "v1");

        let a = store.create(&workspace, None, None).unwrap();
        let b = store.create(&workspace, None, None).unwrap();

        assert_ne!(a.checkpoint_id, b.checkpoint_id);
    }

    #[test]
    fn list_returns_all_checkpoints_for_that_workspace_only() {
        let (store, _data_dir) = store();
        let (workspace_a, _dir_a) = workspace_with_file("a.kicad_pcb", "a");
        let (workspace_b, _dir_b) = workspace_with_file("b.kicad_pcb", "b");

        store.create(&workspace_a, None, None).unwrap();
        store.create(&workspace_b, None, None).unwrap();

        let for_a = store.list(workspace_a.workspace_id).unwrap();
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].workspace_id, workspace_a.workspace_id);
    }

    #[test]
    fn restore_replaces_current_workspace_contents_with_the_snapshot() {
        let (store, _data_dir) = store();
        let (workspace, ws_dir) = workspace_with_file("board.kicad_pcb", "v1");
        let checkpoint = store.create(&workspace, None, None).unwrap();

        std::fs::write(ws_dir.path().join("board.kicad_pcb"), "v2-in-progress").unwrap();
        std::fs::write(
            ws_dir.path().join("scratch.tmp"),
            "should be removed by restore",
        )
        .unwrap();

        store.restore(checkpoint.checkpoint_id, &workspace).unwrap();

        assert_eq!(
            std::fs::read_to_string(ws_dir.path().join("board.kicad_pcb")).unwrap(),
            "v1"
        );
        assert!(!ws_dir.path().join("scratch.tmp").exists());
    }

    #[test]
    fn restore_rejects_a_checkpoint_from_a_different_workspace() {
        let (store, _data_dir) = store();
        let (workspace_a, _dir_a) = workspace_with_file("a.kicad_pcb", "a");
        let (workspace_b, _dir_b) = workspace_with_file("b.kicad_pcb", "b");
        let checkpoint = store.create(&workspace_a, None, None).unwrap();

        let result = store.restore(checkpoint.checkpoint_id, &workspace_b);
        assert!(matches!(result, Err(CheckpointError::WorkspaceMismatch)));
    }

    #[test]
    fn restore_fails_explicitly_when_snapshot_data_is_missing_on_disk() {
        let (store, _data_dir) = store();
        let (workspace, _ws_dir) = workspace_with_file("board.kicad_pcb", "v1");
        let checkpoint = store.create(&workspace, None, None).unwrap();

        std::fs::remove_dir_all(&checkpoint.root_snapshot_path).unwrap();

        let result = store.restore(checkpoint.checkpoint_id, &workspace);
        assert!(matches!(result, Err(CheckpointError::SnapshotMissing)));
    }

    #[test]
    fn delete_removes_only_the_specified_checkpoint() {
        let (store, _data_dir) = store();
        let (workspace, _ws_dir) = workspace_with_file("board.kicad_pcb", "v1");
        let a = store.create(&workspace, None, None).unwrap();
        let b = store.create(&workspace, None, None).unwrap();

        store.delete(a.checkpoint_id).unwrap();

        assert!(store.get(a.checkpoint_id).unwrap().is_none());
        assert!(store.get(b.checkpoint_id).unwrap().is_some());
        assert!(!a.root_snapshot_path.exists());
        assert!(b.root_snapshot_path.exists());
    }

    #[test]
    fn checkpoints_directory_nested_in_workspace_never_recurses_into_itself() {
        // A pathological but legal configuration: the checkpoints storage
        // root happens to live inside the workspace being snapshotted.
        // copy_dir_recursive must skip it, not recurse into an
        // ever-deepening copy of its own prior snapshots.
        let data_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(data_dir.path()).unwrap());

        let workspace_dir = tempfile::tempdir().unwrap();
        std::fs::write(workspace_dir.path().join("board.kicad_pcb"), "v1").unwrap();
        let checkpoints_root = workspace_dir.path().join(".companion-checkpoints");
        std::fs::create_dir_all(&checkpoints_root).unwrap();

        let workspace = WorkspaceAuthorization::new("proj".into(), workspace_dir.path()).unwrap();
        let store = FilesystemCheckpointStore::new(storage, checkpoints_root.clone());

        let first = store.create(&workspace, None, None).unwrap();
        // A second checkpoint must not contain a copy of the first
        // checkpoint's snapshot directory (which lives under
        // checkpoints_root, inside the workspace).
        let second = store.create(&workspace, None, None).unwrap();

        let leaked_nested_copy = second.root_snapshot_path.join(".companion-checkpoints");
        assert!(
            !leaked_nested_copy.exists(),
            "second snapshot must not contain the checkpoints root itself"
        );
        assert_eq!(
            std::fs::read_to_string(first.root_snapshot_path.join("board.kicad_pcb")).unwrap(),
            "v1"
        );
    }
}
