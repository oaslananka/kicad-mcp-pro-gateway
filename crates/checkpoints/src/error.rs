use companion_core::CompanionError;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint not found")]
    NotFound,
    #[error("checkpoint belongs to a different workspace than the one given for restore")]
    WorkspaceMismatch,
    #[error("checkpoint snapshot data is missing on disk; refusing to restore")]
    SnapshotMissing,
    #[error("filesystem error: {0}")]
    Io(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl CompanionError for CheckpointError {
    fn code(&self) -> &'static str {
        match self {
            CheckpointError::NotFound => "CHECKPOINT_NOT_FOUND",
            CheckpointError::WorkspaceMismatch => "CHECKPOINT_WORKSPACE_MISMATCH",
            CheckpointError::SnapshotMissing => "CHECKPOINT_SNAPSHOT_MISSING",
            CheckpointError::Io(_) => "CHECKPOINT_IO",
            CheckpointError::Storage(_) => "CHECKPOINT_STORAGE",
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}
