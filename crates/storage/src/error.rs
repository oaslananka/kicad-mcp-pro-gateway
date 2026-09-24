use companion_core::CompanionError;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database file is not readable or not a valid database: {0}")]
    DbUnreadable(String),

    #[error("migration failed: {0}")]
    MigrationFailed(String),

    #[error("another Gateway instance is already running against this data directory")]
    AnotherInstanceRunning,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl CompanionError for StorageError {
    fn code(&self) -> &'static str {
        match self {
            StorageError::DbUnreadable(_) => "STORAGE_DB_UNREADABLE",
            StorageError::MigrationFailed(_) => "STORAGE_MIGRATION_FAILED",
            StorageError::AnotherInstanceRunning => "STORAGE_ANOTHER_INSTANCE_RUNNING",
            StorageError::Io(_) => "STORAGE_IO",
        }
    }

    fn retryable(&self) -> bool {
        matches!(self, StorageError::AnotherInstanceRunning)
    }
}
