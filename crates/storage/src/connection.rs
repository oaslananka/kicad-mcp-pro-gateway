use std::fs::OpenOptions;
use std::path::Path;
use std::sync::Mutex;

use fs4::FileExt;
use rusqlite::Connection;

use crate::error::StorageError;
use crate::migrations::run_migrations;

/// An open, migrated database plus an exclusive advisory lock on the data
/// directory that is held for the lifetime of this handle. A second
/// [`Storage::open`] against the same directory while this handle is alive
/// fails with [`StorageError::AnotherInstanceRunning`] rather than
/// corrupting shared state.
#[derive(Debug)]
pub struct Storage {
    conn: Mutex<Connection>,
    _lock_file: std::fs::File,
}

impl Storage {
    pub fn open(data_dir: &Path) -> Result<Storage, StorageError> {
        std::fs::create_dir_all(data_dir)?;

        let lock_path = data_dir.join("gateway.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        lock_file
            .try_lock_exclusive()
            .map_err(|_| StorageError::AnotherInstanceRunning)?;

        let db_path = data_dir.join("gateway.db");
        let mut conn =
            Connection::open(&db_path).map_err(|e| StorageError::DbUnreadable(e.to_string()))?;
        run_migrations(&mut conn)?;

        Ok(Storage {
            conn: Mutex::new(conn),
            _lock_file: lock_file,
        })
    }

    pub fn connection(&self) -> &Mutex<Connection> {
        &self.conn
    }
}
