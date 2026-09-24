use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

use crate::error::StorageError;

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(include_str!("../migrations/0001_init.sql"))])
}

/// Validates the file is a readable SQLite database, then applies any
/// pending migrations. A garbage/corrupt file fails at the validity check
/// with [`StorageError::DbUnreadable`] rather than a confusing migration
/// error.
pub fn run_migrations(conn: &mut Connection) -> Result<(), StorageError> {
    conn.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
        .map_err(|e| StorageError::DbUnreadable(e.to_string()))?;

    migrations()
        .to_latest(conn)
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;
    Ok(())
}
