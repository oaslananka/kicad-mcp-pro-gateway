use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

use crate::error::StorageError;

/// The schema version this build expects to find, i.e. the number of applied
/// migrations. Bump this by adding a migration file, never by editing an
/// already-released one.
pub const SCHEMA_VERSION: u32 = 2;

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(include_str!("../migrations/0001_init.sql")),
        M::up(include_str!("../migrations/0002_authorization.sql")),
    ])
}

/// The version the database file itself records, kept in `PRAGMA
/// user_version` by `rusqlite_migration` as it applies each migration.
pub fn schema_version(conn: &Connection) -> Result<u32, StorageError> {
    let version = conn
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(|e| StorageError::DbUnreadable(e.to_string()))?;
    u32::try_from(version).map_err(|_| StorageError::DbUnreadable(format!("{version}")))
}

/// Validates the file is a readable SQLite database, then applies any
/// pending migrations. A garbage/corrupt file fails at the validity check
/// with [`StorageError::DbUnreadable`] rather than a confusing migration
/// error.
///
/// Fails closed in both directions: a file written by a *newer* build than
/// this one is refused outright ([`StorageError::SchemaFromNewerBuild`],
/// checked *before* anything is applied) rather than partially understood,
/// because an older build cannot know what a newer schema's rows mean. After
/// migrating, the file must be at exactly [`SCHEMA_VERSION`].
pub fn run_migrations(conn: &mut Connection) -> Result<(), StorageError> {
    conn.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
        .map_err(|e| StorageError::DbUnreadable(e.to_string()))?;

    let before = schema_version(conn)?;
    if before > SCHEMA_VERSION {
        return Err(StorageError::SchemaFromNewerBuild {
            found: before,
            supported: SCHEMA_VERSION,
        });
    }

    migrations()
        .to_latest(conn)
        .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;

    let after = schema_version(conn)?;
    if after != SCHEMA_VERSION {
        return Err(StorageError::MigrationFailed(format!(
            "expected schema version {SCHEMA_VERSION} after migration, found {after}"
        )));
    }
    Ok(())
}
