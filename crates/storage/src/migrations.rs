use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

use crate::error::StorageError;

/// The schema version this build expects to find, i.e. the number of applied
/// migrations. Bump this by adding a migration file, never by editing an
/// already-released one.
pub const SCHEMA_VERSION: u32 = 8;

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(include_str!("../migrations/0001_init.sql")),
        M::up(include_str!("../migrations/0002_authorization.sql")),
        M::up(include_str!("../migrations/0003_verified_principal.sql")),
        M::up(include_str!(
            "../migrations/0004_audit_principal_verification.sql"
        )),
        M::up(include_str!("../migrations/0005_dynamic_risk.sql")),
        M::up(include_str!("../migrations/0006_actor_replay.sql")),
        M::up(include_str!(
            "../migrations/0007_gateway_actor_challenges.sql"
        )),
        M::up_with_hook(
            include_str!("../migrations/0008_actor_clock_high_water.sql"),
            seed_actor_clock_high_water_v8,
        ),
    ])
}

/// Runs inside the *same migration transaction* as the v8 CREATE TABLE
/// and schema version bump (rusqlite_migration::M::up_with_hook).
/// A failed SELECT/INSERT aborts everything; v7 replay evidence is not
/// silently ignored after a crash between DDL and initialization.
fn seed_actor_clock_high_water_v8(
    tx: &rusqlite::Transaction<'_>,
) -> rusqlite_migration::HookResult {
    let conservative_seed: i64 = tx.query_row(
        "SELECT max(
            coalesce((SELECT max(expires_at) FROM gateway_actor_challenges), 0),
            coalesce((SELECT max(expires_at) FROM verified_actor_replay), 0)
        )",
        [],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO actor_clock_high_water (singleton, last_seen_unix)
         VALUES (1, ?1)",
        [conservative_seed],
    )?;
    Ok(())
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
