use companion_storage::{schema_version, Storage, StorageError, SCHEMA_VERSION};

#[test]
fn fresh_open_creates_all_expected_tables() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).expect("fresh open succeeds");

    let conn = storage.connection().lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    for expected in [
        "device",
        "workspaces",
        "sessions",
        "approvals",
        "audit_events",
        "settings",
        "checkpoints",
        // Authorization authority lives in its own tables, separate from the
        // transport-era `sessions` rows.
        "access_grants",
        "authorization_leases",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing table: {expected}, have: {names:?}"
        );
    }
}

#[test]
fn a_fresh_database_reports_the_current_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).expect("fresh open succeeds");
    let conn = storage.connection().lock().unwrap();
    assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
    assert_eq!(
        SCHEMA_VERSION, 2,
        "one migration per schema version; bump this with the migration"
    );
}

#[test]
fn reopening_a_v1_database_adds_the_authorization_tables_without_touching_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("gateway.db");
    {
        // Build a V1 database: apply only the 0001 migration by hand, exactly
        // as an earlier release would have left it behind.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let v1: &str = include_str!("../migrations/0001_init.sql");
        conn.execute_batch(v1).unwrap();
        conn.execute(
            "INSERT INTO sessions (session_id, device_id, remote_principal, workspace_ids, \
             capability_profile, effective_capabilities, task_scope, issued_at, approved_at, \
             expires_at, risk_policy_version, approval_policy, status) VALUES \
             ('sess_01J00000000000000000000000', 'dev_01J00000000000000000000000', 'agent:legacy', \
             '[\"ws_01J00000000000000000000000\"]', '\"Inspect\"', '[]', 'legacy task', \
             '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-09-01T01:00:00Z', 1, \
             '\"Standard\"', '\"Revoked\"')",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 1i64).unwrap();
    }

    let storage = Storage::open(dir.path()).expect("a V1 database opens and migrates");
    let conn = storage.connection().lock().unwrap();
    assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);

    let legacy_status: String = conn
        .query_row(
            "SELECT status FROM sessions WHERE session_id = 'sess_01J00000000000000000000000'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        legacy_status, "\"Revoked\"",
        "migration 0002 must be additive: the legacy row is still there, revocation intact"
    );
    let lease_count: i64 = conn
        .query_row("SELECT count(*) FROM authorization_leases", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        lease_count, 0,
        "no authority is invented by the schema change"
    );
}

#[test]
fn a_database_written_by_a_newer_build_is_refused_rather_than_partially_read() {
    let dir = tempfile::tempdir().unwrap();
    {
        let storage = Storage::open(dir.path()).expect("first open succeeds");
        let conn = storage.connection().lock().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION as i64 + 1)
            .unwrap();
    }

    let result = Storage::open(dir.path());
    match result {
        Err(StorageError::SchemaFromNewerBuild { found, supported }) => {
            assert_eq!(found, SCHEMA_VERSION + 1);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => panic!("expected SchemaFromNewerBuild, got {other:?}"),
    }
}

#[test]
fn reopening_same_directory_after_close_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    {
        let storage = Storage::open(dir.path()).expect("first open succeeds");
        drop(storage);
    }
    let storage =
        Storage::open(dir.path()).expect("second open succeeds without re-running migrations");
    let conn = storage.connection().lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'device'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn corrupted_database_file_is_reported_as_typed_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("gateway.db"),
        b"not a sqlite database, just garbage bytes",
    )
    .unwrap();

    let result = Storage::open(dir.path());
    match result {
        Err(companion_storage::StorageError::DbUnreadable(_)) => {}
        other => panic!("expected DbUnreadable, got {other:?}"),
    }
}

#[test]
fn data_persists_across_storage_reopens() {
    let dir = tempfile::tempdir().unwrap();
    {
        let storage = Storage::open(dir.path()).expect("first open succeeds");
        let conn = storage.connection().lock().unwrap();
        conn.execute(
            "INSERT INTO workspaces (workspace_id, display_name, canonical_root, created_at, enabled) VALUES ('ws_1', 'Test WS', '/tmp/root', 12345, 1)",
            [],
        )
        .unwrap();
    }

    // Re-open storage
    let storage2 = Storage::open(dir.path()).expect("second open succeeds");
    let conn2 = storage2.connection().lock().unwrap();
    let name: String = conn2
        .query_row(
            "SELECT display_name FROM workspaces WHERE workspace_id = 'ws_1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(name, "Test WS");
}
