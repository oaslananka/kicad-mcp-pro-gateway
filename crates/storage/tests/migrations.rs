use companion_storage::Storage;

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
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing table: {expected}, have: {names:?}"
        );
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
        dir.path().join("companion.db"),
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
