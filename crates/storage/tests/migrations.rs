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
    for (table, column) in [
        ("access_grants", "verified_principal"),
        ("authorization_leases", "verified_principal"),
        ("audit_events", "principal_assurance"),
        ("audit_events", "verified_principal_issuer"),
        ("audit_events", "verified_principal_subject"),
        ("audit_events", "principal_verification_source"),
        ("audit_events", "authentication_strength"),
        ("audit_events", "risk_policy_version"),
        ("audit_events", "base_risk"),
        ("audit_events", "risk_factors_json"),
    ] {
        let sql = format!("SELECT {column} FROM {table} LIMIT 0");
        conn.prepare(&sql)
            .unwrap_or_else(|_| panic!("{table}.{column} must exist after migration"));
    }
    assert_eq!(
        SCHEMA_VERSION, 5,
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
fn reopening_a_v3_database_marks_existing_audit_rows_unverified_without_inventing_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("gateway.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(include_str!("../migrations/0001_init.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0002_authorization.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0003_verified_principal.sql"))
            .unwrap();
        conn.execute(
            "INSERT INTO audit_events (
                operation_id, timestamp, session_id, workspace_id, remote_principal,
                requested_tool, capability, risk, policy_result, approval_decision,
                execution_status, error_class, duration_ms
             ) VALUES (
                'op_01J00000000000000000000000', '2026-09-01T00:00:00Z', NULL, NULL,
                'agent:legacy', 'schematic.read', 'schematic.read', NULL, ?1,
                NULL, ?2, NULL, NULL
             )",
            rusqlite::params!["\"Allow\"", "\"NotExecuted\""],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 3i64).unwrap();
    }

    let storage = Storage::open(dir.path()).expect("a V3 database opens and migrates");
    let conn = storage.connection().lock().unwrap();
    assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);

    let row: (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT principal_assurance, verified_principal_issuer,
                    verified_principal_subject, principal_verification_source,
                    authentication_strength
             FROM audit_events
             WHERE operation_id = 'op_01J00000000000000000000000'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(row.0, "unverified");
    assert_eq!(row.1, None);
    assert_eq!(row.2, None);
    assert_eq!(row.3, None);
    assert_eq!(row.4, None);
}


#[test]
fn reopening_a_v4_database_adds_dynamic_risk_columns_without_rewriting_history() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("gateway.db");
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(include_str!("../migrations/0001_init.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0002_authorization.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../migrations/0003_verified_principal.sql"))
            .unwrap();
        conn.execute_batch(include_str!(
            "../migrations/0004_audit_principal_verification.sql"
        ))
        .unwrap();
        conn.execute(
            "INSERT INTO audit_events (
                operation_id, timestamp, session_id, workspace_id, remote_principal,
                requested_tool, capability, risk, policy_result, approval_decision,
                execution_status, error_class, duration_ms
             ) VALUES (
                'op_01J00000000000000000000001', '2026-09-02T00:00:00Z', NULL, NULL,
                'agent:v4', 'pcb_delete_items', 'pcb.write', ?1, ?2,
                NULL, ?3, NULL, NULL
             )",
            rusqlite::params!["\"High\"", "\"RequireApproval\"", "\"NotExecuted\""],
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 4i64).unwrap();
    }

    let storage = Storage::open(dir.path()).expect("a V4 database opens and migrates");
    let conn = storage.connection().lock().unwrap();
    assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);

    let row: (Option<i64>, Option<String>, String, String, String) = conn
        .query_row(
            "SELECT risk_policy_version, base_risk, risk_factors_json, requested_tool, risk
             FROM audit_events
             WHERE operation_id = 'op_01J00000000000000000000001'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();

    assert_eq!(row.0, None, "migration must not invent a policy version");
    assert_eq!(row.1, None, "migration must not invent a base risk");
    assert_eq!(row.2, "[]", "historical rows have no dynamic risk factors");
    assert_eq!(row.3, "pcb_delete_items");
    assert_eq!(row.4, "\"High\"", "existing effective risk is preserved");
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

/// The migrations are SQLite DDL applied by `rusqlite_migration`, but hosted
/// static analysis also runs its Transact-SQL rules over every `.sql` file, so
/// it annotates the authorization migration for a mandatory identifier-quoting
/// session option near the top of the file and for a compression clause on
/// each `CREATE TABLE`. Neither feature exists in SQLite: each is a syntax
/// error that aborts the migration, which fails the daemon closed at startup
/// rather than running. Those annotations are dispositions, not defects, and
/// this test is what keeps them from being "fixed" into a migration that
/// cannot start.
#[test]
fn sql_server_only_ddl_is_rejected_rather_than_added_to_a_sqlite_migration() {
    const MIGRATION: &str = include_str!("../migrations/0002_authorization.sql");

    let dir = tempfile::tempdir().unwrap();
    let open = |name: &str| {
        rusqlite::Connection::open(dir.path().join(name)).expect("a fresh SQLite database opens")
    };

    open("applied.db")
        .execute_batch(MIGRATION)
        .expect("the migration applies as written");

    let identifier_quoting = format!("SET QUOTED_IDENTIFIER ON;\n{MIGRATION}");
    let compression = format!(
        "{MIGRATION}\nCREATE TABLE probe (id TEXT PRIMARY KEY) WITH (DATA_COMPRESSION = PAGE);"
    );
    for (construct, sql) in [
        ("identifier-quoting session option", identifier_quoting),
        ("table compression clause", compression),
    ] {
        let error = open(&format!("{}.db", construct.replace([' ', '-'], "_")))
            .execute_batch(&sql)
            .expect_err("SQLite must refuse a Transact-SQL-only construct");
        assert!(
            error.to_string().contains("syntax error"),
            "the {construct} must be refused as invalid syntax, got: {error}"
        );
    }
}
