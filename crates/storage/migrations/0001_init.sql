-- Non-secret local state. Private key material never lives in this
-- database; see docs/security/secure-storage.md.

CREATE TABLE device (
    device_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    canonical_root TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    remote_principal TEXT NOT NULL,
    workspace_ids TEXT NOT NULL,
    capability_profile TEXT NOT NULL,
    effective_capabilities TEXT NOT NULL,
    task_scope TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    approved_at TEXT,
    expires_at TEXT NOT NULL,
    risk_policy_version INTEGER NOT NULL,
    approval_policy TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    decision TEXT,
    decided_at TEXT
);

CREATE TABLE audit_events (
    operation_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT,
    workspace_id TEXT,
    remote_principal TEXT,
    requested_tool TEXT NOT NULL,
    capability TEXT,
    risk TEXT,
    policy_result TEXT NOT NULL,
    approval_decision TEXT,
    execution_status TEXT NOT NULL,
    error_class TEXT,
    duration_ms INTEGER
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    session_id TEXT,
    task_id TEXT,
    created_at TEXT NOT NULL,
    root_snapshot_path TEXT NOT NULL
);

CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_audit_events_session ON audit_events(session_id);
CREATE INDEX idx_checkpoints_workspace ON checkpoints(workspace_id);
