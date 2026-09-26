-- Explicit authorization authority, persisted separately from the
-- transport-era `sessions` rows of 0001.
--
-- Additive by construction: nothing here drops, renames, or rewrites an
-- existing table, and the legacy `sessions` table is left intact so
-- pre-migration revocation/TTL history and the audit references that point
-- at a `session_id` all keep resolving. `access_grants` is what authority
-- decisions are made from; see docs/architecture/session-lifecycle.md.

CREATE TABLE access_grants (
    grant_id TEXT PRIMARY KEY,
    -- The transport-era subject record this grant answers. Correlation only:
    -- it carries no authority of its own.
    subject_session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    remote_principal TEXT NOT NULL,
    -- `unverified` is the only value this build can assert; see
    -- companion_core::PrincipalAssurance.
    principal_assurance TEXT NOT NULL,
    workspace_ids TEXT NOT NULL,
    capability_profile TEXT NOT NULL,
    effective_capabilities TEXT NOT NULL,
    task_scope TEXT NOT NULL,
    -- `standing` or `one_shot`.
    grant_kind TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    approved_at TEXT,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT,
    consumed_at TEXT,
    -- The single lease a `one_shot` grant has cut; NULL otherwise.
    issued_lease_id TEXT,
    risk_policy_version INTEGER NOT NULL,
    approval_policy TEXT NOT NULL,
    -- pending_approval | active | suspended | expired | revoked | consumed
    status TEXT NOT NULL,
    -- Non-NULL only for grants derived from a pre-migration `sessions` row,
    -- and unique so re-running the migration updates the same grant instead
    -- of forking a second one with its own authority.
    migrated_from_session_id TEXT UNIQUE,
    -- Honest provenance note, including "we never recorded a revocation
    -- timestamp" where that is the truth.
    migration_note TEXT
);

CREATE TABLE authorization_leases (
    lease_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    subject_session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    remote_principal TEXT NOT NULL,
    principal_assurance TEXT NOT NULL,
    workspace_ids TEXT NOT NULL,
    capabilities TEXT NOT NULL,
    task_scope TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    -- Never later than the issuing grant's `expires_at`; enforced in
    -- companion_core::AuthorizationLease.
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    consumed_by_operation TEXT
);

CREATE INDEX idx_access_grants_status ON access_grants(status);
CREATE INDEX idx_access_grants_subject ON access_grants(subject_session_id);
CREATE INDEX idx_access_grants_device ON access_grants(device_id);
CREATE INDEX idx_authorization_leases_grant ON authorization_leases(grant_id);
