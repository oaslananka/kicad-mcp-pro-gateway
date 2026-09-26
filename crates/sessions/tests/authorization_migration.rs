//! Migration evidence for the authorization model: a persisted
//! transport-era `sessions` row must become explicit authority that survives
//! a process restart, and an unknown or corrupt row must produce none.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use companion_core::{
    AuthorizationStatus, CapabilityProfile, Clock, DeviceId, FakeClock, Session, SessionId,
    SessionStatus, WorkspaceId,
};
use companion_sessions::{
    migrate_legacy_sessions, AuthorizationEvent, AuthorizationRepository, GrantTransition,
    SessionRepository,
};
use companion_storage::Storage;
use time::{Duration, OffsetDateTime};

fn legacy_session(status: SessionStatus, approved: bool) -> Session {
    Session {
        session_id: SessionId::new(),
        device_id: DeviceId::new(),
        remote_principal: "agent:legacy".into(),
        workspace_ids: BTreeSet::from([WorkspaceId::new()]),
        capability_profile: CapabilityProfile::Inspect,
        effective_capabilities: CapabilityProfile::Inspect.effective_capabilities(),
        task_scope: "legacy task".into(),
        issued_at: OffsetDateTime::UNIX_EPOCH,
        approved_at: approved.then_some(OffsetDateTime::UNIX_EPOCH),
        expires_at: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
        risk_policy_version: 1,
        approval_policy: companion_core::ApprovalPolicy::Standard,
        status,
    }
}

/// Mirrors what a daemon start does: open storage, migrate, then drop
/// everything so the next call is a genuine cold open of the same
/// directory.
fn start_and_migrate(data_dir: &Path) {
    let storage = Arc::new(Storage::open(data_dir).unwrap());
    let session_repo = SessionRepository::new(Arc::clone(&storage));
    let authorization_repo = AuthorizationRepository::new(storage);
    let report = migrate_legacy_sessions(&session_repo, &authorization_repo).unwrap();
    if !report.refused_session_ids.is_empty() {
        // Fail-closed rows are reported, never silently upgraded.
        assert!(
            report.grants_written
                + report.rows_without_authority
                + report.refused_session_ids.len()
                > 0
        );
    }
}

fn load_grant(data_dir: &Path, subject: SessionId) -> Option<companion_core::AccessGrant> {
    let storage = Arc::new(Storage::open(data_dir).unwrap());
    AuthorizationRepository::new(storage)
        .load_grant_for_subject(subject)
        .unwrap()
}

#[test]
fn active_expired_and_revoked_legacy_rows_migrate_and_survive_a_process_restart() {
    let dir = tempfile::tempdir().unwrap().keep();
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);

    let active = legacy_session(SessionStatus::Active, true);
    let expired = legacy_session(SessionStatus::Expired, true);
    let revoked = legacy_session(SessionStatus::Revoked, true);
    let connected = legacy_session(SessionStatus::Connected, false);
    {
        let storage = Arc::new(Storage::open(&dir).unwrap());
        let session_repo = SessionRepository::new(Arc::clone(&storage));
        for session in [&active, &expired, &revoked, &connected] {
            session_repo.save(session).unwrap();
        }
    }

    // First daemon start: migrate, then exit.
    start_and_migrate(&dir);

    // Second daemon start: a cold open of the same database file.
    let reloaded_active = load_grant(&dir, active.session_id).expect("active migrated");
    let reloaded_expired = load_grant(&dir, expired.session_id).expect("expired migrated");
    let reloaded_revoked = load_grant(&dir, revoked.session_id).expect("revoked migrated");

    assert_eq!(reloaded_active.status, AuthorizationStatus::Active);
    assert!(reloaded_active.is_usable_at(clock.now()));
    assert_eq!(reloaded_expired.status, AuthorizationStatus::Expired);
    assert!(!reloaded_expired.is_usable_at(clock.now()));
    assert_eq!(reloaded_revoked.status, AuthorizationStatus::Revoked);
    assert!(!reloaded_revoked.is_usable_at(clock.now()));
    assert!(reloaded_revoked.is_terminal());
    assert_eq!(
        reloaded_revoked.migrated_from_session_id,
        Some(revoked.session_id),
        "audit history stays linked to the row the revocation came from"
    );
    assert!(
        reloaded_revoked.revocation_reason.is_some(),
        "the revocation fact survives the migration"
    );
    assert!(
        load_grant(&dir, connected.session_id).is_none(),
        "a transport-era connection record grants no authority"
    );

    // A revoked grant is still revoked after a restart, and no restart can
    // bring it back.
    let result = reloaded_revoked.transition(&AuthorizationEvent::Approve, &clock);
    assert!(result.is_err());
    assert_eq!(
        load_grant(&dir, revoked.session_id).unwrap().status,
        AuthorizationStatus::Revoked
    );
}

#[test]
fn repeated_daemon_starts_do_not_fork_or_duplicate_authority() {
    let dir = tempfile::tempdir().unwrap().keep();
    let active = legacy_session(SessionStatus::Active, true);
    {
        let storage = Arc::new(Storage::open(&dir).unwrap());
        SessionRepository::new(Arc::clone(&storage))
            .save(&active)
            .unwrap();
    }

    start_and_migrate(&dir);
    let first = load_grant(&dir, active.session_id).unwrap();
    start_and_migrate(&dir);
    start_and_migrate(&dir);
    let third = load_grant(&dir, active.session_id).unwrap();

    assert_eq!(first, third);
    let storage = Arc::new(Storage::open(&dir).unwrap());
    let grants = AuthorizationRepository::new(storage)
        .list_all_grants()
        .unwrap();
    assert_eq!(grants.len(), 1, "three restarts, one grant");
}

#[test]
fn a_grant_revoked_after_migration_survives_the_next_restart() {
    let dir = tempfile::tempdir().unwrap().keep();
    let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
    let active = legacy_session(SessionStatus::Active, true);
    {
        let storage = Arc::new(Storage::open(&dir).unwrap());
        let session_repo = SessionRepository::new(Arc::clone(&storage));
        let authorization_repo = AuthorizationRepository::new(storage);
        session_repo.save(&active).unwrap();
        migrate_legacy_sessions(&session_repo, &authorization_repo).unwrap();

        let grant = authorization_repo
            .load_grant_for_subject(active.session_id)
            .unwrap()
            .unwrap();
        let revoked = grant
            .transition(
                &AuthorizationEvent::Revoke {
                    reason: Some("operator revoked it".into()),
                },
                &clock,
            )
            .unwrap();
        authorization_repo.save_grant(&revoked).unwrap();
    }

    // The next start re-runs the migration over the same legacy row. The
    // already-revoked grant must not be silently restored to Active by that
    // re-run, or by anything else.
    start_and_migrate(&dir);
    let reloaded = load_grant(&dir, active.session_id).unwrap();
    assert_eq!(reloaded.status, AuthorizationStatus::Revoked);
    assert!(!reloaded.is_usable_at(clock.now()));
    assert_eq!(
        reloaded.revocation_reason.as_deref(),
        Some("operator revoked it")
    );
}

#[test]
fn a_corrupt_legacy_row_ends_the_migration_with_no_authority_at_all() {
    let dir = tempfile::tempdir().unwrap().keep();
    let mut corrupt = legacy_session(SessionStatus::Active, false);
    corrupt.task_scope = "active but never approved".into();
    {
        let storage = Arc::new(Storage::open(&dir).unwrap());
        SessionRepository::new(Arc::clone(&storage))
            .save(&corrupt)
            .unwrap();
    }

    let storage = Arc::new(Storage::open(&dir).unwrap());
    let report = migrate_legacy_sessions(
        &SessionRepository::new(Arc::clone(&storage)),
        &AuthorizationRepository::new(Arc::clone(&storage)),
    )
    .unwrap();
    assert_eq!(report.grants_written, 0);
    assert_eq!(report.refused_session_ids.len(), 1);
    assert!(report.refused_session_ids[0].contains("no approval"));
    assert_eq!(report.without_authority(), 1);
    drop(storage);

    assert!(
        load_grant(&dir, corrupt.session_id).is_none(),
        "a corrupt row can never authorize anything, now or after a restart"
    );
}
