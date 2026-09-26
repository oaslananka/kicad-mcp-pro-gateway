//! Deterministic migration of persisted transport-era `sessions` rows into
//! explicit [`AccessGrant`] authority.
//!
//! Rules, in full:
//!
//! * `PendingApproval` / `Active` / `Suspended` / `Expired` / `Revoked`
//!   rows map to a grant in the same state, so a pre-migration revocation or
//!   expiry survives migration and stays terminal.
//! * `Unpaired` / `Paired` / `Connected` / `Disconnected` rows never carried
//!   authority. No grant is created for them: the remote must re-request and
//!   a local user must approve. This is the fail-closed direction.
//! * A row that is internally inconsistent (active without a recorded
//!   approval, no workspace, non-positive lifetime) is refused and left
//!   without a grant, so it can never authorize anything.
//! * Grant ids are derived from the legacy row id, so re-running the
//!   migration updates the same grant instead of forking a second copy of the
//!   same authority.
//! * An existing grant is never overwritten. The legacy row predates it, so
//!   re-deriving a revoked/suspended grant from a stale `Active` row would
//!   resurrect authority this build already took away.
//!
//! The migration is additive: `sessions` rows are read, never written,
//! updated, or deleted.

use companion_core::grant_from_legacy_session;

use crate::authorization_repository::AuthorizationRepository;
use crate::grant_machine::GrantError;
use crate::repository::SessionRepository;

/// What one migration pass did. `refused_session_ids` is the fail-closed
/// list: those rows produced no grant and therefore have no authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub grants_written: usize,
    /// Legacy rows that already had a grant, so the pass left them alone.
    /// Non-zero on every start after the first.
    pub grants_already_present: usize,
    /// Legacy rows that were pairing/connectivity records only.
    pub rows_without_authority: usize,
    /// Legacy rows this build refused to interpret. Each one has no grant
    /// and therefore no authority.
    pub refused_session_ids: Vec<String>,
}

impl MigrationReport {
    /// Rows that ended up with no authorization authority at all.
    pub fn without_authority(&self) -> usize {
        self.rows_without_authority + self.refused_session_ids.len()
    }
}

/// Migrates every persisted transport-era session into the authorization
/// model. Idempotent: safe to call on every daemon start, and safe to call
/// twice in a row.
///
/// **Never overwrites an existing grant.** The legacy row is older
/// information than the grant it produced: once an operator has revoked,
/// suspended, or consumed a migrated grant, re-deriving it from the stale
/// `Active` session row would resurrect authority that this build has
/// already taken away. So a row that already has a grant is left exactly as
/// it is, and the pass is a no-op for it.
pub fn migrate_legacy_sessions(
    session_repo: &SessionRepository,
    authorization_repo: &AuthorizationRepository,
) -> Result<MigrationReport, GrantError> {
    let mut report = MigrationReport::default();
    for session in session_repo.list_all()? {
        match grant_from_legacy_session(&session) {
            Ok(Some(grant)) => {
                if authorization_repo.load_grant(grant.grant_id)?.is_some() {
                    report.grants_already_present += 1;
                    continue;
                }
                authorization_repo.save_grant(&grant)?;
                report.grants_written += 1;
            }
            Ok(None) => report.rows_without_authority += 1,
            // Fail closed: the row keeps its history in `sessions`, and the
            // reason is reported so the operator can see why it has no
            // authority.
            Err(error) => report
                .refused_session_ids
                .push(format!("{}: {error}", session.session_id)),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use companion_core::{
        AuthorizationStatus, CapabilityProfile, Clock, DeviceId, FakeClock, Session, SessionId,
        SessionStatus, WorkspaceId,
    };
    use companion_storage::Storage;
    use time::{Duration, OffsetDateTime};

    use super::*;

    fn session_with(clock: &FakeClock, status: SessionStatus, approved: bool) -> Session {
        Session {
            session_id: companion_core::SessionId::new(),
            device_id: DeviceId::new(),
            remote_principal: "agent:legacy".into(),
            workspace_ids: BTreeSet::from([WorkspaceId::new()]),
            capability_profile: CapabilityProfile::Inspect,
            effective_capabilities: CapabilityProfile::Inspect.effective_capabilities(),
            task_scope: "legacy task".into(),
            issued_at: clock.now(),
            approved_at: approved.then_some(clock.now()),
            expires_at: clock.now() + Duration::hours(1),
            risk_policy_version: 1,
            approval_policy: companion_core::ApprovalPolicy::Standard,
            status,
        }
    }

    #[test]
    fn active_expired_and_revoked_legacy_rows_all_migrate_with_their_own_state() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let dir = tempfile::tempdir().unwrap().keep();
        let storage = Arc::new(Storage::open(&dir).unwrap());
        let session_repo = SessionRepository::new(Arc::clone(&storage));
        let authorization_repo = AuthorizationRepository::new(storage);

        let active = session_with(&clock, SessionStatus::Active, true);
        let expired = session_with(&clock, SessionStatus::Expired, true);
        let revoked = session_with(&clock, SessionStatus::Revoked, true);
        let pending = session_with(&clock, SessionStatus::PendingApproval, false);
        let suspended = session_with(&clock, SessionStatus::Suspended, true);
        let connected = session_with(&clock, SessionStatus::Connected, false);
        for session in [
            &active, &expired, &revoked, &pending, &suspended, &connected,
        ] {
            session_repo.save(session).unwrap();
        }

        let report = migrate_legacy_sessions(&session_repo, &authorization_repo).unwrap();
        assert_eq!(report.grants_written, 5);
        assert_eq!(report.grants_already_present, 0);
        assert_eq!(report.rows_without_authority, 1);
        assert!(report.refused_session_ids.is_empty());

        let grants = authorization_repo.list_all_grants().unwrap();
        let by_subject = |session: &Session| {
            grants
                .iter()
                .find(|g| g.subject_session_id == session.session_id)
                .cloned()
                .expect("grant exists")
        };
        assert_eq!(by_subject(&active).status, AuthorizationStatus::Active);
        assert_eq!(by_subject(&expired).status, AuthorizationStatus::Expired);
        assert_eq!(by_subject(&revoked).status, AuthorizationStatus::Revoked);
        assert_eq!(
            by_subject(&pending).status,
            AuthorizationStatus::PendingApproval
        );
        assert_eq!(
            by_subject(&suspended).status,
            AuthorizationStatus::Suspended
        );
        assert_eq!(
            authorization_repo
                .load_grant_for_subject(connected.session_id)
                .unwrap(),
            None,
            "a connected-but-unapproved legacy row must not gain authority"
        );

        let migrated_revocation = by_subject(&revoked);
        assert!(
            !migrated_revocation.is_usable_at(clock.now()),
            "a pre-migration revocation must survive the migration"
        );
        assert!(migrated_revocation.is_terminal());
    }

    #[test]
    fn migration_is_idempotent_across_repeated_runs() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let dir = tempfile::tempdir().unwrap().keep();
        let storage = Arc::new(Storage::open(&dir).unwrap());
        let session_repo = SessionRepository::new(Arc::clone(&storage));
        let authorization_repo = AuthorizationRepository::new(storage);
        session_repo
            .save(&session_with(&clock, SessionStatus::Active, true))
            .unwrap();

        let first = migrate_legacy_sessions(&session_repo, &authorization_repo).unwrap();
        let after_first = authorization_repo.list_all_grants().unwrap();
        let second = migrate_legacy_sessions(&session_repo, &authorization_repo).unwrap();
        let after_second = authorization_repo.list_all_grants().unwrap();

        assert_eq!(first.grants_written, 1);
        assert_eq!(second.grants_written, 0);
        assert_eq!(second.grants_already_present, 1);
        assert_eq!(
            after_first, after_second,
            "re-running must not fork authority"
        );
        assert_eq!(after_first.len(), 1);
    }

    #[test]
    fn corrupt_legacy_rows_are_refused_and_left_without_authority() {
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let dir = tempfile::tempdir().unwrap().keep();
        let storage = Arc::new(Storage::open(&dir).unwrap());
        let session_repo = SessionRepository::new(Arc::clone(&storage));
        let authorization_repo = AuthorizationRepository::new(storage);

        let mut corrupt = session_with(&clock, SessionStatus::Active, false);
        corrupt.session_id = SessionId::new();
        session_repo.save(&corrupt).unwrap();
        session_repo
            .save(&session_with(&clock, SessionStatus::Active, true))
            .unwrap();

        let report = migrate_legacy_sessions(&session_repo, &authorization_repo).unwrap();
        assert_eq!(report.grants_written, 1);
        assert_eq!(report.refused_session_ids.len(), 1);
        assert!(
            report.refused_session_ids[0].contains(&corrupt.session_id.to_string()),
            "the refused row must be reported: {:?}",
            report.refused_session_ids
        );
        assert_eq!(report.without_authority(), 1);
        assert_eq!(
            authorization_repo
                .load_grant_for_subject(corrupt.session_id)
                .unwrap(),
            None
        );
    }
}
