//! Authorization persistence, kept in its own tables so authority never has
//! to be inferred from a transport-era `sessions` row. See
//! `docs/architecture/session-lifecycle.md`.
//!
//! Complex fields (workspace id sets, capability sets, profiles, policies,
//! statuses) are stored as JSON text columns and timestamps as RFC 3339
//! text, matching [`crate::repository::SessionRepository`]. Scalar columns
//! exist for the queries that must stay cheap: "every grant for this subject",
//! "every grant with this status", "every lease of this grant".

use std::sync::Arc;

use companion_core::{
    AccessGrant, AuthorizationLease, AuthorizationPrincipal, GrantId, GrantKind, LeaseId,
    PrincipalAssurance, SessionId,
};
use companion_storage::Storage;
use time::OffsetDateTime;

use crate::grant_machine::GrantError;

pub struct AuthorizationRepository {
    storage: Arc<Storage>,
}

impl AuthorizationRepository {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// Persists a grant. `grant_id` is the primary key, so re-saving an
    /// updated grant (a migration re-run, a revoke) updates that one row and
    /// can never fork a second copy of the same authority.
    pub fn save_grant(&self, grant: &AccessGrant) -> Result<(), GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO access_grants (
                grant_id, subject_session_id, device_id, remote_principal, principal_assurance,
                workspace_ids, capability_profile, effective_capabilities, task_scope, grant_kind,
                issued_at, approved_at, expires_at, revoked_at, revocation_reason, consumed_at,
                issued_lease_id, risk_policy_version, approval_policy, status,
                migrated_from_session_id, migration_note
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)
             ON CONFLICT(grant_id) DO UPDATE SET
                subject_session_id = excluded.subject_session_id,
                device_id = excluded.device_id,
                remote_principal = excluded.remote_principal,
                principal_assurance = excluded.principal_assurance,
                workspace_ids = excluded.workspace_ids,
                capability_profile = excluded.capability_profile,
                effective_capabilities = excluded.effective_capabilities,
                task_scope = excluded.task_scope,
                grant_kind = excluded.grant_kind,
                approved_at = excluded.approved_at,
                expires_at = excluded.expires_at,
                revoked_at = excluded.revoked_at,
                revocation_reason = excluded.revocation_reason,
                consumed_at = excluded.consumed_at,
                issued_lease_id = excluded.issued_lease_id,
                risk_policy_version = excluded.risk_policy_version,
                approval_policy = excluded.approval_policy,
                status = excluded.status,
                migration_note = excluded.migration_note",
            rusqlite::params![
                grant.grant_id.to_string(),
                grant.subject_session_id.to_string(),
                grant.device_id.to_string(),
                grant.principal.name,
                to_json(&grant.principal.assurance)?,
                to_json(&grant.workspace_ids)?,
                to_json(&grant.capability_profile)?,
                to_json(&grant.effective_capabilities)?,
                grant.task_scope,
                to_json(&grant.kind)?,
                format_rfc3339(grant.issued_at)?,
                grant.approved_at.map(format_rfc3339).transpose()?,
                format_rfc3339(grant.expires_at)?,
                grant.revoked_at.map(format_rfc3339).transpose()?,
                grant.revocation_reason,
                grant.consumed_at.map(format_rfc3339).transpose()?,
                grant.issued_lease_id.map(|id| id.to_string()),
                grant.risk_policy_version,
                to_json(&grant.approval_policy)?,
                to_json(&grant.status)?,
                grant.migrated_from_session_id.map(|id| id.to_string()),
                grant.migration_note,
            ],
        )
        .map_err(|e| GrantError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn load_grant(&self, grant_id: GrantId) -> Result<Option<AccessGrant>, GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        let query = format!("{SELECT_GRANT_COLUMNS} WHERE grant_id = ?1");
        match conn.query_row(&query, rusqlite::params![grant_id.to_string()], raw_grant) {
            Ok(raw) => parse_grant(raw).map(Some),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GrantError::Storage(e.to_string())),
        }
    }

    /// The grant that authorizes a transport-era subject, if one exists.
    /// A miss means "no authority", never "assume authority".
    pub fn load_grant_for_subject(
        &self,
        subject_session_id: SessionId,
    ) -> Result<Option<AccessGrant>, GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        let query = format!(
            "{SELECT_GRANT_COLUMNS} WHERE subject_session_id = ?1 ORDER BY issued_at DESC, grant_id DESC"
        );
        match conn.query_row(
            &query,
            rusqlite::params![subject_session_id.to_string()],
            raw_grant,
        ) {
            Ok(raw) => parse_grant(raw).map(Some),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GrantError::Storage(e.to_string())),
        }
    }

    /// Every non-terminal grant for a subject: what a duplicate or replayed
    /// remote request must not be able to mint a second copy of, extend, or
    /// widen.
    pub fn list_live_grants_for_subject(
        &self,
        subject_session_id: SessionId,
    ) -> Result<Vec<AccessGrant>, GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        let query = format!(
            "{SELECT_GRANT_COLUMNS} WHERE subject_session_id = ?1 AND status IN (?2, ?3, ?4) \
             ORDER BY issued_at ASC, grant_id ASC"
        );
        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    subject_session_id.to_string(),
                    to_json(&companion_core::AuthorizationStatus::PendingApproval)?,
                    to_json(&companion_core::AuthorizationStatus::Active)?,
                    to_json(&companion_core::AuthorizationStatus::Suspended)?,
                ],
                raw_grant,
            )
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        collect_grants(rows)
    }

    /// Finds the non-terminal grant, if any, that already answers exactly the
    /// same remote request: same device, principal, task scope, workspace
    /// set, and capability profile.
    ///
    /// This is what makes a replayed or duplicated remote access request a
    /// no-op rather than a second pending grant, a widened scope, or a moved
    /// expiry. A terminal grant never matches, so a genuinely new request
    /// after a revoke/expiry is still honoured.
    pub fn find_live_request(
        &self,
        request: &AccessGrant,
    ) -> Result<Option<AccessGrant>, GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        let query = format!(
            "{SELECT_GRANT_COLUMNS} WHERE device_id = ?1 AND status IN (?2, ?3, ?4) \
             ORDER BY issued_at ASC, grant_id ASC"
        );
        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    request.device_id.to_string(),
                    to_json(&companion_core::AuthorizationStatus::PendingApproval)?,
                    to_json(&companion_core::AuthorizationStatus::Active)?,
                    to_json(&companion_core::AuthorizationStatus::Suspended)?,
                ],
                raw_grant,
            )
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        for row in rows {
            let grant = parse_grant(row.map_err(|e| GrantError::Storage(e.to_string()))?)?;
            if grant.principal == request.principal
                && grant.task_scope == request.task_scope
                && grant.workspace_ids == request.workspace_ids
                && grant.capability_profile == request.capability_profile
            {
                return Ok(Some(grant));
            }
        }
        Ok(None)
    }

    /// Every grant regardless of status, for audit/UI views.
    pub fn list_all_grants(&self) -> Result<Vec<AccessGrant>, GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(SELECT_GRANT_COLUMNS)
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], raw_grant)
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        collect_grants(rows)
    }

    pub fn save_lease(&self, lease: &AuthorizationLease) -> Result<(), GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO authorization_leases (
                lease_id, grant_id, subject_session_id, device_id, remote_principal,
                principal_assurance, workspace_ids, capabilities, task_scope, issued_at,
                expires_at, consumed_at, consumed_by_operation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(lease_id) DO UPDATE SET
                expires_at = excluded.expires_at,
                consumed_at = excluded.consumed_at,
                consumed_by_operation = excluded.consumed_by_operation",
            rusqlite::params![
                lease.lease_id.to_string(),
                lease.grant_id.to_string(),
                lease.subject_session_id.to_string(),
                lease.device_id.to_string(),
                lease.principal.name,
                to_json(&lease.principal.assurance)?,
                to_json(&lease.workspace_ids)?,
                to_json(&lease.capabilities)?,
                lease.task_scope,
                format_rfc3339(lease.issued_at)?,
                format_rfc3339(lease.expires_at)?,
                lease.consumed_at.map(format_rfc3339).transpose()?,
                lease.consumed_by_operation.map(|id| id.to_string()),
            ],
        )
        .map_err(|e| GrantError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn load_lease(&self, lease_id: LeaseId) -> Result<Option<AuthorizationLease>, GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        let query = format!("{SELECT_LEASE_COLUMNS} WHERE lease_id = ?1");
        match conn.query_row(&query, rusqlite::params![lease_id.to_string()], raw_lease) {
            Ok(raw) => parse_lease(raw).map(Some),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GrantError::Storage(e.to_string())),
        }
    }

    pub fn list_leases_for_grant(
        &self,
        grant_id: GrantId,
    ) -> Result<Vec<AuthorizationLease>, GrantError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| GrantError::Storage("mutex poisoned".into()))?;
        let query = format!("{SELECT_LEASE_COLUMNS} WHERE grant_id = ?1 ORDER BY issued_at ASC");
        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![grant_id.to_string()], raw_lease)
            .map_err(|e| GrantError::Storage(e.to_string()))?;
        let mut leases = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| GrantError::Storage(e.to_string()))?;
            leases.push(parse_lease(raw)?);
        }
        Ok(leases)
    }
}

const SELECT_GRANT_COLUMNS: &str = "SELECT grant_id, subject_session_id, device_id, remote_principal, \
     principal_assurance, workspace_ids, capability_profile, effective_capabilities, task_scope, grant_kind, \
     issued_at, approved_at, expires_at, revoked_at, revocation_reason, consumed_at, issued_lease_id, \
     risk_policy_version, approval_policy, status, migrated_from_session_id, migration_note FROM access_grants";

const SELECT_LEASE_COLUMNS: &str = "SELECT lease_id, grant_id, subject_session_id, device_id, remote_principal, \
     principal_assurance, workspace_ids, capabilities, task_scope, issued_at, expires_at, consumed_at, \
     consumed_by_operation FROM authorization_leases";

fn collect_grants(
    rows: impl Iterator<Item = rusqlite::Result<RawGrantRow>>,
) -> Result<Vec<AccessGrant>, GrantError> {
    let mut grants = Vec::new();
    for row in rows {
        let raw = row.map_err(|e| GrantError::Storage(e.to_string()))?;
        grants.push(parse_grant(raw)?);
    }
    Ok(grants)
}

struct RawGrantRow {
    grant_id: String,
    subject_session_id: String,
    device_id: String,
    remote_principal: String,
    principal_assurance: String,
    workspace_ids: String,
    capability_profile: String,
    effective_capabilities: String,
    task_scope: String,
    grant_kind: String,
    issued_at: String,
    approved_at: Option<String>,
    expires_at: String,
    revoked_at: Option<String>,
    revocation_reason: Option<String>,
    consumed_at: Option<String>,
    issued_lease_id: Option<String>,
    risk_policy_version: i64,
    approval_policy: String,
    status: String,
    migrated_from_session_id: Option<String>,
    migration_note: Option<String>,
}

fn raw_grant(row: &rusqlite::Row) -> rusqlite::Result<RawGrantRow> {
    Ok(RawGrantRow {
        grant_id: row.get(0)?,
        subject_session_id: row.get(1)?,
        device_id: row.get(2)?,
        remote_principal: row.get(3)?,
        principal_assurance: row.get(4)?,
        workspace_ids: row.get(5)?,
        capability_profile: row.get(6)?,
        effective_capabilities: row.get(7)?,
        task_scope: row.get(8)?,
        grant_kind: row.get(9)?,
        issued_at: row.get(10)?,
        approved_at: row.get(11)?,
        expires_at: row.get(12)?,
        revoked_at: row.get(13)?,
        revocation_reason: row.get(14)?,
        consumed_at: row.get(15)?,
        issued_lease_id: row.get(16)?,
        risk_policy_version: row.get(17)?,
        approval_policy: row.get(18)?,
        status: row.get(19)?,
        migrated_from_session_id: row.get(20)?,
        migration_note: row.get(21)?,
    })
}

fn parse_grant(raw: RawGrantRow) -> Result<AccessGrant, GrantError> {
    let risk_policy_version = u32::try_from(raw.risk_policy_version)
        .map_err(|_| GrantError::Storage("negative risk policy version".into()))?;
    Ok(AccessGrant {
        grant_id: raw
            .grant_id
            .parse()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        subject_session_id: raw
            .subject_session_id
            .parse()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        device_id: raw
            .device_id
            .parse()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        principal: AuthorizationPrincipal {
            name: raw.remote_principal,
            assurance: parse_assurance(&raw.principal_assurance)?,
        },
        workspace_ids: from_json(&raw.workspace_ids)?,
        capability_profile: from_json(&raw.capability_profile)?,
        effective_capabilities: from_json(&raw.effective_capabilities)?,
        task_scope: raw.task_scope,
        kind: from_json::<GrantKind>(&raw.grant_kind)?,
        issued_at: parse_rfc3339(&raw.issued_at)?,
        approved_at: raw.approved_at.as_deref().map(parse_rfc3339).transpose()?,
        expires_at: parse_rfc3339(&raw.expires_at)?,
        revoked_at: raw.revoked_at.as_deref().map(parse_rfc3339).transpose()?,
        revocation_reason: raw.revocation_reason,
        consumed_at: raw.consumed_at.as_deref().map(parse_rfc3339).transpose()?,
        issued_lease_id: raw
            .issued_lease_id
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        risk_policy_version,
        approval_policy: from_json(&raw.approval_policy)?,
        status: from_json(&raw.status)?,
        migrated_from_session_id: raw
            .migrated_from_session_id
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        migration_note: raw.migration_note,
    })
}

struct RawLeaseRow {
    lease_id: String,
    grant_id: String,
    subject_session_id: String,
    device_id: String,
    remote_principal: String,
    principal_assurance: String,
    workspace_ids: String,
    capabilities: String,
    task_scope: String,
    issued_at: String,
    expires_at: String,
    consumed_at: Option<String>,
    consumed_by_operation: Option<String>,
}

fn raw_lease(row: &rusqlite::Row) -> rusqlite::Result<RawLeaseRow> {
    Ok(RawLeaseRow {
        lease_id: row.get(0)?,
        grant_id: row.get(1)?,
        subject_session_id: row.get(2)?,
        device_id: row.get(3)?,
        remote_principal: row.get(4)?,
        principal_assurance: row.get(5)?,
        workspace_ids: row.get(6)?,
        capabilities: row.get(7)?,
        task_scope: row.get(8)?,
        issued_at: row.get(9)?,
        expires_at: row.get(10)?,
        consumed_at: row.get(11)?,
        consumed_by_operation: row.get(12)?,
    })
}

fn parse_lease(raw: RawLeaseRow) -> Result<AuthorizationLease, GrantError> {
    Ok(AuthorizationLease {
        lease_id: raw
            .lease_id
            .parse()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        grant_id: raw
            .grant_id
            .parse()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        subject_session_id: raw
            .subject_session_id
            .parse()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        device_id: raw
            .device_id
            .parse()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
        principal: AuthorizationPrincipal {
            name: raw.remote_principal,
            assurance: parse_assurance(&raw.principal_assurance)?,
        },
        workspace_ids: from_json(&raw.workspace_ids)?,
        capabilities: from_json(&raw.capabilities)?,
        task_scope: raw.task_scope,
        issued_at: parse_rfc3339(&raw.issued_at)?,
        expires_at: parse_rfc3339(&raw.expires_at)?,
        consumed_at: raw.consumed_at.as_deref().map(parse_rfc3339).transpose()?,
        consumed_by_operation: raw
            .consumed_by_operation
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| GrantError::Storage(format!("{e:?}")))?,
    })
}

/// Fails closed on a stored assurance this build does not know: an unknown
/// value must never be downgraded into a weaker (or invented) claim.
fn parse_assurance(raw: &str) -> Result<PrincipalAssurance, GrantError> {
    from_json(raw).map_err(|_| GrantError::Storage(format!("unknown principal assurance: {raw}")))
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, GrantError> {
    serde_json::to_string(value).map_err(|e| GrantError::Storage(e.to_string()))
}

fn from_json<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, GrantError> {
    serde_json::from_str(raw).map_err(|e| GrantError::Storage(e.to_string()))
}

fn format_rfc3339(t: OffsetDateTime) -> Result<String, GrantError> {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| GrantError::Storage(e.to_string()))
}

fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, GrantError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| GrantError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use companion_core::{
        AuthorizationStatus, CapabilityProfile, Clock, DeviceId, FakeClock, GrantRequest,
        LeaseRequest, SessionId, WorkspaceId,
    };
    use companion_storage::Storage;
    use time::Duration;

    use super::*;
    use crate::grant_machine::{issue_lease, AuthorizationEvent, GrantTransition};

    fn repo() -> AuthorizationRepository {
        let dir = tempfile::tempdir().unwrap().keep();
        AuthorizationRepository::new(Arc::new(Storage::open(&dir).unwrap()))
    }

    fn grant_request(subject_session_id: SessionId, kind: GrantKind) -> GrantRequest {
        GrantRequest {
            subject_session_id,
            device_id: DeviceId::new(),
            principal: AuthorizationPrincipal::unverified("agent:test"),
            workspace_ids: BTreeSet::from([WorkspaceId::new()]),
            capability_profile: CapabilityProfile::Inspect,
            task_scope: "round trip".into(),
            kind,
            lifetime: Duration::hours(1),
        }
    }

    #[test]
    fn save_then_load_round_trips_every_grant_field() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let subject_session_id = SessionId::new();
        let grant = AccessGrant::requested(
            grant_request(subject_session_id, GrantKind::OneShot),
            clock.now(),
        );
        let mut grant = grant
            .transition(&AuthorizationEvent::Approve, &clock)
            .unwrap();
        grant.revocation_reason = Some("probe".into());
        grant.revoked_at = Some(clock.now());
        grant.consumed_at = Some(clock.now());
        grant.issued_lease_id = Some(LeaseId::new());
        grant.migration_note = Some("from a legacy row".into());

        repository.save_grant(&grant).unwrap();
        assert_eq!(
            repository.load_grant(grant.grant_id).unwrap(),
            Some(grant.clone())
        );
        assert_eq!(
            repository
                .load_grant_for_subject(subject_session_id)
                .unwrap(),
            Some(grant)
        );
    }

    #[test]
    fn load_unknown_grant_returns_none() {
        let repository = repo();
        assert!(repository.load_grant(GrantId::new()).unwrap().is_none());
        assert!(repository
            .load_grant_for_subject(SessionId::new())
            .unwrap()
            .is_none());
    }

    #[test]
    fn saving_the_same_grant_twice_updates_in_place() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = AccessGrant::requested(
            grant_request(SessionId::new(), GrantKind::Standing),
            clock.now(),
        );
        repository.save_grant(&grant).unwrap();
        repository.save_grant(&grant).unwrap();

        let revoked = grant
            .transition(
                &AuthorizationEvent::Revoke {
                    reason: Some("migrated revocation".into()),
                },
                &clock,
            )
            .unwrap();
        repository.save_grant(&revoked).unwrap();

        assert_eq!(repository.list_all_grants().unwrap().len(), 1);
        let loaded = repository.load_grant(grant.grant_id).unwrap().unwrap();
        assert_eq!(loaded.status, AuthorizationStatus::Revoked);
        assert_eq!(
            loaded.revocation_reason.as_deref(),
            Some("migrated revocation")
        );
    }

    #[test]
    fn live_grants_exclude_terminal_ones() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let subject_session_id = SessionId::new();
        let requested = AccessGrant::requested(
            grant_request(subject_session_id, GrantKind::Standing),
            clock.now(),
        );
        let mut revoked = requested.clone();
        revoked.grant_id = GrantId::new();
        revoked.status = AuthorizationStatus::Revoked;

        repository.save_grant(&requested).unwrap();
        repository.save_grant(&revoked).unwrap();

        let live = repository
            .list_live_grants_for_subject(subject_session_id)
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].status, AuthorizationStatus::PendingApproval);
        assert_eq!(repository.list_all_grants().unwrap().len(), 2);
    }

    #[test]
    fn leases_round_trip_including_consumption() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = AccessGrant::requested(
            grant_request(SessionId::new(), GrantKind::Standing),
            clock.now(),
        )
        .transition(&AuthorizationEvent::Approve, &clock)
        .unwrap();
        repository.save_grant(&grant).unwrap();

        let (grant, lease) = issue_lease(
            &grant,
            LeaseRequest {
                workspace_ids: grant.workspace_ids.clone(),
                capabilities: grant.effective_capabilities.clone(),
                lifetime: Duration::minutes(30),
            },
            clock.now(),
        )
        .unwrap();
        repository.save_grant(&grant).unwrap();
        repository.save_lease(&lease).unwrap();

        assert_eq!(
            repository.load_lease(lease.lease_id).unwrap(),
            Some(lease.clone())
        );
        assert_eq!(
            repository.list_leases_for_grant(grant.grant_id).unwrap(),
            vec![lease.clone()]
        );

        let operation_id = companion_core::OperationId::new();
        let spent = lease.consumed_by(operation_id, clock.now()).unwrap();
        repository.save_lease(&spent).unwrap();
        assert_eq!(
            repository.load_lease(lease.lease_id).unwrap(),
            Some(spent.clone())
        );
        assert_eq!(spent.consumed_by_operation, Some(operation_id));
        assert_eq!(repository.load_lease(LeaseId::new()).unwrap(), None);
    }

    #[test]
    fn a_stored_assurance_this_build_does_not_know_fails_closed() {
        let repository = repo();
        let clock = FakeClock::new_at(OffsetDateTime::UNIX_EPOCH);
        let grant = AccessGrant::requested(
            grant_request(SessionId::new(), GrantKind::Standing),
            clock.now(),
        );
        repository.save_grant(&grant).unwrap();
        repository
            .storage
            .connection()
            .lock()
            .unwrap()
            .execute(
                "UPDATE access_grants SET principal_assurance = 'verified'",
                [],
            )
            .unwrap();

        let loaded = repository.load_grant(grant.grant_id);
        assert!(
            matches!(loaded, Err(GrantError::Storage(_))),
            "an unknown assurance claim must not be downgraded into a weaker one"
        );
    }
}
