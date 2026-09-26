//! Explicit authorization authority: [`AccessGrant`] and
//! [`AuthorizationLease`].
//!
//! Transport connectivity and authorization authority have different
//! lifecycles, so they are different types here. A relay pipe may drop,
//! reconnect, or be replaced while a grant that still satisfies its own
//! principal/device/workspace/capability/expiry/revocation constraints keeps
//! its authority; conversely, revoking or expiring a grant never touches the
//! pipe. Nothing in this module mentions [`crate::transport_state`] or
//! [`crate::session::SessionEvent`]: no transport event can reach an
//! [`AccessGrant`] because there is no field here for one to reach.
//!
//! The lifecycle *rules* (which transitions are legal) live in
//! `companion-sessions`; the data model and the pure constraint checks live
//! here, alongside the rest of the domain types in [`crate::session`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::capability::{Capability, CapabilityProfile, CapabilitySet};
use crate::ids::{DeviceId, GrantId, LeaseId, OperationId, SessionId, WorkspaceId};
use crate::session::{ApprovalPolicy, Session, SessionStatus};

/// How much the Gateway can vouch for the identity behind a grant's
/// principal.
///
/// `Verified` deliberately does not exist yet: nothing in this repository
/// performs a remote-principal verification handshake, so a grant may only
/// ever claim [`PrincipalAssurance::Unverified`]. Adding a verified tier is
/// the subject of the remote-identity work tracked separately, and inventing
/// it here would let an unverified principal string be treated as a proven
/// identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalAssurance {
    /// The principal string arrived over an untrusted transport and has not
    /// been verified. Authority decisions may still use it, but only together
    /// with the device binding and the approver's explicit consent.
    Unverified,
}

/// The remote principal a grant is issued to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationPrincipal {
    pub name: String,
    pub assurance: PrincipalAssurance,
}

impl AuthorizationPrincipal {
    /// Builds the only principal this build is able to assert: an
    /// unverified, transport-supplied name.
    pub fn unverified(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            assurance: PrincipalAssurance::Unverified,
        }
    }

    pub fn is_unverified(&self) -> bool {
        matches!(self.assurance, PrincipalAssurance::Unverified)
    }
}

/// Whether a grant authorizes ongoing work or exactly one bounded lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    /// Standing authorization: leases may be issued until the grant's own
    /// expiry, each bounded by that same expiry.
    Standing,
    /// One-shot authorization: at most one lease may ever be issued, and the
    /// grant is `Consumed` as soon as that lease is consumed. A new request
    /// needs a new grant id and a new local approval.
    OneShot,
}

/// The authorization lifecycle. Every variant is reachable from a local
/// decision or from the grant's own clock — never from a transport event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    /// Recorded, awaiting a local user's approve/deny decision. Carries no
    /// authority.
    PendingApproval,
    /// Approved and inside its own expiry. The only status that carries
    /// authority.
    Active,
    /// Temporarily withdrawn by a local user; resumable, never automatic.
    Suspended,
    /// `now >= expires_at`. Terminal.
    Expired,
    /// Withdrawn locally. Terminal and irreversible for this grant id.
    Revoked,
    /// A one-shot grant whose single lease has been spent. Terminal.
    Consumed,
}

impl AuthorizationStatus {
    /// Terminal states are never left. Reaching one requires a brand-new
    /// grant (and therefore a brand-new local approval) for access to resume.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            AuthorizationStatus::Expired
                | AuthorizationStatus::Revoked
                | AuthorizationStatus::Consumed
        )
    }
}

/// What a local approval decision is being asked to authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    /// The transport-era subject record whose remote request this grant
    /// answers. Carried for operation/audit correlation only: it holds no
    /// authority of its own.
    pub subject_session_id: SessionId,
    pub device_id: DeviceId,
    pub principal: AuthorizationPrincipal,
    pub workspace_ids: BTreeSet<WorkspaceId>,
    pub capability_profile: CapabilityProfile,
    pub task_scope: String,
    pub kind: GrantKind,
    /// Already policy-bounded by the caller (see
    /// `docs/security/authorization-ttl.md`).
    pub lifetime: Duration,
}

/// The explicit authorization authority record. Nothing here is derived from
/// transport connectivity, and nothing here changes when the pipe changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessGrant {
    pub grant_id: GrantId,
    /// See [`GrantRequest::subject_session_id`].
    pub subject_session_id: SessionId,
    pub device_id: DeviceId,
    pub principal: AuthorizationPrincipal,
    pub workspace_ids: BTreeSet<WorkspaceId>,
    pub capability_profile: CapabilityProfile,
    /// The capabilities the approver actually granted. Never widened
    /// implicitly: a transport event cannot add to this set.
    pub effective_capabilities: CapabilitySet,
    pub task_scope: String,
    pub kind: GrantKind,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub approved_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    pub revocation_reason: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub consumed_at: Option<OffsetDateTime>,
    /// The single lease a [`GrantKind::OneShot`] grant has already cut.
    /// `None` for standing grants and for one-shot grants that have not
    /// issued anything yet.
    pub issued_lease_id: Option<LeaseId>,
    pub risk_policy_version: u32,
    pub approval_policy: ApprovalPolicy,
    pub status: AuthorizationStatus,
    /// Set only on grants produced by [`grant_from_legacy_session`], to the
    /// id of the transport-era `sessions` row they were derived from. This
    /// keeps pre-migration audit history linked to the authority it produced.
    pub migrated_from_session_id: Option<SessionId>,
    /// Honest provenance note. Legacy rows never recorded a revocation
    /// timestamp, so migrated revocations say so instead of inventing one.
    pub migration_note: Option<String>,
}

impl AccessGrant {
    /// A freshly recorded remote access request. It starts
    /// [`AuthorizationStatus::PendingApproval`] and therefore carries no
    /// authority: the fact that a request arrived (over a transport, from a
    /// paired device) is not an approval.
    pub fn requested(request: GrantRequest, now: OffsetDateTime) -> Self {
        Self {
            grant_id: GrantId::new(),
            subject_session_id: request.subject_session_id,
            device_id: request.device_id,
            principal: request.principal,
            effective_capabilities: request.capability_profile.effective_capabilities(),
            workspace_ids: request.workspace_ids,
            capability_profile: request.capability_profile,
            task_scope: request.task_scope,
            kind: request.kind,
            issued_at: now,
            approved_at: None,
            expires_at: now + request.lifetime,
            revoked_at: None,
            revocation_reason: None,
            consumed_at: None,
            issued_lease_id: None,
            risk_policy_version: 1,
            approval_policy: ApprovalPolicy::Standard,
            status: AuthorizationStatus::PendingApproval,
            migrated_from_session_id: None,
            migration_note: None,
        }
    }

    /// Whether the grant's own clock says it is past its lifetime. A grant
    /// that is `Active` but past `expires_at` carries no authority, exactly
    /// like one that is `Revoked`.
    pub fn is_expired_at(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// Whether this grant may be used as authority for an operation at
    /// `now`. Requires an approved, unrevoked, unconsumed, unexpired grant.
    pub fn is_usable_at(&self, now: OffsetDateTime) -> bool {
        self.status == AuthorizationStatus::Active && !self.is_expired_at(now)
    }

    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    pub fn allows_workspace(&self, workspace_id: &WorkspaceId) -> bool {
        self.workspace_ids.contains(workspace_id)
    }

    pub fn allows_capability(&self, capability: &Capability) -> bool {
        self.effective_capabilities.contains(capability)
    }

    /// A one-shot grant stops being able to cut leases the moment its single
    /// lease is issued (it stops being usable authority once that lease is
    /// spent); a standing grant may cut further leases, each still bounded by
    /// the grant's own expiry.
    pub fn may_issue_another_lease(&self) -> bool {
        self.kind == GrantKind::Standing || self.issued_lease_id.is_none()
    }
}

/// The bounded, specific authorization a single unit of work needs. A lease
/// can only ever be *narrower* than the grant it came from: same device,
/// same principal, a subset of the granted workspaces, a subset of the
/// granted capabilities, and an expiry no later than the grant's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationLease {
    pub lease_id: LeaseId,
    pub grant_id: GrantId,
    pub subject_session_id: SessionId,
    pub device_id: DeviceId,
    pub principal: AuthorizationPrincipal,
    pub workspace_ids: BTreeSet<WorkspaceId>,
    pub capabilities: CapabilitySet,
    pub task_scope: String,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub consumed_at: Option<OffsetDateTime>,
    /// Set when the lease is spent, so the audit trail can point back at the
    /// operation it authorized.
    pub consumed_by_operation: Option<OperationId>,
}

/// The scope a caller asks an [`AuthorizationLease`] to cover. Every field
/// is checked against the grant before a lease exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    pub workspace_ids: BTreeSet<WorkspaceId>,
    pub capabilities: CapabilitySet,
    /// Requested lease lifetime. The lease is clamped to the grant's own
    /// remaining lifetime, so a long request cannot outlive its grant.
    pub lifetime: Duration,
}

impl AuthorizationLease {
    /// Issues a lease against `grant`. Fails closed if the grant is not
    /// currently usable, if the requested scope is empty or exceeds the
    /// grant, or if a one-shot grant has already issued its one lease.
    pub fn issued_for(
        grant: &AccessGrant,
        request: LeaseRequest,
        now: OffsetDateTime,
    ) -> Result<Self, AuthorizationError> {
        if request.lifetime <= Duration::ZERO {
            return Err(AuthorizationError::NonPositiveLifetime);
        }
        if request.workspace_ids.is_empty() {
            return Err(AuthorizationError::EmptyScope);
        }
        if !grant.is_usable_at(now) {
            return Err(AuthorizationError::from_grant_state(grant, now));
        }
        if !grant.may_issue_another_lease() {
            return Err(AuthorizationError::OneShotLeaseAlreadyIssued {
                lease_id: grant
                    .issued_lease_id
                    .expect("may_issue_another_lease is false only for a spent one-shot grant"),
            });
        }
        if let Some(workspace_id) = request
            .workspace_ids
            .iter()
            .find(|id| !grant.allows_workspace(id))
        {
            return Err(AuthorizationError::WorkspaceNotGranted {
                workspace_id: *workspace_id,
            });
        }
        if let Some(capability) = request
            .capabilities
            .iter()
            .find(|capability| !grant.allows_capability(capability))
        {
            return Err(AuthorizationError::CapabilityNotGranted {
                capability: *capability,
            });
        }

        Ok(Self {
            lease_id: LeaseId::new(),
            grant_id: grant.grant_id,
            subject_session_id: grant.subject_session_id,
            device_id: grant.device_id,
            principal: grant.principal.clone(),
            workspace_ids: request.workspace_ids,
            capabilities: request.capabilities,
            task_scope: grant.task_scope.clone(),
            issued_at: now,
            // Never beyond the grant: a lease cannot outlive the authority
            // it was cut from.
            expires_at: (now + request.lifetime).min(grant.expires_at),
            consumed_at: None,
            consumed_by_operation: None,
        })
    }

    /// Whether this specific lease may still be spent at `now`. Note that it
    /// is checked against *its own* expiry only; the grant it came from must
    /// be checked too, with [`Self::validate_against`].
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        self.consumed_at.is_none() && now < self.expires_at
    }

    /// Full check of a lease against the grant that issued it. Revocation,
    /// suspension, expiry, and consumption of the *grant* invalidate every
    /// lease cut from it, which is what makes revocation authoritative
    /// across transport replacement.
    pub fn validate_against(
        &self,
        grant: &AccessGrant,
        now: OffsetDateTime,
    ) -> Result<(), AuthorizationError> {
        if self.grant_id != grant.grant_id {
            return Err(AuthorizationError::ForeignGrant);
        }
        if !grant.is_usable_at(now) {
            return Err(AuthorizationError::from_grant_state(grant, now));
        }
        if self.device_id != grant.device_id {
            return Err(AuthorizationError::DeviceBindingMismatch);
        }
        if self.principal != grant.principal {
            return Err(AuthorizationError::PrincipalMismatch);
        }
        if self.expires_at > grant.expires_at {
            return Err(AuthorizationError::LeaseOutlivesGrant);
        }
        if let Some(workspace_id) = self
            .workspace_ids
            .iter()
            .find(|id| !grant.allows_workspace(id))
        {
            return Err(AuthorizationError::WorkspaceNotGranted {
                workspace_id: *workspace_id,
            });
        }
        if let Some(capability) = self
            .capabilities
            .iter()
            .find(|capability| !grant.allows_capability(capability))
        {
            return Err(AuthorizationError::CapabilityNotGranted {
                capability: *capability,
            });
        }
        if self.consumed_at.is_some() {
            return Err(AuthorizationError::LeaseAlreadyConsumed {
                lease_id: self.lease_id,
            });
        }
        if !self.is_valid_at(now) {
            return Err(AuthorizationError::LeaseExpired {
                lease_id: self.lease_id,
            });
        }
        Ok(())
    }

    /// Returns a copy of this lease marked as spent by `operation_id`. The
    /// grant is *not* touched: only the grant state machine may consume a
    /// one-shot grant, and only once the lease is actually spent.
    pub fn consumed_by(
        &self,
        operation_id: OperationId,
        now: OffsetDateTime,
    ) -> Result<Self, AuthorizationError> {
        if self.consumed_at.is_some() {
            return Err(AuthorizationError::LeaseAlreadyConsumed {
                lease_id: self.lease_id,
            });
        }
        if !self.is_valid_at(now) {
            return Err(AuthorizationError::LeaseExpired {
                lease_id: self.lease_id,
            });
        }
        let mut spent = self.clone();
        spent.consumed_at = Some(now);
        spent.consumed_by_operation = Some(operation_id);
        Ok(spent)
    }
}

/// Constraint failures for lease issuance and validation. All of them are
/// denials: there is no "downgrade and continue" path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationError {
    #[error("access grant is awaiting local approval ({status:?})")]
    GrantNotApproved { status: AuthorizationStatus },
    #[error("access grant was revoked")]
    GrantRevoked,
    #[error("access grant expired at {expires_at}")]
    GrantExpired { expires_at: OffsetDateTime },
    #[error("one-shot access grant has already been consumed")]
    GrantConsumed,
    #[error("lease was issued under a different grant")]
    ForeignGrant,
    #[error("lease device binding does not match the grant")]
    DeviceBindingMismatch,
    #[error("lease principal does not match the grant")]
    PrincipalMismatch,
    #[error("workspace {workspace_id} is not granted by this access grant")]
    WorkspaceNotGranted { workspace_id: WorkspaceId },
    #[error("capability {capability} is not granted by this access grant")]
    CapabilityNotGranted { capability: Capability },
    #[error("lease outlives the access grant that issued it")]
    LeaseOutlivesGrant,
    #[error("one-shot access grant already issued lease {lease_id} and cannot issue another")]
    OneShotLeaseAlreadyIssued { lease_id: LeaseId },
    #[error("lease {lease_id} has already been consumed")]
    LeaseAlreadyConsumed { lease_id: LeaseId },
    #[error("lease {lease_id} has expired")]
    LeaseExpired { lease_id: LeaseId },
    #[error("requested lease lifetime must be positive")]
    NonPositiveLifetime,
    #[error("requested lease scope is empty")]
    EmptyScope,
}

impl AuthorizationError {
    fn from_grant_state(grant: &AccessGrant, now: OffsetDateTime) -> Self {
        let status = grant.status;
        match status {
            AuthorizationStatus::Revoked => return Self::GrantRevoked,
            AuthorizationStatus::Consumed => return Self::GrantConsumed,
            AuthorizationStatus::Expired => {
                return Self::GrantExpired {
                    expires_at: grant.expires_at,
                }
            }
            _ => {}
        }
        // A grant left `Active` (or `Suspended`) past its own `expires_at`
        // is already expired, whether or not the state machine has written
        // that transition down yet.
        if grant.is_expired_at(now) {
            return Self::GrantExpired {
                expires_at: grant.expires_at,
            };
        }
        Self::GrantNotApproved { status }
    }
}

/// Failures when reading a persisted transport-era `Session` row as
/// authorization authority. Every variant is a refusal to mint authority.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegacySessionMappingError {
    #[error("legacy session {session_id} is Active but records no approval")]
    ActiveWithoutApproval { session_id: SessionId },
    #[error("legacy session {session_id} grants no workspace")]
    NoWorkspace { session_id: SessionId },
    #[error("legacy session {session_id} has an expiry at or before its issue time")]
    NonPositiveLifetime { session_id: SessionId },
}

/// Maps a persisted transport-era `Session` onto explicit authorization
/// authority. This is the single adapter used both by the schema migration
/// and by the in-process compatibility path, so the two can never disagree.
///
/// * `Ok(None)` — the row is a pairing/connectivity record that never
///   carried authority (`Unpaired`, `Paired`, `Connected`, `Disconnected`).
///   No grant is minted: a remote must re-request and a local user must
///   approve. This is the fail-closed direction.
/// * `Ok(Some(grant))` — the row carried authority and is mapped
///   deterministically, including its `Revoked`/`Expired` state, so a
///   pre-migration revocation survives migration and can never be undone by
///   a later transport event.
/// * `Err(_)` — the row is internally inconsistent (active without an
///   approval, no workspace, non-positive lifetime) and is refused.
pub fn grant_from_legacy_session(
    session: &Session,
) -> Result<Option<AccessGrant>, LegacySessionMappingError> {
    let status = match session.status {
        // Never carried authority: no grant, no authority, no exceptions.
        SessionStatus::Unpaired
        | SessionStatus::Paired
        | SessionStatus::Connected
        | SessionStatus::Disconnected => return Ok(None),
        SessionStatus::PendingApproval => AuthorizationStatus::PendingApproval,
        SessionStatus::Active => AuthorizationStatus::Active,
        SessionStatus::Suspended => AuthorizationStatus::Suspended,
        SessionStatus::Expired => AuthorizationStatus::Expired,
        SessionStatus::Revoked => AuthorizationStatus::Revoked,
    };

    if session.workspace_ids.is_empty() {
        return Err(LegacySessionMappingError::NoWorkspace {
            session_id: session.session_id,
        });
    }
    if session.expires_at <= session.issued_at {
        return Err(LegacySessionMappingError::NonPositiveLifetime {
            session_id: session.session_id,
        });
    }
    if status == AuthorizationStatus::Active && session.approved_at.is_none() {
        return Err(LegacySessionMappingError::ActiveWithoutApproval {
            session_id: session.session_id,
        });
    }

    // A legacy revocation timestamp was never persisted, so migrated
    // revocations carry the fact of revocation and say so, rather than
    // back-dating `revoked_at` to a moment the database never witnessed.
    let migration_note = match status {
        AuthorizationStatus::Revoked => {
            Some("migrated from a transport-era session row that recorded no revocation timestamp; the revocation itself is preserved".to_string())
        }
        _ => Some(format!(
            "migrated from transport-era session {} ({:?})",
            session.session_id, session.status
        )),
    };

    Ok(Some(AccessGrant {
        // Deterministic: derived from the legacy row's own id, so running
        // the migration again updates the same grant instead of forking a
        // second one with different authority.
        grant_id: GrantId::from_ulid(session.session_id.as_ulid()),
        subject_session_id: session.session_id,
        device_id: session.device_id,
        principal: AuthorizationPrincipal::unverified(session.remote_principal.clone()),
        workspace_ids: session.workspace_ids.clone(),
        capability_profile: session.capability_profile.clone(),
        effective_capabilities: session.effective_capabilities.clone(),
        task_scope: session.task_scope.clone(),
        // The transport-era model had no one-shot notion; every legacy
        // session was standing authorization.
        kind: GrantKind::Standing,
        issued_at: session.issued_at,
        approved_at: session.approved_at,
        expires_at: session.expires_at,
        revoked_at: None,
        revocation_reason: match status {
            AuthorizationStatus::Revoked => {
                Some("revoked before the authorization migration".to_string())
            }
            _ => None,
        },
        consumed_at: None,
        issued_lease_id: None,
        risk_policy_version: session.risk_policy_version,
        approval_policy: session.approval_policy,
        status,
        migrated_from_session_id: Some(session.session_id),
        migration_note,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::SessionId;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn grant_request(kind: GrantKind) -> GrantRequest {
        GrantRequest {
            subject_session_id: SessionId::new(),
            device_id: DeviceId::new(),
            principal: AuthorizationPrincipal::unverified("agent:test"),
            workspace_ids: BTreeSet::from([WorkspaceId::new()]),
            capability_profile: CapabilityProfile::Inspect,
            task_scope: "inspect the board".into(),
            kind,
            lifetime: Duration::hours(1),
        }
    }

    fn active_grant(kind: GrantKind) -> AccessGrant {
        let mut grant = AccessGrant::requested(grant_request(kind), now());
        grant.status = AuthorizationStatus::Active;
        grant.approved_at = Some(now());
        grant
    }

    fn lease_request(grant: &AccessGrant) -> LeaseRequest {
        LeaseRequest {
            workspace_ids: grant.workspace_ids.clone(),
            capabilities: grant.effective_capabilities.clone(),
            lifetime: Duration::minutes(30),
        }
    }

    #[test]
    fn a_requested_grant_carries_no_authority_before_local_approval() {
        let grant = AccessGrant::requested(grant_request(GrantKind::Standing), now());
        assert_eq!(grant.status, AuthorizationStatus::PendingApproval);
        assert!(!grant.is_usable_at(now()));
        assert!(!grant.is_usable_at(now() - Duration::hours(1)));
    }

    #[test]
    fn an_unverified_principal_is_all_this_build_can_assert() {
        let principal = AuthorizationPrincipal::unverified("agent:test");
        assert_eq!(principal.assurance, PrincipalAssurance::Unverified);
        assert!(principal.is_unverified());
    }

    #[test]
    fn approved_unexpired_grant_is_usable() {
        let grant = active_grant(GrantKind::Standing);
        assert!(grant.is_usable_at(now()));
        assert!(!grant.is_usable_at(grant.expires_at));
        assert!(!grant.is_usable_at(grant.expires_at + Duration::seconds(1)));
    }

    #[test]
    fn grant_records_effective_capabilities_from_its_profile() {
        let grant = active_grant(GrantKind::Standing);
        assert_eq!(
            grant.effective_capabilities,
            CapabilityProfile::Inspect.effective_capabilities()
        );
        assert!(grant.allows_capability(&Capability::SCHEMATIC_READ));
        assert!(!grant.allows_capability(&Capability::SCHEMATIC_WRITE));
    }

    #[test]
    fn revoked_and_expired_grants_are_terminal_and_not_terminal_statuses_are() {
        for status in [
            AuthorizationStatus::PendingApproval,
            AuthorizationStatus::Active,
            AuthorizationStatus::Suspended,
        ] {
            assert!(!status.is_terminal(), "{status:?} must not be terminal");
        }
        for status in [
            AuthorizationStatus::Revoked,
            AuthorizationStatus::Expired,
            AuthorizationStatus::Consumed,
        ] {
            assert!(status.is_terminal(), "{status:?} must be terminal");
        }
    }

    #[test]
    fn lease_is_never_wider_or_longer_than_its_grant() {
        let grant = active_grant(GrantKind::Standing);
        let request = LeaseRequest {
            workspace_ids: grant.workspace_ids.clone(),
            capabilities: grant.effective_capabilities.clone(),
            // Asks for far longer than the grant has left.
            lifetime: Duration::hours(10),
        };
        let lease = AuthorizationLease::issued_for(&grant, request, now()).unwrap();
        assert_eq!(lease.expires_at, grant.expires_at);
        assert_eq!(lease.device_id, grant.device_id);
        assert_eq!(lease.principal, grant.principal);
        assert_eq!(lease.grant_id, grant.grant_id);
    }

    #[test]
    fn lease_issuance_refuses_an_unapproved_or_expired_or_revoked_grant() {
        let pending = AccessGrant::requested(grant_request(GrantKind::Standing), now());
        assert!(matches!(
            AuthorizationLease::issued_for(&pending, lease_request(&pending), now()),
            Err(AuthorizationError::GrantNotApproved {
                status: AuthorizationStatus::PendingApproval
            })
        ));

        let mut expired = active_grant(GrantKind::Standing);
        expired.status = AuthorizationStatus::Expired;
        assert!(matches!(
            AuthorizationLease::issued_for(&expired, lease_request(&expired), now()),
            Err(AuthorizationError::GrantExpired { .. })
        ));

        let mut revoked = active_grant(GrantKind::Standing);
        revoked.status = AuthorizationStatus::Revoked;
        assert!(matches!(
            AuthorizationLease::issued_for(&revoked, lease_request(&revoked), now()),
            Err(AuthorizationError::GrantRevoked)
        ));
    }

    #[test]
    fn lease_issuance_refuses_scope_the_grant_does_not_cover() {
        let grant = active_grant(GrantKind::Standing);

        let other_workspace = LeaseRequest {
            workspace_ids: BTreeSet::from([WorkspaceId::new()]),
            capabilities: grant.effective_capabilities.clone(),
            lifetime: Duration::minutes(5),
        };
        assert!(matches!(
            AuthorizationLease::issued_for(&grant, other_workspace, now()),
            Err(AuthorizationError::WorkspaceNotGranted { .. })
        ));

        let extra_capability = LeaseRequest {
            workspace_ids: grant.workspace_ids.clone(),
            capabilities: BTreeSet::from([Capability::MANUFACTURING_EXPORT]),
            lifetime: Duration::minutes(5),
        };
        assert!(matches!(
            AuthorizationLease::issued_for(&grant, extra_capability, now()),
            Err(AuthorizationError::CapabilityNotGranted {
                capability: Capability::MANUFACTURING_EXPORT
            })
        ));

        let empty = LeaseRequest {
            workspace_ids: BTreeSet::new(),
            capabilities: grant.effective_capabilities.clone(),
            lifetime: Duration::minutes(5),
        };
        assert!(matches!(
            AuthorizationLease::issued_for(&grant, empty, now()),
            Err(AuthorizationError::EmptyScope)
        ));
    }

    #[test]
    fn revoking_the_grant_invalidates_a_live_lease() {
        let grant = active_grant(GrantKind::Standing);
        let lease = AuthorizationLease::issued_for(&grant, lease_request(&grant), now()).unwrap();
        assert!(lease.validate_against(&grant, now()).is_ok());

        let mut revoked = grant.clone();
        revoked.status = AuthorizationStatus::Revoked;
        assert_eq!(
            lease.validate_against(&revoked, now()),
            Err(AuthorizationError::GrantRevoked),
            "a lease cannot outlive the revocation of its grant, whatever the transport does"
        );
    }

    #[test]
    fn expiry_of_the_grant_invalidates_a_live_lease() {
        let grant = active_grant(GrantKind::Standing);
        let lease = AuthorizationLease::issued_for(&grant, lease_request(&grant), now()).unwrap();
        let later = grant.expires_at;
        assert!(lease.validate_against(&grant, later).is_err());
    }

    #[test]
    fn a_consumed_lease_cannot_be_spent_twice() {
        let grant = active_grant(GrantKind::Standing);
        let lease = AuthorizationLease::issued_for(&grant, lease_request(&grant), now()).unwrap();
        let operation_id = OperationId::new();
        let spent = lease.consumed_by(operation_id, now()).unwrap();
        assert_eq!(spent.consumed_by_operation, Some(operation_id));
        assert!(!spent.is_valid_at(now()));
        assert_eq!(
            lease.validate_against(&grant, now()),
            Ok(()),
            "the unspent original is still spendable exactly once"
        );
        assert!(matches!(
            spent.validate_against(&grant, now()),
            Err(AuthorizationError::LeaseAlreadyConsumed { .. })
        ));
    }

    #[test]
    fn only_a_standing_grant_may_issue_more_than_one_lease() {
        let standing = active_grant(GrantKind::Standing);
        assert!(standing.may_issue_another_lease());
        let one_shot = active_grant(GrantKind::OneShot);
        assert!(one_shot.may_issue_another_lease());
        let spent_one_shot = AccessGrant {
            issued_lease_id: Some(LeaseId::new()),
            ..one_shot.clone()
        };
        assert!(!spent_one_shot.may_issue_another_lease());
        assert!(matches!(
            AuthorizationLease::issued_for(&spent_one_shot, lease_request(&spent_one_shot), now()),
            Err(AuthorizationError::OneShotLeaseAlreadyIssued { .. })
        ));
    }

    fn legacy_session(status: SessionStatus) -> Session {
        Session {
            session_id: SessionId::new(),
            device_id: DeviceId::new(),
            remote_principal: "agent:legacy".into(),
            workspace_ids: BTreeSet::from([WorkspaceId::new()]),
            capability_profile: CapabilityProfile::Inspect,
            effective_capabilities: CapabilityProfile::Inspect.effective_capabilities(),
            task_scope: "legacy task".into(),
            issued_at: now(),
            approved_at: Some(now()),
            expires_at: now() + Duration::hours(1),
            risk_policy_version: 1,
            approval_policy: ApprovalPolicy::Standard,
            status,
        }
    }

    #[test]
    fn legacy_pairing_and_connectivity_rows_mint_no_authority() {
        for status in [
            SessionStatus::Unpaired,
            SessionStatus::Paired,
            SessionStatus::Connected,
            SessionStatus::Disconnected,
        ] {
            let session = legacy_session(status);
            assert_eq!(
                grant_from_legacy_session(&session),
                Ok(None),
                "{status:?} never carried authority and must not mint any"
            );
        }
    }

    #[test]
    fn legacy_authority_rows_map_with_their_own_state_preserved() {
        let session = legacy_session(SessionStatus::Active);
        let mapping = grant_from_legacy_session(&session)
            .unwrap()
            .expect("active legacy session carried authority");
        assert_eq!(mapping.status, AuthorizationStatus::Active);
        assert!(mapping.is_usable_at(now()));
        assert_eq!(mapping.migrated_from_session_id, Some(session.session_id));
        assert_eq!(mapping.subject_session_id, session.session_id);
        assert_eq!(
            mapping.grant_id,
            GrantId::from_ulid(session.session_id.as_ulid()),
            "a migrated grant id is derived from the row it came from"
        );
        assert!(mapping.principal.is_unverified());

        let revoked = grant_from_legacy_session(&legacy_session(SessionStatus::Revoked))
            .unwrap()
            .expect("revoked legacy session stays auditable as revoked");
        assert_eq!(revoked.status, AuthorizationStatus::Revoked);
        assert!(!revoked.is_usable_at(now()));
        assert!(revoked.is_terminal());
        assert!(
            revoked
                .migration_note
                .is_some_and(|note| note.contains("no revocation timestamp")),
            "migration must not invent a revocation timestamp: {:?}",
            revoked.revoked_at
        );

        let expired = grant_from_legacy_session(&legacy_session(SessionStatus::Expired))
            .unwrap()
            .expect("expired legacy session stays auditable as expired");
        assert_eq!(expired.status, AuthorizationStatus::Expired);

        let pending = grant_from_legacy_session(&legacy_session(SessionStatus::PendingApproval))
            .unwrap()
            .expect("pending legacy session maps to a pending grant");
        assert_eq!(pending.status, AuthorizationStatus::PendingApproval);
        assert!(!pending.is_usable_at(now()));

        let suspended = grant_from_legacy_session(&legacy_session(SessionStatus::Suspended))
            .unwrap()
            .expect("suspended legacy session maps to a suspended grant");
        assert_eq!(suspended.status, AuthorizationStatus::Suspended);
    }

    #[test]
    fn legacy_mapping_is_deterministic_across_repeated_runs() {
        let session = legacy_session(SessionStatus::Active);
        let first = grant_from_legacy_session(&session).unwrap().unwrap();
        let second = grant_from_legacy_session(&session).unwrap().unwrap();
        assert_eq!(first, second, "re-migrating a row must not fork authority");
    }

    #[test]
    fn corrupt_legacy_rows_are_refused_rather_than_mapped() {
        let mut active_without_approval = legacy_session(SessionStatus::Active);
        active_without_approval.approved_at = None;
        assert!(matches!(
            grant_from_legacy_session(&active_without_approval),
            Err(LegacySessionMappingError::ActiveWithoutApproval { .. })
        ));

        let mut no_workspace = legacy_session(SessionStatus::Active);
        no_workspace.workspace_ids = BTreeSet::new();
        assert!(matches!(
            grant_from_legacy_session(&no_workspace),
            Err(LegacySessionMappingError::NoWorkspace { .. })
        ));

        let mut backwards_expiry = legacy_session(SessionStatus::Active);
        backwards_expiry.expires_at = backwards_expiry.issued_at;
        assert!(matches!(
            grant_from_legacy_session(&backwards_expiry),
            Err(LegacySessionMappingError::NonPositiveLifetime { .. })
        ));
    }
}
