//! Session data model.
//!
//! This module defines the `Session` record and its `SessionStatus`
//! values. The *transition rules* between statuses (what is legal, what is
//! never legal such as a revoked session becoming active again) are
//! implemented in `crates/sessions`, which owns the state machine and
//! consumes this plain data type. Keeping the data here and the behavior
//! there lets `companion-core` stay free of I/O and free of the state
//! machine's own error type.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::capability::{CapabilityProfile, CapabilitySet};
use crate::ids::{DeviceId, SessionId, WorkspaceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Unpaired,
    Paired,
    Disconnected,
    Connected,
    PendingApproval,
    Active,
    Suspended,
    Expired,
    Revoked,
}

/// Governs whether a specific operation additionally requires an
/// interactive local approval beyond holding the capability. V1 ships a
/// single standard policy; richer policies are additive, not breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalPolicy {
    Standard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub remote_principal: String,
    pub workspace_ids: BTreeSet<WorkspaceId>,
    pub capability_profile: CapabilityProfile,
    pub effective_capabilities: CapabilitySet,
    pub task_scope: String,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub approved_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub risk_policy_version: u32,
    pub approval_policy: ApprovalPolicy,
    pub status: SessionStatus,
}

impl Session {
    pub fn is_usable_at(&self, now: OffsetDateTime) -> bool {
        self.status == SessionStatus::Active && now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session(status: SessionStatus, expires_at: OffsetDateTime) -> Session {
        Session {
            session_id: SessionId::new(),
            device_id: DeviceId::new(),
            remote_principal: "agent:test".into(),
            workspace_ids: BTreeSet::new(),
            capability_profile: CapabilityProfile::Inspect,
            effective_capabilities: CapabilityProfile::Inspect.effective_capabilities(),
            task_scope: "test task".into(),
            issued_at: OffsetDateTime::UNIX_EPOCH,
            approved_at: Some(OffsetDateTime::UNIX_EPOCH),
            expires_at,
            risk_policy_version: 1,
            approval_policy: ApprovalPolicy::Standard,
            status,
        }
    }

    #[test]
    fn active_unexpired_session_is_usable() {
        let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let session = sample_session(SessionStatus::Active, far_future);
        assert!(session.is_usable_at(OffsetDateTime::UNIX_EPOCH));
    }

    #[test]
    fn active_but_expired_session_is_not_usable() {
        let past = OffsetDateTime::UNIX_EPOCH;
        let session = sample_session(SessionStatus::Active, past);
        assert!(!session.is_usable_at(OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1)));
    }

    #[test]
    fn non_active_session_is_never_usable_even_if_unexpired() {
        let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        for status in [
            SessionStatus::Unpaired,
            SessionStatus::Paired,
            SessionStatus::Disconnected,
            SessionStatus::Connected,
            SessionStatus::PendingApproval,
            SessionStatus::Suspended,
            SessionStatus::Expired,
            SessionStatus::Revoked,
        ] {
            let session = sample_session(status, far_future);
            assert!(
                !session.is_usable_at(OffsetDateTime::UNIX_EPOCH),
                "status {status:?} must not be usable"
            );
        }
    }
}
