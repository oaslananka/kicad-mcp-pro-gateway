use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::{OperationId, SessionId};
use crate::risk::RiskLevel;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub operation_id: OperationId,
    pub session_id: SessionId,
    pub reason: String,
    pub risk: RiskLevel,
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Approves the session/profile change that was pending.
    Approved {
        #[serde(with = "time::serde::rfc3339")]
        decided_at: OffsetDateTime,
    },
    /// Approves exactly one operation, without granting standing access.
    AllowOnce {
        #[serde(with = "time::serde::rfc3339")]
        decided_at: OffsetDateTime,
    },
    Denied {
        #[serde(with = "time::serde::rfc3339")]
        decided_at: OffsetDateTime,
        reason: String,
    },
}
