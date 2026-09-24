//! `companion-core`: strongly-typed domain identifiers and data model,
//! error taxonomy, deterministic clock abstraction, and layered
//! configuration for KiCad MCP Pro Gateway.
//!
//! This crate performs no I/O and holds no KiCad-specific knowledge. See
//! `docs/architecture/component-boundaries.md` for why.

pub mod approval;
pub mod audit;
pub mod capability;
pub mod clock;
pub mod config;
pub mod device;
pub mod error;
pub mod ids;
pub mod operation;
pub mod risk;
pub mod session;
pub mod transport_state;

pub use approval::{ApprovalDecision, ApprovalRequest};
pub use audit::{ApprovalDecisionKind, AuditEvent, ExecutionStatus, PolicyResultKind};
pub use capability::{Capability, CapabilityProfile, CapabilitySet};
pub use clock::{Clock, SystemClock};
pub use config::{CliOverrides, CompanionConfig, ConfigError, TransportMode};
pub use device::{DeviceFingerprint, DeviceIdentity, DevicePublicKey};
pub use error::CompanionError;
pub use ids::{
    AccountId, CheckpointId, DeviceId, IdParseError, OperationId, SessionId, TaskId, WorkspaceId,
};
pub use operation::{OperationError, OperationRequest, OperationResult};
pub use risk::RiskLevel;
pub use session::{ApprovalPolicy, Session, SessionStatus};
pub use transport_state::{CoreConnectionState, TransportState};

#[cfg(any(test, feature = "test-util"))]
pub use clock::FakeClock;
