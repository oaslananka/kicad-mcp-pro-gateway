//! `companion-sessions`: the explicit session and authorization state
//! machines, their persistence, and the boundary between transport
//! connectivity and authorization authority. See
//! `docs/architecture/session-lifecycle.md`.

mod approvals;
mod authorization_repository;
mod grant_machine;
mod migration;
mod repository;
mod state_machine;
mod transport_boundary;

pub use approvals::{apply_grant_decision, apply_session_decision};
pub use authorization_repository::AuthorizationRepository;
pub use grant_machine::{
    authorization_event_for, consume_lease, issue_lease, subject_of, within_lifetime,
    AuthorizationEvent, GrantError, GrantTransition,
};
pub use migration::{migrate_legacy_sessions, MigrationReport};
pub use repository::SessionRepository;
pub use state_machine::{new_unpaired_session, SessionError, SessionEvent, SessionTransition};
pub use transport_boundary::{
    fold_transport_events, is_pipe_usable, transport_state_after, TransportConnectivityEvent,
};
