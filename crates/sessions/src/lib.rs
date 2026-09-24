//! `companion-sessions`: the explicit session state machine and session
//! persistence. See `docs/architecture/session-lifecycle.md`.

mod approvals;
mod repository;
mod state_machine;

pub use approvals::apply_session_decision;
pub use repository::SessionRepository;
pub use state_machine::{new_unpaired_session, SessionError, SessionEvent, SessionTransition};
