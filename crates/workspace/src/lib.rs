//! `companion-workspace`: authorized workspace records and canonical
//! filesystem path boundary enforcement. See
//! `docs/security/threat-model.md` (T3) for the threat this defends
//! against.

mod boundary;
mod repository;

pub use boundary::{WorkspaceAuthorization, WorkspaceBoundary, WorkspaceError};
pub use repository::WorkspaceRepository;
