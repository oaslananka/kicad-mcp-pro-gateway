//! `companion-audit`: structured, append-only audit trail for every
//! policy-mediated operation. See `docs/architecture/data-flow.md` for
//! when audit records are written, and `docs/security/threat-model.md`
//! for what must never appear in one.

mod error;
mod repository;

pub use error::AuditError;
pub use repository::AuditRepository;
