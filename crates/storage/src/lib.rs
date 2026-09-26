//! `companion-storage`: SQLite persistence and migrations for all
//! non-secret Gateway state (device metadata, workspaces, sessions,
//! approvals, audit events, settings, checkpoints).
//!
//! Private key material is never persisted here — see
//! `docs/security/secure-storage.md` and the `companion-identity` crate's
//! `SecretStore`.

mod connection;
mod error;
mod migrations;

pub use connection::Storage;
pub use error::StorageError;
pub use migrations::{run_migrations, schema_version, SCHEMA_VERSION};
