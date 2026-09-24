//! `companion-checkpoints`: conservative, local, file-copy-based
//! checkpoints for authorized workspaces. See
//! `docs/superpowers/specs/2026-09-16-companion-v1-design.md` §11 for why
//! this is intentionally not a distributed revision graph in V1.

mod error;
mod fs_ops;
mod store;

pub use error::CheckpointError;
pub use store::{CheckpointMetadata, FilesystemCheckpointStore};
