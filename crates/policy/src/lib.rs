//! `companion-policy`: the deterministic policy evaluation engine and the
//! tool-name-to-capability registry. See
//! `docs/architecture/data-flow.md` for the pipeline this crate implements
//! the core of, and `docs/security/threat-model.md` for the threats it
//! defends against.

mod engine;
mod tool_catalog;
mod tool_registry;

pub use engine::{ApprovalReason, DenyReason, PolicyDecision, PolicyEngine};
pub use tool_catalog::{ToolCatalogError, ToolCatalogSnapshot};
pub use tool_registry::{
    TomlToolRegistry, ToolCapabilityResolver, ToolRegistryCoverage, ToolRegistryError,
};
