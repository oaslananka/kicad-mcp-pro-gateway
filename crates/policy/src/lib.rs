//! `companion-policy`: the deterministic policy evaluation engine and the
//! tool-name-to-capability registry. See
//! `docs/architecture/data-flow.md` for the pipeline this crate implements
//! the core of, and `docs/security/threat-model.md` for the threats it
//! defends against.

mod authorization_ttl;
mod engine;
mod operation_effects;
mod tool_catalog;
mod tool_registry;

pub use authorization_ttl::{AuthorizationTtlPolicy, EffectiveAuthorizationTtl};
pub use engine::{ApprovalReason, DenyReason, PolicyDecision, PolicyEngine};
pub use operation_effects::{
    NormalizedOperationEffects, OperationEffect, OperationEffectNormalizationError,
    PathArgumentContract, ToolEffectContract, ToolEffectContractError,
};
pub use tool_catalog::{ToolCatalogError, ToolCatalogSnapshot};
pub use tool_registry::{
    TomlToolRegistry, ToolCapabilityResolver, ToolContractSource, ToolRegistryCoverage,
    ToolRegistryError, TOOL_EFFECT_CONTRACT_VERSION,
};
