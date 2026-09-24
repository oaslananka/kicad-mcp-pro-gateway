//! An `OperationRequest` is a single candidate action a remote session wants
//! to perform. It is opaque with respect to KiCad domain semantics — this
//! crate never knows what `tool_name` "does." The policy crate derives effects
//! from reviewed contracts; `target_path` is non-authoritative caller metadata.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::{OperationId, SessionId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRequest {
    pub operation_id: OperationId,
    pub session_id: SessionId,
    pub workspace_id: WorkspaceId,
    /// The tool name exactly as named by kicad-mcp-pro's MCP tool registry.
    pub tool_name: String,
    /// JSON object forwarded unchanged as MCP `tools/call.arguments`. Policy
    /// derives filesystem effects from reviewed tool contracts, not from a
    /// caller-declared effect summary.
    #[serde(default)]
    pub arguments: serde_json::Map<String, serde_json::Value>,
    /// Legacy caller metadata retained for wire compatibility. Gateway policy
    /// deliberately ignores it as authorization evidence.
    pub target_path: Option<std::path::PathBuf>,
    #[serde(with = "time::serde::rfc3339")]
    pub requested_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationResult {
    pub operation_id: OperationId,
    pub success: bool,
    pub payload: serde_json::Value,
    pub error: Option<OperationError>,
    pub duration_ms: u64,
}
