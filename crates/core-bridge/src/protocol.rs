//! JSON-RPC 2.0 envelope and MCP method shapes used against kicad-mcp-pro.
//! This crate is a client only — it never invents protocol extensions.

use serde::{Deserialize, Serialize};

/// Upstream's primary, stateless MCP contract.
pub const FINAL_MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// Explicit backward-compatible initialize/session lane retained by upstream.
pub const LEGACY_MCP_PROTOCOL_VERSION: &str = "2025-11-25";

/// Primary Gateway core-bridge protocol. Kept as an alias for callers that only
/// need the promoted default rather than lane-specific behavior.
pub const MCP_PROTOCOL_VERSION: &str = FINAL_MCP_PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolLane {
    #[default]
    Final2026,
    Legacy2025,
}

impl ProtocolLane {
    pub const fn protocol_version(self) -> &'static str {
        match self {
            Self::Final2026 => FINAL_MCP_PROTOCOL_VERSION,
            Self::Legacy2025 => LEGACY_MCP_PROTOCOL_VERSION,
        }
    }

    pub const fn uses_initialize(self) -> bool {
        matches!(self, Self::Legacy2025)
    }

    pub const fn uses_session_ids(self) -> bool {
        matches!(self, Self::Legacy2025)
    }
}

#[derive(Debug, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: String,
    pub method: String,
    pub params: serde_json::Value,
}

impl JsonRpcRequest {
    pub fn new(
        id: impl Into<String>,
        method: impl Into<String>,
        params: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0",
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse {
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<JsonRpcErrorBody>,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcErrorBody {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}
