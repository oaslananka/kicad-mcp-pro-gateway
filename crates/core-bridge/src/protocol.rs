//! JSON-RPC 2.0 envelope and MCP method shapes used against kicad-mcp-pro.
//! This crate is a client only — it never invents protocol extensions.

use serde::{Deserialize, Serialize};

/// Primary MCP protocol version published by kicad-mcp-pro 3.37.0.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// Explicit backward-compatible initialize/session lane retained by upstream.
pub const MCP_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

/// Wire-level MCP compatibility lane. There is no automatic fallback between
/// lanes: callers select one policy explicitly and requests stay within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpProtocolLane {
    Final2026,
    Legacy2025,
}

impl Default for McpProtocolLane {
    fn default() -> Self {
        Self::Final2026
    }
}

impl McpProtocolLane {
    pub const fn protocol_version(self) -> &'static str {
        match self {
            Self::Final2026 => MCP_PROTOCOL_VERSION,
            Self::Legacy2025 => MCP_LEGACY_PROTOCOL_VERSION,
        }
    }

    pub const fn bootstrap_method(self) -> &'static str {
        match self {
            Self::Final2026 => "server/discover",
            Self::Legacy2025 => "initialize",
        }
    }

    pub const fn uses_legacy_sessions(self) -> bool {
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
