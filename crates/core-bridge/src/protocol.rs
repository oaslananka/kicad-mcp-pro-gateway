//! JSON-RPC 2.0 envelope and MCP method shapes used against kicad-mcp-pro.
//! This crate is a client only — it never invents protocol extensions.

use serde::{Deserialize, Serialize};

/// The MCP protocol version this client negotiates, as documented by
/// kicad-mcp-pro at the time this crate was written
/// (`docs/mcp/transport.md` in that repository).
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";

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
