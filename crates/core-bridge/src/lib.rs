//! `companion-core-bridge`: the adapter that talks to the local
//! kicad-mcp-pro MCP server. This crate contains no KiCad domain logic —
//! see `docs/architecture/component-boundaries.md`.

pub mod client;
pub mod error;
pub mod protocol;

#[cfg(any(test, feature = "test-util"))]
pub mod mock_server;

pub use client::{CoreBridgeClient, CoreBridgeConfig};
pub use error::CoreBridgeError;
pub use protocol::{
    ProtocolLane, ToolDescriptor, FINAL_MCP_PROTOCOL_VERSION, LEGACY_MCP_PROTOCOL_VERSION,
    MCP_PROTOCOL_VERSION,
};

#[cfg(any(test, feature = "test-util"))]
pub use mock_server::{MockMcpServer, RecordedHttpRequest, ToolCallBehavior};
