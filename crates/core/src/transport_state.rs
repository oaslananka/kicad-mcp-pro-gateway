use serde::{Deserialize, Serialize};

/// State of the Companion-to-relay transport pipe itself. This is
/// independent of any session's authorization state — see
/// `docs/security/trust-boundaries.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// Reachability of the local kicad-mcp-pro MCP endpoint, as last observed
/// by the core bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreConnectionState {
    Unknown,
    Reachable,
    Unreachable,
}
