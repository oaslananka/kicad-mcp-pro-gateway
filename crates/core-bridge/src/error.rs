use companion_core::CompanionError;

#[derive(Debug, thiserror::Error)]
pub enum CoreBridgeError {
    #[error("core bridge endpoint '{endpoint}' is not a loopback/local address; only localhost targets are allowed by default")]
    EndpointNotAllowed { endpoint: String },
    #[error("kicad-mcp-pro is unreachable: {0}")]
    Unreachable(String),
    #[error("kicad-mcp-pro call timed out")]
    Timeout,
    #[error("kicad-mcp-pro returned a malformed or unexpected response: {0}")]
    ProtocolError(String),
    #[error("kicad-mcp-pro tool call failed: {message}")]
    ToolError { code: Option<i64>, message: String },
}

impl CompanionError for CoreBridgeError {
    fn code(&self) -> &'static str {
        match self {
            CoreBridgeError::EndpointNotAllowed { .. } => "CORE_BRIDGE_ENDPOINT_NOT_ALLOWED",
            CoreBridgeError::Unreachable(_) => "CORE_UNREACHABLE",
            CoreBridgeError::Timeout => "CORE_TIMEOUT",
            CoreBridgeError::ProtocolError(_) => "CORE_PROTOCOL_ERROR",
            CoreBridgeError::ToolError { .. } => "CORE_TOOL_ERROR",
        }
    }

    fn retryable(&self) -> bool {
        matches!(
            self,
            CoreBridgeError::Unreachable(_) | CoreBridgeError::Timeout
        )
    }
}
