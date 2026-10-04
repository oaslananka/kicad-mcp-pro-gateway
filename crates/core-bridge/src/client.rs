//! The MCP Streamable HTTP client to the local kicad-mcp-pro server.
//!
//! Gateway deliberately keeps a small audited surface: protocol connect /
//! discovery, tools/list, and tools/call. The primary upstream contract is
//! stateless MCP 2026-07-28; an explicit legacy 2025-11-25 initialize/session
//! lane remains available for compatibility.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use url::Url;

use crate::error::CoreBridgeError;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, ProtocolLane, ToolDescriptor};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct CoreBridgeConfig {
    pub endpoint: Url,
    pub timeout: Duration,
    pub protocol_lane: ProtocolLane,
}

impl CoreBridgeConfig {
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            timeout: DEFAULT_TIMEOUT,
            protocol_lane: ProtocolLane::Final2026,
        }
    }

    pub fn with_protocol_lane(mut self, protocol_lane: ProtocolLane) -> Self {
        self.protocol_lane = protocol_lane;
        self
    }
}

pub struct CoreBridgeClient {
    http: reqwest::Client,
    endpoint: Url,
    protocol_lane: ProtocolLane,
    session_id: Mutex<Option<String>>,
}

impl CoreBridgeClient {
    pub fn new(config: CoreBridgeConfig) -> Result<Self, CoreBridgeError> {
        assert_loopback(&config.endpoint)?;
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| {
                CoreBridgeError::ProtocolError(format!("failed to build http client: {e}"))
            })?;
        Ok(Self {
            http,
            endpoint: config.endpoint,
            protocol_lane: config.protocol_lane,
            session_id: Mutex::new(None),
        })
    }

    pub const fn protocol_lane(&self) -> ProtocolLane {
        self.protocol_lane
    }

    /// Establishes protocol readiness without leaking legacy transport-session
    /// mechanics into callers. The final lane uses direct server/discover;
    /// only the explicit legacy lane performs initialize.
    pub async fn connect(
        &self,
        correlation_id: &str,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        match self.protocol_lane {
            ProtocolLane::Final2026 => {
                self.send("server/discover", json!({}), correlation_id, None)
                    .await
            }
            ProtocolLane::Legacy2025 => self.initialize(correlation_id).await,
        }
    }

    /// Performs the legacy MCP initialize handshake.
    ///
    /// Final-protocol callers must use connect(), which sends server/discover
    /// and never sends legacy lifecycle/session fields.
    pub async fn initialize(
        &self,
        correlation_id: &str,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        if !self.protocol_lane.uses_initialize() {
            return Err(CoreBridgeError::ProtocolError(
                "initialize is only valid for the explicit MCP 2025-11-25 legacy lane".into(),
            ));
        }

        let params = json!({
            "protocolVersion": self.protocol_lane.protocol_version(),
            "capabilities": {},
            "clientInfo": { "name": "kicad-mcp-pro-gateway", "version": env!("CARGO_PKG_VERSION") },
        });
        self.send("initialize", params, correlation_id, None).await
    }

    pub async fn list_tools(
        &self,
        correlation_id: &str,
    ) -> Result<Vec<ToolDescriptor>, CoreBridgeError> {
        let result = self
            .send("tools/list", json!({}), correlation_id, None)
            .await?;
        let tools = result
            .get("tools")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        serde_json::from_value(tools).map_err(|e| {
            CoreBridgeError::ProtocolError(format!("malformed tools/list result: {e}"))
        })
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
        correlation_id: &str,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        let params = json!({ "name": name, "arguments": arguments });
        self.send("tools/call", params, correlation_id, Some(name))
            .await
    }

    fn prepare_params(&self, params: Value) -> Result<Value, CoreBridgeError> {
        if self.protocol_lane != ProtocolLane::Final2026 {
            return Ok(params);
        }

        let mut params = match params {
            Value::Object(map) => map,
            _ => {
                return Err(CoreBridgeError::ProtocolError(
                    "final MCP request params must be a JSON object".into(),
                ))
            }
        };

        if params.contains_key("_meta") {
            return Err(CoreBridgeError::ProtocolError(
                "final MCP request metadata is owned by the core bridge".into(),
            ));
        }

        params.insert(
            "_meta".into(),
            json!({
                "io.modelcontextprotocol/protocolVersion": self.protocol_lane.protocol_version(),
                "io.modelcontextprotocol/clientInfo": {
                    "name": "kicad-mcp-pro-gateway",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "io.modelcontextprotocol/clientCapabilities": {},
            }),
        );

        Ok(Value::Object(params))
    }

    async fn send(
        &self,
        method: &str,
        params: serde_json::Value,
        correlation_id: &str,
        name: Option<&str>,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        let params = self.prepare_params(params)?;
        let request_body = JsonRpcRequest::new(correlation_id, method, params);

        let mut req = self
            .http
            .post(self.endpoint.clone())
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header(
                "MCP-Protocol-Version",
                self.protocol_lane.protocol_version(),
            )
            .json(&request_body);

        if self.protocol_lane == ProtocolLane::Final2026 {
            req = req.header("Mcp-Method", method);
            if let Some(name) = name {
                req = req.header("Mcp-Name", name);
            }
        }

        if self.protocol_lane.uses_session_ids() {
            if let Some(session_id) = self
                .session_id
                .lock()
                .expect("session_id mutex poisoned")
                .clone()
            {
                req = req.header("MCP-Session-Id", session_id);
            }
        }

        let response = req.send().await.map_err(|e| {
            if e.is_timeout() {
                CoreBridgeError::Timeout
            } else {
                CoreBridgeError::Unreachable(e.to_string())
            }
        })?;

        if self.protocol_lane.uses_session_ids() {
            if let Some(session_header) = response.headers().get("MCP-Session-Id") {
                if let Ok(value) = session_header.to_str() {
                    *self.session_id.lock().expect("session_id mutex poisoned") =
                        Some(value.to_string());
                }
            }
        }

        if !response.status().is_success() {
            return Err(CoreBridgeError::ProtocolError(format!(
                "http status {}",
                response.status()
            )));
        }

        let body: JsonRpcResponse = response.json().await.map_err(|e| {
            CoreBridgeError::ProtocolError(format!("response body was not valid JSON-RPC: {e}"))
        })?;

        if let Some(err) = body.error {
            return Err(CoreBridgeError::ToolError {
                code: Some(err.code),
                message: err.message,
            });
        }

        body.result.ok_or_else(|| {
            CoreBridgeError::ProtocolError("response had neither result nor error".into())
        })
    }
}

/// Refuses any endpoint that is not loopback/local. This is a second gate
/// against reaching an arbitrary network host, independent of whatever the
/// daemon's own configuration validation does.
fn assert_loopback(endpoint: &Url) -> Result<(), CoreBridgeError> {
    let host = endpoint.host_str().unwrap_or("");
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<Ipv4Addr>()
            .map(|a| a.is_loopback())
            .unwrap_or(false)
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<Ipv6Addr>()
            .map(|a| a.is_loopback())
            .unwrap_or(false);

    if is_loopback {
        Ok(())
    } else {
        Err(CoreBridgeError::EndpointNotAllowed {
            endpoint: endpoint.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_final_protocol_lane() {
        let config = CoreBridgeConfig::new(Url::parse("http://127.0.0.1:3334/mcp").unwrap());
        assert_eq!(config.protocol_lane, ProtocolLane::Final2026);
    }

    #[test]
    fn loopback_hosts_are_allowed() {
        for url in [
            "http://127.0.0.1:3334/mcp",
            "http://localhost:3334/mcp",
            "http://[::1]:3334/mcp",
        ] {
            assert!(assert_loopback(&Url::parse(url).unwrap()).is_ok(), "{url}");
        }
    }

    #[test]
    fn non_loopback_hosts_are_rejected() {
        for url in [
            "http://example.com/mcp",
            "http://192.168.1.5:3334/mcp",
            "http://8.8.8.8/mcp",
        ] {
            let result = assert_loopback(&Url::parse(url).unwrap());
            assert!(
                matches!(result, Err(CoreBridgeError::EndpointNotAllowed { .. })),
                "{url}"
            );
        }
    }

    #[test]
    fn client_construction_rejects_non_loopback_endpoint() {
        let config = CoreBridgeConfig::new(Url::parse("http://example.com/mcp").unwrap());
        let result = CoreBridgeClient::new(config);
        assert!(matches!(
            result,
            Err(CoreBridgeError::EndpointNotAllowed { .. })
        ));
    }
}
