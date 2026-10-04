//! The MCP Streamable HTTP client to the local kicad-mcp-pro server.
//!
//! This is deliberately a *minimal* client surface (protocol bootstrap,
//! `tools/list`, `tools/call`) rather than a full MCP SDK. The final
//! 2026-07-28 lane is stateless and uses `server/discover`; the maintained
//! 2025-11-25 lane keeps the legacy initialize/session contract explicitly.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Map, Value};
use url::Url;

use crate::error::CoreBridgeError;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, McpProtocolLane, ToolDescriptor};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct CoreBridgeConfig {
    pub endpoint: Url,
    pub timeout: Duration,
    pub protocol_lane: McpProtocolLane,
}

impl CoreBridgeConfig {
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            timeout: DEFAULT_TIMEOUT,
            protocol_lane: McpProtocolLane::Final2026,
        }
    }

    pub fn with_protocol_lane(mut self, protocol_lane: McpProtocolLane) -> Self {
        self.protocol_lane = protocol_lane;
        self
    }
}

pub struct CoreBridgeClient {
    http: reqwest::Client,
    endpoint: Url,
    protocol_lane: McpProtocolLane,
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

    /// Performs the selected lane's wire-level bootstrap.
    ///
    /// Final MCP 2026-07-28 uses direct `server/discover` and never emits
    /// `initialize`. The legacy lane uses the 2025-11-25 initialize flow.
    pub async fn bootstrap(
        &self,
        correlation_id: &str,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        match self.protocol_lane {
            McpProtocolLane::Final2026 => {
                self.send("server/discover", json!({}), correlation_id)
                    .await
            }
            McpProtocolLane::Legacy2025 => {
                let params = json!({
                    "protocolVersion": self.protocol_lane.protocol_version(),
                    "capabilities": {},
                    "clientInfo": {
                        "name": "kicad-mcp-pro-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                });
                self.send("initialize", params, correlation_id).await
            }
        }
    }

    /// Backward-compatible API name for callers that previously invoked
    /// `initialize`. On the final lane this delegates to `server/discover`
    /// and therefore does not put an initialize request on the wire.
    pub async fn initialize(
        &self,
        correlation_id: &str,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        self.bootstrap(correlation_id).await
    }

    pub async fn list_tools(
        &self,
        correlation_id: &str,
    ) -> Result<Vec<ToolDescriptor>, CoreBridgeError> {
        let result = self.send("tools/list", json!({}), correlation_id).await?;
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
        self.send("tools/call", params, correlation_id).await
    }

    async fn send(
        &self,
        method: &str,
        params: serde_json::Value,
        correlation_id: &str,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        let request_name = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let params = match self.protocol_lane {
            McpProtocolLane::Final2026 => final_request_params(params)?,
            McpProtocolLane::Legacy2025 => params,
        };
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

        match self.protocol_lane {
            McpProtocolLane::Final2026 => {
                req = req.header("Mcp-Method", method);
                if let Some(name) = request_name {
                    req = req.header("Mcp-Name", name);
                }
            }
            McpProtocolLane::Legacy2025 => {
                if let Some(session_id) = self
                    .session_id
                    .lock()
                    .expect("session_id mutex poisoned")
                    .clone()
                {
                    req = req.header("MCP-Session-Id", session_id);
                }
            }
        }

        let response = req.send().await.map_err(|e| {
            if e.is_timeout() {
                CoreBridgeError::Timeout
            } else {
                CoreBridgeError::Unreachable(e.to_string())
            }
        })?;

        match self.protocol_lane {
            McpProtocolLane::Final2026 => {
                if response.headers().contains_key("MCP-Session-Id") {
                    return Err(CoreBridgeError::ProtocolError(
                        "final MCP 2026-07-28 lane returned a legacy session id".into(),
                    ));
                }
            }
            McpProtocolLane::Legacy2025 => {
                if let Some(session_header) = response.headers().get("MCP-Session-Id") {
                    if let Ok(value) = session_header.to_str() {
                        *self.session_id.lock().expect("session_id mutex poisoned") =
                            Some(value.to_string());
                    }
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

fn final_request_params(params: Value) -> Result<Value, CoreBridgeError> {
    let Value::Object(mut params) = params else {
        return Err(CoreBridgeError::ProtocolError(
            "MCP request params must be a JSON object".into(),
        ));
    };

    let mut metadata = Map::new();
    metadata.insert(
        "io.modelcontextprotocol/protocolVersion".into(),
        Value::String(crate::protocol::MCP_PROTOCOL_VERSION.into()),
    );
    metadata.insert(
        "io.modelcontextprotocol/clientInfo".into(),
        json!({
            "name": "kicad-mcp-pro-gateway",
            "version": env!("CARGO_PKG_VERSION")
        }),
    );
    metadata.insert(
        "io.modelcontextprotocol/clientCapabilities".into(),
        json!({}),
    );
    params.insert("_meta".into(), Value::Object(metadata));
    Ok(Value::Object(params))
}

/// Refuses any endpoint that is not loopback/local. This is a second gate
/// against reaching an arbitrary network host, independent of whatever the
/// daemon's own configuration validation does — see
/// `docs/security/trust-boundaries.md`.
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
