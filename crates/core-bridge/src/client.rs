//! The MCP Streamable HTTP client to the local kicad-mcp-pro server.
//!
//! This is deliberately a *minimal* client surface (`initialize`,
//! `tools/list`, `tools/call`) rather than a full MCP SDK: kicad-mcp-pro's
//! documented contract at the time of writing needs only these three
//! methods for Companion's purposes, and a smaller surface is easier to
//! keep correct and audited. See `docs/protocol/README.md`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::json;
use url::Url;

use crate::error::CoreBridgeError;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, ToolDescriptor, MCP_PROTOCOL_VERSION};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct CoreBridgeConfig {
    pub endpoint: Url,
    pub timeout: Duration,
}

impl CoreBridgeConfig {
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

pub struct CoreBridgeClient {
    http: reqwest::Client,
    endpoint: Url,
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
            session_id: Mutex::new(None),
        })
    }

    /// Performs the MCP `initialize` handshake. Returns the raw server
    /// `result` payload — Companion does not need to interpret every field
    /// of it, only that the call succeeded.
    pub async fn initialize(
        &self,
        correlation_id: &str,
    ) -> Result<serde_json::Value, CoreBridgeError> {
        let params = json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "kicad-mcp-pro-companion", "version": env!("CARGO_PKG_VERSION") },
        });
        self.send("initialize", params, correlation_id).await
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
        let request_body = JsonRpcRequest::new(correlation_id, method, params);

        let mut req = self
            .http
            .post(self.endpoint.clone())
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION)
            .json(&request_body);

        if let Some(session_id) = self
            .session_id
            .lock()
            .expect("session_id mutex poisoned")
            .clone()
        {
            req = req.header("MCP-Session-Id", session_id);
        }

        let response = req.send().await.map_err(|e| {
            if e.is_timeout() {
                CoreBridgeError::Timeout
            } else {
                CoreBridgeError::Unreachable(e.to_string())
            }
        })?;

        if let Some(session_header) = response.headers().get("MCP-Session-Id") {
            if let Ok(value) = session_header.to_str() {
                *self.session_id.lock().expect("session_id mutex poisoned") =
                    Some(value.to_string());
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
