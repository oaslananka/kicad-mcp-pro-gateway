//! A minimal in-process mock MCP server for testing `CoreBridgeClient`
//! without a real kicad-mcp-pro instance. Test-only — see
//! `docs/development/testing.md`. It hand-rolls just enough HTTP/1.1
//! parsing to receive one JSON-RPC POST per connection; it is not a
//! general-purpose HTTP server and must never be used outside tests.

#![cfg(any(test, feature = "test-util"))]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

#[derive(Clone)]
pub enum ToolCallBehavior {
    Success(Value),
    Error {
        code: i64,
        message: String,
    },
    /// Never responds, to exercise the client's timeout path.
    Hang,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordedMcpRequest {
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub params: Value,
}

impl RecordedMcpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

pub struct MockMcpServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    behavior: Arc<Mutex<ToolCallBehavior>>,
    call_count: Arc<AtomicUsize>,
    tool_calls: Arc<Mutex<Vec<Value>>>,
    requests: Arc<Mutex<Vec<RecordedMcpRequest>>>,
}

impl MockMcpServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock mcp server");
        let addr = listener.local_addr().expect("mock mcp server local addr");
        let shutdown = Arc::new(Notify::new());
        let behavior = Arc::new(Mutex::new(ToolCallBehavior::Success(
            json!({ "content": [] }),
        )));
        let call_count = Arc::new(AtomicUsize::new(0));
        let tool_calls = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));

        let shutdown_task = Arc::clone(&shutdown);
        let behavior_task = Arc::clone(&behavior);
        let call_count_task = Arc::clone(&call_count);
        let tool_calls_task = Arc::clone(&tool_calls);
        let requests_task = Arc::clone(&requests);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            let behavior = Arc::clone(&behavior_task);
                            let call_count = Arc::clone(&call_count_task);
                            let tool_calls = Arc::clone(&tool_calls_task);
                            let requests = Arc::clone(&requests_task);
                            tokio::spawn(async move {
                                let _ = handle_connection(
                                    stream,
                                    behavior,
                                    call_count,
                                    tool_calls,
                                    requests,
                                ).await;
                            });
                        }
                    }
                    _ = shutdown_task.notified() => break,
                }
            }
        });

        Self {
            addr,
            shutdown,
            behavior,
            call_count,
            tool_calls,
            requests,
        }
    }

    pub fn endpoint(&self) -> url::Url {
        url::Url::parse(&format!("http://{}/mcp", self.addr)).expect("mock endpoint is a valid url")
    }

    pub fn set_tool_call_behavior(&self, behavior: ToolCallBehavior) {
        *self.behavior.lock().expect("mock behavior mutex poisoned") = behavior;
    }

    pub fn tool_call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    pub fn tool_calls(&self) -> Vec<Value> {
        self.tool_calls
            .lock()
            .expect("mock tool call mutex poisoned")
            .clone()
    }

    pub fn requests(&self) -> Vec<RecordedMcpRequest> {
        self.requests
            .lock()
            .expect("mock requests mutex poisoned")
            .clone()
    }

    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    behavior: Arc<Mutex<ToolCallBehavior>>,
    call_count: Arc<AtomicUsize>,
    tool_calls: Arc<Mutex<Vec<Value>>>,
    requests: Arc<Mutex<Vec<RecordedMcpRequest>>>,
) -> std::io::Result<()> {
    let (headers, body) = read_http_request(&mut stream).await?;
    let request: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let payload = json!({ "jsonrpc": "2.0", "id": Value::Null, "error": { "code": -32700, "message": "parse error" } });
            return write_response(&mut stream, 400, &payload).await;
        }
    };

    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    requests
        .lock()
        .expect("mock requests mutex poisoned")
        .push(RecordedMcpRequest {
            method: method.clone(),
            headers,
            params,
        });

    match method.as_str() {
        "server/discover" => {
            let result = json!({
                "resultType": "complete",
                "supportedVersions": [crate::protocol::MCP_PROTOCOL_VERSION],
                "capabilities": { "tools": {}, "resources": {} },
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "mock-kicad-mcp-pro",
                        "version": "0.0.0-mock"
                    }
                },
                "ttlMs": 3_600_000,
                "cacheScope": "private"
            });
            write_response(
                &mut stream,
                200,
                &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            )
            .await
        }
        "initialize" => {
            let result = json!({
                "protocolVersion": crate::protocol::MCP_LEGACY_PROTOCOL_VERSION,
                "serverInfo": { "name": "mock-kicad-mcp-pro", "version": "0.0.0-mock" },
                "capabilities": {},
            });
            write_response_with_headers(
                &mut stream,
                200,
                &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                &[("MCP-Session-Id", "mock-legacy-session")],
            )
            .await
        }
        "tools/list" => {
            let result = json!({
                "tools": [
                    { "name": "schematic.read", "description": "Read the current schematic" },
                    { "name": "schematic.add_symbol", "description": "Add a symbol" },
                ]
            });
            write_response(
                &mut stream,
                200,
                &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            )
            .await
        }
        "tools/call" => {
            call_count.fetch_add(1, Ordering::SeqCst);
            tool_calls
                .lock()
                .expect("mock tool call mutex poisoned")
                .push(request.get("params").cloned().unwrap_or(Value::Null));
            let current = behavior
                .lock()
                .expect("mock behavior mutex poisoned")
                .clone();
            match current {
                ToolCallBehavior::Success(value) => {
                    write_response(
                        &mut stream,
                        200,
                        &json!({ "jsonrpc": "2.0", "id": id, "result": value }),
                    )
                    .await
                }
                ToolCallBehavior::Error { code, message } => {
                    let payload = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } });
                    write_response(&mut stream, 200, &payload).await
                }
                ToolCallBehavior::Hang => std::future::pending::<std::io::Result<()>>().await,
            }
        }
        other => {
            let payload = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {other}") } });
            write_response(&mut stream, 200, &payload).await
        }
    }
}

async fn read_http_request(
    stream: &mut TcpStream,
) -> std::io::Result<(BTreeMap<String, String>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];

    let header_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before headers completed",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let mut headers = BTreeMap::new();
    for line in header_text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    while buf.len() < header_end + content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let end = (header_end + content_length).min(buf.len());
    Ok((headers, buf[header_end..end].to_vec()))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn write_response(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    write_response_with_headers(stream, status, body, &[]).await
}

async fn write_response_with_headers(
    stream: &mut TcpStream,
    status: u16,
    body: &Value,
    extra_headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let body_bytes = serde_json::to_vec(body).expect("mock response is always serializable");
    let status_text = if status == 200 { "OK" } else { "Bad Request" };
    let mut header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body_bytes.len()
    );
    for (name, value) in extra_headers {
        header.push_str(name);
        header.push_str(": ");
        header.push_str(value);
        header.push_str("\r\n");
    }
    header.push_str("Connection: close\r\n\r\n");
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body_bytes).await?;
    stream.flush().await
}
