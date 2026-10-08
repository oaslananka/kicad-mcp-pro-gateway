//! Authenticated outbound cloud heartbeat transport.
//!
//! It intentionally accepts NO remote operations, sessions, or principal
//! claims yet: production principal attestation, durable replay detection,
//! and OAuth-backed MCP ingress must land before a privileged lane is enabled.
//! The transport verifies the server using standard WebPKI TLS (wss) and
//! authenticates this device by signing an ephemeral server challenge using
//! its existing native secure-store Ed25519 key.
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use companion_core::TransportState;
use companion_identity::DeviceIdentityStore;
use companion_protocol::Envelope;
use companion_transport::{InboundEnvelope, Transport, TransportError, TransportHealth};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use url::Url;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct RelayTransport {
    url: Url,
    identity_store: Arc<dyn DeviceIdentityStore + Send + Sync>,
    socket: Mutex<Option<Socket>>,
    state: StdMutex<TransportState>,
}

impl RelayTransport {
    pub fn new(url: Url, identity_store: Arc<dyn DeviceIdentityStore + Send + Sync>) -> Self {
        Self {
            url,
            identity_store,
            socket: Mutex::new(None),
            state: StdMutex::new(TransportState::Disconnected),
        }
    }

    fn error(error: &str) -> TransportError {
        TransportError::ConnectFailed(error.into())
    }
}

fn challenge_message(device_id: &str, nonce: &str) -> Vec<u8> {
    format!("kicad-mcp-cloud-relay/auth/v1\n{device_id}\n{nonce}").into_bytes()
}

async fn next_text(socket: &mut Socket) -> Result<String, TransportError> {
    let received = tokio::time::timeout(Duration::from_secs(15), socket.next())
        .await
        .map_err(|_| RelayTransport::error("remote device-auth handshake timed out"))?;
    let Message::Text(raw) = received
        .ok_or_else(|| RelayTransport::error("relay closed handshake"))?
        .map_err(|_| RelayTransport::error("relay handshake read failed"))?
    else {
        return Err(RelayTransport::error("unexpected relay handshake frame"));
    };
    if raw.len() > 4096 {
        return Err(RelayTransport::error("oversized relay handshake"));
    }
    Ok(raw.to_string())
}

fn protocol_field<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, TransportError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RelayTransport::error("malformed relay handshake"))
}

#[async_trait::async_trait]
impl Transport for RelayTransport {
    async fn connect(&self) -> Result<(), TransportError> {
        *self.state.lock().expect("state mutex poisoned") = TransportState::Connecting;
        let device = self
            .identity_store
            .public_identity()
            .map_err(|_| Self::error("secure device identity read failed"))?
            .ok_or_else(|| Self::error("device identity is not initialized"))?;
        let device_id = device.device_id.to_string();
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(12), connect_async(self.url.as_str()))
                .await
                .map_err(|_| Self::error("TLS/WebSocket connect timed out"))?
                .map_err(|_| Self::error("TLS/WebSocket connect failed"))?;

        let challenge_raw = next_text(&mut stream).await?;
        let challenge: serde_json::Value = serde_json::from_str(&challenge_raw)
            .map_err(|_| Self::error("invalid challenge JSON"))?;
        if protocol_field(&challenge, "type")? != "challenge" {
            return Err(Self::error("unexpected challenge type"));
        }
        let nonce = protocol_field(&challenge, "nonce")?;
        if URL_SAFE_NO_PAD
            .decode(nonce)
            .map(|bytes| bytes.len() != 32)
            .unwrap_or(true)
        {
            return Err(Self::error("invalid challenge nonce"));
        }
        if challenge
            .get("expires_in_seconds")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|ttl| ttl == 0 || ttl > 30)
        {
            return Err(Self::error("invalid challenge expiry"));
        }
        let signature = self
            .identity_store
            .sign(&challenge_message(&device_id, nonce))
            .map_err(|_| Self::error("device signing failed"))?;
        let proof = serde_json::json!({
            "type": "proof",
            "device_id": device_id,
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        });
        stream
            .send(Message::Text(proof.to_string().into()))
            .await
            .map_err(|_| Self::error("device proof send failed"))?;
        let ready_raw = next_text(&mut stream).await?;
        let ready: serde_json::Value =
            serde_json::from_str(&ready_raw).map_err(|_| Self::error("invalid ready JSON"))?;
        if protocol_field(&ready, "type")? != "ready"
            || protocol_field(&ready, "device_id")? != device_id
        {
            return Err(Self::error("relay did not authenticate this device"));
        }
        *self.socket.lock().await = Some(stream);
        *self.state.lock().expect("state mutex poisoned") = TransportState::Connected;
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), TransportError> {
        if let Some(mut socket) = self.socket.lock().await.take() {
            let _ = socket.close(None).await;
        }
        *self.state.lock().expect("state mutex poisoned") = TransportState::Disconnected;
        Ok(())
    }

    async fn send(&self, _envelope: Envelope) -> Result<(), TransportError> {
        // No remote sessions/operations cross this transport before verified
        // actor credential validation and durable replay protection exist.
        Err(TransportError::SendFailed(
            "privileged cloud relay messages are not enabled".into(),
        ))
    }

    async fn receive(&self) -> Result<InboundEnvelope, TransportError> {
        let mut guard = self.socket.lock().await;
        let socket = guard.as_mut().ok_or(TransportError::NotConnected)?;
        let incoming = tokio::time::timeout(Duration::from_secs(25), socket.next()).await;
        match incoming {
            Err(_) => {
                let heartbeat = serde_json::json!({
                    "type": "heartbeat",
                    "message_id": ulid::Ulid::new().to_string(),
                });
                socket
                    .send(Message::Text(heartbeat.to_string().into()))
                    .await
                    .map_err(|_| TransportError::ReceiveFailed("heartbeat send failed".into()))?;
                Err(TransportError::NoMessage)
            }
            Ok(Some(Ok(Message::Text(raw)))) => {
                if raw.len() > 4096 {
                    return Err(TransportError::ReceiveFailed(
                        "oversized relay frame".into(),
                    ));
                }
                let value: serde_json::Value = serde_json::from_str(&raw)
                    .map_err(|_| TransportError::ReceiveFailed("invalid relay frame".into()))?;
                if value.get("type").and_then(serde_json::Value::as_str) == Some("heartbeat_ack")
                    && value
                        .get("message_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|id| !id.is_empty() && id.len() <= 80)
                {
                    return Err(TransportError::NoMessage);
                }
                Err(TransportError::ReceiveFailed(
                    "untrusted remote command rejected".into(),
                ))
            }
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => {
                Err(TransportError::NoMessage)
            }
            _ => Err(TransportError::ReceiveFailed(
                "relay socket closed or invalid".into(),
            )),
        }
    }

    fn state(&self) -> TransportState {
        *self.state.lock().expect("state mutex poisoned")
    }

    async fn health(&self) -> TransportHealth {
        TransportHealth {
            connected: self.state() == TransportState::Connected,
            last_error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_domain_separated_and_binds_the_current_device_and_nonce() {
        // Every test instance uses fresh IDs; no hardcoded cryptographic nonce
        // is supplied to the production challenge-signing routine.
        let device_id = companion_core::DeviceId::new().to_string();
        let nonce = ulid::Ulid::new().to_string();
        let proof_input = challenge_message(&device_id, &nonce);
        let expected = format!("kicad-mcp-cloud-relay/auth/v1\n{device_id}\n{nonce}");
        assert_eq!(proof_input, expected.into_bytes());
        assert_ne!(
            proof_input,
            challenge_message(&device_id, "different-nonce")
        );
        assert_ne!(proof_input, challenge_message("different-device", &nonce));
    }
}
