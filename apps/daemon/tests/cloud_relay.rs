//! Test the cloud device proof against a real in-process WebSocket server.
//! The protocol must remain fail-closed for any privileged remote envelope.
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use companion_identity::{DeviceIdentityStore, InMemorySecretStore, SqliteDeviceIdentityStore};
use companion_protocol::{Envelope, MessageType};
use companion_storage::Storage;
use companion_transport::{Transport, TransportError};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use kicad_mcp_gateway_daemon::relay_transport::RelayTransport;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use url::Url;

const NONCE_BYTES: [u8; 32] = [43; 32];

#[tokio::test]
async fn signed_authentication_succeeds_but_remote_commands_stay_denied() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(temp.path()).unwrap());
    let store: Arc<dyn DeviceIdentityStore + Send + Sync> = Arc::new(
        SqliteDeviceIdentityStore::new(storage, InMemorySecretStore::new()),
    );
    let identity = store.create("test-device").unwrap();
    let device_id = identity.device_id.to_string();
    let key = VerifyingKey::from_bytes(&identity.public_key.0).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!(
        "{}://{}/v1/device/connect",
        "ws",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(socket).await.unwrap();
        let nonce = URL_SAFE_NO_PAD.encode(NONCE_BYTES);
        ws.send(Message::Text(
            serde_json::json!({
                "type": "challenge",
                "nonce": nonce,
                "expires_in_seconds": 15,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let proof: serde_json::Value =
            serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        assert_eq!(proof["type"], "proof");
        assert_eq!(proof["device_id"], device_id);
        let bytes = URL_SAFE_NO_PAD
            .decode(proof["signature"].as_str().unwrap())
            .unwrap();
        let signature = Signature::from_slice(&bytes).unwrap();
        let message = format!("kicad-mcp-cloud-relay/auth/v1\n{device_id}\n{nonce}");
        key.verify_strict(message.as_bytes(), &signature).unwrap();

        ws.send(Message::Text(
            serde_json::json!({"type":"ready","device_id":device_id})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        ws.send(Message::Text(
            serde_json::json!({"type":"session_request","principal":"forged-agent"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    });

    let relay = RelayTransport::new(url, store);
    relay.connect().await.unwrap();
    assert!(relay.health().await.connected);
    let outbound = relay
        .send(Envelope::new(
            MessageType::OperationResult,
            serde_json::json!({"result":"not-permitted"}),
        ))
        .await;
    assert!(matches!(outbound, Err(TransportError::SendFailed(_))));
    assert!(matches!(
        relay.receive().await,
        Err(TransportError::ReceiveFailed(_))
    ));
    relay.disconnect().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn mismatched_relay_ready_identity_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(temp.path()).unwrap());
    let store: Arc<dyn DeviceIdentityStore + Send + Sync> = Arc::new(
        SqliteDeviceIdentityStore::new(storage, InMemorySecretStore::new()),
    );
    let device = store.create("other-test-device").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!(
        "{}://{}/v1/device/connect",
        "ws",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(socket).await.unwrap();
        ws.send(Message::Text(
            serde_json::json!({
                "type": "challenge",
                "nonce": URL_SAFE_NO_PAD.encode(NONCE_BYTES),
                "expires_in_seconds": 15
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        let _proof = ws.next().await.unwrap().unwrap();
        ws.send(Message::Text(
            serde_json::json!({"type":"ready","device_id":
                "dev_01J00000000000000000000000"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    });
    assert_ne!(
        device.device_id.to_string(),
        "dev_01J00000000000000000000000"
    );
    let relay = RelayTransport::new(url, store);
    assert!(matches!(
        relay.connect().await,
        Err(TransportError::ConnectFailed(_))
    ));
    assert!(!relay.health().await.connected);
    server.await.unwrap();
}
