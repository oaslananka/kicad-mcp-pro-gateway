//! Device-owned, read-only Cloud Web association probe.
//!
//! A signed query establishes the local key's Cloud Web ownership record.
//! Neither a successful poll nor a secure Web account grants any remote tool
//! permissions. An absent/unreachable/stale/revoked response is NOT paired.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_identity::DeviceIdentityStore;
use serde::Deserialize;

const CLOUD_URL: &str = "https://kicad-mcp-pro.oaslananka.dev/api/devices";
const STATUS_DOMAIN: &str = "kicad-mcp-cloud-web/device-status/v1";
const CLOUD_PROBE_TIMEOUT: Duration = Duration::from_millis(850);

struct SignedStatusProbe {
    device_id: String,
    timestamp: String,
    nonce: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudStatusReply {
    paired: bool,
    device_id: String,
    can_execute_tools: bool,
}

/// Exact v1 method/URI/body binding shared with Cloud Web.
/// Never reuse signed pairing invitations as status-probe credentials.
fn signed_message(device_id: &str, timestamp: &str, nonce: &str) -> Vec<u8> {
    format!("{STATUS_DOMAIN}\nGET\n/api/devices\n{device_id}\n{timestamp}\n{nonce}").into_bytes()
}

fn make_proof(
    identity_store: Arc<dyn DeviceIdentityStore + Send + Sync>,
) -> Option<SignedStatusProbe> {
    let identity = identity_store.public_identity().ok().flatten()?;
    let device_id = identity.device_id.to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .to_string();
    // Two independent ULIDs provide 160 random bits and a 52-character
    // Crockford-base32 nonce without adding another random generator.
    let nonce = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
    let signature = identity_store
        .sign(&signed_message(&device_id, &timestamp, &nonce))
        .ok()?;
    Some(SignedStatusProbe {
        device_id,
        timestamp,
        nonce,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

async fn poll(identity_store: Arc<dyn DeviceIdentityStore + Send + Sync>) -> Option<bool> {
    // Secure-store signing is blocking; do not stall the async IPC executor.
    let proof = tokio::task::spawn_blocking(move || make_proof(identity_store))
        .await
        .ok()??;
    let client = reqwest::Client::builder()
        .timeout(CLOUD_PROBE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let mut response = client
        .get(CLOUD_URL)
        .header("X-Kicad-Device-Id", &proof.device_id)
        .header("X-Kicad-Timestamp", &proof.timestamp)
        .header("X-Kicad-Nonce", &proof.nonce)
        .header("X-Kicad-Signature", &proof.signature)
        .send()
        .await
        .ok()?;
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    // No unbounded response buffering and no redirect to an untrusted host.
    if response.content_length().is_some_and(|size| size > 1024) {
        return None;
    }
    let mut bytes = Vec::with_capacity(256);
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len().saturating_add(chunk.len()) > 1024 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    let reply: CloudStatusReply = serde_json::from_slice(&bytes).ok()?;
    if reply.device_id != proof.device_id || reply.can_execute_tools {
        return None;
    }
    Some(reply.paired)
}

/// A device association is only a display state, not authorization evidence.
pub async fn is_paired(identity_store: Arc<dyn DeviceIdentityStore + Send + Sync>) -> bool {
    poll(identity_store).await.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{signed_message, CloudStatusReply};

    #[test]
    fn signing_material_is_path_method_device_and_nonce_bound() {
        let nonce = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
        let expected = format!(
            "kicad-mcp-cloud-web/device-status/v1\nGET\n/api/devices\ndev_01J00000000000000000000000\n1791617000\n{nonce}"
        );
        assert_eq!(
            String::from_utf8(signed_message(
                "dev_01J00000000000000000000000",
                "1791617000",
                &nonce
            ))
            .unwrap(),
            expected
        );
        assert_ne!(
            signed_message("device-a", "100", &nonce),
            signed_message("device-b", "100", &nonce)
        );
        let another_nonce = format!("{}{}", ulid::Ulid::new(), ulid::Ulid::new());
        assert_ne!(
            signed_message("device-a", "100", &nonce),
            signed_message("device-a", "100", &another_nonce)
        );
    }

    #[test]
    fn status_reply_cannot_smuggle_extra_grant_fields() {
        assert!(serde_json::from_str::<CloudStatusReply>(
            r#"{"device_id":"dev_01J00000000000000000000000","paired":true,"can_execute_tools":false,"grant":"admin"}"#
        ).is_err());
    }
}
