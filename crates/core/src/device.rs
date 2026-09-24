use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::DeviceId;

/// Raw Ed25519 public key bytes. Never secret — safe to log, persist in
/// SQLite, and send to the cloud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicKey(pub [u8; 32]);

/// A human-readable, display-only derivation of a device's public key.
/// Never used as a security check by itself — it exists so a user can
/// visually confirm a device during pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFingerprint(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: DeviceId,
    pub public_key: DevicePublicKey,
    pub fingerprint: DeviceFingerprint,
    pub display_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
