//! The versioned Companion transport envelope. See `docs/protocol/README.md`
//! for the full message type registry and security notes. This is a wire
//! format, not a trust decision: everything received in an envelope is
//! untrusted input until session/policy validation says otherwise.

use companion_core::DeviceId;
use serde::{Deserialize, Serialize};

/// The current transport protocol version. A receiver rejects any envelope
/// whose major component does not match, rather than guessing at
/// compatibility.
pub const PROTOCOL_VERSION: &str = "0.1.0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error(
        "incompatible protocol version: expected major version {expected_major}, got {actual}"
    )]
    IncompatibleVersion {
        expected_major: String,
        actual: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    PairingBegin,
    PairingChallenge,
    PairingProof,
    PairingResult,
    SessionRequest,
    SessionDecision,
    OperationRequest,
    OperationResult,
    SessionRevoke,
    Heartbeat,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol_version: String,
    pub message_id: String,
    pub message_type: MessageType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub payload: serde_json::Value,
}

impl Envelope {
    pub fn new(message_type: MessageType, payload: serde_json::Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            message_id: ulid::Ulid::new().to_string(),
            message_type,
            device_id: None,
            timestamp: None,
            correlation_id: None,
            payload,
        }
    }

    pub fn with_device_id(mut self, device_id: DeviceId) -> Self {
        self.device_id = Some(device_id);
        self
    }

    pub fn with_timestamp(mut self, timestamp: time::OffsetDateTime) -> Self {
        self.timestamp = timestamp
            .format(&time::format_description::well_known::Rfc3339)
            .ok();
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Rejects any envelope whose protocol version major component doesn't
    /// match this build's. Receivers must call this before acting on
    /// `payload` at all.
    pub fn check_protocol_version(&self) -> Result<(), EnvelopeError> {
        let expected_major = major_component(PROTOCOL_VERSION);
        let actual_major = major_component(&self.protocol_version);
        if expected_major == actual_major {
            Ok(())
        } else {
            Err(EnvelopeError::IncompatibleVersion {
                expected_major: expected_major.to_string(),
                actual: self.protocol_version.clone(),
            })
        }
    }
}

fn major_component(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn matching_major_version_is_accepted() {
        let envelope = Envelope::new(MessageType::Heartbeat, json!({}));
        assert!(envelope.check_protocol_version().is_ok());
    }

    #[test]
    fn mismatched_major_version_is_rejected() {
        let mut envelope = Envelope::new(MessageType::Heartbeat, json!({}));
        envelope.protocol_version = "9.0.0".to_string();
        assert_eq!(
            envelope.check_protocol_version(),
            Err(EnvelopeError::IncompatibleVersion {
                expected_major: "0".to_string(),
                actual: "9.0.0".to_string()
            })
        );
    }

    #[test]
    fn minor_version_difference_is_still_accepted() {
        let mut envelope = Envelope::new(MessageType::Heartbeat, json!({}));
        envelope.protocol_version = "0.99.0".to_string();
        assert!(envelope.check_protocol_version().is_ok());
    }

    #[test]
    fn unknown_message_type_fails_to_deserialize_rather_than_being_ignored() {
        let raw = json!({
            "protocol_version": "0.1.0",
            "message_id": "01J000000000000000000000",
            "message_type": "arbitrary_shell_exec",
            "payload": {}
        });
        let result: Result<Envelope, _> = serde_json::from_value(raw);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn oversized_envelope_payload_is_rejected_by_the_shared_codec() {
        let huge_payload = json!({ "blob": "a".repeat(crate::codec::MAX_MESSAGE_BYTES + 10) });
        let envelope = Envelope::new(MessageType::OperationRequest, huge_payload);

        let (mut client, mut server) = tokio::io::duplex(8 * 1024 * 1024);
        // A too-large message never gets a trailing newline written by a
        // well-behaved writer either, since write_message itself refuses
        // it — assert that refusal directly.
        let write_result = crate::codec::write_message(&mut client, &envelope).await;
        assert!(matches!(
            write_result,
            Err(crate::codec::CodecError::MessageTooLarge { .. })
        ));
        drop(client);
        let _ = &mut server; // unused once write is rejected before anything is sent
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let envelope = Envelope::new(
            MessageType::OperationRequest,
            json!({ "tool": "schematic.read" }),
        )
        .with_device_id(DeviceId::new())
        .with_correlation_id("corr-1");
        let json_str = serde_json::to_string(&envelope).unwrap();
        let back: Envelope = serde_json::from_str(&json_str).unwrap();
        assert_eq!(envelope, back);
    }
}
