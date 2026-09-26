use companion_protocol::{
    read_message, write_message, CodecError, Envelope, MessageType, MAX_MESSAGE_BYTES,
};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TestPayload {
    values: Vec<u8>,
    number: u32,
    text: String,
}

impl Arbitrary for TestPayload {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Vec<u8>>(), any::<u32>(), any::<String>())
            .prop_map(|(values, number, text)| TestPayload {
                values,
                number,
                text,
            })
            .boxed()
    }
}

proptest! {
    #[test]
    fn codec_write_read_roundtrip_arbitrary_payload(payload in any::<TestPayload>()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut buf = Vec::new();
            let write_res = write_message(&mut buf, &payload).await;

            if buf.len() > MAX_MESSAGE_BYTES {
                let is_too_large = matches!(write_res, Err(CodecError::MessageTooLarge { max: _ }));
                prop_assert!(is_too_large);
                return Ok(());
            }

            prop_assert!(write_res.is_ok());
            let mut cursor = std::io::Cursor::new(buf);
            let read_back: TestPayload = read_message(&mut cursor).await.unwrap();
            prop_assert_eq!(payload, read_back);
            Ok(())
        })?;
    }

    #[test]
    fn codec_rejects_messages_exceeding_max_size(
        size in (MAX_MESSAGE_BYTES + 1)..(MAX_MESSAGE_BYTES + 1000)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let oversized = vec![b'a'; size];
            let mut cursor = std::io::Cursor::new(oversized);

            let result: Result<TestPayload, _> = read_message(&mut cursor).await;
            let is_too_large = matches!(result, Err(CodecError::MessageTooLarge { max: _ }));
            prop_assert!(is_too_large);
            Ok(())
        })?;
    }

    #[test]
    fn envelope_version_check_rejects_major_mismatch(
        major in prop_oneof![Just(1u8), Just(2u8), Just(9u8), Just(99u8)]
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut envelope = Envelope::new(MessageType::Heartbeat, json!({}));
            envelope.protocol_version = format!("{major}.0.0");

            let result = envelope.check_protocol_version();
            if major != 0 {
                let is_incompatible = matches!(result, Err(companion_protocol::EnvelopeError::IncompatibleVersion { expected_major: _, actual: _ }));
                prop_assert!(is_incompatible);
            } else {
                prop_assert!(result.is_ok());
            }
            Ok(())
        })?;
    }

    #[test]
    fn envelope_accepts_minor_patch_differences(
        minor in 0u8..255,
        patch in 0u8..255
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut envelope = Envelope::new(MessageType::Heartbeat, json!({}));
            envelope.protocol_version = format!("0.{minor}.{patch}");

            let result = envelope.check_protocol_version();
            prop_assert!(result.is_ok());
            Ok(())
        })?;
    }

    #[test]
    fn envelope_roundtrip_through_codec_preserves_all_fields(
        msg_type in 0..8u8,
        payload_str in ".*",
        _device_id_str in ".*",
        correlation_id_str in ".*"
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let message_type = match msg_type {
                0 => MessageType::PairingBegin,
                1 => MessageType::PairingChallenge,
                2 => MessageType::PairingProof,
                3 => MessageType::PairingResult,
                4 => MessageType::SessionRequest,
                5 => MessageType::SessionDecision,
                6 => MessageType::OperationRequest,
                7 => MessageType::OperationResult,
                _ => MessageType::Heartbeat,
            };

            let device_id = companion_core::DeviceId::new();
            let env = Envelope::new(message_type, json!({ "data": payload_str }))
                .with_device_id(device_id)
                .with_correlation_id(correlation_id_str);

            let mut buf = Vec::new();
            write_message(&mut buf, &env).await.unwrap();
            let mut cursor = std::io::Cursor::new(buf);
            let read_back: Envelope = read_message(&mut cursor).await.unwrap();

            prop_assert_eq!(env.clone(), read_back.clone());
            prop_assert_eq!(env.device_id, read_back.device_id);
            prop_assert_eq!(env.correlation_id, read_back.correlation_id);
            prop_assert_eq!(env.message_type, read_back.message_type);
            Ok(())
        })?;
    }

    #[test]
    fn codec_handles_malformed_json_gracefully(
        data in proptest::collection::vec(any::<u8>(), 0..5000)
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(data);
            let result: Result<Envelope, _> = read_message(&mut cursor).await;
            let is_ok_or_expected_err = result.is_ok() || matches!(result, Err(CodecError::Json(_)) | Err(CodecError::ConnectionClosed));
            prop_assert!(is_ok_or_expected_err);
            Ok(())
        })?;
    }
}
