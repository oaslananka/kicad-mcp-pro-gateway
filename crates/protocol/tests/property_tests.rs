use companion_protocol::{read_message, write_message, Envelope, MessageType};
use proptest::prelude::*;
use serde_json::json;

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_or_exceed_limits(data in proptest::collection::vec(any::<u8>(), 0..20000)) {
        let mut cursor = std::io::Cursor::new(data);
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            // Must return Ok(Envelope) or Err(CodecError) - never panic or hang
            let _ = read_message::<_, Envelope>(&mut cursor).await;
        });
    }

    #[test]
    fn envelope_roundtrip_property(msg_type in 0..5u8, payload_str in ".*") {
        let message_type = match msg_type {
            0 => MessageType::SessionRequest,
            1 => MessageType::SessionDecision,
            2 => MessageType::OperationRequest,
            3 => MessageType::OperationResult,
            _ => MessageType::Heartbeat,
        };

        let env = Envelope::new(message_type, json!({ "payload": payload_str }));
        let mut buf = Vec::new();
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

        rt.block_on(async {
            write_message(&mut buf, &env).await.unwrap();
            let mut cursor = std::io::Cursor::new(buf);
            let read_back: Envelope = read_message(&mut cursor).await.unwrap();
            assert_eq!(env, read_back);
        });
    }
}
