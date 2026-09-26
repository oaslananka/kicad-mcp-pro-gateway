//! Property/fuzz coverage for the trust-boundary codecs in
//! `companion-protocol` (T9 in the threat model): the newline-delimited JSON
//! IPC framing, its size limit, the transport envelope, and the local IPC
//! request surface.
//!
//! Every target here is bounded so routine CI stays cheap, and the historical
//! edge cases these parsers have to survive are enumerated in the
//! `historical_*` corpora below so they are exercised on every run instead of
//! depending on random generation. See `docs/development/testing.md` for the
//! longer local fuzz lane and for how to reproduce a failure from its
//! minimized seed.

use companion_core::DeviceId;
use companion_protocol::{
    read_message, write_message, CodecError, Envelope, IpcRequest, MessageType, MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;

thread_local! {
    /// One current-thread runtime per test thread, reused by every case in
    /// every property that runs on it. The codec's I/O needs a tokio reactor,
    /// so a bare `futures::executor::block_on` cannot stand in for it, and a
    /// multi-threaded runtime would spawn a worker pool per case; a
    /// current-thread runtime drives the same futures with no worker threads
    /// and no extra descriptors beyond the reactor's own.
    static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
}

/// Drives `future` to completion on the calling thread's runtime.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    RUNTIME.with(|runtime| runtime.block_on(future))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TestPayload {
    values: Vec<u8>,
    number: u32,
    text: String,
}

fn payload_with_text(text: String) -> TestPayload {
    TestPayload {
        values: Vec::new(),
        number: 0,
        text,
    }
}

/// The serialized length of `TestPayload` is `overhead + text.len()`, so the
/// exact size-limit boundary can be exercised instead of hoping a random
/// payload lands on it.
fn payload_overhead() -> usize {
    serde_json::to_vec(&payload_with_text(String::new()))
        .expect("payload serializes")
        .len()
}

/// Every `MessageType` this build knows, enumerated because `Arbitrary` cannot
/// be derived for it from an integration test — both the trait and the type are
/// foreign here, and a wire enum must not grow a test-only derive. A new
/// variant has to be added to this list.
const ALL_MESSAGE_TYPES: [MessageType; 10] = [
    MessageType::PairingBegin,
    MessageType::PairingChallenge,
    MessageType::PairingProof,
    MessageType::PairingResult,
    MessageType::SessionRequest,
    MessageType::SessionDecision,
    MessageType::OperationRequest,
    MessageType::OperationResult,
    MessageType::SessionRevoke,
    MessageType::Heartbeat,
];

/// The complete set of local IPC request tags. A tag outside this set must
/// never decode: the local API has no "run arbitrary tool" verb, so an
/// unrecognized verb has to fail closed rather than fall through to anything.
const KNOWN_IPC_REQUEST_TAGS: [&str; 18] = [
    "Identity",
    "Status",
    "PairingStatus",
    "BeginPairing",
    "ListSessions",
    "ApproveSession",
    "DenySession",
    "PauseSession",
    "ResumeSession",
    "RevokeSession",
    "ListWorkspaces",
    "AuthorizeWorkspace",
    "RemoveWorkspace",
    "AuditSummary",
    "ListPendingApprovals",
    "ApproveOperation",
    "DenyOperation",
    "DaemonShutdown",
];

/// Version strings that show up at this boundary: compatible values, and
/// malformed or hostile ones that must be classified by their major component
/// rather than by string similarity.
fn historical_protocol_versions() -> Vec<String> {
    [
        // Same major component as this build.
        "0.1.0",
        "0.0.0",
        "0.99.99",
        "0.1.0-beta.1",
        "0.1.0+build.7",
        // Malformed, but the documented rule is "compare the major component".
        "",
        "0",
        "0.1",
        " 0.1.0",
        // Incompatible majors and look-alikes.
        "1",
        "1.0.0",
        "00.1.0",
        "0x1.0.0",
        "-1.0.0",
        "v0.1.0",
        "0.1.0 ",
        "0.1.0\n",
        "0.1.0/../1.0.0",
        "٠.١.٠",
        "\u{0}0.1.0",
        "0.1.0\u{0}",
    ]
    .iter()
    .map(|version| (*version).to_string())
    .collect()
}

/// Byte strings that have actually broken, or would break, newline-delimited
/// JSON framing: split frames, lone delimiters, CRLF, invalid UTF-8, and a
/// second document appended to the first.
fn historical_framing_inputs() -> Vec<Vec<u8>> {
    [
        &b""[..],
        b"\n",
        b"\n\n",
        b"\r\n",
        b"{}",
        b"null",
        b"{\"a\":1}\n{\"b\":2}",
        b"{\"a\":1}\r\n{\"b\":2}\r\n",
        b"{}\n{",
        b"{\"a\":\"\\u0000\"}\n",
        b"{\"a\":\"\\ud800\"}\n",
        &[0xff, 0xfe, b'\n', b'{', b'}'][..],
        b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n",
        b"  \t{}\n",
        b"{\"a\":1}\n\n\n",
    ]
    .iter()
    .map(|input| input.to_vec())
    .collect()
}

/// Body text used to smuggle a second message, an embedded delimiter, or
/// non-ASCII control characters across the framing boundary.
fn historical_payload_text() -> Vec<String> {
    let mut text: Vec<String> = [
        "",
        " ",
        "\n",
        "\r\n",
        "}\n{\"forged\":true}",
        "\u{2028}\u{2029}",
        "\u{feff}",
        "\u{0}",
        "ünïcödé",
        "\u{1F600}",
    ]
    .iter()
    .map(|text| (*text).to_string())
    .collect();
    text.push("x".repeat(64));
    text
}

fn framed_text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(historical_payload_text()),
        "[ -~]{0,64}",
    ]
}

/// Arbitrary JSON for a request payload position. `serde_json::Value` is not
/// `proptest::Arbitrary`, so the shapes are built explicitly.
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        framed_text().prop_map(Value::from),
    ];
    leaf.prop_recursive(3, 24, 2, |inner| {
        prop::collection::vec(inner, 0..3).prop_map(Value::Array)
    })
}

/// Frame bodies never contain the delimiter; the delimiter is the framing.
fn frame_bytes(size: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        any::<u8>().prop_filter("frames are split on newlines", |byte| *byte != b'\n'),
        size,
    )
}

/// One frame body: raw bytes (usually not JSON), documents that have shown up
/// on this boundary, and generated JSON. Mixing them keeps both the
/// decode-success and the decode-failure side of the framing property
/// populated.
fn frame_line() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        frame_bytes(0..64),
        prop::sample::select(historical_json_lines()),
        json_value().prop_map(|value| serde_json::to_vec(&value).expect("value serializes")),
    ]
}

/// JSON documents a peer has actually sent, including ones that are valid JSON
/// but not a message, and scalars the envelope type would reject.
fn historical_json_lines() -> Vec<Vec<u8>> {
    [
        &b"{}"[..],
        b"null",
        b"true",
        b"0",
        b"[]",
        b"[1,2,3]",
        b"{\"a\":{\"b\":[null,true]}}",
        b"{\"protocol_version\":\"0.1.0\"}",
        b"{\"protocol_version\":\"0.1.0\",\"message_id\":\"01ARZ3NDEKTSV4RRFFQ69G5FAV\",\"message_type\":\"heartbeat\",\"payload\":{}}",
        b"{\"message_type\":\"arbitrary_shell_exec\",\"payload\":{}}",
        b"1e400",
        b"\"\\u0000\"",
        b"\"\\ud800\"",
        b"\"\\udfff\\udbff\"",
    ]
    .iter()
    .map(|line| line.to_vec())
    .collect()
}

/// A fixed set of literals, as owned strings so a generated case can never
/// borrow from the corpus.
fn literals(values: &[&'static str]) -> impl Strategy<Value = String> {
    prop::sample::select(values.to_vec()).prop_map(str::to_string)
}

/// The bytes of the first frame in `bytes`, excluding the delimiter.
fn first_frame(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte == b'\n') {
        Some(delimiter) => &bytes[..delimiter],
        None => bytes,
    }
}

/// Reads exactly one frame and asserts the codec agreed with a plain
/// `serde_json::from_slice` of the same line, on both success and failure.
fn assert_next_frame(cursor: &mut std::io::Cursor<Vec<u8>>) -> Result<(), TestCaseError> {
    let before = cursor.position() as usize;
    let result: Result<Value, _> = block_on(read_message(cursor));
    let after = cursor.position() as usize;
    let remaining = &cursor.get_ref()[before..];

    let line = first_frame(remaining);
    let delimited = remaining.len() > line.len();
    if after != before + line.len() + usize::from(delimited) {
        return Err(TestCaseError::fail(format!(
            "frame consumed {consumed} of {expected} buffered bytes",
            consumed = after - before,
            expected = line.len() + usize::from(delimited),
        )));
    }

    if remaining.is_empty() {
        return match result {
            Err(CodecError::ConnectionClosed) => Ok(()),
            other => Err(TestCaseError::fail(format!(
                "a drained stream must report ConnectionClosed, got {other:?}"
            ))),
        };
    }

    match (result, serde_json::from_slice::<Value>(line)) {
        (Ok(decoded), Ok(expected)) => {
            if decoded != expected {
                return Err(TestCaseError::fail(format!(
                    "decoded {decoded} from a frame holding {expected}"
                )));
            }
            Ok(())
        }
        (Err(CodecError::Json(_)), Err(_)) => Ok(()),
        (Ok(_), Err(_)) => Err(TestCaseError::fail(
            "codec decoded a line serde_json rejects",
        )),
        (Err(error), Ok(_)) => Err(TestCaseError::fail(format!(
            "codec rejected a valid JSON line: {error}"
        ))),
        (Err(error), _) => Err(TestCaseError::fail(format!(
            "unexpected codec error: {error}"
        ))),
    }
}

proptest! {
    #[test]
    fn repeated_reads_partition_the_stream_at_newline_boundaries(
        lines in prop::collection::vec(frame_line(), 0..6),
        trailer in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..256),
            prop::sample::select(historical_framing_inputs()),
        ],
    ) {
        let mut framed = Vec::new();
        for line in &lines {
            framed.extend_from_slice(line);
            framed.push(b'\n');
        }
        framed.extend_from_slice(&trailer);

        let mut cursor = std::io::Cursor::new(framed);

        // One read per frame, plus one for whatever the peer left buffered.
        // Nothing is ever merged across a delimiter and nothing is skipped.
        for _ in 0..=lines.len() {
            assert_next_frame(&mut cursor)?;
        }
    }

    #[test]
    fn a_payload_within_the_size_limit_round_trips_unchanged(
        values in prop::collection::vec(any::<u8>(), 0..64),
        number in any::<u32>(),
        text in framed_text(),
    ) {
        let payload = TestPayload { values, number, text };

        let mut buf = Vec::new();
        block_on(async { write_message(&mut buf, &payload).await })?;
        prop_assert!(
            buf.len() <= MAX_MESSAGE_BYTES + 1,
            "framed message exceeded the limit: {}",
            buf.len()
        );

        let mut cursor = std::io::Cursor::new(buf);
        let read_back: TestPayload = block_on(read_message(&mut cursor))?;
        prop_assert_eq!(payload, read_back);
    }

    #[test]
    fn arbitrary_bytes_below_the_limit_never_panic_and_never_hit_the_size_limit(
        data in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..4096),
            prop::sample::select(historical_framing_inputs()),
        ],
    ) {
        let mut cursor = std::io::Cursor::new(data);

        let result: Result<Value, _> = block_on(read_message(&mut cursor));
        match result {
            Ok(_) => {}
            // The framing is newline-delimited JSON with no length header and
            // the reader is an in-memory cursor, so there is no `Io` variant to
            // allow for: a stream that ends mid-message surfaces as
            // `ConnectionClosed` when nothing was buffered, and as a JSON error
            // otherwise. Accepting `CodecError::Io` here would let a genuine
            // unexpected-error path pass as expected behaviour.
            Err(error) => prop_assert!(
                matches!(error, CodecError::Json(_) | CodecError::ConnectionClosed),
                "input below the size limit must not fail with {error}"
            ),
        }
    }

    #[test]
    fn protocol_version_compatibility_is_decided_by_the_major_component(
        version in prop_oneof![
            prop::sample::select(historical_protocol_versions()),
            any::<String>(),
        ],
    ) {
        let expected_major = PROTOCOL_VERSION.split('.').next().unwrap_or_default();

        let mut envelope = Envelope::new(MessageType::Heartbeat, json!({}));
        envelope.protocol_version = version.clone();

        let accepted = envelope.check_protocol_version().is_ok();
        prop_assert!(
            accepted == (version.split('.').next().unwrap_or_default() == expected_major),
            "unexpected compatibility verdict for {version:?}"
        );
    }

    #[test]
    fn an_envelope_round_trips_through_the_codec_without_losing_a_field(
        message_type in 0..ALL_MESSAGE_TYPES.len(),
        device_id in prop::option::of(device_ids()),
        correlation_id in framed_text(),
        timestamp in prop::option::of(framed_text()),
        text in framed_text(),
    ) {
        let mut envelope = Envelope::new(
            ALL_MESSAGE_TYPES[message_type],
            json!({ "data": text, "nested": [1, 2, { "deep": true }] }),
        )
        .with_correlation_id(correlation_id);
        // Assigned rather than generated: `device_id` and `timestamp` are
        // optional wire metadata, so the round trip has to carry whatever the
        // peer sent — including nothing at all.
        envelope.device_id = device_id;
        envelope.timestamp = timestamp;

        let mut buf = Vec::new();
        block_on(async { write_message(&mut buf, &envelope).await })?;

        let mut cursor = std::io::Cursor::new(buf);
        let read_back: Envelope = block_on(read_message(&mut cursor))?;
        prop_assert_eq!(&envelope, &read_back);
    }
}

/// The size limit is a hard boundary, so it is asserted exactly rather than
/// sampled: a payload of precisely `MAX_MESSAGE_BYTES` is writable, the first
/// byte over it is refused, and a refused write emits nothing at all — a
/// partial frame is what the peer would then be handed to parse.
#[test]
fn write_message_refuses_the_first_byte_over_the_limit_without_emitting_a_frame() {
    let overhead = payload_overhead();

    let at_limit = payload_with_text("a".repeat(MAX_MESSAGE_BYTES - overhead));
    assert_eq!(
        serde_json::to_vec(&at_limit)
            .expect("payload serializes")
            .len(),
        MAX_MESSAGE_BYTES
    );

    let mut buf = Vec::new();
    block_on(async { write_message(&mut buf, &at_limit).await })
        .expect("a message of exactly the limit is writable");
    assert_eq!(
        buf.len(),
        MAX_MESSAGE_BYTES + 1,
        "a framed message adds exactly one delimiter"
    );

    let mut cursor = std::io::Cursor::new(&buf);
    let read_back: TestPayload =
        block_on(read_message(&mut cursor)).expect("a message at the limit round trips");
    assert_eq!(at_limit, read_back);

    let over_limit = payload_with_text("a".repeat(MAX_MESSAGE_BYTES - overhead + 1));
    let mut rejected = Vec::new();
    let result = block_on(write_message(&mut rejected, &over_limit));
    assert!(matches!(
        result,
        Err(CodecError::MessageTooLarge { max }) if max == MAX_MESSAGE_BYTES
    ));
    assert!(
        rejected.is_empty(),
        "a refused message must not leave a partial frame behind"
    );
}

// Bounded separately: pushing more than a megabyte through the codec once per
// generated case is the most expensive thing in the suite, and the interesting
// inputs are the sizes immediately around the limit rather than many random
// ones.
proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    #[test]
    fn oversized_input_is_refused_after_reading_only_the_limit(
        excess in prop::sample::select(vec![1usize, 2, 7, 64, 4096]),
    ) {
        let mut cursor = std::io::Cursor::new(vec![b'a'; MAX_MESSAGE_BYTES + excess]);

        let result: Result<Value, _> = block_on(read_message(&mut cursor));
        match result {
            Err(CodecError::MessageTooLarge { max }) => {
                prop_assert_eq!(max, MAX_MESSAGE_BYTES);
            }
            other => {
                prop_assert!(false, "oversized input must be refused, got {other:?}");
            }
        }
        // Unchecked resource growth would show up as consuming the whole
        // input, or as buffering past the limit before noticing.
        prop_assert_eq!(cursor.position() as usize, MAX_MESSAGE_BYTES + 1);
    }
}

/// The one canonical spelling of the session id used below. ULID bodies are
/// Crockford base32 and therefore case-insensitive, so the wire format accepts
/// more spellings than this — every accepted spelling has to normalize back to
/// this exact value, or two spellings could end up denoting two identities.
const SESSION_ID: &str = "sess_01ARZ3NDEKTSV4RRFFQ69G5FAV";

/// Crockford base32 without the ambiguous letters, in both cases: a ULID body
/// is case-insensitive, so both are legal spellings of the same value.
const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyz";

/// The first characters a canonical ULID body can start with: the 128-bit value
/// is carried by 26 five-bit characters, so the first one only has three
/// significant bits and minted ids always start in `0..=7`.
const CANONICAL_FIRST: &str = "01234567";

/// Arbitrary device ids on the wire, so the envelope round trip has to carry
/// whatever id the peer sent rather than a freshly generated one.
fn device_ids() -> impl Strategy<Value = DeviceId> {
    let first = prop::sample::select(
        CANONICAL_FIRST
            .chars()
            .chain(CROCKFORD.chars())
            .collect::<Vec<char>>(),
    );
    let rest = prop::collection::vec(
        prop::sample::select(CROCKFORD.chars().collect::<Vec<char>>()),
        25..=25,
    );
    (first, rest).prop_map(|(first, rest): (char, Vec<char>)| {
        let body: String = std::iter::once(first).chain(rest).collect();
        DeviceId::from_str(&format!("dev_{body}")).expect("26 Crockford characters are a ULID")
    })
}

/// Spellings of one id body that a peer can put on the wire: the canonical one
/// and the same body in the other case, since a ULID body is case-insensitive
/// Crockford base32.
fn id_spellings(prefix: &str, body: &str) -> Vec<String> {
    vec![
        format!("{prefix}{body}"),
        format!("{prefix}{}", body.to_lowercase()),
    ]
}

#[test]
fn a_canonical_session_id_decodes_into_the_matching_request() {
    let decoded: IpcRequest = serde_json::from_value(json!({
        "request": "ApproveSession",
        "payload": { "session_id": SESSION_ID }
    }))
    .expect("a canonical session id decodes");

    assert!(matches!(
        decoded,
        IpcRequest::ApproveSession { session_id } if session_id.to_string() == SESSION_ID
    ));
}

#[test]
fn a_lowercase_session_id_names_the_same_session_as_the_canonical_spelling() {
    let lowercase: IpcRequest = serde_json::from_value(json!({
        "request": "ApproveSession",
        "payload": { "session_id": "sess_01arz3ndektsv4rrffq69g5fav" }
    }))
    .expect("ULID bodies are case-insensitive Crockford base32");

    let (canonical, lowercase) = (
        serde_json::from_value::<IpcRequest>(json!({
            "request": "ApproveSession",
            "payload": { "session_id": SESSION_ID }
        }))
        .expect("canonical spelling decodes"),
        lowercase,
    );
    assert_eq!(canonical, lowercase);
}

/// 26 Crockford characters are 130 bits and a ULID is 128, so the first
/// character only carries three significant bits: an id body whose first
/// character is above `7` decodes to the identity spelled with that character
/// reduced modulo 8 rather than being rejected. Every id this codebase mints
/// has a first character in `0..=7`, so this only widens the set of spellings
/// that reach an existing identity. It is a property of the ULID wire format,
/// not a Gateway decision, so it is pinned here; rejecting it in `typed_id!`
/// would narrow the accepted input space and is a separate hardening change.
#[test]
fn an_id_whose_first_character_does_not_fit_the_body_decodes_to_the_truncated_identity() {
    let aliased = DeviceId::from_str("dev_81ARZ3NDEKTSV4RRFFQ69G5FAV").expect("decodes");
    let canonical = DeviceId::from_str("dev_01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("decodes");

    assert_eq!(aliased, canonical);
    assert_eq!(aliased.to_string(), "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV");
}

proptest! {
    /// Every spelling of an id that decodes has to denote the same identity,
    /// and the canonical spelling always decodes. A peer can send any case, so
    /// two spellings of one id must never end up as two identities.
    #[test]
    fn every_id_spelling_that_decodes_denotes_the_same_identity(
        device_id in device_ids(),
    ) {
        let canonical = device_id.to_string();
        let body = canonical["dev_".len()..].to_string();

        prop_assert_eq!(
            DeviceId::from_str(&canonical)
                .expect("a canonical id decodes")
                .to_string(),
            canonical.clone()
        );
        for spelling in id_spellings("dev_", &body) {
            let Ok(decoded) = DeviceId::from_str(&spelling) else {
                continue;
            };
            prop_assert!(
                decoded.to_string() == canonical,
                "{spelling} decoded to a different identity"
            );
        }
    }

    #[test]
    fn an_unknown_local_ipc_request_tag_never_decodes(
        tag in prop_oneof![
            literals(&[
                // Case and separator variants of real verbs.
                "status", "STATUS", "run_shell", "exec", "tool_call", "authorize_workspace",
                // Verbs that do not exist and must not be added implicitly.
                "RunShell", "ToolsCall", "ShutdownNow", "AuthorizeWorkspace", "ApproveSessio",
                // Tag-smuggling attempts around a real verb.
                "Status ", " Status", "Status\u{0}", "IdentityStatus", "",
            ]),
            "[A-Za-z_]{0,32}",
        ],
        payload in json_value(),
    ) {
        let encoded = json!({ "request": tag, "payload": payload });

        if let Ok(request) = serde_json::from_value::<IpcRequest>(encoded) {
            // A tag outside the local API contract must never become a
            // request, and a decoded request must keep its own tag.
            prop_assert!(
                KNOWN_IPC_REQUEST_TAGS.contains(&tag.as_str()),
                "unknown request tag {tag:?} decoded"
            );
            let re_encoded = serde_json::to_value(&request).expect("request re-encodes");
            prop_assert_eq!(re_encoded["request"].as_str(), Some(tag.as_str()));
        }
    }

    #[test]
    fn only_a_session_id_decodes_as_one_and_every_accepted_spelling_normalizes(
        request in literals(&[
            "ApproveSession",
            "DenySession",
            "PauseSession",
            "ResumeSession",
            "RevokeSession",
        ]),
        id in literals(&[
            // Right shape, wrong domain: a device, workspace, operation, or
            // account id must not be accepted where a session id is required.
            "dev_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "op_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "acct_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            // One extra id appended to a valid one.
            "sess_01ARZ3NDEKTSV4RRFFQ69G5FAV\nsess_01ARZ3NDEKTSV4RRFFQ69G5FB0",
            "sess_01ARZ3NDEKTSV4RRFFQ69G5FAV ",
            // Truncated, empty, or not an id at all.
            "",
            "not-a-ulid",
            "sess_",
            "sess_01ARZ3NDEKTSV4RRFFQ69G5FA",
            // Crockford base32 is case-insensitive, so this names the same
            // session as the canonical spelling and must normalize to it.
            "sess_01arz3ndektsv4rrffq69g5fav",
        ]),
    ) {
        let encoded = json!({ "request": request, "payload": { "session_id": id } });

        if let Ok(decoded) = serde_json::from_value::<IpcRequest>(encoded) {
            // Whatever spelling was on the wire, the decoded request is the
            // session it denotes and no other: a device, workspace, or
            // operation id can never be laundered into a session id, and two
            // spellings can never mean two sessions.
            let re_encoded = serde_json::to_value(&decoded).expect("request re-encodes");
            prop_assert_eq!(re_encoded["request"].as_str(), Some(request.as_str()));
            prop_assert_eq!(
                re_encoded["payload"]["session_id"].as_str(),
                Some(SESSION_ID)
            );
        }
    }

    #[test]
    fn a_nested_request_tag_is_payload_data_and_never_a_second_verb(
        outer in literals(&["Status", "Identity", "ListWorkspaces"]),
        inner in literals(&["DaemonShutdown", "AuthorizeWorkspace", "RevokeSession"]),
        path in framed_text(),
    ) {
        let encoded = json!({
            "request": outer,
            "payload": { "request": inner, "payload": { "path": path } }
        });

        if let Ok(request) = serde_json::from_value::<IpcRequest>(encoded) {
            let re_encoded = serde_json::to_value(&request).expect("request re-encodes");
            prop_assert_eq!(re_encoded["request"].as_str(), Some(outer.as_str()));
        }
    }
}
