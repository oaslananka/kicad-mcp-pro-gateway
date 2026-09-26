# Outbound Relay Security Contract

This document defines the security contract between the Gateway daemon and a production outbound relay. It specifies the expectations, guarantees, and limitations to ensure secure communication despite the relay being untrusted.

The contract is split into two parts:
- **Current testable behavior**: What is implemented and testable in the repository (primarily in the mock transport and protocol crates).
- **Normative production contract**: What a production relay must adhere to, and what the Gateway must enforce in a production deployment.

Note: The repository currently contains a mock transport for testing. No production cloud transport is implemented in this repository.

## Overview

The Gateway daemon initiates outbound connections to a relay (or cloud service) using the Gateway transport protocol (see [protocol/README.md](../protocol/README.md)). The relay is considered untrusted; therefore, the contract assumes the relay may be compromised, malicious, or subject to network attacks.

## Current Testable Behavior (in repository)

### Protocol and Transport

- The Gateway transport protocol uses versioned envelopes with `protocol_version`, `message_id`, `message_type`, `device_id`, `timestamp`, `correlation_id`, and `payload` (see [protocol/README.md](../protocol/README.md)).
- The `message_id` is a ULID/UUID and is unique per message.
- The protocol enforces a maximum envelope size of `MAX_MESSAGE_BYTES` (defined in `companion-protocol::codec`, currently 1 MiB).
- Unknown `message_type` values are rejected (not ignored).
- The mock transport (`crates/transport/mock.rs`) allows scripted connection failures and receipt of envelopes for testing.
- The reconnect logic (`crates/transport/reconnect.rs`) provides exponential backoff with jitter; reconnecting the transport does not itself create session authority.

### Current implementation limits and enforced properties

- **Production transport / TLS**: No production cloud transport or production TLS relay client exists in this repository. The normal daemon does not expose an inbound public relay listener; the test transport is in-process.
- **Device / relay authentication**: The local Ed25519 device identity exists, but production pairing proof and relay TLS authentication are not implemented by the mock transport.
- **Message size limits**: Envelopes exceeding `MAX_MESSAGE_BYTES` are rejected by the protocol codec; the current value is 1 MiB.
- **Unknown message types**: Unknown `message_type` values fail deserialization instead of being ignored.
- **Replay protection**: No production replay cache, durable dedupe store, or freshness-window enforcement exists yet. The envelope carries `message_id` and `timestamp` so the production transport can implement them.
- **Ordering / idempotency**: No production sequencing or `correlation_id` dedupe engine exists yet. The envelope exposes the fields required by the normative contract below.
- **Rate limiting / backpressure**: No production relay rate limiter exists yet.
- **VerifiedPrincipal**: No `VerifiedPrincipal` type exists yet; current `remote_principal: String` values are unverified input and MUST NOT be treated as authenticated identity.

## Normative Production Contract

### Authentication and Identity

1. **Device Authentication**: The Gateway MUST authenticate itself to the relay using its device identity (Ed25519 key pair) during the pairing process. The relay MUST verify the Gateway's proof of possession of the private key.
2. **Relay Authentication**: The Gateway MUST authenticate the relay via TLS server certificate validation (standard PKI). The relay's identity is used only for message source validation and does not confer any privileges.
3. **Session Binding**: After pairing, a session is established. The Gateway binds the session to the pinned relay TLS identity — the server certificate identity it validated during the handshake — only to ensure messages originate from that same relay. The relay identity is not a `device_id` value the relay asserts, and it does not confer any authorization privileges. A `device_id` inside an envelope is only ever compared against the local `DeviceIdentity.device_id`.

### Message Integrity and Confidentiality

- All messages MUST be encrypted and integrity-protected via TLS 1.2 or higher.
- The Gateway MUST NOT rely on the relay for message confidentiality or integrity; these are provided by the transport layer (TLS).

### Replay, Ordering, and Idempotency (Production Requirements)

1. **Replay Detection**: Each state-changing message carries a unique `message_id` and a `timestamp`. The Gateway MUST validate freshness against a production-configured `REPLAY_VALIDITY_WINDOW` using a trustworthy local time source. A message outside that window is rejected before session lookup, policy evaluation, forwarding, or replay-cache insertion. Within the window, a previously accepted `message_id` is rejected as a replay. Replay state MUST remain effective across process restart, either through durable replay/dedupe state or an equivalently strong session/epoch binding that makes pre-restart messages invalid. Expired replay entries are evicted to bound storage.
2. **Ordering**: Transport arrival order does not itself grant semantic ordering. Independent requests MAY be accepted in arrival order after normal validation. A request that depends on prior state MUST carry an explicit sequencing or precondition mechanism; a missing or unsatisfied dependency fails closed instead of being guessed from timestamps.
3. **Idempotency**: Duplicate-operation detection MUST be scoped at least by `session_id` plus `correlation_id`, and by the bound principal/device context where applicable. Reusing the same `correlation_id` in another, expired, or differently bound session does not automatically identify the same operation. A duplicate within the same valid scope returns the previously recorded outcome rather than executing again.

### Reconnect and Resume

1. **Reconnect Does Not Recreate Authority**: Reconnect restores only the transport pipe. It MUST NOT mint, extend, refresh, widen, or resurrect authorization, and it MUST NOT recover authority from relay-supplied state.
2. **Locally valid authorization may survive transport replacement**: A future local `AuthorizationLease` MAY remain usable across a reconnect only when it is still locally valid (not expired or revoked), remains bound to the same `VerifiedPrincipal`, device, workspace, and capability scope, and the reconnect does not change or refresh those bounds. Otherwise the remote actor MUST re-authenticate and obtain any required local approval again.

### Resource Limits and Backpressure (Production Requirements)

1. **Message Size Limits**: The Gateway enforces a maximum envelope size of `MAX_MESSAGE_BYTES` (defined in `companion-protocol::codec`) and maximum payload size per message type. Messages exceeding these limits are rejected without processing.
2. **Rate Limiting**: The Gateway MUST implement a token-bucket rate limiter (or equivalent) for incoming messages from the relay to prevent resource exhaustion. Limits are configurable and fail closed (excess messages are dropped).
3. **Backpressure**: If the Gateway is unable to process incoming messages due to internal backpressure (e.g., queue full), it applies backpressure at the transport level by delaying `receive()` operations or closing the connection after a timeout. The relay is expected to handle connection closures and retry with its own backoff.

### Compromise Assumptions

If the relay is compromised, the following are the limits of what the attacker can cause:

- **Cannot**: 
  - Execute arbitrary operations on the Gateway without a valid session approved by the local user.
  - Access the device's private key material (stored in secure storage, never transmitted).
  - Bypass policy checks for workspace access, capability execution, or audit recording.
  - Forge messages that appear to originate from the Gateway (without the device private key).
- **Can**:
  - Send malformed or oversized messages (which will be rejected by size limits and schema validation).
  - Attempt to flood the Gateway with messages (subject to rate limiting).
  - Cause a denial-of-service by consuming network bandwidth or attempting to exhaust connection slots (mitigated by rate limits and connection timeouts).
  - Learn metadata such as message frequencies and approximate timing (but not content due to TLS encryption).
  - Cause the Gateway to disconnect repeatedly (which triggers reconnect logic but does not grant privileges).
  - Attempt replay or reordering of relay-originated state-changing messages; a compliant Gateway rejects stale/duplicate inputs and applies explicit sequencing rules where required.
  - Send messages with invalid `device_id` (which will be rejected by the Gateway).

### Authentication Evidence and VerifiedPrincipal (Future Work)

- The validated/pinned relay TLS identity authenticates the transport pipe and relay endpoint only. It is not the remote user/agent identity and is not a `VerifiedPrincipal`.
- A `VerifiedPrincipal` represents the authenticated remote actor whose authorization grant or future `AuthorizationLease` is being exercised. Before the Gateway creates or binds one, it MUST locally verify principal evidence that is cryptographically bound to the session/request.
- Principal evidence MUST identify a trusted issuer or trust root, a subject/principal identifier, the intended audience or local device binding, freshness/expiry, replay resistance, and integrity/proof. The exact future credential, token, or signature format is implementation-defined as long as those properties are testable.
- The current `remote_principal: String` field is cloud/remote-supplied unverified input. It MUST NOT be treated as authenticated identity or used by itself to grant authority.
- The `VerifiedPrincipal` type and principal-evidence mechanism do not yet exist in this repository.

### Outbound-Only Connectivity and Failure Behavior

- The Gateway ONLY initiates outbound connections to the relay. It does NOT listen for inbound connections from the relay.
- If the relay becomes unavailable, the Gateway:
  - Drops the transport connection.
  - Enters a reconnect state with exponential backoff and jitter.
  - Continues to function normally for local operations (core-bridge and IPC) without requiring the transport.
  - Does NOT retry indefinitely without backoff; the reconnect policy includes a maximum attempt limit (configurable) after which it considers the relay permanently unavailable and stops retrying until manually reset or configuration change.
- Local tool execution and session approvals remain functional even when the transport is disconnected.

### Binding to Authorization Grants

- The Gateway does NOT use the relay's identity to authorize any operation. Authorization is derived solely from:
  - Local user approvals (via desktop/UI/CLI) bound to a session.
  - Session metadata (workspace IDs, allowed capabilities, expiry time) stored locally.
- The relay's role is limited to transporting messages; it does NOT influence authorization decisions.

## Protocol Invariants (Production Requirements)

The following invariants MUST hold at all times in a production deployment:

1. **I1**: No operation is executed without a valid, non-expired, non-revoked session that has been approved by the local user for the requested workspace and capability.
2. **I2**: All inbound messages are validated for size, schema, and message type before further processing.
3. **I3**: Replay detection is enforced for all state-changing message types using `message_id`, freshness, and durable replay/session binding. Out-of-window messages are rejected before processing or caching, duplicate in-window ids are rejected, and process restart does not reset replay protection.
4. **I4**: The transport connection does not imply any authorization; a connected transport alone grants zero privileges.
5. **I5**: Production transport establishes the Gateway device proof to the relay and validates/pins the relay TLS identity, while remote-actor identity is verified separately before a `VerifiedPrincipal` can be bound to authorization.
6. **I6**: The Gateway never sends unencrypted or unauthenticated messages over the transport; TLS is mandatory for all connections.
7. **I7**: Error messages sent to the relay do not contain sensitive information (e.g., private keys, local paths).

## Abuse Cases

The following abuse cases are considered in the design and MUST be addressed by a production implementation:

- **AC1**: Relay attempts to replay an old `operation.request` message.
  - Expected: Gateway rejects the message. An in-window `message_id` already seen in the window is rejected as a replay; a `timestamp` outside the validity window is rejected on arrival and is not cached.
- **AC2**: Relay floods the Gateway with messages.
  - Expected: Gateway's rate limiter drops excess messages; transport may be closed if overwhelmed.
- **AC3**: Relay sends an oversized envelope.
  - Expected: Gateway rejects the message due to size limit violation.
- **AC4**: Relay attempts to send a message with an unknown `message_type`.
  - Expected: Gateway rejects the message (unknown message types are rejected, not ignored).
- **AC5**: Relay sends a `session.request` with a mismatched `device_id`.
  - Expected: Gateway rejects the message because the `device_id` does not match the local device identity.
- **AC6**: Relay successfully pairs and then attempts to execute an operation without session approval.
  - Expected: Gateway requires local user approval for each session; operation is not executed without approval.
- **AC7**: Relay replays pre-restart messages or presents stale authority after Gateway restart.
  - Expected: Restart does not reset replay protection and never resurrects expired/revoked authority. A persisted authorization may remain usable only if it still satisfies the local lease/principal/scope rules above; otherwise re-authentication and approval are required.
- **AC8**: Relay tries to flood the connection to cause resource exhaustion via TLS handshakes.
  - Expected: Gateway enforces connection rate limits and may temporarily cease connection attempts.

## Conformance Testing

To test compliance with this contract independently of a specific relay vendor, the following approaches are recommended:

1. **Mock Relay Test Suite**: Implement a mock relay that can be configured to behave correctly or to exhibit specific malicious behaviors (replay, flooding, malformed messages, etc.). The Gateway's reaction to each scenario should be validated.
2. **Protocol Fuzzing**: Use protocol fuzzers to generate random envelope variations and ensure the Gateway rejects invalid messages without crashing or leaking state.
3. **Interoperability Test Plan**: Define a minimal set of behaviors that any relay must implement to be considered compatible:
   - TLS 1.2+ server with valid certificate.
   - Implement the Gateway transport envelope V1 (as per [protocol/README.md](../protocol/README.md)).
   - Handle the pairing flow (`pairing.begin`, `pairing.challenge`, `pairing.proof`, `pairing.result`).
   - Handle session requests and operation requests/responses.
   - Respect connection closures and retry with backoff.
4. **Abuse Case Fixtures**: Provide a set of test fixtures (pre-captured message sequences) representing each abuse case (AC1-AC8) and verify the Gateway's deterministic handling.

The repository includes conformance fixtures under `tests/fixtures/protocol-abuse/` (see [fixture index](#fixture-index)). Every fixture is structurally wire-valid — canonical typed identifiers (`dev_`/`ws_`/`sess_`/`op_` plus a 26-character ULID body) and canonical envelope fields — except the two scenarios whose declared purpose is to be rejected (`invalid_envelope.json`, `unknown_message_type.json`) and the size-limit scenario (`oversized.json`). `crates/protocol/tests/conformance_fixtures.rs` asserts those invariants, plus index/fixture-set lockstep, on every `cargo test --workspace`; the semantic expectations of each abuse case remain production-conformance inputs, not current implementation guarantees.

### Fixture Index

| Fixture File | Abuse Case | Description |
|--------------|------------|-------------|
| `replay.json` | AC1 | Captured `operation.request` message replayed after a session reboot. |
| `duplicate.json` | AC1 | Duplicate `operation.request` with the same `message_id` within the replay validity window. |
| `out_of_order.json` | AC1 | Two independent requests arrive in timestamp order different from transport order; the conformance profile must handle them deterministically without inferring authority from order alone. |
| `stale_timestamp.json` | AC1 | `operation.request` whose `timestamp` is outside the validity window; must be rejected without processing or caching. |
| `oversized.json` | AC3 | Envelope with payload exceeding `MAX_MESSAGE_BYTES`. |
| `invalid_envelope.json` | AC3, AC4 | Malformed JSON or missing required fields. |
| `unknown_message_type.json` | AC4 | Envelope with `message_type` not in the V1 registry. |
| `mismatched_device_id.json` | AC5 | `session.request` with `device_id` not matching the Gateway's persistent identity. |
| `unapproved_operation.json` | AC6 | `operation.request` for a session that has not been approved by the local user. |
| `post_reboot_session.json` | AC7 | A request presents pre-restart session authority after reboot; conformance decides from durable replay state and the locally persisted lease/principal scope, never from relay claims alone. |
| `flood.json` | AC2, AC8 | High-volume message stream to test rate limiting and connection handling. |

## Sequence Diagrams

See [sequence-diagrams.md](./sequence-diagrams.md) for detailed interaction flows.

## References

- [Trust Boundaries](../security/trust-boundaries.md)
- [Protocol Specification](../protocol/README.md)
- [Data Flow Architecture](../architecture/data-flow.md)
- [Session Lifecycle](../architecture/session-lifecycle.md)
