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
- The transport layer (TCP/TLS) provides encryption and integrity protection.
- The mock transport (`crates/transport/mock.rs`) allows scripted connection failures and receipt of envelopes for testing.
- The reconnect logic (`crates/transport/reconnect.rs`) provides exponential backoff with jitter and restores transport connectivity only—it never resurrects session authorization.

### Security Properties (enforced by mock transport and protocol)

- **Device Authentication**: During pairing, the Gateway proves possession of its device identity (Ed25519 key pair) to the relay.
- **Relay Authentication**: The Gateway validates the relay's TLS certificate (standard PKI). The relay's identity is not used for authorization decisions.
- **Message Size Limits**: Envelopes exceeding `MAX_MESSAGE_BYTES` are rejected by the protocol codec.
- **Replay Detection**: The protocol does not currently implement a replay cache in the repository, but the envelope design includes `message_id` and `timestamp` to enable replay detection in production.
- **Ordering**: The Gateway does not guarantee in-order delivery; however, the `correlation_id` ties requests to responses.
- **Idempotency**: Operations are designed to be idempotent where possible, but the mock transport does not enforce idempotency.
- **Reconnect**: Upon transport disconnection, the Gateway attempts to reconnect with exponential backoff and jitter. Reconnect restores the transport layer only; it does not recover session state from the relay.
- **Outbound-Only**: The Gateway only initiates outbound connections; it does not listen for inbound connections from the relay.

## Normative Production Contract

### Authentication and Identity

1. **Device Authentication**: The Gateway MUST authenticate itself to the relay using its device identity (Ed25519 key pair) during the pairing process. The relay MUST verify the Gateway's proof of possession of the private key.
2. **Relay Authentication**: The Gateway MUST authenticate the relay via TLS server certificate validation (standard PKI). The relay's identity is used only for message source validation and does not confer any privileges.
3. **Session Binding**: After pairing, a session is established. The Gateway binds the session to the pinned relay TLS identity — the server certificate identity it validated during the handshake — only to ensure messages originate from that same relay. The relay identity is not a `device_id` value the relay asserts, and it does not confer any authorization privileges. A `device_id` inside an envelope is only ever compared against the local `DeviceIdentity.device_id`.

### Message Integrity and Confidentiality

- All messages MUST be encrypted and integrity-protected via TLS 1.2 or higher.
- The Gateway MUST NOT rely on the relay for message confidentiality or integrity; these are provided by the transport layer (TLS).

### Replay, Ordering, and Idempotency (Production Requirements)

1. **Replay Detection**: Each message includes a unique `message_id` (ULID/UUID) and a `timestamp`. The Gateway MUST validate the `timestamp` against a narrow validity window around local time (configurable, default ±60s) and MUST reject, without processing, forwarding, or caching, any state-changing message (e.g., `session.request`, `operation.request`) whose `timestamp` falls outside that window — an out-of-window message is never treated as fresh. Within the window, the Gateway MUST reject any `message_id` already seen in the window (replay) and MUST evict cache entries that fall outside the window so the cache stays bounded. The window size is a production-configurable parameter.
2. **Ordering**: The Gateway does NOT guarantee in-order delivery of messages from the relay. However, state-changing messages are processed in the order they are received after deduplication and validity checks. The `correlation_id` ties requests to responses.
3. **Idempotency**: Operations MUST be designed to be idempotent where possible. The Gateway MUST process duplicate `operation.request` messages with the same `correlation_id` as a single operation, returning the same result.

### Reconnect and Resume

1. **Reconnect Does Not Recreate Authority**: If the transport connection drops, the Gateway will attempt to reconnect using exponential backoff with jitter (configurable). Upon reconnection:
   - The transport layer is restored, but no session state is recovered from the relay.
   - Existing sessions are NOT resumed automatically. The Gateway MUST treat the reconnected transport as a new pipe and require re-establishment of any sessions via the pairing/session protocol if needed.
   - Authorization (sessions, approvals) is stored locally and is not affected by transport reconnects.
2. **Resume Not Supported**: The contract does NOT support resuming a session after a transport interruption without re-authentication. A new session MUST be established if the previous session cannot be recovered locally.

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
  - Replay state-changing messages within the configured detection window (if the Gateway's replay detection is not yet implemented or misconfigured).
  - Send messages with invalid `device_id` (which will be rejected by the Gateway).

### Authentication Evidence and VerifiedPrincipal (Future Work)

- Authentication evidence consists of the successful TLS handshake (validating the relay's TLS certificate) and, for session establishment, the device identity proof exchanged during pairing.
- The Gateway binds the authentication evidence to a `VerifiedPrincipal` representing the relay only for the purpose of message source validation. This principal does not carry any authorization capabilities; authorization is granted solely by the local user via session approvals.
- Note: The `VerifiedPrincipal` type does not yet exist in the repository (see GitHub #19). This section describes the intended behavior for future implementation.

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
3. **I3**: Replay detection is enforced for all state-changing message types using `message_id` and `timestamp`. A state-changing message whose `timestamp` falls outside the configured validity window is rejected and is never processed or cached (fail closed), and cache entries outside the window are evicted to bound memory.
4. **I4**: The transport connection does not imply any authorization; a connected transport alone grants zero privileges.
5. **I5**: Session establishment requires mutual device authentication (Gateway proves identity to relay; relay's TLS certificate is validated by Gateway).
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
- **AC7**: Relay attempts to derive session state from a previous connection after a reboot.
  - Expected: Gateway does not persist session state to the relay; session state is local only. After reboot, the Gateway requires re-pairing to establish a new session.
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

The repository includes conformance fixtures under `tests/fixtures/protocol-abuse/` (see [fixture index](#fixture-index)).

### Fixture Index

| Fixture File | Abuse Case | Description |
|--------------|------------|-------------|
| `replay.json` | AC1 | Captured `operation.request` message replayed after a session reboot. |
| `duplicate.json` | AC1 | Duplicate `operation.request` with same `message_id` within the nonce window. |
| `out_of_order.json` | AC1 | `operation.request` messages sent out of sequence (by `timestamp`). |
| `stale_timestamp.json` | AC1 | `operation.request` whose `timestamp` is outside the validity window; must be rejected without processing or caching. |
| `oversized.json` | AC3 | Envelope with payload exceeding `MAX_MESSAGE_BYTES`. |
| `invalid_envelope.json` | AC3, AC4 | Malformed JSON or missing required fields. |
| `unknown_message_type.json` | AC4 | Envelope with `message_type` not in the V1 registry. |
| `mismatched_device_id.json` | AC5 | `session.request` with `device_id` not matching the Gateway's persistent identity. |
| `unapproved_operation.json` | AC6 | `operation.request` for a session that has not been approved by the local user. |
| `post_reboot_session.json` | AC7 | Attempt to resume a session after a simulated Gateway reboot. |
| `flood.json` | AC2, AC8 | High-volume message stream to test rate limiting and connection handling. |

## Sequence Diagrams

See [sequence-diagrams.md](./sequence-diagrams.md) for detailed interaction flows.

## References

- [Trust Boundaries](../security/trust-boundaries.md)
- [Protocol Specification](../protocol/README.md)
- [Data Flow Architecture](../architecture/data-flow.md)
- [Session Lifecycle](../architecture/session-lifecycle.md)
