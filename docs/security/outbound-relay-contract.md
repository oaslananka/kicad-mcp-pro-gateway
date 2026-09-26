# Outbound Relay Security Contract

This document defines the security contract between the Gateway daemon and a production outbound relay. It specifies the expectations, guarantees, and limitations to ensure secure communication despite the relay being untrusted.

## Overview

The Gateway daemon initiates outbound connections to a relay (or cloud service) using the Gateway transport protocol (see [protocol/README.md](../protocol/README.md)). The relay is considered untrusted; therefore, the contract assumes the relay may be compromised, malicious, or subject to network attacks.

## Contract Guarantees

### Authentication and Identity

1. **Device Authentication**: The Gateway authenticates itself to the relay using its device identity (Ed25519 key pair) during the pairing process. The relay must verify the Gateway's proof of possession of the private key.
2. **Relay Authentication**: The Gateway does not authenticate the relay beyond TLS server certificate validation (standard PKI). The relay's identity is not used for authorization decisions.
3. **Session Binding**: After pairing, a session is established. The Gateway binds the session to the verified device identity of the relay only for the purpose of ensuring messages originate from the paired relay. The relay's identity does not confer any privileges.

### Message Integrity and Confidentiality

- All messages are encrypted and integrity-protected via TLS 1.2 or higher.
- The Gateway does not rely on the relay for message confidentiality or integrity; these are provided by the transport layer (TLS).

### Replay, Ordering, and Idempotency

1. **Replay Detection**: Each message includes a unique `message_id` (ULID/UUID) and a `timestamp`. The Gateway MUST detect and reject replayed state-changing messages (e.g., `session.request`, `operation.request`) based on `message_id` and `timestamp` within a configured window.
2. **Ordering**: The Gateway does not guarantee in-order delivery of messages from the relay. However, state-changing messages are processed in the order they are received after deduplication and validity checks. The `correlation_id` ties requests to responses.
3. **Idempotency**: Operations are designed to be idempotent where possible. The Gateway MUST process duplicate `operation.request` messages with the same `correlation_id` as a single operation, returning the same result.

### Reconnect and Resume

1. **Reconnect Does Not Recreate Authority**: If the transport connection drops, the Gateway will attempt to reconnect using exponential backoff with jitter. Upon reconnection:
   - The transport layer is restored, but no session state is recovered from the relay.
   - Existing sessions are NOT resumed automatically. The Gateway MUST treat the reconnected transport as a new pipe and require re-establishment of any sessions via the pairing/session protocol if needed.
   - Authorization (sessions, approvals) is stored locally and is not affected by transport reconnects.
2. **Resume Not Supported**: The contract does not support resuming a session after a transport interruption without re-authentication. A new session must be established if the previous session cannot be recovered locally.

### Resource Limits and Backpressure

1. **Message Size Limits**: The Gateway enforces a maximum envelope size (e.g., 4 KiB) and maximum payload size per message type. Messages exceeding these limits are rejected without processing.
2. **Rate Limiting**: The Gateway implements a token-bucket rate limiter for incoming messages from the relay to prevent resource exhaustion. Limits are configurable and fail closed (excess messages are dropped).
3. **Backpressure**: If the Gateway is unable to process incoming messages due to internal backpressure (e.g., queue full), it applies backpressure at the transport level by delaying `receive()` operations or closing the connection after a timeout. The relay is expected to handle connection closures and retry with its own backoff.

### Compromise Assumptions

If the relay is compromised, the following are the limits of what the attacker can cause:

- **Cannot**: 
  - Execute arbitrary operations on the Gateway without a valid session approved by the local user.
  - Access the device's private key material (stored in secure storage, never transmitted).
  - Bypass policy checks for workspace access, capability execution, or audit recording.
  - Replay state-changing messages beyond the configured detection window.
  - Forge messages that appear to originate from the Gateway (without the device private key).
- **Can**:
  - Send malformed or oversized messages (which will be rejected by size limits and schema validation).
  - Attempt to flood the Gateway with messages (subject to rate limiting).
  - Cause a denial-of-service by consuming network bandwidth or attempting to exhaust connection slots (mitigated by rate limits and connection timeouts).
  - Learn metadata such as message frequencies and approximate timing (but not content due to TLS encryption).
  - Cause the Gateway to disconnect repeatedly (which triggers reconnect logic but does not grant privileges).

### Authentication Evidence and VerifiedPrincipal

- Authentication evidence consists of the successful TLS handshake (validating the relay's TLS certificate) and, for session establishment, the device identity proof exchanged during pairing.
- The Gateway binds the authentication evidence to a `VerifiedPrincipal` representing the relay only for the purpose of message source validation. This principal does not carry any authorization capabilities; authorization is granted solely by the local user via session approvals.

### Outbound-Only Connectivity and Failure Behavior

- The Gateway ONLY initiates outbound connections to the relay. It does not listen for inbound connections from the relay.
- If the relay becomes unavailable, the Gateway:
  - Drops the transport connection.
  - Enters a reconnect state with exponential backoff and jitter.
  - Continues to function normally for local operations (core-bridge and IPC) without requiring the transport.
  - Does not retry indefinitely without backoff; the reconnect policy includes a maximum attempt limit (configurable) after which it considers the relay permanently unavailable and stops retrying until manually reset or configuration change.
- Local tool execution and session approvals remain functional even when the transport is disconnected.

### Binding to Authorization Grants

- The Gateway does not use the relay's identity to authorize any operation. Authorization is derived solely from:
  - Local user approvals (via desktop/UI/CLI) bound to a session.
  - Session metadata (workspace IDs, allowed capabilities, expiry time) stored locally.
- The relay's role is limited to transporting messages; it does not influence authorization decisions.

## Protocol Invariants

The following invariants MUST hold at all times:

1. **I1**: No operation is executed without a valid, non-expired, non-revoked session that has been approved by the local user for the requested workspace and capability.
2. **I2**: All inbound messages are validated for size, schema, and message type before further processing.
3. **I3**: Replay detection is enforced for all state-changing message types using `message_id` and `timestamp`.
4. **I4**: The transport connection does not imply any authorization; a connected transport alone grants zero privileges.
5. **I5**: Session establishment requires mutual device authentication (Gateway proves identity to relay; relay's TLS certificate is validated by Gateway).
6. **I6**: The Gateway never sends unencrypted or unauthenticated messages over the transport; TLS is mandatory for all connections.
7. **I7**: Error messages sent to the relay do not contain sensitive information (e.g., private keys, local paths).

## Abuse Cases

The following abuse cases are considered in the design:

- **AC1**: Relay attempts to replay an old `operation.request` message.
  - Expected: Gateway detects replay via `message_id` and rejects the message.
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

## Sequence Diagrams

See [sequence-diagrams.md](./sequence-diagrams.md) for detailed interaction flows.

## References

- [Trust Boundaries](../security/trust-boundaries.md)
- [Protocol Specification](../protocol/README.md)
- [Data Flow Architecture](../architecture/data-flow.md)
- [Session Lifecycle](../architecture/session-lifecycle.md)
