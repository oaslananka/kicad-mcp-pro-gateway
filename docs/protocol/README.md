# Protocol

This directory documents the wire protocols Companion speaks. All protocols
here are **open and documented** per project principle 12 — nothing about
pairing, session negotiation, or the operation envelope is a secret format.

## Two distinct protocols — do not confuse them

1. **Local core-bridge protocol**: standard MCP over Streamable HTTP, exactly
   as implemented by kicad-mcp-pro (`initialize`, `tools/list`, `tools/call`,
   JSON-RPC 2.0 envelopes, protocol version `2025-11-25` at the time of
   writing, optional `MCP-Session-Id`). Companion is a client of this
   protocol; it does not extend or modify it. See
   [`crates/core-bridge`](../../crates/core-bridge).
2. **Companion transport protocol**: the envelope Companion uses to talk to
   a relay/cloud. The normal daemon starts with outbound transport disabled;
   an in-process mock is available only when explicitly selected for local
   development/testing. A production hosted relay is out of scope for this
   repository. See below.

## Companion transport envelope (V1)

Every message on the Companion transport is versioned and typed:

```jsonc
{
  "protocol_version": "0.1.0",
  "message_id": "01J...",       // ULID/UUID, unique per message
  "message_type": "session.request", // see message_type registry below
  "device_id": "dev_...",
  "timestamp": "2026-09-16T12:00:00Z", // required on state-changing messages
  "correlation_id": "01J...",   // ties requests to responses/results
  "payload": { /* message_type-specific */ }
}
```

- `protocol_version` follows semver and is checked on receipt; an
  incompatible major version is rejected rather than best-effort parsed.
- `message_id` is unique per message and is the basis for replay detection
  on state-changing messages once a real relay exists.
- `device_id` is mandatory on inbound `session.request` and
  `operation.request` messages. Companion rejects the message unless it
  matches the persistent local `DeviceIdentity.device_id`; operation
  requests must also reference a session bound to that same device.
- Unknown `message_type` values are rejected, not ignored — silent
  best-effort parsing of unknown message types is exactly the kind of
  implicit trust this project exists to prevent.

## Message type registry (V1, growing)

| `message_type` | Direction | Purpose |
|---|---|---|
| `pairing.begin` | Companion → relay | Start device pairing |
| `pairing.challenge` | relay → Companion | Server challenge nonce |
| `pairing.proof` | Companion → relay | Signed device proof |
| `pairing.result` | relay → Companion | Paired / rejected |
| `session.request` | relay → Companion | Remote principal requests a session |
| `session.decision` | Companion → relay | Local approve/deny |
| `operation.request` | relay → Companion | `OperationRequest` for an active session |
| `operation.result` | Companion → relay | `OperationResult` or typed error |
| `session.revoke` | Companion → relay | Local revoke notification |
| `heartbeat` | both | Liveness / reconnect signal |

## Security notes

- TLS + standard crypto primitives only; no custom encryption is
  implemented anywhere in this repository.
- Device identity uses Ed25519; private key material never appears in any
  protocol payload.
- Pairing codes/nonces are short-lived and single-use; production
  rate-limiting is a server-side (future cloud) responsibility, but the
  client-side models here are shaped so that a reusable-secret-forever
  design is structurally impossible (see
  [`crates/protocol`](../../crates/protocol)).
- A valid transport connection is authentication of the *pipe*, not
  authorization of an *operation* — see
  [trust-boundaries.md](../security/trust-boundaries.md).

## Versioning

Both protocols are explicitly versioned from day one. Breaking changes to
the Companion transport envelope bump `protocol_version`'s major component;
receivers must reject majors they do not understand rather than guess.
