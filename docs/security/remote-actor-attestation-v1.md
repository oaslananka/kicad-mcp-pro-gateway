# Remote actor attestation v1 — proposed Gateway acceptance contract

**Status: PROPOSED, not an implemented trust path.** This document is a
reviewable contract for [Gateway Issue #19](https://github.com/oaslananka/kicad-mcp-pro-gateway/issues/19).
It does not open a remote transport, accept OAuth tokens, or authorize
operations. The existing outbound relay pilot remains **heartbeat only**.

## Non-interchangeable identities

- Device enrollment (fresh Ed25519 challenge) proves device identity to the
  private relay, **not** a remote human/AI principal.
- Validating the relay's WebPKI/TLS endpoint proves the relay transport peer,
  **not** the actor who requested a KiCad operation.
- A remote client-provided `remote_principal` string remains unverified
  display data. No label, session ID or signed device challenge may be
  promoted into a `VerifiedPrincipal`.
- A future OAuth HTTP resource server verifies client/user tokens for its
  own resource; that alone cannot create a Gateway grant.
- The Gateway's `InboundEnvelope.verified_principal` may be populated only
  after a *locally verified* cryptographic assertion from an **independently
  owner-trusted attestation issuer** tied to the actual authenticated actor
  and this precise Gateway-bound request. An untrusted relay must not be
  able to mint evidence by signing its own unchecked claims.

## Required future request-bound assertion fields (exact schema TBD)

`contract_version=actor-attestation/v1`, `issuer`, trusted `key_id`,
`subject`, `client_id`, exact `audience`/`resource`, `device_id`,
`workspace_id`, `message_id`, `correlation_id`, SHA-256 over the
**Gateway-recomputed canonical request bytes**, a locally issued one-time
`gateway_challenge` and authenticated `connection_epoch`, signed
`issued_at`, `expires_at` and `nonce`, and a vetted algorithm/signature.

The signature domain is version-separated, e.g.
`kicad-mcp/actor-attestation/v1\n` followed by fixed, canonical bytes.
**RFC 8785 JSON Canonicalization Scheme (JCS) is REQUIRED for v1**, with
strict I-JSON constraints, deterministic numeric/Unicode handling, duplicate
JSON member rejection and identical interoperable serialized test vectors.
Reject noncanonical or ambiguously encoded input; never sign arbitrary
platform-dependent serialization. Compute request hashes locally from the
validated canonical request, never from an untrusted relayed digest.
**Signature algorithm selection MUST come exclusively from locally pinned
issuer/key policy**, not from a caller-controlled `alg`, JWT header or payload.
Reject `none`, unexpected algorithms, mismatched key types and algorithm/key
confusion; every accepted key ID has one explicit approved algorithm.

**Open architecture decision:** choose an independent trust root, proof
issuance flow, key lifecycle and provision of Gateway challenges. The
currently untrusted relay must not become an implicitly trusted user
attestation issuer. No arbitrary JWKS URL/key in the incoming envelope is
trustworthy. Access-token forwarding is not a substitute for a reviewed
issuer/audience and proof-of-possession design.

## Mandatory verification order (before any remote operation)

1. Reject unsupported protocol versions, malformed/oversized envelopes,
   unknown operation and effect descriptions or ambiguous canonical bytes.
2. Resolve the owner-pinned verifier key; cryptographically verify signature
   and delegated issuer/scope, then authenticate the subject/client mapping.
3. Check the exact audience, OAuth resource, current local device,
   workspace, active transport epoch, Gateway-issued challenge, timestamp
   limits, message/correlation IDs and *computed* full-request digest.
4. Atomically consume challenge/nonce/message identity in a persistent,
   fail-closed replay store. Lost or unavailable replay storage means deny,
   including after restart, reconnection, process crash and clock rollback.
5. Produce the existing provider-neutral `VerifiedPrincipal` for exactly
   this inbound envelope. Keep raw provider credentials, tokens, signature,
   nonce and secret/private path data out of audit and IPC.
6. Independently re-check the local active/unrevoked/unused grant, workspace
   membership, source-pinned capability/effect policy, dynamic risk, any
   required local approval and **durable pre-execution audit** before
   `tools/call`. Verified identity alone grants zero authority.

## Minimum hostile interoperability tests

- False or changed display claim; absent, unsigned or `alg=none` assertion;
  unknown/revoked signer; attacker-supplied key material or key URL.
- Relay rebinds an otherwise valid assertion to a different request body,
  device, tenant, resource, workspace, client, method, arguments or effect.
- Replayed nonce/challenge/message/correlation ID; two simultaneous replays;
  old transport epoch after reconnect; clock skew/expiry/issuer rotation;
  crash/restart before or after consuming durable replay state.
- Untrusted relay attempts to create actor authority with its own signer,
  forged transport labels or a valid enrolled device signature.
- Grant missing/revoked/expired/spent; read-only grant attempts write;
  workspace removed during approval; audit persistence failure.

Any missing verification evidence **fails closed**. The mock transport may
inject `VerifiedPrincipal` only for tests; the native heartbeat transport
continues to refuse sending/receiving privileged envelopes. This proposal
does not implement the signer, OAuth provider, replay database or Gateway
verifier and is NOT production remote-access approval.

References: `docs/security/outbound-relay-contract.md`,
`docs/security/trust-boundaries.md`,
`crates/transport/src/transport.rs`, RFC 7515 §10.10, RFC 8707,
RFC 9728, RFC 8785, and MCP authorization/HTTP transport 2026-07-28.
