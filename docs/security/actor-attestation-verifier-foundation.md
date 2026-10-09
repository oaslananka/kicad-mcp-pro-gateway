# Offline actor-attestation verifier foundation

Status: **implemented as an unused, fail-closed library**, NOT an enabled
remote identity provider, remote transport or permission for remote tool calls.

This first stage implements the proposed actor-attestation contract from
[Gateway Issue #19](https://github.com/oaslananka/kicad-mcp-pro-gateway/issues/19)
without granting any privileges. The existing heartbeat-only pilot continues
to refuse remote operation envelopes.

## Current testable functionality

- An independently trusted public Ed25519 issuer key is supplied by the
  **local caller** as a pinned key ID, issuer and verification key. No issuer
  key is loaded from URLs, request headers, relayed JWKS or the device key.
  No production key provisioning, delegated signer or credential validation
  service exists yet.
- A versioned, short-lived, canonical RFC 8785/JCS JSON assertion binds the
  verified subject/client to exact audience/resource, local device/workspace,
  message/correlation IDs, local channel SHA-256, Gateway challenge and epoch,
  and a SHA-256 of the full canonical tool/request/effect JSON.
- The verifier refuses duplicate/unknown JSON keys, noncanonical text,
  wrong signer, expired/too-long/future proofs, wrong policy or channel,
  mismatched request hash, wrong device/workspace/message/challenge, and
  missing fields. An unsigned client display label cannot become identity.
- Before yielding a provider-neutral VerifiedPrincipal, SQLite atomically
  records independently hashed nonce, message, challenge and correlation
  identifiers with four uniqueness constraints, surviving process restarts.
  A second use, concurrent reuse or SQLite failure returns an error.
- New migration 0006 creates only non-secret proof fingerprints and expiry.
  The store deliberately **never auto-deletes** replay history without a
  separately qualified persistent clock high-water and retention scheme.
  When 250,000 records are reached, further claims **fail closed**; this
  is not yet suitable for unbounded production use.

## Isolation and uncompromised production gates

The verifier is **not called** by the current native relay, daemon transport,
local session authorization path or MCP HTTP endpoints. Test signers use
deterministic fixture keys that are never considered production issuer keys.

Callers must provide an independently authenticated local channel binding
and Gateway-issued challenge/epoch; this crate does **not** issue them or
validate OAuth tokens. No attacker-supplied `ExpectedActorRequest` is a
trusted source of channel/request context. Even a correctly verified result
never creates/extends a grant or skips device/workspace checks, effects,
local approval and durable audit-before-execution.

Production work still required before any transport activation:
- owner-managed independent issuer key provisioning and authenticated
  assertion issuance (without trusting the relay);
- locally generated one-time challenges/channel epochs, signed wire
  interoperability fixtures and source-pinned operation policy;
- bounded durable replay retention/high-water under clock rollback and
  crash/restart tests across independent Gateway instances;
- authorization grant, scope, workspace, audit failure and read-only E2E
  denial paths; OAuth/MCP 2026-07-28 resource server validation;
- separate owner authorization for external TLS/WSS ingress.

## Schema and rollback

Schema version goes from v5 to **v6**, additively. A Gateway executable
expecting only schema v5 intentionally refuses the newer database: do not
bypass this protection or downgrade schema manually. Back up the local
Gateway database before any *future authorized* application upgrade and
plan a compatible forward fix or operator-approved restore, preserving
revocations, grants and audit evidence. **This PR does not deploy or modify
any live Gateway SQLite database.**

Focused tests:

```sh
cargo +1.88 test -p companion-storage --locked
cargo +1.88 test -p companion-identity --locked
cargo +1.88 test -p companion-audit --locked
cargo +1.88 clippy -p companion-storage -p companion-identity --all-targets --locked -- -D warnings
```
