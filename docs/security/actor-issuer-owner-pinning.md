# Owner-pinned actor issuer keys and offline rotation

Status: **offline-only library trust policy**, not a configured identity
provider, live Gateway transport verifier or user credential authenticator.

A new `OwnerPinnedActorIssuers` snapshot offers an explicit bounded list of
trusted **public** Ed25519 verification keys. Claims supply untrusted
`issuer`/`key_id` lookup hints, but cannot provision any key, request a
different signature algorithm or redirect to an arbitrary JWKS URL.

- At most 32 locally owner-approved keys; no empty or whitespace-padded issuers/IDs, duplicate
  issuer-and-key IDs, reused signing public keys (even across issuers), or
  invalid validity ranges. Every key has an explicit `Active` or `Revoked`
  state, and `valid_from_unix` / `valid_until_unix` bounds.
- Any accepted proof must be within the key's configured validity interval
  **both at the trusted Gateway clock and across the entire signed claim
  issuance/expiration window**. The independently trusted issuer, signature,
  request/channel binding, Gateway-issued one-time challenge, replay storage
  and local authorization remain separate mandatory gates.
- Planned rotation is represented by two distinct active public keys with
  bounded, explicitly reviewed overlapping validity. Revocation rejects
  proofs immediately even if their prior signatures and expiration are valid.
  Neither a revoked key nor an unknown key falls back to another key.
- The proof's key identifier must match its own pinned public key; changing
  the key identifier cannot turn a signature by the old private key into a
  valid signature for the new key.
- Policy assembly is a **local owner-controlled responsibility**. This
  module deliberately has no remote policy loader, network/JWKS discovery,
  key signer, OAuth token verification or file format. A production
  trust-policy provision/rollback/revocation persistence mechanism and
  credential-vetting issuer are future implementation gates.
- The function is unused by native transport; valid verification alone
  authorizes **zero** remote KiCad operations.

The policy is fail-closed on no pins, malformed pins, duplicates,
out-of-window, unknown or revoked keys. Offline tests exercise these
states, rotation overlap, and successful real Ed25519 signatures bound
to previously issued, single-use Gateway challenges. No database
migration, secret persistence, production Gateway restart, Cloud Relay
deployment, release/tag or public listener is included.


## Non-oracular rejection and operational diagnostics

Unknown keys, revoked keys, out-of-window proofs and malformed owner
pins intentionally return the same `ActorAttestationError::Invalid` to
the caller, avoiding an information oracle on the owner trust registry.
A future local owner-only, authenticated, redacted diagnostic channel
can separately categorize rejections; this unused offline module does
not emit key IDs, raw proofs or token claims to logs.
