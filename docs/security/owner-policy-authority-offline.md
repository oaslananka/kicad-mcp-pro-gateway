# Offline owner-policy generation and revocation serialization

Status: **UNUSED OFFLINE TRUSTED-STORE CONTRACT**. There is NO
production independently trusted root/counter provider, OAuth issuer,
user grant, native tool execution or public listener. Policy updates
are no longer permitted through an in-memory-only setter.
See [trusted durable commit contract](owner-policy-durable-commit-contract.md)
for mandatory third-party store guarantees and rollback limits.

The existing owner-signed strict JCS policy manifest cannot safely be used
by a caller that supplies an arbitrary `active_generation` on each actor
request: using a stale number could revive a cached manifest after revocation.
The new `OwnerPolicyAuthority` owns the already verified active policy,
immutable owner Ed25519 verifying root and process-local generation. No
per-request generation or raw policy key vector is accepted from a request.

- `from_trusted_store` reads a **previously authenticated committed**
  root and active generation via a hypothetical `TrustedOwnerPolicyStore`.
  Startup requires the exact matching owner-signed, unexpired manifest.
  Neither trust root nor generation can be provided by a remote relay,
  unsigned actor or manifest; no trusted store implementation is shipped.
- `verify_candidate_commit_and_activate` holds a writer lock across
  signature/JCS verification, generation validation and the store's
  compare-and-commit. Only a successfully committed, higher generation is
  published. A rejected candidate changes nothing; ANY durable-store
  error permanently disables the authority, because its commit outcome
  may be ambiguous. No in-memory-only update API remains.
- `verify_actor_and_consume` holds the matching reader lock until
  verified actor request/channel/challenge/replay consumption finishes.
  A writer cannot publish a revocation while an old-key read is in flight.
  After a new policy is committed, subsequent proofs cannot use the old
  policy. Lock-poison errors fail closed.
- The authenticated Gateway clock checks the owner manifest's issuance
  and expiry for **each** proof; the underlying owner-pinned actor issuer
  key state, signed request/channel and replay checks remain mandatory.
- The module deliberately does not implement signing, network key
  discovery, dynamic JWKS, on-disk policy caching, database migration or
  mobile/cloud OAuth. It grants zero tool execution capability.

**Critical non-guarantees:** The trusted store is only a Rust trait,
with no production implementation or authenticated initial enrollment.
Even a secure OS keyring and an ordinary SQLite transaction do not
independently prove power-loss durability or monotonic protection after
restoring full-disk backups. The current module assumes the external
provider performs an atomic cross-process, root-bound compare-and-commit
and no uncoordinated external revocation bypasses it. Failure to establish
these guarantees means **no production actor verification or tools**.

Tests cover strictly monotonic updates, owner-signature forgery,
expired updates, concurrent updates that serialize, and actual
Ed25519 actor proof revocation after an owner policy transition.
Use the documented Rust `std::sync::RwLock` poisoning behavior;
do not recover by ignoring a poisoned owner-policy lock.
