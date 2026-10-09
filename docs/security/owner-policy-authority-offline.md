# Offline owner-policy generation and revocation serialization

Status: **UNUSED, PROCESS-LOCAL ONLY**. This adds NO production trust root
enrollment, no persistent monotonic counter, no OAuth issuer, no user grants,
no native Gateway operation, no release, and no public network access.

The existing owner-signed strict JCS policy manifest cannot safely be used
by a caller that supplies an arbitrary `active_generation` on each actor
request: using a stale number could revive a cached manifest after revocation.
The new `OwnerPolicyAuthority` owns the already verified active policy,
immutable owner Ed25519 verifying root and process-local generation. No
per-request generation or raw policy key vector is accepted from a request.

- `from_trusted_local_state` accepts an **already locally authenticated**
  owner root and durable prior generation from a *future external trust
  provider*; the new manifest must be valid, owner-signed and strictly
  newer. Neither trust root nor prior generation can be supplied by a
  relay or unsigned actor. No loader or fallback is provided here.
- `verify_candidate_and_replace_in_memory` holds a writer lock across
  signature/JCS verification and the strictly monotonic generation check.
  Valid replacements are swapped atomically; invalid, stale, unknown or
  expired updates cannot mutate the active policy.
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

**Critical non-guarantees:** The root and last accepted generation are
still only provided as call arguments from a presumed trusted external
source. There is NO OS-vetted bootstrap or durable compare-and-swap
implementation. After restart, the module itself knows nothing of old
generations; restoring all database files can roll back replay evidence
and locally stored counters. Trusted root custody, cross-restart
anti-rollback and crash-atomic durable policy update MUST be implemented
and reviewed before wiring this module into the live Gateway. An invalid
or missing external trust source must deny, never substitute a zero
generation or a key supplied by remote devices.

Tests cover strictly monotonic updates, owner-signature forgery,
expired updates, concurrent updates that serialize, and actual
Ed25519 actor proof revocation after an owner policy transition.
Use the documented Rust `std::sync::RwLock` poisoning behavior;
do not recover by ignoring a poisoned owner-policy lock.
