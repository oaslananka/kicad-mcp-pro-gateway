# Owner-Gateway-issued actor challenge — offline-only security foundation

Status: **offline library + additive SQLite migration, NOT deployed, NOT wired
to native transport, NOT an independent actor signer or OAuth flow.**

The previous actor verifier checked exact signatures and durable replay but
trusted the calling code to supply a challenge. It now requires a challenge
that the Gateway **issued and durably registered first**, bound to locally
authenticated device/workspace, connection epoch and channel binding.

## Challenge issuance

- `issue_gateway_challenge(storage, &LocalGatewayChannel)` obtains **32 bytes
  from OS CSPRNG** via `rand_core::OsRng::try_fill_bytes`. A failed entropy
  source fails closed; an unpadded Base64URL token is returned only after
  successful SQLite commit.
- The local caller must derive device, workspace, authenticated connection
  epoch and transport binding from verified native Gateway state, **not**
  from relay/device-provided labels or an arbitrary HTTP request.
- SQLite v7 table `gateway_actor_challenges` stores only SHA-256-based,
  domain-separated hashes of the challenge and each context value plus
  issued/expiry timestamps and a consumed flag, **never raw challenge or
  transport channel IDs**.
- Each challenge is valid for at most 60 seconds, is single-use, and remains
  unusable after a process restart, channel change, or storage failure.
  Issuance is capped at 250,000 retained entries, fail closed if full.
  There is **no automatic deletion** pending reviewed clock-rollback-safe
  high-water/retention rules.

## Atomic actor verification

The existing `verify_and_consume_actor_assertion` continues to validate the
owner-pinned independent issuer Ed25519 signature, strict RFC 8785 JCS
canonicalization, actual full request digest and authenticated-channel digest,
exact actor/device/workspace/epoch IDs and time limits. Only **after** all
cryptographic checks does it open an SQLite `BEGIN IMMEDIATE` transaction.

That transaction conditionally consumes the one issued challenge matching
the trusted native Gateway context AND atomically reserves all four existing
replay dimensions (nonce/message/challenge/correlation). A failed replay
insert, wrong channel or persistence error rolls back challenge consumption.
No `VerifiedPrincipal` is returned until commit succeeds. SQLite transaction
behavior follows the documented `rusqlite::TransactionBehavior::Immediate`
contract; contention or errors deny rather than fall back.

## Tests and strict operational limits

New negative tests reject missing challenges (including another Gateway
instance with same signer), stale/other-epoch challenge, tampered context,
invalid signatures and replayed proofs. Storage tests exercise two independent
issued challenges, replay collision mid-transaction, restoration of the
unconsumed second challenge, wrong persisted binding, restart and deleted
challenge tables.

Migration **v6 to v7 is additive**. The later offline
[clock high-water v8 foundation](actor-clock-high-water-foundation.md)
now rejects locally observed clock rollback during issuance and proof
consumption; it does **not** enable record deletion or live transport. Existing v5/v6 binaries must continue to
reject an upgraded v7 database. No live database is migrated by this PR;
any future approved deployment requires data backup, migration/rollback
compatibility review and a verified restoration plan.

Still missing: independently authenticated OAuth user/agent credentials,
separate trusted attestation *signing service* and owner key provisioning,
verified device-channel integration into the native Gateway daemon,
clock-safe replay retention/compaction, policy-backed local grants,
audit-before-execution and hostile full remote read-only E2E.

The private Cloud Relay remains device-authenticated **heartbeat only**;
transport connectivity/valid signature/issued challenge do **not** authorize
remote tool calls. No public listener, production release, tag, code-signing,
runtime rollout or Gateway service restart is performed by this work.
