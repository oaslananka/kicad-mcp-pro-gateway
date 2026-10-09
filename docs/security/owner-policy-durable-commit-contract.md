# Owner-policy activation: trusted durable commit contract

Status: **source-only interface and fail-closed tests**. No production
implementation of the trusted store exists. This is NOT a keyring,
platform-backed monotonic counter, trust bootstrap, live identity provider
or authorization for any remote operations.

`OwnerPolicyAuthority` now accepts only a `TrustedOwnerPolicyStore`
that returns an independently established owner Ed25519 verification
root **and** the generation of the currently committed owner-signed
manifest. Startup requires an exact match between that generation
and the signed, canonical, unexpired manifest. There is no empty
policy fallback, TOFU key import, first-run `generation=0` default
or remote root enrollment.

The `compare_and_commit` contract is deliberately stronger than an
ordinary file write or SQLite transaction in the local Gateway data
directory:

1. Verify the currently bound owner root and exact previous generation;
   reject any stale expected generation or root change. Serialize this
   across all processes and any other owner-policy administrative client.
2. Atomically commit a **strictly increasing** generation to an
   independently trusted, durable and rollback-resistant source, then
   return success only after that commit is complete.
3. After power loss or a crash, return exactly the committed root and
   generation; no silent downgrade to an earlier database snapshot.
4. Missing, unreadable, disputed or untrusted root/generation values fail
   closed; the caller cannot supply them through request headers, the
   signed manifest, cloud relay, IPC or actor claims.
5. Clearly qualify recovery from owner-root compromise, reset or lost
   counter through a separately owner-authorized process. No generic
   fallback to a newly observed root.

The module itself **does not satisfy** these properties: a future
platform-specific store must be threat-modeled, implemented and tested
before production usage. OS secret stores may authenticate a key but
do not automatically guarantee a monotonic counter protected against
restoring an old full-disk backup. Existing SQLite v8 clock high-water
also does not supply that guarantee.

## Atomicity of visible policy changes

During an offline candidate update, a write lock prevents any actor
proof from completing while the owner manifest signature/generation is
verified and `compare_and_commit` is running. The newer in-memory
policy is published **only after successful trusted-store commit**.
Rejected signatures or stale generations leave the old active policy
unchanged and the store untouched.

If the trusted-store call returns an error, the state is *ambiguous*:
it may have committed despite reporting failure. In **every** such
case this authority permanently changes to an unavailable state.
It must never keep verifying actor proofs with possibly revoked keys
or retry the same instance after a failed store call. Only a new
authority constructed against an independently trusted committed
snapshot and its matching owner-signed manifest can become active.

Unit/integration tests use an explicitly **test-only in-memory mock**
that can reject before changing state or return an error after committing
a higher generation. The tests prove the API permanently disables
proofs after either failure, blocks stale/forged updates, refuses
mismatched bootstrap generations, and recovers via a fresh object only
when the supplied manifest matches the mock's committed generation.
A concurrent-writer test verifies serialized updates and that the
largest authorized generation is retained. This mock does not
prove actual OS hardware, power-loss or rollback resistance.

Additional guards — independent OAuth credential verification, native
Gateway channel/request authentication, local workspace grants, risk,
auditable approval-before-execution and hostile E2E — remain mandatory.
The live private VPS pilot and Cloud Relay have not been changed.

References:
- [Rust RwLock exclusive-write poisoning](https://doc.rust-lang.org/std/sync/struct.RwLock.html)
- [SQLite atomic commit scope and storage assumptions](https://www.sqlite.org/atomiccommit.html)
