# Owner-policy commitment v1: source-only protocol

Status: DESIGN/CONTRACT ONLY. No production trusted store, hardware provisioning, monotonic counter provider, recovery channel, remote tool authorization, or release is implemented. This document extends the existing signed owner-issuer-manifest/v1 contract, without a live migration.

## Authority and identity

An independently authenticated, explicit local owner action must authorize initial enrollment. An out-of-band validated Ed25519 owner public key fingerprint is pinned. There is no trust-on-first-use, automatic enrollment, network-supplied root, default generation zero, or silent recovery.

Commitment v1 is one logical, atomic current-state tuple:

1. Independently enrolled owner verification root and explicit device/provider domain.
2. Strictly positive owner-policy generation.
3. SHA-256 of the exact, canonical, owner-signed manifest envelope (not merely unsigned payload or generation).

The source-only TrustedOwnerPolicyState models the root, generation and signed-manifest digest. Binding the tuple to independently attested device, provider and local owner approval, plus durable storage, is **not** implemented. The trait has no usable production implementation.

The owner signature, domain, JCS encoding, issuer keys, revocations, generation and expiration are validated before calculating the digest. Initial activation requires the trusted state to match all three fields and checks an atomic snapshot again before publication. Candidate updates serialize validation with a root + expected generation + expected digest CAS and commit a strictly larger generation AND exact new digest before making policy visible.

**Security limit:** a double read does not exclude future noncooperating writers. A real store MUST guarantee all-writer cross-process synchronization across verification, publication and use, or supply another equivalent, independently verified current-state proof. Source-only tests and this Rust object do not guarantee this. Never connect live authorization to the trait as-is.

## Crash and rollback states

| Event | Required result |
| --- | --- |
| Candidate not yet durably prepared | Prior exact independently committed tuple only, or deny |
| Candidate prepared, trust commit not started | Uncommitted candidate grants no authority |
| Trusted commit completed but caller crashed or returned an error | Deny while ambiguous; independently reconcile after restart |
| Trusted generation advanced but exact signed manifest unavailable | Deny, never reconstruct another same-generation signed policy |
| Signed alternative manifest at same generation | Deny on digest mismatch |
| Local database, journal, filesystem or whole disk restored | Compare against independent rollback-resistant trusted anchor or deny |
| Root store missing, hardware clear, profile/device migration, witness reset, lost keys | Deny; explicit authenticated owner recovery is required |
| Clock cannot be independently qualified or manifest expired | Deny |

A storage preparation journal and filesystem fsync alone are NOT a monotonic trust anchor. Raw TPM2 NV increment alone cannot atomically bind a SHA-256 manifest digest to the counter; a multi-resource transaction may need to stop in a safely denied state after power loss. Generation jumps are NOT necessarily expressible by one TPM counter increment. Providers must address counter wear, exhaustion, protected read/write, resets, trusted current generation, fencing, locks and crash points.

## Platform eligibility and alternatives

- Windows CNG Microsoft Platform Crypto Provider supports TPM-backed non-exportable private keys; it does not automatically authenticate the owner Ed25519 root or supply a manifest+generation atomic monotonic CAS.
- Linux TPM2 NV counter supports authorized increments and reads, not a transaction committing the signed manifest digest; actual TPM hierarchy policy, NV reset/clear, index ACLs, cross-process exclusion and hardware durability must be qualified.
- macOS Secure Enclave supports non-exportable P-256 private keys, not hardware-held Ed25519 owner keys. Keychain ThisDeviceOnly affects migration/access, not a proven hardware-monotonic application policy counter.
- An independent owner-approved witness is possible only after proving signed, replay-safe and mutually authenticated (device, owner root, generation, manifest digest) commitments, concurrent CAS, reset/equivocation recovery, privacy, availability, and offline fail-closed behavior. Cloud Relay itself MUST NOT automatically become a trusted witness.

Official primary references:

- https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/how-windows-uses-the-tpm
- https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers
- https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_nvincrement.1/
- https://tpm2-tools.readthedocs.io/en/latest/man/common/nv-attrs/
- https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
- https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility

## Root rotation, issuer revocation, and recovery

Issuer key rotation/revocation requires a newer owner-signed manifest with a different commitment digest. Replacement/revocation of the owner trust root is a separate, **not implemented** protocol that requires independent owner authorization and an anti-rollback recorded transition (or a specially qualified physical recovery). Neither user-controlled identity claims nor a restored disk snapshot can change the enrolled root. Any uncertain root, generation, manifest, witness, or provider => deny; never return to generation zero or use SQLite/Keychain as an unchecked fallback.

## Evidence and stop conditions

Current source-only tests cover same-generation divergent valid owner signatures, digest drift at bootstrap, generation update ordering, pre/post-commit ambiguous failure and exact-manifest restart reconciliation using only an in-memory test fake. They do not prove TPM/Keychain behavior, privileged competing processes, power-loss atomicity, monotonic full-disk rollback resistance, trusted time, or real owner enrollment.

Production implementation remains blocked until provider eligibility, authenticated owner provisioning and destructive recovery tests on qualified non-production hardware are explicitly authorized. Independent OAuth actor signer, authenticated Gateway request/channel binding, local workspace/grant/effect/risk policy, audit-before-execution and hostile E2E remain mandatory before any remote KiCad operation. No public ingress, live SQLite migration, VPS rollout, tag or release follows from this change.

## Enrollment and recovery v1 — modeled state machine (no production adapter)

The test-only executable model lives in
crates/identity/tests/owner_provisioning_model.rs. It uses real canonical JCS,
Ed25519 manifest verification and the existing OwnerPolicyAuthority constructor,
but deliberately keeps its owner approval, trusted commit and disk snapshots
inside a non-shipping test harness. It does NOT simulate OS-backed trust,
privileged writes, real power failures, secure UI, or device attestation.

### Owner approval contract (future adapter responsibility)

An actual onboarding UI must independently authenticate the human owner,
present the local device identity, owner root fingerprint, policy generation,
issuer list, key status/revocations, expiry, and the exact canonical signed
manifest digest for explicit review. Its authorization artifact must be
authenticated, one-time, session-/device-bound, expire promptly, resist
replay and *not* be constructible by a network caller or recovery file.
Declining, timing out, canceling, or failing identity verification causes
DENY. A hash comparison against a fake struct alone is NOT owner consent.
The test-only ModelOwnerApproval stands in for a qualified local ceremony.

The first enrollment MUST bind one qualifying device/provider domain,
owner root, positive manifest generation and SHA-256 of the exact signed
manifest, atomically in an independently rollback-resistant authority.
The existing production Rust trait contains no enrollment or reset API.
It must NOT add an automatic create-if-missing path.

### States and transition requirements

| State | Entry | Permitted next action | Remote actor authority |
| --- | --- | --- | --- |
| UNENROLLED | No independently trusted record | Verify eligible device/provider + explicit owner review; prepare only | DENY |
| PREPARING | Correct signature and matching local approval, candidate durable preparation incomplete | Abort and deny; repeat only with fresh owner approval | DENY |
| PREPARED | Exact canonical signed manifest durably prepared, anchor not yet committed | Commit under qualified all-writer fencing; else deny | DENY |
| COMMIT_UNKNOWN | Commit error, lost response, or crash at linearization | No in-process retry/activation; independently re-read complete anchor + exact blob after restart | DENY |
| COMMITTED_OFFLINE | Trusted anchor committed exact tuple | Reconstruct and verify exact policy; no privilege until separate OAuth/channel/grant/audit gates | DENY for remote tools |
| RECOVERY_REQUIRED | Wrong/missing manifest, trust reset, conflicting root/digest, stale backup, trusted clock/provider unavailable | Deny; separately authenticate owner to a distinct recovery process | DENY |
| ROOT_ROTATION_PENDING | Owner intends to replace pinned root | Not supported by current trait; require new versioned dual-authenticated/root-revocation protocol | DENY |

COMMIT_UNKNOWN can resolve only to *the current independently trusted tuple*
after boot; an old uncommitted prepared file is not evidence. If a counter
advanced but the manifest is missing, remain unavailable rather than use the
old root/key list. A verified source-only model restart is not production
authorization.

### Negative evidence and remaining hard problems

Tests reject unsigned/unapproved bootstrap, unqualified provider, forged
owner root, another valid owner-signed same-generation policy, wrong device
domain, crash before/after prepared/committed state, backup rollback after
revocation, missing policy file, external authority outage, reset followed by
silent re-enrollment, and racing stale CAS writers. A simulated independent
reset latch is intentionally *not* a hardware guarantee. A TPM clear or
independent witness rollback must be detectable outside the restored disk,
otherwise a freshly empty local store is indistinguishable from first-run
enrollment; no production rollout is acceptable.

The true implementation must separately demonstrate: independently bound
owner interaction, attested device/witness identity, all-writer fencing during
verification and actor use, atomic verified root+generation+manifest digest CAS,
rollback-resistant journal recovery, platform reset behavior, trusted time,
prevention of policy resurrection after key revocation, and negative E2E
when any authority source disappears. Physical fault injection requires
separate owner approval on isolated non-production hardware.

Stop conditions: any automatic trust-on-first-use, mutable local counter
masquerading as anti-rollback, unbounded privilege on root reset, recovery
by copied SQLite/Keychain files, cloud relay self-attestation, missing actor
authentication, or audit/grant bypass. No rollout, public ingress, database
migration, release, or remote tool execution is authorized by this tranche.
### Local owner ceremony v1 — replay/expiry and provenance test model

The offline `TestOwnerCeremony` fixture now models a **single outstanding,
one-use, purpose-scoped** owner consent ceremony. It rejects absent simulated
owner authentication, zero challenge/session nonce, mismatched session,
challenge, owner-root fingerprint, exact signed-manifest digest, device domain,
or intent; cancelled, expired, future-clock, excessively long and replayed
consent also deny. A rejected presentation burns the pending ceremony rather
than leaving a guessable replay window. Enrollment consent does not authorize
recovery or owner-root rotation. An ambiguous commit cannot reuse the approval;
restart must reconcile the exact signed manifest commitment.

This is a **contract model, NOT a credential protocol**: fixed test nonces,
in-memory locks, simulated Boolean owner authentication, test approval objects
and test time do not establish secure consent, authenticated UI, device
binding or trusted time. No real WebAuthn/platform authenticator is wired to
Gateway. A future implementer must qualify verifier-generated unpredictable
challenges, origin/verifier binding, owner presence/user verification,
device/session/purpose/exact signed-manifest binding, durable one-time
consumption, maximum age and trusted-time semantics. The actual ceremony
must remain on an independently authenticated owner-controlled LOCAL channel.

The test anchor also maintains separately simulated history:
`VerifiedNeverEnrolled`, `PreviouslyEnrolled`, or `Unverifiable`.
An empty store after previous enrollment, or missing history, is NOT evidence
of a virgin device and MUST NOT trigger silent enrollment. This simulated
history is not real hardware/witness qualification. TPM clear, profile/device
migration, lost hardware identity, restored backup, witness replacement, and
recovery remain independently owner-gated and fail closed.

Protocol research, not implementation evidence:
- W3C WebAuthn Level 3 (2026-08-25):
  https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
- NIST SP 800-63B-4 (2025):
  https://csrc.nist.gov/pubs/sp/800/63/b/4/final

Do not turn this fixture into a production token or API. Real owner identity
proof, trusted platform/witness provenance, cross-process all-writer fencing,
independent trusted clock, root rotation, abuse-case validation and remote
Gateway authorization remain independent non-bypassable security gates.
