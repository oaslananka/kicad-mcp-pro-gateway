# Owner authenticator and independent trust-witness qualification (source-only v1)

Status: **research and negative contract tests only**. No production provider,
enrollment API, native credential prompt, hardware commitment or trust activation.

## Why there are two independent proofs

1. **Local owner ceremony:** a previously enrolled/pinned owner credential must
   authenticate the local owner on a trusted, owner-controlled interaction.
   The verifier must validate signature, credential ID, WebAuthn RP ID and
   origin (or an equivalently reviewed native authentication protocol), user
   verification/presence, an unpredictable challenge, expected operation
   purpose, session, device and reset epoch, pinned policy-owner root, exact
   signed-manifest digest and short lifetime. An owner's WebAuthn signature
   must not be mistaken for approval of arbitrary UI text: the complete
   context must be incorporated into the signed challenge and independently
   displayed or confirmed through a qualified trusted local surface.
2. **Independent trust history/commitment:** an authority outside restorable
   Gateway application files must attest whether the device is provably
   never enrolled, already enrolled, or history-unknown; identify the same
   hardware/witness domain and reset epoch; commit the exact
   (owner root, device, epoch, generation, signed-manifest digest) under
   all-writer fencing and restore-replay detection. A storage outage or lost
   provenance is **NOT** evidence of first use.

WebAuthn user verification is not an anti-rollback database. Credential
`signCount` may remain zero, and the assertion may represent a backed-up,
multi-device passkey. Neither is a substitute for a hardware/witness generation.

The source-only `owner_provider_qualification_model.rs` intentionally uses
**fake verifier booleans**, deterministic test nonces, in-memory history and
fence counters. Its accepted branch demonstrates a test contract, not a
cryptographic proof or an OS-backed durable write. Production must implement
and qualify *both* boundaries independently. This fixture MUST NOT be copied
into the daemon or advertised as an owner credential implementation.

## Candidate provider qualification

| Candidate | What current documentation establishes | Still unqualified for this protocol |
| --- | --- | --- |
| WebAuthn Level 3 authenticator | RP-scoped signature, origin/challenge checks and UV/UP results available to a conforming verifier | Owner enrollment identity, trusted local review of exact policy/intent, device-bound history, reliable hardware monotonic generation, WebAuthn recovery identity |
| Windows CNG Platform Crypto Provider / TPM | TPM-backed key protection available | Independent owner-root binding, reset/epoch provenance, atomic root/generation/digest commit, reliable all-writer CAS and restore detection |
| Linux TPM2 NV counter | TPM has NV counter operations under appropriate policies | Owner/witness auth and provisioning, root/manifest atomic binding, counter exhaustion/wear, crash reconciliation, whole-disk restore/reset and process fencing |
| macOS Secure Enclave + Keychain | Hardware-backed keys and migration/access controls are available | A proven monotonic policy-generation counter, Ed25519-root binding protocol and reset/restore history |
| Independent signed witness | Could potentially record and sign append-only commitments | Authenticated identity, independently anchored monotonicity, anti-equivocation, availability/offline denial, recovery, privacy and lifecycle costs |

**Decision:** all provider candidates remain *unqualified* until platform
experiments and threat model review establish the missing properties; no
automatic selection, installation or default fallback.

## Versioned recovery candidate (not accepted implementation)

- Every request is purpose-separated: `FirstEnrollment` consent cannot
  recover, and `Recovery` consent cannot enroll a purported new device.
- Recovery requires a fresh independent owner proof plus an independently
  verified previously enrolled root, device identity and reset epoch. A
  copyable disk policy, empty trust store, lost NV index, TPM clear or unknown
  witness history must enter `RECOVERY_REQUIRED` without permission to mint
  a new owner root. Lost credential or root rotation needs a separate,
  owner-approved multi-party or independent recovery protocol.
- Verify an owner-signed candidate for the **same pinned root** and strictly
  greater generation; commit exact candidate digest using an externally
  enforced atomic transaction and unique writer fence. An old writer or old
  policy loses. Only then may a trusted reconciler admit that exact blob.
- A crash before commitment leaves the old trusted policy generation;
  prepared newer bytes cannot activate. A crash after commitment may have
  an ambiguous result: do not repeat authorization; independently re-read
  the anchored tuple and verify signed policy and trusted expiry. If exact
  policy bytes are missing or conflicting, fail closed pending fresh recovery.
- Runtime remote execution remains **DENIED** until independent authenticated
  actor/channel, grants, effect/risk checks and durable audit-first gates pass.

A genuine implementation must also handle power-cut/fsync order, noncooperating
writers, hardware reset, lost owner credential, witness replacement, trusted
time loss, root rotation and physical attack assumptions. Those remain OPEN.

## Source-only validation and escalation gate

The focused provider-eligibility tests cover wrong credential/RP/origin/UV, scoped challenges, passkey backup and signature-counter semantics, uncertain history, reset, owner root and missing witness CAS/fencing. The existing owner_provisioning_model.rs fixture separately covers disk rollback, crash faults, single-use consent and stale writers. Both remain source-only models; neither establishes hardware durability.

Before OS-provider work: request a separate owner decision on approved
platform/device, attestation acceptance, provisioning and reset procedure,
failure/recovery UX, experiments and rollback evidence. Physical fault
injection, secrets, releases, migrations, VPS changes, public ingress and
remote KiCad execution are OUT OF SCOPE.

### Primary references (as of 2026-10-10)

- W3C WebAuthn Level 3 Recommendation, authentication assertion verification
  and signCount semantics:
  https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
- NIST SP 800-63B-4 final (authentication, phishing/replay resistance):
  https://csrc.nist.gov/pubs/sp/800/63/b/4/final
- Microsoft Platform Crypto Provider:
  https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers
- TPM2 NV counter:
  https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_nvincrement.1/
- Apple Secure Enclave keys:
  https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
