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
