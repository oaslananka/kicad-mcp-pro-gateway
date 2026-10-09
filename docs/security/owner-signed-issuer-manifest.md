# Owner-signed issuer-key manifests (offline verifier only)

Status: **SOURCE-ONLY FOUNDATION; NOT INSTALLED, NOT LIVE, NOT AN OAUTH IDENTITY ISSUER**.

The existing offline `OwnerPinnedActorIssuers` now has an independent
owner-signature verification entry point,
`verify_owner_signed_issuer_manifest(bytes, owner_root, minimum_generation_exclusive,
trusted_now_unix)`.

The owner root is a separately provisioned, **locally authenticated
Ed25519 public key**, independent of the remote actor issuer signing key.
It is never read from the manifest, a relay message, an HTTP claim, JWKS,
or an unsigned device display name. Its private key is not used or stored
by this module. No caller-provided signature algorithm is selectable.

## Strict proposed v1 envelope

The complete envelope is RFC 8785 JCS canonical JSON, UTF-8, at most
16 KiB. Duplicate property names, unknown fields, noncanonical serializations,
oversized payloads, unknown enumerated states or algorithms fail closed.
The signed bytes are precisely the ASCII domain:

`kicad-mcp/owner-issuer-manifest/v1\n`

followed by the **canonical JCS bytes of the typed payload** (not the
complete envelope). The envelope contains exactly `payload` and
`signature`, which is a canonical, unpadded base64url Ed25519 signature.

The payload fields are `contract_version` (fixed
`owner-issuer-manifest/v1`), positive `generation` (I-JSON safe integer),
`issued_at`, `expires_at` (UTC Unix seconds, max 30 days validity) and
1–32 `keys` entries. Each key specifies `issuer`, `key_id`,
`public_key` (canonical unpadded base64url Ed25519 public bytes),
`valid_from_unix`, `valid_until_unix`, and `state` as exactly
`active` or `revoked`. Duplicate issuer/key IDs, reused public keys
across any issuer, invalid validity windows, ambiguous or whitespace-padded
IDs, and use of the **owner root itself** as an actor issuer key are denied.

## Generation monotonicity and remaining gates

The passed minimum generation is an **already trusted and durably
recorded owner-policy floor**; an incoming generation must be strictly
higher. This verifies candidate *updates*, not a persisted policy loader:
the library does not record the floor, establish its provenance, implement
secure owner-key provisioning or activate a policy in the Gateway daemon.
**Supplying zero on every restart is insecure** and cannot be presented
as rollback protection.

A future integration must atomically persist the accepted generation and
owner-root identity in an independently trusted local state boundary,
reject any old or missing trust state without bootstrap authorization, and
qualify crash/DB-backup restoration and root-compromise recovery. The
current SQLite v8 local wall-clock high-water does **not** protect against
restoring its entire database. Production owner-key lifecycle and an
independent credential-vetted OAuth actor signer are separately required.

In addition to checking manifest expiry for each assertion, the
`verify_and_consume` API requires the **current owner-policy generation**
from trusted local state on each attempt. An old in-memory active-key
snapshot cannot silently outlive an owner-signed revocation when the
trusted current generation advances. A caller that supplies the old
generation defeats this protection; secure provenance/atomic persistence
of that value remains a mandatory integration gate.

The verified policy keeps its key list **private** and exposes only
`verify_and_consume`, which rechecks the signed manifest's validity
window against trusted Gateway-local time on **every actor proof**.
Previously accepted manifests must not keep granting actor verification
after expiry, even if an issuer key itself remains active.

The companion
[offline owner-policy authority](owner-policy-authority-offline.md)
serializes signed manifest activation and actor verification, so remote
requests cannot independently supply an old current-generation number.
It now requires an external durable trusted-store contract and denies
all verification on ambiguous commit failures; the interface itself
**is not** an implemented or verified durable trust provider.

Valid manifest signatures install only **public verification keys**.
A manifest is NOT an actor's credential or consent, does NOT establish
a remote principal until the *separate* actor signature, channel/request
binding, durable replay and local grants pass, and grants ZERO remote
KiCad tools. The current Gateway/Relay transport remains heartbeat-only.
No live secrets, configuration files, signing services, SQLite migrations,
ports, production rollout, tag, release or OAuth HTTP endpoints are added.

References: [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785)
and the pinned Ed25519 verification API. Tests exercise good owner
signatures, key rotation/revocation, forged owners, duplicate/unknown JSON,
wrong domain, generation rollback, expired signatures, key aliasing,
invalid base64url, limits, and actual offline actor-proof verification.
