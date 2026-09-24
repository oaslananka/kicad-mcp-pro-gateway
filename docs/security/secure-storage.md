# Secure Storage

## What must never be plaintext-persisted

Device private key material must never be written to SQLite, a plain config
file, logs, telemetry, or returned through the local IPC API or CLI output
(including under `--verbose`).

## `SecretStore` abstraction

```rust
pub trait SecretStore: Send + Sync {
    fn store_device_key(&self, device_id: &DeviceId, key: &SigningKeyMaterial) -> Result<(), SecretStoreError>;
    fn load_device_key(&self, device_id: &DeviceId) -> Result<Option<SigningKeyMaterial>, SecretStoreError>;
    fn delete_device_key(&self, device_id: &DeviceId) -> Result<(), SecretStoreError>;
}
```

`SigningKeyMaterial` intentionally has no `Debug`/`Display` impl that prints
bytes, and is wrapped so it zeroizes on drop.

## Platform adapters

| Platform | Production backend |
|---|---|
| Windows | DPAPI |
| macOS | Keychain (`keyring` Apple-native backend) |
| Linux | Secret Service over D-Bus (`keyring` synchronous backend, Rust crypto) |

Production adapters are implemented for Windows, macOS, and Linux. Windows
uses DPAPI; macOS uses the native Keychain provider; Linux uses the synchronous
Secret Service provider over D-Bus with Rust crypto and vendored libdbus. The
macOS/Linux adapter stores the raw 32-byte Ed25519 secret through the keyring
binary-secret API under a fixed application service namespace and the local
`DeviceId` as the account key. Access is serialized because the underlying
platform stores do not guarantee reliable concurrent access to one credential.

`InMemorySecretStore` remains explicitly test-only. **No production code path
silently falls back to plaintext storage or to the keyring mock backend.** If a
native credential service cannot be opened or an operation fails, identity
creation/loading fails with a typed backend error rather than degrading to a
file-based secret store. Unsupported operating systems still fail startup with
`IDENTITY_SECRET_STORE_UNAVAILABLE`.

The keyring integration is pinned to `keyring = 3.6.3`. The repository declares
Rust 1.88 as its minimum supported Rust version and verifies that floor in CI.

## Device identity lifecycle

1. On daemon start, check whether a device identity exists (`storage`
   metadata table has a device row + `SecretStore` has a matching key).
2. If not, generate an Ed25519 keypair using the OS CSPRNG (via a mature,
   reviewed crate — no custom RNG or crypto).
3. Persist the private key via `SecretStore` only.
4. Persist non-secret device metadata (device id, public key, display name,
   created_at, fingerprint) via `storage`.
5. Compute a human-readable fingerprint from the public key (e.g. a
   truncated, grouped hash) for display during pairing.
6. Never log the private key. Never include it in any error's contextual
   data. Never send it to the cloud — only the public key and signatures
   ever cross the transport boundary.

## Constant-time and redaction rules

- Any comparison involving a secret (pairing code, token) uses
  constant-time comparison, not `==` on a `String`/`&[u8]`.
- Types that wrap sensitive data implement a redacted `Debug` (e.g.
  `SigningKeyMaterial(REDACTED)`) so an accidental `{:?}` in a log statement
  cannot leak it. This is covered by a dedicated unit test per sensitive
  type, not just a code-review convention.

## What SQLite is for

SQLite holds everything else: device metadata (public fields only), pairing
metadata, authorized workspaces, sessions, approvals, audit events,
settings, checkpoint metadata. See [`crates/storage`](../../crates/storage)
for the schema and migrations.
