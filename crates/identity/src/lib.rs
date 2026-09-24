//! `companion-identity`: device keypair lifecycle, secure-storage
//! abstraction, and fingerprinting. See `docs/security/secure-storage.md`.

pub mod device;
pub mod secret_store;

pub use device::{DeviceIdentityStore, IdentityError, SqliteDeviceIdentityStore};
pub use secret_store::{SecretStore, SecretStoreError, SigningKeyMaterial};

#[cfg(any(test, feature = "test-util"))]
pub use secret_store::memory::InMemorySecretStore;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use secret_store::native_keyring::NativeKeyringSecretStore;

#[cfg(target_os = "windows")]
pub use secret_store::windows_dpapi::DpapiSecretStore;
