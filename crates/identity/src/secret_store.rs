//! Abstraction over OS secure storage for device private key material.
//!
//! See `docs/security/secure-storage.md`. No production code path may fall
//! back to plaintext storage if a platform adapter is unavailable.

use std::fmt;

use companion_core::{CompanionError, DeviceId};
use zeroize::Zeroize;

pub mod memory;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod native_keyring;
#[cfg(target_os = "windows")]
pub mod windows_dpapi;

/// Wraps a raw Ed25519 signing key so it can never be accidentally printed
/// or logged, and is zeroized when dropped.
pub struct SigningKeyMaterial([u8; 32]);

impl SigningKeyMaterial {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Clone for SigningKeyMaterial {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKeyMaterial(REDACTED)")
    }
}

impl Drop for SigningKeyMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("secret store backend error: {0}")]
    Backend(String),
}

impl CompanionError for SecretStoreError {
    fn code(&self) -> &'static str {
        "IDENTITY_SECRET_STORE_BACKEND"
    }

    fn retryable(&self) -> bool {
        false
    }
}

/// Persists and retrieves device private key material. Implementors must
/// never write plaintext key bytes to disk.
pub trait SecretStore: Send + Sync {
    fn store_device_key(
        &self,
        device_id: &DeviceId,
        key: &SigningKeyMaterial,
    ) -> Result<(), SecretStoreError>;
    fn load_device_key(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<SigningKeyMaterial>, SecretStoreError>;
    fn delete_device_key(&self, device_id: &DeviceId) -> Result<(), SecretStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let key = SigningKeyMaterial::from_bytes([0x42; 32]);
        let debug = format!("{key:?}");
        assert_eq!(debug, "SigningKeyMaterial(REDACTED)");
        assert!(!debug.contains("42"));
    }
}
