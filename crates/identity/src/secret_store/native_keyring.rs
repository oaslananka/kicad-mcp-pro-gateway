//! macOS Keychain / Linux Secret Service backed `SecretStore` adapter.
//!
//! Uses the OS-native keyring provider selected at compile time. There is no
//! plaintext or file fallback. Keyring calls are serialized because the
//! underlying platform stores do not guarantee reliable concurrent access to
//! the same credential.

use std::sync::Mutex;

use companion_core::DeviceId;
use zeroize::Zeroizing;

use super::{SecretStore, SecretStoreError, SigningKeyMaterial};

const SERVICE_NAME: &str = "dev.oaslananka.kicad-mcp-pro-gateway.device-key";

trait KeyringBackend: Send + Sync {
    fn set_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String>;
    fn get_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, String>;
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), String>;
}

struct SystemKeyringBackend {
    builder: Box<keyring::CredentialBuilder>,
    operation_lock: Mutex<()>,
}

impl SystemKeyringBackend {
    fn new() -> Self {
        Self::with_builder(keyring::default::default_credential_builder())
    }

    fn with_builder(builder: Box<keyring::CredentialBuilder>) -> Self {
        Self {
            builder,
            operation_lock: Mutex::new(()),
        }
    }

    fn entry(&self, service: &str, account: &str) -> Result<keyring::Entry, String> {
        let credential = self
            .builder
            .build(None, service, account)
            .map_err(|err| err.to_string())?;
        Ok(keyring::Entry::new_with_credential(credential))
    }

    fn lock_operations(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.operation_lock
            .lock()
            .map_err(|_| "credential operation lock poisoned".to_owned())
    }
}

impl KeyringBackend for SystemKeyringBackend {
    fn set_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
        let _guard = self.lock_operations()?;
        self.entry(service, account)?
            .set_secret(secret)
            .map_err(|err| err.to_string())
    }

    fn get_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
        let _guard = self.lock_operations()?;
        match self.entry(service, account)?.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err.to_string()),
        }
    }

    fn delete_secret(&self, service: &str, account: &str) -> Result<(), String> {
        let _guard = self.lock_operations()?;
        match self.entry(service, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }
}

pub struct NativeKeyringSecretStore {
    backend: Box<dyn KeyringBackend>,
}

impl NativeKeyringSecretStore {
    pub fn new() -> Self {
        Self {
            backend: Box::new(SystemKeyringBackend::new()),
        }
    }

    #[cfg(test)]
    fn with_backend<B>(backend: B) -> Self
    where
        B: KeyringBackend + 'static,
    {
        Self {
            backend: Box::new(backend),
        }
    }
}

impl Default for NativeKeyringSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for NativeKeyringSecretStore {
    fn store_device_key(
        &self,
        device_id: &DeviceId,
        key: &SigningKeyMaterial,
    ) -> Result<(), SecretStoreError> {
        let account = device_id.to_string();
        let key_bytes = Zeroizing::new(key.to_bytes());
        self.backend
            .set_secret(SERVICE_NAME, &account, &key_bytes[..])
            .map_err(SecretStoreError::Backend)
    }

    fn load_device_key(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<SigningKeyMaterial>, SecretStoreError> {
        let account = device_id.to_string();
        let Some(secret) = self
            .backend
            .get_secret(SERVICE_NAME, &account)
            .map_err(SecretStoreError::Backend)?
        else {
            return Ok(None);
        };
        let secret = Zeroizing::new(secret);
        if secret.len() != 32 {
            return Err(SecretStoreError::Backend(
                "stored device key has wrong length".to_owned(),
            ));
        }

        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&secret);
        Ok(Some(SigningKeyMaterial::from_bytes(bytes)))
    }

    fn delete_device_key(&self, device_id: &DeviceId) -> Result<(), SecretStoreError> {
        let account = device_id.to_string();
        self.backend
            .delete_secret(SERVICE_NAME, &account)
            .map_err(SecretStoreError::Backend)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use crate::{SecretStore, SigningKeyMaterial};
    use companion_core::DeviceId;

    use super::*;

    type FakeEntries = Arc<Mutex<HashMap<(String, String), Vec<u8>>>>;

    #[derive(Clone, Default)]
    struct FakeBackend {
        entries: FakeEntries,
    }

    impl KeyringBackend for FakeBackend {
        fn set_secret(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
            self.entries
                .lock()
                .unwrap()
                .insert((service.to_owned(), account.to_owned()), secret.to_vec());
            Ok(())
        }

        fn get_secret(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(&(service.to_owned(), account.to_owned()))
                .cloned())
        }

        fn delete_secret(&self, service: &str, account: &str) -> Result<(), String> {
            self.entries
                .lock()
                .unwrap()
                .remove(&(service.to_owned(), account.to_owned()));
            Ok(())
        }
    }

    #[test]
    fn binary_device_key_round_trips_through_backend() {
        let store = NativeKeyringSecretStore::with_backend(FakeBackend::default());
        let device_id = DeviceId::new();
        let key = SigningKeyMaterial::from_bytes([0xa5; 32]);

        store.store_device_key(&device_id, &key).unwrap();
        let loaded = store.load_device_key(&device_id).unwrap().unwrap();

        assert_eq!(loaded.to_bytes(), [0xa5; 32]);
    }

    #[test]
    fn missing_device_key_returns_none() {
        let store = NativeKeyringSecretStore::with_backend(FakeBackend::default());

        assert!(store.load_device_key(&DeviceId::new()).unwrap().is_none());
    }

    #[test]
    fn delete_device_key_is_idempotent() {
        let store = NativeKeyringSecretStore::with_backend(FakeBackend::default());
        let device_id = DeviceId::new();

        store.delete_device_key(&device_id).unwrap();
        store.delete_device_key(&device_id).unwrap();
    }

    #[test]
    fn wrong_length_secret_is_rejected_without_echoing_secret_bytes() {
        let backend = FakeBackend::default();
        let device_id = DeviceId::new();
        backend.entries.lock().unwrap().insert(
            (SERVICE_NAME.to_owned(), device_id.to_string()),
            vec![7, 8, 9],
        );
        let store = NativeKeyringSecretStore::with_backend(backend);

        let err = store.load_device_key(&device_id).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("wrong length"));
        assert!(!message.contains("7, 8, 9"));
    }

    #[test]
    fn system_backend_treats_missing_entry_as_none_and_delete_as_idempotent() {
        let backend =
            SystemKeyringBackend::with_builder(keyring::mock::default_credential_builder());

        assert_eq!(backend.get_secret("svc", "acct").unwrap(), None);
        backend.delete_secret("svc", "acct").unwrap();
    }
}
