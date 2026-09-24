//! Test-only in-memory `SecretStore`. Never used in production — nothing
//! outside `#[cfg(test)]`/`test-util` builds can construct it.

#![cfg(any(test, feature = "test-util"))]

use std::collections::HashMap;
use std::sync::Mutex;

use companion_core::DeviceId;

use super::{SecretStore, SecretStoreError, SigningKeyMaterial};

#[derive(Default)]
pub struct InMemorySecretStore {
    keys: Mutex<HashMap<DeviceId, SigningKeyMaterial>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemorySecretStore {
    fn store_device_key(
        &self,
        device_id: &DeviceId,
        key: &SigningKeyMaterial,
    ) -> Result<(), SecretStoreError> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| SecretStoreError::Backend("mutex poisoned".into()))?;
        keys.insert(*device_id, key.clone());
        Ok(())
    }

    fn load_device_key(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<SigningKeyMaterial>, SecretStoreError> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| SecretStoreError::Backend("mutex poisoned".into()))?;
        Ok(keys.get(device_id).cloned())
    }

    fn delete_device_key(&self, device_id: &DeviceId) -> Result<(), SecretStoreError> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| SecretStoreError::Backend("mutex poisoned".into()))?;
        keys.remove(device_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_then_load_round_trips() {
        let store = InMemorySecretStore::new();
        let device_id = DeviceId::new();
        let key = SigningKeyMaterial::from_bytes([7; 32]);
        store.store_device_key(&device_id, &key).unwrap();

        let loaded = store
            .load_device_key(&device_id)
            .unwrap()
            .expect("key present");
        assert_eq!(loaded.to_bytes(), [7; 32]);
    }

    #[test]
    fn load_unknown_device_returns_none_not_error() {
        let store = InMemorySecretStore::new();
        let result = store.load_device_key(&DeviceId::new()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_then_load_returns_none() {
        let store = InMemorySecretStore::new();
        let device_id = DeviceId::new();
        store
            .store_device_key(&device_id, &SigningKeyMaterial::from_bytes([1; 32]))
            .unwrap();

        store.delete_device_key(&device_id).unwrap();

        assert!(store.load_device_key(&device_id).unwrap().is_none());
    }
}
