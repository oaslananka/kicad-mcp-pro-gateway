//! Windows production `SecretStore` backed by DPAPI (`CryptProtectData` /
//! `CryptUnprotectData`), scoped to the current Windows user profile. The
//! encrypted blob for each device is written under `<store_dir>/<device_id>.bin`.

#![cfg(target_os = "windows")]

use std::path::PathBuf;

use companion_core::DeviceId;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

use super::{SecretStore, SecretStoreError, SigningKeyMaterial};

pub struct DpapiSecretStore {
    store_dir: PathBuf,
}

impl DpapiSecretStore {
    pub fn new(store_dir: PathBuf) -> Self {
        Self { store_dir }
    }

    fn path_for(&self, device_id: &DeviceId) -> PathBuf {
        self.store_dir.join(format!("{device_id}.bin"))
    }
}

fn protect(plaintext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| SecretStoreError::Backend(format!("CryptProtectData failed: {e}")))?;

        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        Ok(bytes)
    }
}

fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| SecretStoreError::Backend(format!("CryptUnprotectData failed: {e}")))?;

        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut _));
        Ok(bytes)
    }
}

impl SecretStore for DpapiSecretStore {
    fn store_device_key(
        &self,
        device_id: &DeviceId,
        key: &SigningKeyMaterial,
    ) -> Result<(), SecretStoreError> {
        std::fs::create_dir_all(&self.store_dir)
            .map_err(|e| SecretStoreError::Backend(e.to_string()))?;
        let encrypted = protect(&key.to_bytes())?;
        std::fs::write(self.path_for(device_id), encrypted)
            .map_err(|e| SecretStoreError::Backend(e.to_string()))
    }

    fn load_device_key(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<SigningKeyMaterial>, SecretStoreError> {
        let path = self.path_for(device_id);
        if !path.exists() {
            return Ok(None);
        }
        let encrypted =
            std::fs::read(&path).map_err(|e| SecretStoreError::Backend(e.to_string()))?;
        let decrypted = unprotect(&encrypted)?;
        let bytes: [u8; 32] = decrypted
            .try_into()
            .map_err(|_| SecretStoreError::Backend("decrypted key has wrong length".into()))?;
        Ok(Some(SigningKeyMaterial::from_bytes(bytes)))
    }

    fn delete_device_key(&self, device_id: &DeviceId) -> Result<(), SecretStoreError> {
        let path = self.path_for(device_id);
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| SecretStoreError::Backend(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = DpapiSecretStore::new(dir.path().to_path_buf());
        let device_id = DeviceId::new();
        let key = SigningKeyMaterial::from_bytes([9; 32]);

        store.store_device_key(&device_id, &key).unwrap();
        let loaded = store
            .load_device_key(&device_id)
            .unwrap()
            .expect("key present");
        assert_eq!(loaded.to_bytes(), [9; 32]);
    }

    #[test]
    fn on_disk_blob_is_not_the_plaintext_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = DpapiSecretStore::new(dir.path().to_path_buf());
        let device_id = DeviceId::new();
        let key = SigningKeyMaterial::from_bytes([9; 32]);
        store.store_device_key(&device_id, &key).unwrap();

        let raw = std::fs::read(dir.path().join(format!("{device_id}.bin"))).unwrap();
        assert_ne!(raw, vec![9u8; 32]);
    }

    #[test]
    fn missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = DpapiSecretStore::new(dir.path().to_path_buf());
        assert!(store.load_device_key(&DeviceId::new()).unwrap().is_none());
    }
}
