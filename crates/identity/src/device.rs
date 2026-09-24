//! Device identity lifecycle: generation, persistence, and signing.
//!
//! Non-secret metadata (device id, public key, fingerprint, display name)
//! is persisted via `companion-storage`. The private key never touches
//! `companion-storage` — it only ever passes through a [`SecretStore`].

use std::sync::Arc;

use companion_core::{
    CompanionError, DeviceFingerprint, DeviceId, DeviceIdentity, DevicePublicKey,
};
use companion_storage::Storage;
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::secret_store::{SecretStore, SecretStoreError, SigningKeyMaterial};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("device identity already exists")]
    AlreadyExists,
    #[error("no device identity exists yet")]
    NotFound,
    #[error("secret store error: {0}")]
    SecretStore(#[from] SecretStoreError),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("stored key material is invalid: {0}")]
    InvalidKeyMaterial(String),
}

impl CompanionError for IdentityError {
    fn code(&self) -> &'static str {
        match self {
            IdentityError::AlreadyExists => "IDENTITY_ALREADY_EXISTS",
            IdentityError::NotFound => "IDENTITY_NOT_FOUND",
            IdentityError::SecretStore(_) => "IDENTITY_SECRET_STORE_BACKEND",
            IdentityError::Storage(_) => "IDENTITY_STORAGE",
            IdentityError::InvalidKeyMaterial(_) => "IDENTITY_INVALID_KEY_MATERIAL",
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}

pub trait DeviceIdentityStore {
    fn load(&self) -> Result<Option<DeviceIdentity>, IdentityError>;
    fn create(&self, display_name: &str) -> Result<DeviceIdentity, IdentityError>;
    fn public_identity(&self) -> Result<Option<DeviceIdentity>, IdentityError>;
    fn sign(&self, message: &[u8]) -> Result<Signature, IdentityError>;
}

pub struct SqliteDeviceIdentityStore<S: SecretStore> {
    storage: Arc<Storage>,
    secret_store: S,
}

impl<S: SecretStore> SqliteDeviceIdentityStore<S> {
    pub fn new(storage: Arc<Storage>, secret_store: S) -> Self {
        Self {
            storage,
            secret_store,
        }
    }
}

fn compute_fingerprint(public_key: &[u8; 32]) -> DeviceFingerprint {
    let hash = Sha256::digest(public_key);
    let hex: String = hash.iter().take(10).map(|b| format!("{b:02X}")).collect();
    let grouped: String = hex
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-");
    DeviceFingerprint(grouped)
}

fn format_rfc3339(t: OffsetDateTime) -> Result<String, IdentityError> {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| IdentityError::Storage(e.to_string()))
}

fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, IdentityError> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| IdentityError::Storage(e.to_string()))
}

impl<S: SecretStore> DeviceIdentityStore for SqliteDeviceIdentityStore<S> {
    fn load(&self) -> Result<Option<DeviceIdentity>, IdentityError> {
        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| IdentityError::Storage("mutex poisoned".into()))?;
        let result = conn.query_row(
            "SELECT device_id, public_key, fingerprint, display_name, created_at FROM device LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        );

        match result {
            Ok((device_id_str, public_key, fingerprint, display_name, created_at)) => {
                let device_id: DeviceId = device_id_str
                    .parse()
                    .map_err(|e| IdentityError::Storage(format!("{e:?}")))?;
                if public_key.len() != 32 {
                    return Err(IdentityError::InvalidKeyMaterial(
                        "stored public key is not 32 bytes".into(),
                    ));
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&public_key);

                Ok(Some(DeviceIdentity {
                    device_id,
                    public_key: DevicePublicKey(pk),
                    fingerprint: DeviceFingerprint(fingerprint),
                    display_name,
                    created_at: parse_rfc3339(&created_at)?,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(IdentityError::Storage(e.to_string())),
        }
    }

    fn create(&self, display_name: &str) -> Result<DeviceIdentity, IdentityError> {
        if self.load()?.is_some() {
            return Err(IdentityError::AlreadyExists);
        }

        let mut csprng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let device_id = DeviceId::new();
        let fingerprint = compute_fingerprint(verifying_key.as_bytes());
        let created_at = OffsetDateTime::now_utc();

        self.secret_store.store_device_key(
            &device_id,
            &SigningKeyMaterial::from_bytes(signing_key.to_bytes()),
        )?;

        let conn = self
            .storage
            .connection()
            .lock()
            .map_err(|_| IdentityError::Storage("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO device (device_id, public_key, fingerprint, display_name, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                device_id.to_string(),
                verifying_key.as_bytes().to_vec(),
                fingerprint.0,
                display_name,
                format_rfc3339(created_at)?,
            ],
        )
        .map_err(|e| IdentityError::Storage(e.to_string()))?;

        Ok(DeviceIdentity {
            device_id,
            public_key: DevicePublicKey(*verifying_key.as_bytes()),
            fingerprint,
            display_name: display_name.to_string(),
            created_at,
        })
    }

    fn public_identity(&self) -> Result<Option<DeviceIdentity>, IdentityError> {
        self.load()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, IdentityError> {
        let identity = self.load()?.ok_or(IdentityError::NotFound)?;
        let key_material = self
            .secret_store
            .load_device_key(&identity.device_id)?
            .ok_or(IdentityError::NotFound)?;
        let signing_key = SigningKey::from_bytes(&key_material.to_bytes());
        Ok(signing_key.sign(message))
    }
}
