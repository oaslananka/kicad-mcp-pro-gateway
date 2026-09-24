use std::sync::Arc;

use companion_identity::{
    DeviceIdentityStore, IdentityError, InMemorySecretStore, SqliteDeviceIdentityStore,
};
use companion_storage::Storage;
use ed25519_dalek::{Verifier, VerifyingKey};

fn store() -> SqliteDeviceIdentityStore<InMemorySecretStore> {
    let dir = tempfile::tempdir().unwrap();
    // Leak the tempdir so it outlives the Storage handle for the duration of the test process;
    // each test gets its own directory so this does not accumulate meaningfully.
    let path = dir.keep();
    let storage = Arc::new(Storage::open(&path).unwrap());
    SqliteDeviceIdentityStore::new(storage, InMemorySecretStore::new())
}

#[test]
fn load_on_fresh_store_returns_none() {
    let store = store();
    assert!(store.load().unwrap().is_none());
}

#[test]
fn create_then_load_returns_matching_identity() {
    let store = store();
    let created = store.create("dev-machine").unwrap();

    let loaded = store
        .load()
        .unwrap()
        .expect("identity present after create");
    assert_eq!(loaded.device_id, created.device_id);
    assert_eq!(loaded.public_key, created.public_key);
    assert_eq!(loaded.fingerprint, created.fingerprint);
    assert!(!loaded.fingerprint.0.is_empty());
}

#[test]
fn create_twice_fails_rather_than_overwriting() {
    let store = store();
    store.create("dev-machine").unwrap();

    let second = store.create("dev-machine-2");
    assert!(matches!(second, Err(IdentityError::AlreadyExists)));
}

#[test]
fn sign_produces_a_signature_verifiable_against_the_public_key() {
    let store = store();
    let identity = store.create("dev-machine").unwrap();

    let message = b"hello companion";
    let signature = store.sign(message).unwrap();

    let verifying_key = VerifyingKey::from_bytes(&identity.public_key.0).unwrap();
    assert!(verifying_key.verify(message, &signature).is_ok());
}

#[test]
fn fingerprint_is_deterministic_for_the_same_public_key() {
    let store = store();
    let identity = store.create("dev-machine").unwrap();
    let reloaded = store.load().unwrap().unwrap();
    assert_eq!(identity.fingerprint, reloaded.fingerprint);
}

#[test]
fn fingerprints_differ_between_distinct_identities() {
    let store_a = store();
    let store_b = store();
    let identity_a = store_a.create("machine-a").unwrap();
    let identity_b = store_b.create("machine-b").unwrap();
    assert_ne!(identity_a.fingerprint, identity_b.fingerprint);
}
