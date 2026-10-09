// Test-only fake trusted authority. It does NOT simulate a durable or
// rollback-resistant OS secret/monotonic store and must never ship to runtime.
use std::sync::{Arc, Mutex};

use companion_identity::{
    actor_attestation::ActorAttestationError,
    owner_policy_authority::{TrustedOwnerPolicyState, TrustedOwnerPolicyStore},
};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub enum Failure {
    None,
    BeforeCommit,
    AfterCommit,
}

struct State {
    root: VerifyingKey,
    generation: u64,
    manifest_sha256: [u8; 32],
    failure: Failure,
}

pub struct TestOwnerStore {
    inner: Mutex<State>,
}

impl TestOwnerStore {
    pub fn new(root: VerifyingKey, generation: u64, signed_manifest: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(State {
                root,
                generation,
                manifest_sha256: Sha256::digest(signed_manifest).into(),
                failure: Failure::None,
            }),
        })
    }

    pub fn set_failure(&self, failure: Failure) {
        self.inner.lock().unwrap().failure = failure;
    }

    pub fn generation(&self) -> u64 {
        self.inner.lock().unwrap().generation
    }
}

impl TrustedOwnerPolicyStore for TestOwnerStore {
    fn read_committed(&self) -> Result<TrustedOwnerPolicyState, ActorAttestationError> {
        let locked = self
            .inner
            .lock()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        Ok(TrustedOwnerPolicyState {
            root: locked.root,
            committed_generation: locked.generation,
            committed_manifest_sha256: locked.manifest_sha256,
        })
    }

    fn compare_and_commit(
        &self,
        pinned_owner_root: &VerifyingKey,
        expected_generation: u64,
        expected_manifest_sha256: &[u8; 32],
        next_generation: u64,
        next_manifest_sha256: &[u8; 32],
    ) -> Result<(), ActorAttestationError> {
        let mut locked = self
            .inner
            .lock()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        if locked.root != *pinned_owner_root
            || locked.generation != expected_generation
            || &locked.manifest_sha256 != expected_manifest_sha256
            || next_generation <= expected_generation
        {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        if matches!(locked.failure, Failure::BeforeCommit) {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        locked.generation = next_generation;
        locked.manifest_sha256 = *next_manifest_sha256;
        if matches!(locked.failure, Failure::AfterCommit) {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        Ok(())
    }
}
