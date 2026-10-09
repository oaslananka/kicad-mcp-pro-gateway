//! OFFLINE-ONLY owner policy activation contract, NO OS trust provider.
//!
//! A real provider MUST already authenticate a separately provisioned owner
//! root and make its policy generation monotonic and non-rollbackable across
//! process/database restart. This module contains NO such implementation.

use std::sync::{Arc, RwLock};

use companion_core::VerifiedPrincipal;
use companion_storage::Storage;
use ed25519_dalek::VerifyingKey;

use crate::{
    actor_attestation::{ActorAttestationError, ExpectedActorRequest},
    owner_manifest::{verify_owner_signed_issuer_manifest, VerifiedOwnerIssuerManifest},
};

/// Provenance must come from a future independently authenticated local
/// owner trust authority, never untrusted caller, relay or manifest values.
pub struct TrustedOwnerPolicyState {
    pub root: VerifyingKey,
    pub committed_generation: u64,
}

/// Contract for a separately vetted OS-owner-bound, monotonic durable store.
/// THIS CRATE PROVIDES NO PRODUCTION IMPLEMENTATION.
///
/// compare_and_commit MUST be process-/machine-wide atomic, protect the
/// owner root identity, reject stale expected generations, and return Ok
/// ONLY AFTER durable commit. A crash or ambiguous commit outcome cannot
/// silently substitute an older trust snapshot on the next process boot.
pub trait TrustedOwnerPolicyStore: Send + Sync {
    fn read_committed(&self) -> Result<TrustedOwnerPolicyState, ActorAttestationError>;

    fn compare_and_commit(
        &self,
        pinned_owner_root: &VerifyingKey,
        expected_generation: u64,
        next_generation: u64,
    ) -> Result<(), ActorAttestationError>;
}

/// Fail-closed owner policy reader/writer synchronization.
///
/// A rejected manifest leaves the current trusted policy usable. A failed
/// or ambiguous durable commit permanently disables this authority's actor
/// verification for its remaining lifetime, even if storage later recovers.
/// Lock poisoning on writer panic also denies all later reads/writes.
pub struct OwnerPolicyAuthority {
    root: VerifyingKey,
    trusted_store: Arc<dyn TrustedOwnerPolicyStore>,
    active: RwLock<Option<VerifiedOwnerIssuerManifest>>,
}

impl OwnerPolicyAuthority {
    /// No implicit TOFU bootstrap, no default generation=0, no fallback to
    /// caller/root-from-manifest: the trusted store must already contain
    /// a valid owner root and strictly positive active committed generation.
    /// The initial signed manifest must MATCH that committed generation.
    pub fn from_trusted_store(
        trusted_store: Arc<dyn TrustedOwnerPolicyStore>,
        active_manifest: &[u8],
        trusted_now_unix: i64,
    ) -> Result<Self, ActorAttestationError> {
        let committed = trusted_store.read_committed()?;
        if committed.committed_generation == 0 {
            return Err(ActorAttestationError::Invalid);
        }
        let active = verify_owner_signed_issuer_manifest(
            active_manifest,
            &committed.root,
            committed.committed_generation - 1,
            trusted_now_unix,
        )?;
        if active.generation != committed.committed_generation {
            return Err(ActorAttestationError::Invalid);
        }
        Ok(Self {
            root: committed.root,
            trusted_store,
            active: RwLock::new(Some(active)),
        })
    }

    /// Strictly validate a new owner manifest, then COMMIT the generation
    /// under a trusted store CAS while holding the write lock. Make the new
    /// in-memory key list visible ONLY after commit succeeds.
    ///
    /// If a commit failed, including after an uncertain durable write,
    /// permanently disable this instance. No old policy fallback: it
    /// could revive a just-revoked issuer key after actual disk commit.
    pub fn verify_candidate_commit_and_activate(
        &self,
        signed_manifest: &[u8],
        trusted_now_unix: i64,
    ) -> Result<u64, ActorAttestationError> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        let previous = guard
            .as_ref()
            .ok_or(ActorAttestationError::StorageUnavailable)?
            .generation;
        let candidate = verify_owner_signed_issuer_manifest(
            signed_manifest,
            &self.root,
            previous,
            trusted_now_unix,
        )?;
        let generation = candidate.generation;
        if self
            .trusted_store
            .compare_and_commit(&self.root, previous, generation)
            .is_err()
        {
            *guard = None;
            return Err(ActorAttestationError::StorageUnavailable);
        }
        *guard = Some(candidate);
        Ok(generation)
    }

    /// A read lock linearizes with durable-commit + activation, and denies
    /// after an ambiguous store failure or writer panic. No remote request
    /// can choose a stale manifest or trust-store generation.
    pub fn verify_actor_and_consume(
        &self,
        proof: &[u8],
        expected: &ExpectedActorRequest<'_>,
        storage: &Storage,
    ) -> Result<VerifiedPrincipal, ActorAttestationError> {
        let guard = self
            .active
            .read()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        let active = guard
            .as_ref()
            .ok_or(ActorAttestationError::StorageUnavailable)?;
        active.verify_and_consume(proof, expected, storage, active.generation)
    }

    pub fn active_generation(&self) -> Result<u64, ActorAttestationError> {
        let guard = self
            .active
            .read()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        guard
            .as_ref()
            .map(|active| active.generation)
            .ok_or(ActorAttestationError::StorageUnavailable)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::sync::Mutex;

    struct UnitTestStore {
        root: VerifyingKey,
        committed: Mutex<u64>,
    }
    impl TrustedOwnerPolicyStore for UnitTestStore {
        fn read_committed(&self) -> Result<TrustedOwnerPolicyState, ActorAttestationError> {
            Ok(TrustedOwnerPolicyState {
                root: self.root,
                committed_generation: *self.committed.lock().unwrap(),
            })
        }
        fn compare_and_commit(
            &self,
            root: &VerifyingKey,
            expected: u64,
            next: u64,
        ) -> Result<(), ActorAttestationError> {
            let mut value = self.committed.lock().unwrap();
            if &self.root != root || *value != expected || next <= expected {
                return Err(ActorAttestationError::StorageUnavailable);
            }
            *value = next;
            Ok(())
        }
    }

    #[test]
    fn poisoned_owner_policy_lock_always_denies_instead_of_recovering() {
        let owner = SigningKey::from_bytes(&[88; 32]);
        let payload = json!({
            "contract_version": "owner-issuer-manifest/v1",
            "generation": 12,
            "issued_at": 1799999980,
            "expires_at": 1800000200,
            "keys": [{
                "issuer": "known-issuer",
                "key_id": "known-id",
                "public_key": URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[91;32]).verifying_key().as_bytes()),
                "valid_from_unix": 1799999900,
                "valid_until_unix": 1800000400,
                "state": "active"
            }]
        });
        let mut signed_bytes = b"kicad-mcp/owner-issuer-manifest/v1\n".to_vec();
        signed_bytes.extend_from_slice(&serde_json_canonicalizer::to_vec(&payload).unwrap());
        let signature = owner.sign(&signed_bytes);
        let envelope = serde_json_canonicalizer::to_vec(&json!({
            "payload":payload,
            "signature":URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }))
        .unwrap();
        let store = Arc::new(UnitTestStore {
            root: owner.verifying_key(),
            committed: Mutex::new(12),
        });
        let authority =
            OwnerPolicyAuthority::from_trusted_store(store, &envelope, 1800000000).unwrap();

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _write = authority.active.write().unwrap();
            panic!("intentional test-only poisoned exclusive owner policy lock");
        }));
        assert!(panic_result.is_err());
        assert_eq!(
            authority.active_generation(),
            Err(ActorAttestationError::StorageUnavailable)
        );
        assert_eq!(
            authority.verify_candidate_commit_and_activate(&envelope, 1800000000),
            Err(ActorAttestationError::StorageUnavailable)
        );
    }
}
