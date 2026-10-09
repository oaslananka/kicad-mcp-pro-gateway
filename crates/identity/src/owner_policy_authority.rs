//! OFFLINE-ONLY owner policy activation contract, NO OS trust provider.
//!
//! A real provider MUST already authenticate a separately provisioned owner
//! root and make its policy generation monotonic and non-rollbackable across
//! process/database restart. This module contains NO such implementation.

use std::sync::{Arc, RwLock};

use companion_core::VerifiedPrincipal;
use companion_storage::Storage;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::{
    actor_attestation::{ActorAttestationError, ExpectedActorRequest},
    owner_manifest::{verify_owner_signed_issuer_manifest, VerifiedOwnerIssuerManifest},
};

/// Provenance must come from a future independently authenticated local
/// owner trust authority, never untrusted caller, relay or manifest values.
pub struct TrustedOwnerPolicyState {
    pub root: VerifyingKey,
    pub committed_generation: u64,
    /// SHA-256 of the exact canonical, owner-signed manifest envelope.
    pub committed_manifest_sha256: [u8; 32],
}

/// Source-only commitment v1 contract; see docs/security/owner-policy-commitment-v1.md.
/// Contract for a separately vetted OS-owner-bound, monotonic durable store.
/// THIS CRATE PROVIDES NO PRODUCTION IMPLEMENTATION.
///
/// compare_and_commit MUST be process-/machine-wide atomic, protect the
/// owner root identity, reject stale expected generation + manifest digest,
/// and atomically bind the next generation to the exact signed manifest digest.
/// Return Ok ONLY AFTER durable commit. A crash or ambiguous commit outcome cannot
/// silently substitute an older trust snapshot or a different owner-signed
/// manifest with the same generation on the next process boot. The actual
/// store must also exclude noncooperating cross-process writers during use.
pub trait TrustedOwnerPolicyStore: Send + Sync {
    fn read_committed(&self) -> Result<TrustedOwnerPolicyState, ActorAttestationError>;

    fn compare_and_commit(
        &self,
        pinned_owner_root: &VerifyingKey,
        expected_generation: u64,
        expected_manifest_sha256: &[u8; 32],
        next_generation: u64,
        next_manifest_sha256: &[u8; 32],
    ) -> Result<(), ActorAttestationError>;
}

/// Fail-closed owner policy reader/writer synchronization.
///
/// A rejected manifest leaves the current trusted policy usable. A failed
/// or ambiguous durable commit permanently disables this authority's actor
/// verification for its remaining lifetime, even if storage later recovers.
/// Lock poisoning on writer panic also denies all later reads/writes.
struct ActivePolicy {
    manifest: VerifiedOwnerIssuerManifest,
    signed_manifest_sha256: [u8; 32],
}

pub struct OwnerPolicyAuthority {
    root: VerifyingKey,
    trusted_store: Arc<dyn TrustedOwnerPolicyStore>,
    active: RwLock<Option<ActivePolicy>>,
}

impl OwnerPolicyAuthority {
    /// No implicit TOFU bootstrap, no default generation=0, no fallback to
    /// caller/root-from-manifest: the trusted store must already contain
    /// a valid owner root, strictly positive active committed generation, and
    /// the SHA-256 of the exact committed signed manifest bytes.
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
        let signed_manifest_sha256: [u8; 32] = Sha256::digest(active_manifest).into();
        if active.generation != committed.committed_generation
            || signed_manifest_sha256 != committed.committed_manifest_sha256
        {
            return Err(ActorAttestationError::Invalid);
        }
        // The trusted store may have changed while the signature/JCS parser
        // ran. Recheck root AND generation immediately before publishing an
        // active authority; the store contract must make each read an
        // atomic, version-bound snapshot. External writers must also honor
        // the provider's cross-process serialization requirements.
        let latest = trusted_store.read_committed()?;
        if latest.root != committed.root
            || latest.committed_generation != committed.committed_generation
            || latest.committed_manifest_sha256 != committed.committed_manifest_sha256
        {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        Ok(Self {
            root: committed.root,
            trusted_store,
            active: RwLock::new(Some(ActivePolicy {
                manifest: active,
                signed_manifest_sha256,
            })),
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
            .manifest
            .generation;
        let expected_sha256 = guard
            .as_ref()
            .ok_or(ActorAttestationError::StorageUnavailable)?
            .signed_manifest_sha256;
        let candidate = verify_owner_signed_issuer_manifest(
            signed_manifest,
            &self.root,
            previous,
            trusted_now_unix,
        )?;
        let generation = candidate.generation;
        let next_sha256: [u8; 32] = Sha256::digest(signed_manifest).into();
        if self
            .trusted_store
            .compare_and_commit(
                &self.root,
                previous,
                &expected_sha256,
                generation,
                &next_sha256,
            )
            .is_err()
        {
            *guard = None;
            return Err(ActorAttestationError::StorageUnavailable);
        }
        *guard = Some(ActivePolicy {
            manifest: candidate,
            signed_manifest_sha256: next_sha256,
        });
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
        active
            .manifest
            .verify_and_consume(proof, expected, storage, active.manifest.generation)
    }

    pub fn active_generation(&self) -> Result<u64, ActorAttestationError> {
        let guard = self
            .active
            .read()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        guard
            .as_ref()
            .map(|active| active.manifest.generation)
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
        committed: Mutex<(u64, [u8; 32])>,
    }
    impl TrustedOwnerPolicyStore for UnitTestStore {
        fn read_committed(&self) -> Result<TrustedOwnerPolicyState, ActorAttestationError> {
            let committed = self.committed.lock().unwrap();
            Ok(TrustedOwnerPolicyState {
                root: self.root,
                committed_generation: committed.0,
                committed_manifest_sha256: committed.1,
            })
        }
        fn compare_and_commit(
            &self,
            root: &VerifyingKey,
            expected: u64,
            expected_sha256: &[u8; 32],
            next: u64,
            next_sha256: &[u8; 32],
        ) -> Result<(), ActorAttestationError> {
            let mut value = self.committed.lock().unwrap();
            if &self.root != root
                || value.0 != expected
                || &value.1 != expected_sha256
                || next <= expected
            {
                return Err(ActorAttestationError::StorageUnavailable);
            }
            *value = (next, *next_sha256);
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
            committed: Mutex::new((12, Sha256::digest(&envelope).into())),
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
