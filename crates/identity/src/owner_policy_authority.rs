//! OFFLINE-ONLY serialized owner policy activation, NOT durable provisioning.
//!
//! The owner root and the initial high-water generation must come from
//! independently authenticated local state, never the relay or manifest.
//! The current in-memory generation is LOST on restart, so this module
//! cannot establish owner trust or provide cross-restart rollback safety.

use std::sync::RwLock;

use companion_core::VerifiedPrincipal;
use companion_storage::Storage;
use ed25519_dalek::VerifyingKey;

use crate::{
    actor_attestation::{ActorAttestationError, ExpectedActorRequest},
    owner_manifest::{verify_owner_signed_issuer_manifest, VerifiedOwnerIssuerManifest},
};

/// Only an owner-trusted signer can update the immutable policy snapshot.
/// A read lock remains held through entire proof validation so an update
/// cannot revoke keys mid-verification and then let an old proof return.
/// Ordinary rejected updates leave the lock usable and policy unchanged.
/// Only a panic during an exclusive write poisons the lock; in that case
/// ALL later reads/writes deny instead of recovering untrusted state.
pub struct OwnerPolicyAuthority {
    root: VerifyingKey,
    active: RwLock<VerifiedOwnerIssuerManifest>,
}

impl OwnerPolicyAuthority {
    /// Source-only constructor. The root and persisted generation floor
    /// MUST have been loaded from an authenticated anti-rollback authority.
    /// Never bootstrap with a caller-supplied key or untrusted floor=0.
    pub fn from_trusted_local_state(
        root: VerifyingKey,
        initial_manifest: &[u8],
        trusted_prior_generation: u64,
        trusted_now_unix: i64,
    ) -> Result<Self, ActorAttestationError> {
        let active = verify_owner_signed_issuer_manifest(
            initial_manifest,
            &root,
            trusted_prior_generation,
            trusted_now_unix,
        )?;
        Ok(Self {
            root,
            active: RwLock::new(active),
        })
    }

    /// Writer lock serializes concurrent updates; stale, tampered, revoked
    /// root or lower/equal generation submissions cannot replace state.
    /// This is NOT durable commit: a future integration must persist the
    /// owner-controlled generation BEFORE exposing the new policy.
    pub fn verify_candidate_and_replace_in_memory(
        &self,
        signed_manifest: &[u8],
        trusted_now_unix: i64,
    ) -> Result<u64, ActorAttestationError> {
        let mut guard = self
            .active
            .write()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        let candidate = verify_owner_signed_issuer_manifest(
            signed_manifest,
            &self.root,
            guard.generation,
            trusted_now_unix,
        )?;
        let generation = candidate.generation;
        *guard = candidate;
        Ok(generation)
    }

    /// No untrusted request may supply an old owner policy generation.
    /// A read lock linearizes with policy replacement, including revocation.
    /// This remains an unused offline verifier, not a transport/tool grant.
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
        guard.verify_and_consume(proof, expected, storage, guard.generation)
    }

    pub fn active_generation(&self) -> Result<u64, ActorAttestationError> {
        let guard = self
            .active
            .read()
            .map_err(|_| ActorAttestationError::StorageUnavailable)?;
        Ok(guard.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

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
        let authority = OwnerPolicyAuthority::from_trusted_local_state(
            owner.verifying_key(),
            &envelope,
            11,
            1800000000,
        )
        .unwrap();

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
            authority.verify_candidate_and_replace_in_memory(&envelope, 1800000000),
            Err(ActorAttestationError::StorageUnavailable)
        );
    }
}
