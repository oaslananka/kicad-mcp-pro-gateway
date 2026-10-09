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
/// A failed or panicking write poisons the lock: ALL subsequent calls deny.
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
