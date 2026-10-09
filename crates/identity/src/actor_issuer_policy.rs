//! Explicit owner-pinned actor attestation verifier trust. Offline only.
//! Caller-supplied assertion fields select ONLY among preapproved public
//! keys; they never add key material, algorithms, or an external JWKS URL.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;

use crate::actor_attestation::{
    verify_and_consume_actor_assertion, ActorAttestationError, ExpectedActorRequest,
    PinnedActorIssuer, SignedActorClaims,
};
use companion_core::VerifiedPrincipal;
use companion_storage::Storage;

const MAX_PINNED_KEYS: usize = 32;
const MAX_ASSERTION_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorIssuerKeyState {
    /// Owner approved key for a bounded interval, including rotation overlap.
    Active,
    /// Explicitly revoked, including the remainder of its original validity.
    Revoked,
}

pub struct OwnerPinnedActorKey {
    pub issuer: String,
    pub key_id: String,
    pub public_key: VerifyingKey,
    pub valid_from_unix: i64,
    pub valid_until_unix: i64,
    pub state: ActorIssuerKeyState,
}

pub struct OwnerPinnedActorIssuers {
    keys: Vec<OwnerPinnedActorKey>,
}

fn allowed_id(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
}

impl OwnerPinnedActorIssuers {
    /// Fail closed on invalid policy, duplicate (issuer, key_id) or reused
    /// public keys. An issuer cannot silently inherit another issuer's key.
    /// A policy snapshot must be assembled from *local owner-approved state*.
    /// This module deliberately has no file/JWKS/network loader or signer.
    pub fn new(keys: Vec<OwnerPinnedActorKey>) -> Result<Self, ActorAttestationError> {
        if keys.is_empty() || keys.len() > MAX_PINNED_KEYS {
            return Err(ActorAttestationError::Invalid);
        }
        let mut names = HashSet::new();
        let mut public_keys = HashSet::new();
        for key in &keys {
            let valid_identifiers = allowed_id(&key.issuer) && allowed_id(&key.key_id);
            let valid_window =
                key.valid_from_unix > 0 && key.valid_until_unix > key.valid_from_unix;
            if !valid_identifiers || !valid_window {
                return Err(ActorAttestationError::Invalid);
            }
            let unique_name = names.insert((key.issuer.clone(), key.key_id.clone()));
            let unique_public_key = public_keys.insert(key.public_key.to_bytes());
            if !unique_name || !unique_public_key {
                return Err(ActorAttestationError::Invalid);
            }
        }
        Ok(Self { keys })
    }

    /// Deliberately non-oracular: revoked keys, unknown issuers and
    /// invalid time windows produce the SAME Invalid error. Distinguishing
    /// them to a future remote caller would reveal the owner's trust
    /// configuration or key revocation state. Owner-only diagnostics must
    /// be designed separately, with redaction and authenticated access.
    ///
    /// Untrusted issuer/key IDs are lookup *hints*, not authorization.
    /// Time validity is measured against BOTH actual verified assertion
    /// times and trusted Gateway local time; revoked keys are never allowed.
    pub fn verify_and_consume(
        &self,
        proof_bytes: &[u8],
        expected: &ExpectedActorRequest<'_>,
        storage: &Storage,
    ) -> Result<VerifiedPrincipal, ActorAttestationError> {
        use ActorAttestationError::Invalid;
        if proof_bytes.len() > MAX_ASSERTION_BYTES {
            return Err(Invalid);
        }
        let proof: SignedActorClaims = serde_json::from_slice(proof_bytes).map_err(|_| Invalid)?;
        let claims = &proof.payload;
        let key = self
            .keys
            .iter()
            .find(|key| key.issuer == claims.issuer && key.key_id == claims.key_id)
            .ok_or(Invalid)?;
        if key.state != ActorIssuerKeyState::Active
            || claims.issued_at < key.valid_from_unix
            || claims.expires_at > key.valid_until_unix
            || expected.now_unix < key.valid_from_unix
            || expected.now_unix > key.valid_until_unix
        {
            return Err(Invalid);
        }
        verify_and_consume_actor_assertion(
            proof_bytes,
            &PinnedActorIssuer {
                issuer: key.issuer.clone(),
                key_id: key.key_id.clone(),
                public_key: key.public_key,
            },
            expected,
            storage,
        )
    }
}
