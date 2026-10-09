//! Source-only proof of owner approval for actor issuer verification keys.
//!
//! The owner-signature root MUST be provisioned independently through an
//! authenticated local channel. This module is NOT a file loader, signer,
//! OAuth verifier, transport authenticator or authorization engine.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_core::VerifiedPrincipal;
use companion_storage::Storage;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    actor_attestation::{ActorAttestationError, ExpectedActorRequest},
    actor_issuer_policy::{ActorIssuerKeyState, OwnerPinnedActorIssuers, OwnerPinnedActorKey},
};

const DOMAIN: &[u8] = b"kicad-mcp/owner-issuer-manifest/v1\n";
const MAX_SIGNED_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_GENERATION: u64 = 9_007_199_254_740_991; // I-JSON safe integer
const MAX_MANIFEST_LIFETIME: i64 = 30 * 24 * 60 * 60;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    payload: ManifestPayload,
    signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestPayload {
    contract_version: String,
    generation: u64,
    issued_at: i64,
    expires_at: i64,
    keys: Vec<ManifestKey>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestKey {
    issuer: String,
    key_id: String,
    public_key: String,
    valid_from_unix: i64,
    valid_until_unix: i64,
    state: ManifestKeyState,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManifestKeyState {
    Active,
    Revoked,
}

/// Trusted snapshot with a private issuer policy: consumers cannot access
/// the keys without rechecking the manifest expiry on EVERY proof.
pub struct VerifiedOwnerIssuerManifest {
    pub generation: u64,
    issued_at: i64,
    expires_at: i64,
    issuers: OwnerPinnedActorIssuers,
}

impl VerifiedOwnerIssuerManifest {
    /// The caller supplies Gateway-local authenticated context AND the
    /// current generation from independently trusted local owner-policy
    /// state. Old in-memory snapshots are refused as soon as that generation
    /// advances, including when an owner has revoked an issuer.
    /// Signature, challenge, request, durable replay and local time are
    /// verified by the underlying issuer policy after these gates.
    pub fn verify_and_consume(
        &self,
        proof: &[u8],
        expected: &ExpectedActorRequest<'_>,
        storage: &Storage,
        trusted_active_generation: u64,
    ) -> Result<VerifiedPrincipal, ActorAttestationError> {
        if self.generation != trusted_active_generation
            || expected.now_unix < self.issued_at
            || expected.now_unix >= self.expires_at
        {
            return Err(ActorAttestationError::Invalid);
        }
        self.issuers.verify_and_consume(proof, expected, storage)
    }
}

fn canonical_b64(s: &str, expected_len: usize) -> Result<Vec<u8>, ActorAttestationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ActorAttestationError::Invalid)?;
    if bytes.len() != expected_len || URL_SAFE_NO_PAD.encode(&bytes) != s {
        return Err(ActorAttestationError::Invalid);
    }
    Ok(bytes)
}

fn parse_canonical_manifest(bytes: &[u8]) -> Result<SignedManifest, ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if bytes.is_empty() || bytes.len() > MAX_SIGNED_MANIFEST_BYTES {
        return Err(Invalid);
    }
    // Typed parsing rejects duplicate keys, unknown fields and unsupported
    // wire values; exact re-canonicalization forbids ambiguous encoding.
    let signed: SignedManifest = serde_json::from_slice(bytes).map_err(|_| Invalid)?;
    if serde_json_canonicalizer::to_vec(&signed).map_err(|_| Invalid)? != bytes {
        return Err(Invalid);
    }
    Ok(signed)
}

fn validate_manifest_freshness(
    payload: &ManifestPayload,
    minimum_generation_exclusive: u64,
    trusted_now_unix: i64,
) -> Result<(), ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if trusted_now_unix <= 0
        || minimum_generation_exclusive >= MAX_GENERATION
        || payload.contract_version != "owner-issuer-manifest/v1"
        || payload.generation == 0
        || payload.generation > MAX_GENERATION
        || payload.generation <= minimum_generation_exclusive
        || payload.issued_at <= 0
        || payload.issued_at > trusted_now_unix
        || payload.expires_at <= trusted_now_unix
        || payload.expires_at <= payload.issued_at
        || payload.expires_at.saturating_sub(payload.issued_at) > MAX_MANIFEST_LIFETIME
        || payload.keys.is_empty()
        || payload.keys.len() > 32
    {
        return Err(Invalid);
    }
    Ok(())
}

fn verify_owner_signature(
    signed: &SignedManifest,
    owner_root: &VerifyingKey,
) -> Result<(), ActorAttestationError> {
    use ActorAttestationError::Invalid;
    let sig_bytes = canonical_b64(&signed.signature, 64)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| Invalid)?;
    let canonical_payload =
        serde_json_canonicalizer::to_vec(&signed.payload).map_err(|_| Invalid)?;
    let mut signed_message = Vec::with_capacity(DOMAIN.len() + canonical_payload.len());
    signed_message.extend_from_slice(DOMAIN);
    signed_message.extend_from_slice(&canonical_payload);
    owner_root
        .verify_strict(&signed_message, &signature)
        .map_err(|_| Invalid)
}

fn owner_approved_issuer_keys(
    payload: &ManifestPayload,
    owner_root: &VerifyingKey,
) -> Result<OwnerPinnedActorIssuers, ActorAttestationError> {
    use ActorAttestationError::Invalid;
    let mut keys = Vec::with_capacity(payload.keys.len());
    for k in &payload.keys {
        let pub_bytes = canonical_b64(&k.public_key, 32)?;
        let pub_bytes: [u8; 32] = pub_bytes.try_into().map_err(|_| Invalid)?;
        let public_key = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| Invalid)?;
        // Owner manifest roots and actor issuer signers must be independent.
        if public_key.as_bytes() == owner_root.as_bytes() {
            return Err(Invalid);
        }
        let state = match k.state {
            ManifestKeyState::Active => ActorIssuerKeyState::Active,
            ManifestKeyState::Revoked => ActorIssuerKeyState::Revoked,
        };
        keys.push(OwnerPinnedActorKey {
            issuer: k.issuer.clone(),
            key_id: k.key_id.clone(),
            public_key,
            valid_from_unix: k.valid_from_unix,
            valid_until_unix: k.valid_until_unix,
            state,
        });
    }
    OwnerPinnedActorIssuers::new(keys)
}

/// Verify strict RFC 8785 JCS, Ed25519 signature under an independently
/// owner-provisioned root, bounded time and strictly increasing generation.
/// The passed minimum generation is a TRUSTED persisted value, never supplied
/// from the incoming manifest, relay, OAuth caller or asserted actor.
pub fn verify_owner_signed_issuer_manifest(
    bytes: &[u8],
    owner_root: &VerifyingKey,
    minimum_generation_exclusive: u64,
    trusted_now_unix: i64,
) -> Result<VerifiedOwnerIssuerManifest, ActorAttestationError> {
    let signed = parse_canonical_manifest(bytes)?;
    validate_manifest_freshness(
        &signed.payload,
        minimum_generation_exclusive,
        trusted_now_unix,
    )?;
    verify_owner_signature(&signed, owner_root)?;
    let issuers = owner_approved_issuer_keys(&signed.payload, owner_root)?;
    Ok(VerifiedOwnerIssuerManifest {
        generation: signed.payload.generation,
        issued_at: signed.payload.issued_at,
        expires_at: signed.payload.expires_at,
        issuers,
    })
}
