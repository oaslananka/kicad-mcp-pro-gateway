//! Source-only proof of owner approval for actor issuer verification keys.
//!
//! The owner-signature root MUST be provisioned independently through an
//! authenticated local channel. This module is NOT a file loader, signer,
//! OAuth verifier, transport authenticator or authorization engine.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    actor_attestation::ActorAttestationError,
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

/// Trusted and validated owner-signed key list. The caller MUST remember
/// generation in independently trusted local state before activating this
/// snapshot. Without such persistence, the anti-rollback floor is not durable.
pub struct VerifiedOwnerIssuerManifest {
    pub generation: u64,
    pub issuers: OwnerPinnedActorIssuers,
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
    use ActorAttestationError::Invalid;
    if bytes.is_empty()
        || bytes.len() > MAX_SIGNED_MANIFEST_BYTES
        || trusted_now_unix <= 0
        || minimum_generation_exclusive >= MAX_GENERATION
    {
        return Err(Invalid);
    }

    // Typed parsing rejects duplicate keys, unknown fields and unsupported
    // wire values. Exact re-canonicalization rejects ambiguous serialization
    // and noncanonical input *before* an owner signature may be accepted.
    let signed: SignedManifest = serde_json::from_slice(bytes).map_err(|_| Invalid)?;
    if serde_json_canonicalizer::to_vec(&signed).map_err(|_| Invalid)? != bytes {
        return Err(Invalid);
    }
    let payload = &signed.payload;
    if payload.contract_version != "owner-issuer-manifest/v1"
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

    let sig_bytes = canonical_b64(&signed.signature, 64)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| Invalid)?;
    let canonical_payload = serde_json_canonicalizer::to_vec(payload).map_err(|_| Invalid)?;
    let mut signed_message = Vec::with_capacity(DOMAIN.len() + canonical_payload.len());
    signed_message.extend_from_slice(DOMAIN);
    signed_message.extend_from_slice(&canonical_payload);
    owner_root
        .verify_strict(&signed_message, &signature)
        .map_err(|_| Invalid)?;

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

    let issuers = OwnerPinnedActorIssuers::new(keys)?;
    Ok(VerifiedOwnerIssuerManifest {
        generation: payload.generation,
        issuers,
    })
}
