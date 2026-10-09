//! Offline-only, fail-closed verifier for candidate remote actor proofs.
//!
//! No relay or HTTP endpoint invokes this module. It cannot grant access.
//! The expected context MUST come from the authenticated local Gateway,
//! never from the incoming actor assertion.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_core::{PrincipalVerificationSource, VerifiedPrincipal};
use companion_storage::{ActorReplayError, ActorReplayEvidence, IssuedActorChallenge, Storage};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"kicad-mcp/actor-attestation/v1\n";
const MAX_ASSERTION_BYTES: usize = 8192;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_LIFETIME_SECONDS: i64 = 60;
const MAX_CLOCK_SKEW_SECONDS: i64 = 15;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorClaims {
    pub contract_version: String,
    pub issuer: String,
    pub key_id: String,
    pub alg: String,
    pub subject: String,
    pub client_id: String,
    pub audience: String,
    pub resource: String,
    pub device_id: String,
    pub workspace_id: String,
    pub message_id: String,
    pub correlation_id: String,
    pub request_sha256: String,
    /// Signed digest of the locally authenticated transport channel binding.
    pub channel_binding_sha256: String,
    pub gateway_challenge: String,
    pub connection_epoch: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedActorClaims {
    pub payload: ActorClaims,
    pub signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalOperation {
    method: String,
    tool: String,
    arguments: serde_json::Value,
    device_id: String,
    workspace_id: String,
    message_id: String,
    correlation_id: String,
    effect: String,
}

/// All context fields must be supplied from authenticated local state.
pub struct ExpectedActorRequest<'a> {
    pub canonical_operation: &'a [u8],
    pub device_id: &'a str,
    pub workspace_id: &'a str,
    pub message_id: &'a str,
    pub correlation_id: &'a str,
    pub challenge: &'a str,
    pub challenge_issued_at: i64,
    pub challenge_expires_at: i64,
    pub connection_epoch: &'a str,
    pub transport_binding: &'a str,
    pub audience: &'a str,
    pub resource: &'a str,
    pub now_unix: i64,
}

/// Authenticated device channel parameters are supplied ONLY by Gateway's
/// native transport after device proof, never by the untrusted relay.
pub struct LocalGatewayChannel<'a> {
    pub device_id: &'a str,
    pub workspace_id: &'a str,
    pub connection_epoch: &'a str,
    pub transport_binding: &'a str,
    pub now_unix: i64,
}

#[derive(Clone)]
pub struct GatewayIssuedChallenge {
    pub challenge: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

fn issue_binding(
    challenge: &str,
    device_id: &str,
    workspace_id: &str,
    connection_epoch: &str,
    transport_binding: &str,
    issued_at: i64,
    expires_at: i64,
) -> IssuedActorChallenge {
    IssuedActorChallenge {
        challenge_hash: fingerprint(&["gateway-actor-challenge-v1", challenge]),
        device_hash: fingerprint(&["device", device_id]),
        workspace_hash: fingerprint(&["workspace", workspace_id]),
        epoch_hash: fingerprint(&["epoch", connection_epoch]),
        channel_hash: fingerprint(&["channel", transport_binding]),
        issued_at,
        expires_at,
    }
}

/// Generate 256 bits of OS entropy and persist a one-time, channel-bound
/// challenge before returning it. No raw challenge is persisted in SQLite.
/// Caller MUST provide trusted local channel identifiers and wall-clock time.
pub fn issue_gateway_challenge(
    storage: &Storage,
    local: &LocalGatewayChannel<'_>,
) -> Result<GatewayIssuedChallenge, ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if !safe_claim(local.device_id)
        || !safe_claim(local.workspace_id)
        || !safe_claim(local.connection_epoch)
        || !safe_claim(local.transport_binding)
        || local.now_unix <= 0
    {
        return Err(Invalid);
    }
    let expires_at = local.now_unix.checked_add(60).ok_or(Invalid)?;
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ActorAttestationError::StorageUnavailable)?;
    let challenge = URL_SAFE_NO_PAD.encode(bytes);
    storage
        .register_actor_challenge(&issue_binding(
            &challenge,
            local.device_id,
            local.workspace_id,
            local.connection_epoch,
            local.transport_binding,
            local.now_unix,
            expires_at,
        ))
        .map_err(error_from_replay)?;
    Ok(GatewayIssuedChallenge {
        challenge,
        issued_at: local.now_unix,
        expires_at,
    })
}

/// A local, owner-pinned independently trusted public signing key.
pub struct PinnedActorIssuer {
    pub issuer: String,
    pub key_id: String,
    pub public_key: VerifyingKey,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActorAttestationError {
    #[error("remote actor proof invalid or mismatched")]
    Invalid,
    #[error("remote actor proof rejected as replay")]
    Replay,
    #[error("durable actor proof storage unavailable")]
    StorageUnavailable,
}

fn safe_claim(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

fn fingerprint(parts: &[&str]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().into()
}

fn error_from_replay(error: ActorReplayError) -> ActorAttestationError {
    match error {
        ActorReplayError::Replay => ActorAttestationError::Replay,
        ActorReplayError::Unavailable | ActorReplayError::Invalid => {
            ActorAttestationError::StorageUnavailable
        }
    }
}

// Keep validation stages separate and auditable. No single stage can
// convert untrusted claims into identity without signature + replay gates.
fn check_signer_policy(
    claims: &ActorClaims,
    policy: &PinnedActorIssuer,
) -> Result<(), ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if claims.contract_version != "actor-attestation/v1"
        || claims.alg != "Ed25519"
        || claims.issuer != policy.issuer
        || claims.key_id != policy.key_id
        || !safe_claim(&policy.issuer)
        || !safe_claim(&policy.key_id)
    {
        return Err(Invalid);
    }
    Ok(())
}

fn check_local_binding(
    claims: &ActorClaims,
    expected: &ExpectedActorRequest<'_>,
) -> Result<(), ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if claims.audience != expected.audience
        || claims.resource != expected.resource
        || claims.device_id != expected.device_id
        || claims.workspace_id != expected.workspace_id
        || claims.message_id != expected.message_id
        || claims.correlation_id != expected.correlation_id
        || claims.gateway_challenge != expected.challenge
        || claims.connection_epoch != expected.connection_epoch
    {
        return Err(Invalid);
    }
    Ok(())
}

fn check_claim_shapes(
    claims: &ActorClaims,
    expected: &ExpectedActorRequest<'_>,
) -> Result<(), ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if !safe_claim(&claims.subject)
        || !safe_claim(&claims.client_id)
        || !safe_claim(&claims.nonce)
        || !safe_claim(&claims.gateway_challenge)
        || !safe_claim(&claims.connection_epoch)
        || !safe_claim(expected.transport_binding)
        || !safe_claim(&claims.message_id)
        || !safe_claim(&claims.correlation_id)
        || !safe_claim(&claims.device_id)
        || !safe_claim(&claims.workspace_id)
    {
        return Err(Invalid);
    }
    Ok(())
}

fn check_freshness(claims: &ActorClaims, now_unix: i64) -> Result<(), ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if claims.issued_at > now_unix.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        || claims.expires_at < now_unix
        || claims.expires_at <= claims.issued_at
        || claims.expires_at.saturating_sub(claims.issued_at) > MAX_LIFETIME_SECONDS
    {
        return Err(Invalid);
    }
    Ok(())
}

fn check_canonical_request(
    claims: &ActorClaims,
    expected: &ExpectedActorRequest<'_>,
) -> Result<(), ActorAttestationError> {
    use ActorAttestationError::Invalid;
    // Caller must already have validated the operation's effective policy.
    // These parsing checks never enable tools/call.
    let operation: CanonicalOperation =
        serde_json::from_slice(expected.canonical_operation).map_err(|_| Invalid)?;
    if serde_json_canonicalizer::to_vec(&operation).map_err(|_| Invalid)?
        != expected.canonical_operation
        || operation.method != "tools/call"
        || !safe_claim(&operation.tool)
        || !safe_claim(&operation.effect)
        || !operation.arguments.is_object()
        || operation.device_id != claims.device_id
        || operation.workspace_id != claims.workspace_id
        || operation.message_id != claims.message_id
        || operation.correlation_id != claims.correlation_id
    {
        return Err(Invalid);
    }
    let request_digest = Sha256::digest(expected.canonical_operation);
    let expected_digest: String = request_digest.iter().map(|b| format!("{b:02x}")).collect();
    let channel_digest = Sha256::digest(expected.transport_binding.as_bytes());
    let channel_hex: String = channel_digest.iter().map(|b| format!("{b:02x}")).collect();
    if claims.request_sha256 != expected_digest || claims.channel_binding_sha256 != channel_hex {
        return Err(Invalid);
    }
    Ok(())
}

/// Verifies signature and exact request/channel binding, THEN atomically
/// consumes replay evidence in durable SQLite before returning any identity.
/// It does not perform local grant, workspace, risk or audit authorization.
pub fn verify_and_consume_actor_assertion(
    proof_bytes: &[u8],
    policy: &PinnedActorIssuer,
    expected: &ExpectedActorRequest<'_>,
    storage: &Storage,
) -> Result<VerifiedPrincipal, ActorAttestationError> {
    use ActorAttestationError::Invalid;
    if proof_bytes.len() > MAX_ASSERTION_BYTES
        || expected.canonical_operation.len() > MAX_REQUEST_BYTES
    {
        return Err(Invalid);
    }
    let proof: SignedActorClaims = serde_json::from_slice(proof_bytes).map_err(|_| Invalid)?;
    // Exact JCS bytes reject duplicate keys, whitespace, reordered fields,
    // ambiguous encodings and noncanonical numeric serialization.
    if serde_json_canonicalizer::to_vec(&proof).map_err(|_| Invalid)? != proof_bytes {
        return Err(Invalid);
    }
    let claims = &proof.payload;
    check_signer_policy(claims, policy)?;
    check_local_binding(claims, expected)?;
    check_claim_shapes(claims, expected)?;
    check_freshness(claims, expected.now_unix)?;
    if claims.issued_at
        < expected
            .challenge_issued_at
            .saturating_sub(MAX_CLOCK_SKEW_SECONDS)
        || claims.expires_at
            > expected
                .challenge_expires_at
                .saturating_add(MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(Invalid);
    }
    check_canonical_request(claims, expected)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .map_err(|_| Invalid)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| Invalid)?;
    let canonical_payload = serde_json_canonicalizer::to_vec(claims).map_err(|_| Invalid)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + canonical_payload.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&canonical_payload);
    policy
        .public_key
        .verify_strict(&message, &signature)
        .map_err(|_| Invalid)?;

    let issuer = claims.issuer.as_str();
    storage
        .consume_issued_actor_proof(
            &ActorReplayEvidence {
                issuer,
                nonce_hash: fingerprint(&[issuer, &claims.nonce]),
                message_hash: fingerprint(&[issuer, &claims.message_id]),
                challenge_hash: fingerprint(&[
                    issuer,
                    &claims.device_id,
                    &claims.connection_epoch,
                    &claims.gateway_challenge,
                ]),
                correlation_hash: fingerprint(&[
                    issuer,
                    &claims.subject,
                    &claims.device_id,
                    &claims.connection_epoch,
                    &claims.correlation_id,
                ]),
                expires_at: claims.expires_at,
            },
            &issue_binding(
                expected.challenge,
                expected.device_id,
                expected.workspace_id,
                expected.connection_epoch,
                expected.transport_binding,
                expected.challenge_issued_at,
                expected.challenge_expires_at,
            ),
            expected.now_unix,
        )
        .map_err(error_from_replay)?;

    let binding = fingerprint(&[
        issuer,
        &claims.subject,
        &claims.client_id,
        &claims.device_id,
        expected.transport_binding,
    ]);
    let transport_binding = binding.iter().map(|b| format!("{b:02x}")).collect();
    Ok(VerifiedPrincipal {
        issuer: claims.issuer.clone(),
        subject: claims.subject.clone(),
        account_or_tenant: None,
        client_or_agent: Some(claims.client_id.clone()),
        authentication_strength: "signed_request_bound_ed25519".into(),
        verification_source: PrincipalVerificationSource::AuthenticatedTransport,
        transport_binding,
    })
}
