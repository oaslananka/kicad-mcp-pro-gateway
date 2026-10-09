use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_identity::actor_attestation::{
    issue_gateway_challenge, verify_and_consume_actor_assertion, ActorAttestationError,
    ActorClaims, ExpectedActorRequest, GatewayIssuedChallenge, LocalGatewayChannel,
    PinnedActorIssuer, SignedActorClaims,
};
use companion_storage::Storage;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000;
const DOMAIN: &[u8] = b"kicad-mcp/actor-attestation/v1\n";

fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[31_u8; 32])
}

fn issuer() -> PinnedActorIssuer {
    PinnedActorIssuer {
        issuer: "trusted-issuer".into(),
        key_id: "owner-pinned-key".into(),
        public_key: issuer_key().verifying_key(),
    }
}

fn operation() -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&json!({
        "method": "tools/call",
        "tool": "schematic.inspect",
        "arguments": {"project":"example", "depth":2},
        "device_id": "dev_trusted",
        "workspace_id": "ws_trusted",
        "message_id": "message-1",
        "correlation_id": "correlation-1",
        "effect": "schematic.read"
    }))
    .unwrap()
}

fn context<'a>(request: &'a [u8], issued: &'a GatewayIssuedChallenge) -> ExpectedActorRequest<'a> {
    ExpectedActorRequest {
        canonical_operation: request,
        device_id: "dev_trusted",
        workspace_id: "ws_trusted",
        message_id: "message-1",
        correlation_id: "correlation-1",
        challenge: &issued.challenge,
        challenge_issued_at: issued.issued_at,
        challenge_expires_at: issued.expires_at,
        connection_epoch: "trusted-connection-1",
        transport_binding: "local-channel-binding-1",
        audience: "gateway-device",
        resource: "https://example.invalid/mcp",
        now_unix: NOW,
    }
}

fn minted(store: &Storage) -> GatewayIssuedChallenge {
    issue_gateway_challenge(
        store,
        &LocalGatewayChannel {
            device_id: "dev_trusted",
            workspace_id: "ws_trusted",
            connection_epoch: "trusted-connection-1",
            transport_binding: "local-channel-binding-1",
            now_unix: NOW - 20,
        },
    )
    .unwrap()
}

fn claims(request: &[u8], issued: &GatewayIssuedChallenge) -> ActorClaims {
    let hash = Sha256::digest(request);
    ActorClaims {
        contract_version: "actor-attestation/v1".into(),
        issuer: "trusted-issuer".into(),
        key_id: "owner-pinned-key".into(),
        alg: "Ed25519".into(),
        subject: "account-subject-1".into(),
        client_id: "authenticated-agent-1".into(),
        audience: "gateway-device".into(),
        resource: "https://example.invalid/mcp".into(),
        device_id: "dev_trusted".into(),
        workspace_id: "ws_trusted".into(),
        message_id: "message-1".into(),
        correlation_id: "correlation-1".into(),
        request_sha256: hash.iter().map(|v| format!("{v:02x}")).collect(),
        channel_binding_sha256: Sha256::digest(b"local-channel-binding-1")
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
        gateway_challenge: issued.challenge.clone(),
        connection_epoch: "trusted-connection-1".into(),
        issued_at: NOW - 10,
        expires_at: NOW + 30,
        nonce: "unique-nonce-1".into(),
    }
}

fn sign(payload: ActorClaims) -> Vec<u8> {
    let canonical = serde_json_canonicalizer::to_vec(&payload).unwrap();
    let mut signed_bytes = DOMAIN.to_vec();
    signed_bytes.extend_from_slice(&canonical);
    let signature = issuer_key().sign(&signed_bytes);
    serde_json_canonicalizer::to_vec(&SignedActorClaims {
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
    .unwrap()
}

fn verify(
    bytes: &[u8],
    ctx: &ExpectedActorRequest<'_>,
    store: &Storage,
) -> Result<companion_core::VerifiedPrincipal, ActorAttestationError> {
    verify_and_consume_actor_assertion(bytes, &issuer(), ctx, store)
}

#[test]
fn verified_actor_requires_real_signature_and_one_durable_consumption() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&store);
    let assertion = sign(claims(&request, &issued));
    let principal = verify(&assertion, &context(&request, &issued), &store).unwrap();
    assert_eq!(principal.issuer, "trusted-issuer");
    assert_eq!(principal.subject, "account-subject-1");
    assert_eq!(
        principal.client_or_agent.as_deref(),
        Some("authenticated-agent-1")
    );
    assert!(!principal.transport_binding.is_empty());
    assert_eq!(
        verify(&assertion, &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Replay)
    );
    drop(store);
    let reopened = Storage::open(dir.path()).unwrap();
    assert_eq!(
        verify(&assertion, &context(&request, &issued), &reopened).err(),
        Some(ActorAttestationError::Replay)
    );
}

#[test]
fn rejects_wrong_source_request_device_epoch_audience_and_modified_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&store);
    let proof = sign(claims(&request, &issued));

    let mut ctx = context(&request, &issued);
    ctx.device_id = "different-device";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request, &issued);
    ctx.connection_epoch = "reconnected-session";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request, &issued);
    ctx.audience = "attacker-service";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request, &issued);
    ctx.transport_binding = "foreign-authenticated-channel";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request, &issued);
    ctx.challenge = "attacker-challenge";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );

    let tampered = request
        .iter()
        .copied()
        .map(|b| if b == b'2' { b'9' } else { b })
        .collect::<Vec<_>>();
    assert_eq!(
        verify(&proof, &context(&tampered, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    assert!(
        verify(&proof, &context(&request, &issued), &store).is_ok(),
        "bad attempts cannot consume valid proof"
    );
}

#[test]
fn fail_closed_on_invalid_algorithm_signature_expiry_and_foreign_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&store);
    let base = claims(&request, &issued);
    let mut none = claims(&request, &issued);
    none.alg = "none".into();
    assert_eq!(
        verify(&sign(none), &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut expired = claims(&request, &issued);
    expired.expires_at = NOW - 1;
    assert_eq!(
        verify(&sign(expired), &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut future = claims(&request, &issued);
    future.issued_at = NOW + 40;
    future.expires_at = NOW + 50;
    assert_eq!(
        verify(&sign(future), &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut whitespace = claims(&request, &issued);
    whitespace.subject = "   ".into();
    assert_eq!(
        verify(&sign(whitespace), &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut foreign = claims(&request, &issued);
    foreign.issuer = "relay-itself".into();
    assert_eq!(
        verify(&sign(foreign), &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );

    let mut forged: SignedActorClaims = serde_json::from_slice(&sign(base)).unwrap();
    let foreign_key = SigningKey::from_bytes(&[22; 32]);
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&serde_json_canonicalizer::to_vec(&forged.payload).unwrap());
    forged.signature = URL_SAFE_NO_PAD.encode(foreign_key.sign(&signed).to_bytes());
    let bad = serde_json_canonicalizer::to_vec(&forged).unwrap();
    assert_eq!(
        verify(&bad, &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
}

#[test]
fn rejects_noncanonical_or_ambiguous_json_and_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let req = operation();
    let issued = minted(&store);
    let proof = sign(claims(&req, &issued));
    let spaced = [b"  ".as_slice(), proof.as_slice()].concat();
    assert_eq!(
        verify(&spaced, &context(&req, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let with_unknown =
        String::from_utf8(proof.clone())
            .unwrap()
            .replacen("{", "{\"unexpected\":true,", 1);
    assert_eq!(
        verify(with_unknown.as_bytes(), &context(&req, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let with_duplicate = String::from_utf8(proof.clone()).unwrap().replacen(
        "\"payload\":",
        "\"payload\":null,\"payload\":",
        1,
    );
    assert_eq!(
        verify(with_duplicate.as_bytes(), &context(&req, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let noncanonical_req = [b"\n".as_slice(), req.as_slice()].concat();
    assert_eq!(
        verify(&proof, &context(&noncanonical_req, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
}

#[test]
fn concurrent_nonce_replay_conflicts_atomically_and_storage_failure_denies() {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Storage::open(dir.path()).unwrap());
    let request = operation();
    let issued = minted(&store);
    let assertion = sign(claims(&request, &issued));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let shared = store.clone();
            let proof = assertion.clone();
            let req = request.clone();
            let issued = issued.clone();
            std::thread::spawn(move || verify(&proof, &context(&req, &issued), &shared))
        })
        .collect();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|x| x.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| x.as_ref().err() == Some(&ActorAttestationError::Replay))
            .count(),
        7
    );

    let mut changed = claims(&request, &issued);
    changed.nonce = "unused-nonce".into();
    changed.message_id = "unused-message".into();
    changed.gateway_challenge = "unused-challenge".into();
    changed.correlation_id = "unused-correlation".into();
    // As the signed IDs no longer match the local context, fail before DB.
    let changed_proof = sign(changed);
    assert_eq!(
        verify(&changed_proof, &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let conn = store.connection().lock().unwrap();
    conn.execute("DROP TABLE verified_actor_replay", [])
        .unwrap();
    drop(conn);
    let new_dir = tempfile::tempdir().unwrap();
    let clean_store = Storage::open(new_dir.path()).unwrap();
    let new_issued = minted(&clean_store);
    let fresh = sign(claims(&request, &new_issued));
    assert!(verify(&fresh, &context(&request, &new_issued), &clean_store).is_ok());
    // Storage failure with a valid previously consumed proof still denies.
    assert_eq!(
        verify(&fresh, &context(&request, &new_issued), &store).err(),
        Some(ActorAttestationError::StorageUnavailable)
    );
}

#[test]
fn challenge_is_generated_by_gateway_and_bound_to_persistent_local_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&store);
    let second = minted(&store);
    assert_ne!(
        issued.challenge, second.challenge,
        "CSPRNG challenges cannot repeat"
    );
    assert_eq!(issued.challenge.len(), 43, "256-bit unpadded base64url");
    assert_eq!(issued.expires_at - issued.issued_at, 60);
    let signed = sign(claims(&request, &issued));

    // A different Gateway has no record of this challenge, even if it has
    // the same trusted verifier key and the same apparent session labels.
    let other_dir = tempfile::tempdir().unwrap();
    let other = Storage::open(other_dir.path()).unwrap();
    assert_eq!(
        verify(&signed, &context(&request, &issued), &other).err(),
        Some(ActorAttestationError::Replay)
    );
    assert!(verify(&signed, &context(&request, &issued), &store).is_ok());
}

#[test]
fn expired_or_wrongly_bound_challenge_cannot_mint_a_verified_actor() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&store);
    let signed = sign(claims(&request, &issued));
    let mut ctx = context(&request, &issued);
    ctx.now_unix = issued.expires_at + 1;
    assert_eq!(
        verify(&signed, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );

    let other = issue_gateway_challenge(
        &store,
        &LocalGatewayChannel {
            device_id: "dev_trusted",
            workspace_id: "ws_trusted",
            connection_epoch: "other-connection-epoch",
            transport_binding: "local-channel-binding-1",
            now_unix: NOW - 20,
        },
    )
    .unwrap();
    // Even a valid signature produced using someone else's challenge cannot
    // be accepted by a different active native channel.
    let attacker = sign(claims(&request, &other));
    let mut local = context(&request, &other);
    local.connection_epoch = "trusted-connection-1";
    assert_eq!(
        verify(&attacker, &local, &store).err(),
        Some(ActorAttestationError::Replay),
        "a valid signature is not sufficient without the matching persisted epoch"
    );
}

#[test]
fn unsigned_unissued_and_oversized_challenges_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&store);
    let valid = sign(claims(&request, &issued));
    let mut ctx = context(&request, &issued);
    ctx.challenge = "not-a-gateway-issued-challenge";
    assert_eq!(
        verify(&valid, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    assert_eq!(
        verify(&vec![b'a'; 8193], &context(&request, &issued), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    // Failed attempts cannot invalidate a correctly signed original.
    assert!(verify(&valid, &context(&request, &issued), &store).is_ok());
}
