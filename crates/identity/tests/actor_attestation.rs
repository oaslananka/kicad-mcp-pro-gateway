use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_identity::actor_attestation::{
    verify_and_consume_actor_assertion, ActorAttestationError, ActorClaims, ExpectedActorRequest,
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

fn context<'a>(request: &'a [u8]) -> ExpectedActorRequest<'a> {
    ExpectedActorRequest {
        canonical_operation: request,
        device_id: "dev_trusted",
        workspace_id: "ws_trusted",
        message_id: "message-1",
        correlation_id: "correlation-1",
        challenge: "gateway-generated-challenge-1",
        connection_epoch: "trusted-connection-1",
        transport_binding: "local-channel-binding-1",
        audience: "gateway-device",
        resource: "https://example.invalid/mcp",
        now_unix: NOW,
    }
}

fn claims(request: &[u8]) -> ActorClaims {
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
        gateway_challenge: "gateway-generated-challenge-1".into(),
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
    let assertion = sign(claims(&request));
    let principal = verify(&assertion, &context(&request), &store).unwrap();
    assert_eq!(principal.issuer, "trusted-issuer");
    assert_eq!(principal.subject, "account-subject-1");
    assert_eq!(
        principal.client_or_agent.as_deref(),
        Some("authenticated-agent-1")
    );
    assert!(!principal.transport_binding.is_empty());
    assert_eq!(
        verify(&assertion, &context(&request), &store).err(),
        Some(ActorAttestationError::Replay)
    );
    drop(store);
    let reopened = Storage::open(dir.path()).unwrap();
    assert_eq!(
        verify(&assertion, &context(&request), &reopened).err(),
        Some(ActorAttestationError::Replay)
    );
}

#[test]
fn rejects_wrong_source_request_device_epoch_audience_and_modified_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let proof = sign(claims(&request));

    let mut ctx = context(&request);
    ctx.device_id = "different-device";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request);
    ctx.connection_epoch = "reconnected-session";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request);
    ctx.audience = "attacker-service";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request);
    ctx.transport_binding = "foreign-authenticated-channel";
    assert_eq!(
        verify(&proof, &ctx, &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    ctx = context(&request);
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
        verify(&proof, &context(&tampered), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    assert!(
        verify(&proof, &context(&request), &store).is_ok(),
        "bad attempts cannot consume valid proof"
    );
}

#[test]
fn fail_closed_on_invalid_algorithm_signature_expiry_and_foreign_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let base = claims(&request);
    let mut none = claims(&request);
    none.alg = "none".into();
    assert_eq!(
        verify(&sign(none), &context(&request), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut expired = claims(&request);
    expired.expires_at = NOW - 1;
    assert_eq!(
        verify(&sign(expired), &context(&request), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut future = claims(&request);
    future.issued_at = NOW + 40;
    future.expires_at = NOW + 50;
    assert_eq!(
        verify(&sign(future), &context(&request), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut whitespace = claims(&request);
    whitespace.subject = "   ".into();
    assert_eq!(
        verify(&sign(whitespace), &context(&request), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut foreign = claims(&request);
    foreign.issuer = "relay-itself".into();
    assert_eq!(
        verify(&sign(foreign), &context(&request), &store).err(),
        Some(ActorAttestationError::Invalid)
    );

    let mut forged: SignedActorClaims = serde_json::from_slice(&sign(base)).unwrap();
    let foreign_key = SigningKey::from_bytes(&[22; 32]);
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&serde_json_canonicalizer::to_vec(&forged.payload).unwrap());
    forged.signature = URL_SAFE_NO_PAD.encode(foreign_key.sign(&signed).to_bytes());
    let bad = serde_json_canonicalizer::to_vec(&forged).unwrap();
    assert_eq!(
        verify(&bad, &context(&request), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
}

#[test]
fn rejects_noncanonical_or_ambiguous_json_and_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let req = operation();
    let proof = sign(claims(&req));
    let spaced = [b"  ".as_slice(), proof.as_slice()].concat();
    assert_eq!(
        verify(&spaced, &context(&req), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let with_unknown =
        String::from_utf8(proof.clone())
            .unwrap()
            .replacen("{", "{\"unexpected\":true,", 1);
    assert_eq!(
        verify(with_unknown.as_bytes(), &context(&req), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let with_duplicate = String::from_utf8(proof.clone()).unwrap().replacen(
        "\"payload\":",
        "\"payload\":null,\"payload\":",
        1,
    );
    assert_eq!(
        verify(with_duplicate.as_bytes(), &context(&req), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let noncanonical_req = [b"\n".as_slice(), req.as_slice()].concat();
    assert_eq!(
        verify(&proof, &context(&noncanonical_req), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
}

#[test]
fn concurrent_nonce_replay_conflicts_atomically_and_storage_failure_denies() {
    let dir = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Storage::open(dir.path()).unwrap());
    let request = operation();
    let assertion = sign(claims(&request));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let shared = store.clone();
            let proof = assertion.clone();
            let req = request.clone();
            std::thread::spawn(move || verify(&proof, &context(&req), &shared))
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

    let mut changed = claims(&request);
    changed.nonce = "unused-nonce".into();
    changed.message_id = "unused-message".into();
    changed.gateway_challenge = "unused-challenge".into();
    changed.correlation_id = "unused-correlation".into();
    // As the signed IDs no longer match the local context, fail before DB.
    let changed_proof = sign(changed);
    assert_eq!(
        verify(&changed_proof, &context(&request), &store).err(),
        Some(ActorAttestationError::Invalid)
    );
    let conn = store.connection().lock().unwrap();
    conn.execute("DROP TABLE verified_actor_replay", [])
        .unwrap();
    drop(conn);
    let new_dir = tempfile::tempdir().unwrap();
    let clean_store = Storage::open(new_dir.path()).unwrap();
    let fresh = sign(claims(&request));
    assert!(verify(&fresh, &context(&request), &clean_store).is_ok());
    // Storage failure with the same valid proof must never yield a principal.
    assert_eq!(
        verify(&fresh, &context(&request), &store).err(),
        Some(ActorAttestationError::StorageUnavailable)
    );
}
