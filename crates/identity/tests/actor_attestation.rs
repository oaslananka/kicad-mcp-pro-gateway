use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_identity::actor_attestation::{
    issue_gateway_challenge, verify_and_consume_actor_assertion, ActorAttestationError,
    ActorClaims, ExpectedActorRequest, GatewayIssuedChallenge, LocalGatewayChannel,
    PinnedActorIssuer, SignedActorClaims,
};
use companion_identity::actor_issuer_policy::{
    ActorIssuerKeyState, OwnerPinnedActorIssuers, OwnerPinnedActorKey,
};
use companion_identity::owner_policy_authority::OwnerPolicyAuthority;
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

fn sign_with_key(payload: ActorClaims, key: &SigningKey) -> Vec<u8> {
    let canonical = serde_json_canonicalizer::to_vec(&payload).unwrap();
    let mut signed_bytes = DOMAIN.to_vec();
    signed_bytes.extend_from_slice(&canonical);
    let signature = key.sign(&signed_bytes);
    serde_json_canonicalizer::to_vec(&SignedActorClaims {
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
    .unwrap()
}

fn sign(payload: ActorClaims) -> Vec<u8> {
    sign_with_key(payload, &issuer_key())
}

fn owner_key(id: &str, seed: u8, state: ActorIssuerKeyState) -> OwnerPinnedActorKey {
    OwnerPinnedActorKey {
        issuer: "trusted-issuer".into(),
        key_id: id.into(),
        public_key: SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        valid_from_unix: NOW - 100,
        valid_until_unix: NOW + 500,
        state,
    }
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

#[test]
fn owner_pinned_rotation_overlap_accepts_both_distinct_verified_signers() {
    let keys = OwnerPinnedActorIssuers::new(vec![
        owner_key("owner-pinned-key", 31, ActorIssuerKeyState::Active),
        owner_key("replacement-key", 32, ActorIssuerKeyState::Active),
    ])
    .unwrap();
    let request = operation();
    let store_a_dir = tempfile::tempdir().unwrap();
    let store_a = Storage::open(store_a_dir.path()).unwrap();
    let issued_a = minted(&store_a);
    let old_assertion = sign(claims(&request, &issued_a));
    let old = keys
        .verify_and_consume(&old_assertion, &context(&request, &issued_a), &store_a)
        .unwrap();
    assert_eq!(old.subject, "account-subject-1");
    assert_eq!(
        keys.verify_and_consume(&old_assertion, &context(&request, &issued_a), &store_a)
            .err(),
        Some(ActorAttestationError::Replay)
    );

    let store_b_dir = tempfile::tempdir().unwrap();
    let store_b = Storage::open(store_b_dir.path()).unwrap();
    let issued_b = minted(&store_b);
    let mut rotated = claims(&request, &issued_b);
    rotated.key_id = "replacement-key".into();
    let new_assertion = sign_with_key(rotated, &SigningKey::from_bytes(&[32; 32]));
    let new = keys
        .verify_and_consume(&new_assertion, &context(&request, &issued_b), &store_b)
        .unwrap();
    assert_eq!(new.subject, old.subject);
}

#[test]
fn revoked_unknown_and_out_of_window_issuer_keys_deny_without_consuming_challenge() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&store);
    let proof = sign(claims(&request, &issued));
    let revoked = OwnerPinnedActorIssuers::new(vec![owner_key(
        "owner-pinned-key",
        31,
        ActorIssuerKeyState::Revoked,
    )])
    .unwrap();
    assert_eq!(
        revoked
            .verify_and_consume(&proof, &context(&request, &issued), &store)
            .err(),
        Some(ActorAttestationError::Invalid)
    );
    let missing = OwnerPinnedActorIssuers::new(vec![owner_key(
        "unrelated-key",
        33,
        ActorIssuerKeyState::Active,
    )])
    .unwrap();
    assert_eq!(
        missing
            .verify_and_consume(&proof, &context(&request, &issued), &store)
            .err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut future_key = owner_key("owner-pinned-key", 31, ActorIssuerKeyState::Active);
    future_key.valid_from_unix = NOW + 20;
    let inactive = OwnerPinnedActorIssuers::new(vec![future_key]).unwrap();
    assert_eq!(
        inactive
            .verify_and_consume(&proof, &context(&request, &issued), &store)
            .err(),
        Some(ActorAttestationError::Invalid)
    );
    let mut expired = owner_key("owner-pinned-key", 31, ActorIssuerKeyState::Active);
    expired.valid_until_unix = NOW - 1;
    assert_eq!(
        OwnerPinnedActorIssuers::new(vec![expired])
            .unwrap()
            .verify_and_consume(&proof, &context(&request, &issued), &store)
            .err(),
        Some(ActorAttestationError::Invalid)
    );
    // Failed policy checks must never consume a valid Gateway challenge.
    let trusted = OwnerPinnedActorIssuers::new(vec![owner_key(
        "owner-pinned-key",
        31,
        ActorIssuerKeyState::Active,
    )])
    .unwrap();
    assert!(trusted
        .verify_and_consume(&proof, &context(&request, &issued), &store)
        .is_ok());
}

#[test]
fn owner_pin_policy_rejects_duplicate_ids_reused_key_material_and_empty_trust() {
    assert!(OwnerPinnedActorIssuers::new(vec![]).is_err());
    assert!(OwnerPinnedActorIssuers::new(vec![
        owner_key("owner-pinned-key", 31, ActorIssuerKeyState::Active),
        owner_key("owner-pinned-key", 32, ActorIssuerKeyState::Active),
    ])
    .is_err());
    assert!(OwnerPinnedActorIssuers::new(vec![
        owner_key("owner-pinned-key", 31, ActorIssuerKeyState::Active),
        owner_key("other-key-id", 31, ActorIssuerKeyState::Active),
    ])
    .is_err());
    let mut invalid = owner_key("owner-pinned-key", 31, ActorIssuerKeyState::Active);
    invalid.valid_until_unix = invalid.valid_from_unix;
    assert!(OwnerPinnedActorIssuers::new(vec![invalid]).is_err());
    assert!(
        OwnerPinnedActorIssuers::new(vec![owner_key(" ", 31, ActorIssuerKeyState::Active),])
            .is_err()
    );
    assert!(OwnerPinnedActorIssuers::new(vec![owner_key(
        " leading",
        31,
        ActorIssuerKeyState::Active
    ),])
    .is_err());
    assert!(OwnerPinnedActorIssuers::new(vec![owner_key(
        "trailing ",
        31,
        ActorIssuerKeyState::Active
    ),])
    .is_err());
    assert!(OwnerPinnedActorIssuers::new(
        (1..=33)
            .map(|n| { owner_key(&format!("key-{n}"), n, ActorIssuerKeyState::Active) })
            .collect()
    )
    .is_err());
}

#[test]
fn owner_signed_manifest_policy_controls_actual_offline_actor_verification() {
    use companion_identity::owner_manifest::verify_owner_signed_issuer_manifest;
    let owner_root = SigningKey::from_bytes(&[89; 32]);
    let make_manifest = |generation: u64, key_state: &str| {
        let payload = json!({
            "contract_version": "owner-issuer-manifest/v1",
            "generation": generation,
            "issued_at": NOW - 50,
            "expires_at": NOW + 100,
            "keys": [{
                "issuer": "trusted-issuer",
                "key_id": "owner-pinned-key",
                "public_key": URL_SAFE_NO_PAD.encode(issuer_key().verifying_key().to_bytes()),
                "valid_from_unix": NOW - 100,
                "valid_until_unix": NOW + 500,
                "state": key_state
            }]
        });
        let mut signed_bytes = b"kicad-mcp/owner-issuer-manifest/v1\n".to_vec();
        signed_bytes.extend_from_slice(&serde_json_canonicalizer::to_vec(&payload).unwrap());
        let signature = owner_root.sign(&signed_bytes);
        serde_json_canonicalizer::to_vec(&json!({
            "payload":payload,
            "signature":URL_SAFE_NO_PAD.encode(signature.to_bytes())
        }))
        .unwrap()
    };

    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let request = operation();
    let issued = minted(&storage);
    let actor_assertion = sign(claims(&request, &issued));

    let trusted = verify_owner_signed_issuer_manifest(
        &make_manifest(40, "active"),
        &owner_root.verifying_key(),
        39,
        NOW,
    )
    .unwrap();
    assert_eq!(trusted.generation, 40);
    assert!(trusted
        .verify_and_consume(&actor_assertion, &context(&request, &issued), &storage, 40)
        .is_ok());

    let mut expired_manifest_context = context(&request, &issued);
    expired_manifest_context.now_unix = NOW + 101;
    assert_eq!(
        trusted
            .verify_and_consume(&actor_assertion, &expired_manifest_context, &storage, 40,)
            .err(),
        Some(ActorAttestationError::Invalid),
        "an in-memory owner policy must not authorize anything after manifest expiry"
    );

    let second_dir = tempfile::tempdir().unwrap();
    let second_store = Storage::open(second_dir.path()).unwrap();
    let second_issued = issue_gateway_challenge(
        &second_store,
        &LocalGatewayChannel {
            device_id: "dev_trusted",
            workspace_id: "ws_trusted",
            connection_epoch: "trusted-connection-1",
            transport_binding: "local-channel-binding-1",
            now_unix: NOW,
        },
    )
    .unwrap();
    let second_assertion = sign(claims(&request, &second_issued));
    let revoked = verify_owner_signed_issuer_manifest(
        &make_manifest(41, "revoked"),
        &owner_root.verifying_key(),
        40,
        NOW,
    )
    .unwrap();
    assert_eq!(
        revoked
            .verify_and_consume(
                &second_assertion,
                &context(&request, &second_issued),
                &second_store,
                41
            )
            .err(),
        Some(ActorAttestationError::Invalid),
        "a genuinely signed actor assertion must still be refused after owner revocation"
    );
    assert_eq!(
        trusted
            .verify_and_consume(
                &second_assertion,
                &context(&request, &second_issued),
                &second_store,
                41,
            )
            .err(),
        Some(ActorAttestationError::Invalid),
        "old signed owner manifest must deny when the trusted active generation advances"
    );
    let remaining: i64 = second_store
        .connection()
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM gateway_actor_challenges WHERE consumed = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining, 1,
        "policy denials cannot spend a valid challenge"
    );
    // The authority never exposes the generation to the remote caller;
    // a signed key revocation atomically replaces the in-memory policy.
    let authority = OwnerPolicyAuthority::from_trusted_local_state(
        owner_root.verifying_key(),
        &make_manifest(50, "active"),
        49,
        NOW,
    )
    .unwrap();
    let first_dir = tempfile::tempdir().unwrap();
    let first_store = Storage::open(first_dir.path()).unwrap();
    let first_issued = minted(&first_store);
    let first_proof = sign(claims(&request, &first_issued));
    assert!(authority
        .verify_actor_and_consume(
            &first_proof,
            &context(&request, &first_issued),
            &first_store
        )
        .is_ok());

    assert_eq!(
        authority.verify_candidate_and_replace_in_memory(&make_manifest(51, "revoked"), NOW),
        Ok(51)
    );
    let denied_dir = tempfile::tempdir().unwrap();
    let denied_store = Storage::open(denied_dir.path()).unwrap();
    let denied_issued = minted(&denied_store);
    let denied_proof = sign(claims(&request, &denied_issued));
    assert_eq!(
        authority
            .verify_actor_and_consume(
                &denied_proof,
                &context(&request, &denied_issued),
                &denied_store
            )
            .err(),
        Some(ActorAttestationError::Invalid),
        "new owner policy must revoke actor even for an otherwise valid proof"
    );
}
