use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_identity::actor_attestation::ActorAttestationError;
use companion_identity::owner_manifest::verify_owner_signed_issuer_manifest;
use companion_identity::owner_policy_authority::OwnerPolicyAuthority;
#[path = "support/owner_store.rs"]
mod owner_store;
use ed25519_dalek::{Signer, SigningKey};
use owner_store::{Failure, TestOwnerStore};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000;
const DOMAIN: &[u8] = b"kicad-mcp/owner-issuer-manifest/v1\n";

fn owner() -> SigningKey {
    SigningKey::from_bytes(&[89; 32])
}

fn issuer(seed: u8, id: &str, state: &str) -> Value {
    json!({
        "issuer": "identity-provider.example",
        "key_id": id,
        "public_key": URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes()
        ),
        "valid_from_unix": NOW - 100,
        "valid_until_unix": NOW + 300,
        "state": state
    })
}

fn payload() -> Value {
    json!({
        "contract_version": "owner-issuer-manifest/v1",
        "generation": 12,
        "issued_at": NOW - 20,
        "expires_at": NOW + 240,
        "keys": [issuer(31, "old-key", "active"),issuer(32, "new-key", "active")]
    })
}

fn wrap(root: &SigningKey, claims: &Value) -> Vec<u8> {
    let canonical = serde_json_canonicalizer::to_vec(claims).unwrap();
    let mut data = DOMAIN.to_vec();
    data.extend_from_slice(&canonical);
    let signature = root.sign(&data);
    serde_json_canonicalizer::to_vec(&json!({
        "payload": claims,
        "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }))
    .unwrap()
}

fn load(bytes: &[u8], floor: u64) -> Result<u64, ActorAttestationError> {
    verify_owner_signed_issuer_manifest(bytes, &owner().verifying_key(), floor, NOW)
        .map(|validated| validated.generation)
}

#[test]
fn trusted_owner_signature_enables_rotation_overlap_above_persisted_floor() {
    let valid = wrap(&owner(), &payload());
    assert_eq!(load(&valid, 11), Ok(12));
    assert_eq!(load(&valid, 12), Err(ActorAttestationError::Invalid));
    assert_eq!(load(&valid, 13), Err(ActorAttestationError::Invalid));
    assert_eq!(load(&valid, 0), Ok(12));

    let mut rotated = payload();
    rotated["generation"] = json!(13);
    rotated["keys"][0]["state"] = json!("revoked");
    assert_eq!(load(&wrap(&owner(), &rotated), 12), Ok(13));
}

#[test]
fn unknown_root_modified_claims_or_domain_never_admit_keys() {
    let signer = owner();
    let valid = wrap(&signer, &payload());
    let wrong_root = SigningKey::from_bytes(&[99; 32]).verifying_key();
    assert!(verify_owner_signed_issuer_manifest(&valid, &wrong_root, 11, NOW).is_err());

    let mut changed: Value = serde_json::from_slice(&valid).unwrap();
    changed["payload"]["keys"][0]["state"] = json!("revoked");
    let forged = serde_json_canonicalizer::to_vec(&changed).unwrap();
    assert_eq!(load(&forged, 11), Err(ActorAttestationError::Invalid));

    let mut bytes = DOMAIN[..DOMAIN.len() - 1].to_vec();
    bytes.extend_from_slice(&serde_json_canonicalizer::to_vec(&payload()).unwrap());
    let bad_domain_sig = signer.sign(&bytes);
    let wrong = serde_json_canonicalizer::to_vec(&json!({
        "payload":payload(),"signature": URL_SAFE_NO_PAD.encode(bad_domain_sig.to_bytes())
    }))
    .unwrap();
    assert_eq!(load(&wrong, 11), Err(ActorAttestationError::Invalid));
}

#[test]
fn rejects_invalid_json_duplicate_keys_unknown_fields_and_noncanonical_bytes() {
    let valid = wrap(&owner(), &payload());
    let original = String::from_utf8(valid.clone()).unwrap();
    let dup = original.replacen(
        "\"generation\":12",
        "\"generation\":12,\"generation\":12",
        1,
    );
    assert_ne!(dup, original);
    assert_eq!(
        load(dup.as_bytes(), 11),
        Err(ActorAttestationError::Invalid)
    );

    let noncanonical =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&valid).unwrap()).unwrap();
    assert_eq!(load(&noncanonical, 11), Err(ActorAttestationError::Invalid));

    let mut unknown = payload();
    unknown["unexpected"] = json!("no");
    assert_eq!(
        load(&wrap(&owner(), &unknown), 11),
        Err(ActorAttestationError::Invalid)
    );
    let extra = String::from_utf8(valid).unwrap().replacen(
        "\"signature\":",
        "\"extra\":true,\"signature\":",
        1,
    );
    assert_eq!(
        load(extra.as_bytes(), 11),
        Err(ActorAttestationError::Invalid)
    );
}

#[test]
fn limits_generation_lifetime_key_count_and_time_before_accepting() {
    let mut claims = payload();
    claims["generation"] = json!(0);
    assert_eq!(
        load(&wrap(&owner(), &claims), 0),
        Err(ActorAttestationError::Invalid)
    );
    claims["generation"] = json!(9_007_199_254_740_992u64);
    assert_eq!(
        load(&wrap(&owner(), &claims), 0),
        Err(ActorAttestationError::Invalid)
    );

    claims = payload();
    claims["issued_at"] = json!(NOW + 1);
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );
    claims["issued_at"] = json!(NOW - 31 * 24 * 60 * 60);
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );
    claims = payload();
    claims["expires_at"] = json!(NOW);
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );
    claims = payload();
    claims["contract_version"] = json!("owner-issuer-manifest/v2");
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );
    claims = payload();
    claims["keys"] = json!([]);
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );
    claims["keys"] = json!((1u8..=33u8)
        .map(|i| issuer(i, &format!("issuer-key-{i}"), "active"))
        .collect::<Vec<_>>());
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );
    assert_eq!(
        load(&vec![b'a'; 16385], 0),
        Err(ActorAttestationError::Invalid)
    );
    assert_eq!(load(&[], 0), Err(ActorAttestationError::Invalid));
}

#[test]
fn invalid_pin_material_duplicates_revoked_root_and_states_reject() {
    let mut claims = payload();
    claims["keys"][1]["key_id"] = json!("old-key");
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );

    claims = payload();
    claims["keys"][1]["public_key"] = claims["keys"][0]["public_key"].clone();
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );

    claims = payload();
    claims["keys"][0]["public_key"] =
        json!(URL_SAFE_NO_PAD.encode(owner().verifying_key().to_bytes()));
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );

    claims = payload();
    claims["keys"][0]["public_key"] = json!("!!!");
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );

    claims = payload();
    claims["keys"][0]["state"] = json!("auto_trust");
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );

    claims = payload();
    claims["keys"][0]["key_id"] = json!(" leading-space");
    assert_eq!(
        load(&wrap(&owner(), &claims), 11),
        Err(ActorAttestationError::Invalid)
    );
}

#[test]
fn invalid_signature_format_is_uniformly_denied() {
    let mut envelope: Value = serde_json::from_slice(&wrap(&owner(), &payload())).unwrap();
    for s in ["", "none", "=", "abc=", "%%"] {
        envelope["signature"] = json!(s);
        let raw = serde_json_canonicalizer::to_vec(&envelope).unwrap();
        assert_eq!(load(&raw, 11), Err(ActorAttestationError::Invalid));
    }
}

fn active_test_authority() -> (
    std::sync::Arc<TestOwnerStore>,
    OwnerPolicyAuthority,
    Vec<u8>,
) {
    let active = wrap(&owner(), &payload());
    let store = TestOwnerStore::new(owner().verifying_key(), 12, &active);
    let authority = OwnerPolicyAuthority::from_trusted_store(store.clone(), &active, NOW).unwrap();
    (store, authority, active)
}

#[test]
fn owner_authority_rejects_stale_updates_and_commits_only_strictly_higher_generation() {
    let (_store, authority, first) = active_test_authority();
    assert_eq!(authority.active_generation(), Ok(12));
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&first, NOW),
        Err(ActorAttestationError::Invalid),
        "owner replay cannot revert an already active policy generation"
    );
    assert_eq!(authority.active_generation(), Ok(12));
    let mut next = payload();
    next["generation"] = json!(13);
    next["keys"][0]["state"] = json!("revoked");
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&wrap(&owner(), &next), NOW),
        Ok(13)
    );
    assert_eq!(authority.active_generation(), Ok(13));
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&first, NOW),
        Err(ActorAttestationError::Invalid)
    );
    assert_eq!(authority.active_generation(), Ok(13));
}

#[test]
fn forged_and_expired_owner_updates_preserve_current_in_memory_policy() {
    let (_store, authority, _active) = active_test_authority();
    let mut next = payload();
    next["generation"] = json!(13);
    let rogue = SigningKey::from_bytes(&[100u8; 32]);
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&wrap(&rogue, &next), NOW),
        Err(ActorAttestationError::Invalid)
    );
    assert_eq!(authority.active_generation(), Ok(12));

    next["expires_at"] = json!(NOW);
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&wrap(&owner(), &next), NOW),
        Err(ActorAttestationError::Invalid)
    );
    assert_eq!(authority.active_generation(), Ok(12));
}

#[test]
fn simultaneous_owner_updates_serialize_and_never_decrease_generation() {
    use std::sync::Arc;
    let active = wrap(&owner(), &payload());
    let store = TestOwnerStore::new(owner().verifying_key(), 12, &active);
    let authority =
        Arc::new(OwnerPolicyAuthority::from_trusted_store(store.clone(), &active, NOW).unwrap());
    let manifests: Vec<Vec<u8>> = (13..21)
        .map(|generation| {
            let mut v = payload();
            v["generation"] = json!(generation);
            wrap(&owner(), &v)
        })
        .collect();

    std::thread::scope(|scope| {
        for signed in &manifests {
            let authority = Arc::clone(&authority);
            scope.spawn(move || {
                let _ = authority.verify_candidate_commit_and_activate(signed, NOW);
            });
        }
    });
    assert_eq!(authority.active_generation(), Ok(20));
}

#[test]
fn trusted_store_requires_exact_active_generation_and_no_tofu_bootstrap() {
    let envelope = wrap(&owner(), &payload());
    let zero = TestOwnerStore::new(owner().verifying_key(), 0, &envelope);
    assert!(OwnerPolicyAuthority::from_trusted_store(zero, &envelope, NOW).is_err());
    let stale = TestOwnerStore::new(owner().verifying_key(), 11, &envelope);
    assert!(OwnerPolicyAuthority::from_trusted_store(stale, &envelope, NOW).is_err());
    let advanced = TestOwnerStore::new(owner().verifying_key(), 13, &envelope);
    assert!(OwnerPolicyAuthority::from_trusted_store(advanced, &envelope, NOW).is_err());
    let rogue = TestOwnerStore::new(
        SigningKey::from_bytes(&[97; 32]).verifying_key(),
        12,
        &envelope,
    );
    assert!(OwnerPolicyAuthority::from_trusted_store(rogue, &envelope, NOW).is_err());
    let trusted = TestOwnerStore::new(owner().verifying_key(), 12, &envelope);
    assert_eq!(
        OwnerPolicyAuthority::from_trusted_store(trusted, &envelope, NOW)
            .unwrap()
            .active_generation(),
        Ok(12)
    );
}

#[test]
fn failed_precommit_disables_entire_authority_without_advancing_test_store() {
    let (trusted, authority, active) = active_test_authority();
    let mut next = payload();
    next["generation"] = json!(13);
    trusted.set_failure(Failure::BeforeCommit);
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&wrap(&owner(), &next), NOW),
        Err(ActorAttestationError::StorageUnavailable)
    );
    assert_eq!(trusted.generation(), 12);
    assert_eq!(
        authority.active_generation(),
        Err(ActorAttestationError::StorageUnavailable)
    );
    trusted.set_failure(Failure::None);
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&wrap(&owner(), &next), NOW),
        Err(ActorAttestationError::StorageUnavailable),
        "a failed operation must NEVER permit in-process resurrection"
    );
    assert_eq!(trusted.generation(), 12);
    let after_restart = OwnerPolicyAuthority::from_trusted_store(trusted, &active, NOW).unwrap();
    assert_eq!(after_restart.active_generation(), Ok(12));
}

#[test]
fn ambiguous_postcommit_error_disables_old_policy_and_needs_new_manifest_after_restart() {
    let (trusted, authority, active) = active_test_authority();
    let mut next = payload();
    next["generation"] = json!(13);
    next["keys"][0]["state"] = json!("revoked");
    let signed_next = wrap(&owner(), &next);
    trusted.set_failure(Failure::AfterCommit);
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&signed_next, NOW),
        Err(ActorAttestationError::StorageUnavailable)
    );
    assert_eq!(
        trusted.generation(),
        13,
        "the fake committed before returning an error"
    );
    assert_eq!(
        authority.active_generation(),
        Err(ActorAttestationError::StorageUnavailable)
    );
    assert!(OwnerPolicyAuthority::from_trusted_store(trusted.clone(), &active, NOW).is_err());
    trusted.set_failure(Failure::None);
    let recovered = OwnerPolicyAuthority::from_trusted_store(trusted, &signed_next, NOW).unwrap();
    assert_eq!(recovered.active_generation(), Ok(13));
}

#[test]
fn different_valid_owner_signed_manifest_at_same_generation_is_not_equivalent() {
    let committed = wrap(&owner(), &payload());
    let mut alternative = payload();
    alternative["keys"][0]["state"] = json!("revoked");
    let alternative = wrap(&owner(), &alternative);
    assert_eq!(
        load(&alternative, 11),
        Ok(12),
        "both manifests are genuinely owner-signed"
    );
    assert_ne!(committed, alternative);

    let trusted = TestOwnerStore::new(owner().verifying_key(), 12, &committed);
    assert!(OwnerPolicyAuthority::from_trusted_store(trusted.clone(), &alternative, NOW).is_err());
    assert_eq!(
        OwnerPolicyAuthority::from_trusted_store(trusted, &committed, NOW)
            .unwrap()
            .active_generation(),
        Ok(12)
    );
}

#[test]
fn recovery_refuses_other_signed_policy_even_when_generation_matches() {
    let (trusted, authority, _) = active_test_authority();
    let mut next = payload();
    next["generation"] = json!(13);
    next["keys"][0]["state"] = json!("revoked");
    let committed = wrap(&owner(), &next);
    assert_eq!(
        authority.verify_candidate_commit_and_activate(&committed, NOW),
        Ok(13)
    );
    let mut alternate = next;
    alternate["keys"][1]["state"] = json!("revoked");
    let signed_alternate = wrap(&owner(), &alternate);
    assert_eq!(load(&signed_alternate, 12), Ok(13));
    assert!(
        OwnerPolicyAuthority::from_trusted_store(trusted.clone(), &signed_alternate, NOW).is_err(),
        "disk restore must not substitute another same-generation policy"
    );
    assert_eq!(
        OwnerPolicyAuthority::from_trusted_store(trusted, &committed, NOW)
            .unwrap()
            .active_generation(),
        Ok(13)
    );
}

#[test]
fn bootstrap_rechecks_atomic_root_generation_and_manifest_digest_before_publication() {
    use companion_identity::owner_policy_authority::{
        TrustedOwnerPolicyState, TrustedOwnerPolicyStore,
    };
    use ed25519_dalek::VerifyingKey;
    use sha2::Digest;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ChangingTrustedStore {
        first: TrustedOwnerPolicyState,
        later: TrustedOwnerPolicyState,
        reads: AtomicUsize,
    }
    impl TrustedOwnerPolicyStore for ChangingTrustedStore {
        fn read_committed(&self) -> Result<TrustedOwnerPolicyState, ActorAttestationError> {
            let s = if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.first
            } else {
                &self.later
            };
            Ok(TrustedOwnerPolicyState {
                root: s.root,
                committed_generation: s.committed_generation,
                committed_manifest_sha256: s.committed_manifest_sha256,
            })
        }
        fn compare_and_commit(
            &self,
            _: &VerifyingKey,
            _: u64,
            _: &[u8; 32],
            _: u64,
            _: &[u8; 32],
        ) -> Result<(), ActorAttestationError> {
            Err(ActorAttestationError::StorageUnavailable)
        }
    }
    let envelope = wrap(&owner(), &payload());
    for changed in [
        TrustedOwnerPolicyState {
            root: owner().verifying_key(),
            committed_generation: 13,
            committed_manifest_sha256: sha2::Sha256::digest(&envelope).into(),
        },
        TrustedOwnerPolicyState {
            root: SigningKey::from_bytes(&[99; 32]).verifying_key(),
            committed_generation: 12,
            committed_manifest_sha256: sha2::Sha256::digest(&envelope).into(),
        },
        TrustedOwnerPolicyState {
            root: owner().verifying_key(),
            committed_generation: 12,
            committed_manifest_sha256: [0u8; 32],
        },
    ] {
        let store = std::sync::Arc::new(ChangingTrustedStore {
            first: TrustedOwnerPolicyState {
                root: owner().verifying_key(),
                committed_generation: 12,
                committed_manifest_sha256: sha2::Sha256::digest(&envelope).into(),
            },
            later: changed,
            reads: AtomicUsize::new(0),
        });
        assert!(
            OwnerPolicyAuthority::from_trusted_store(store.clone(), &envelope, NOW).is_err(),
            "initial owner root/generation/manifest digest changed mid-verification"
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);
    }
}
