use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_identity::actor_attestation::ActorAttestationError;
use companion_identity::owner_manifest::verify_owner_signed_issuer_manifest;
use ed25519_dalek::{Signer, SigningKey};
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
