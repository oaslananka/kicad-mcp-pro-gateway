// Contract-model tests ONLY: no runtime enrollment entrypoint, OS provider,
// remote actor authorization, trusted UI, or hardware security claims.
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use companion_identity::{
    actor_attestation::ActorAttestationError,
    owner_manifest::verify_owner_signed_issuer_manifest,
    owner_policy_authority::{
        OwnerPolicyAuthority, TrustedOwnerPolicyState, TrustedOwnerPolicyStore,
    },
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000;
const DEVICE_DOMAIN: &str = "offline-test-device-a";
const DOMAIN: &[u8] = b"kicad-mcp/owner-issuer-manifest/v1\n";

fn owner(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn signed_manifest(owner: &SigningKey, generation: u64, state: &str) -> Vec<u8> {
    let payload = json!({
        "contract_version": "owner-issuer-manifest/v1",
        "generation": generation,
        "issued_at": NOW - 30,
        "expires_at": NOW + 120,
        "keys": [{
            "issuer": "independent-issuer",
            "key_id": "issuer-key",
            "public_key": URL_SAFE_NO_PAD.encode(owner_key().verifying_key().to_bytes()),
            "valid_from_unix": NOW - 100,
            "valid_until_unix": NOW + 200,
            "state": state
        }]
    });
    let mut message = DOMAIN.to_vec();
    message.extend(serde_json_canonicalizer::to_vec(&payload).unwrap());
    serde_json_canonicalizer::to_vec(&json!({
        "payload": payload,
        "signature": URL_SAFE_NO_PAD.encode(owner.sign(&message).to_bytes())
    }))
    .unwrap()
}
fn owner_key() -> SigningKey {
    owner(31)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// Test harness stand-in for an independently authenticated, explicitly
// reviewed local owner ceremony. A caller-supplied Boolean/struct is NOT
// evidence of owner approval in a real enrollment provider.
struct ModelOwnerApproval {
    root: VerifyingKey,
    reviewed_manifest_sha256: [u8; 32],
    device_domain: &'static str,
    purpose: CeremonyPurpose,
}
fn owner_test_ceremony(key: &SigningKey, reviewed_manifest: &[u8]) -> ModelOwnerApproval {
    ModelOwnerApproval {
        root: key.verifying_key(),
        reviewed_manifest_sha256: digest(reviewed_manifest),
        device_domain: DEVICE_DOMAIN,
        purpose: CeremonyPurpose::FirstEnrollment,
    }
}

#[derive(Clone, Copy)]
struct Commitment {
    root: VerifyingKey,
    generation: u64,
    signed_manifest_sha256: [u8; 32],
    device_domain: &'static str,
}

// The test model treats this as an independently protected history latch.
// Neither an untrusted disk snapshot nor an empty TPM index proves a pristine
// device. Actual reset provenance is a platform/witness qualification gate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TrustHistory {
    VerifiedNeverEnrolled,
    PreviouslyEnrolled,
    Unverifiable,
}

// Test-only substitute for ONE qualified, independently anchored, atomic
// root+generation+manifest-digest authority. This mutex is neither durable
// nor privileged, and MUST NEVER be installed as a production provider.
struct ModelAnchor {
    value: Mutex<Option<Commitment>>,
    reachable: Mutex<bool>,
    // Simulated independent hardware reset evidence. A real provider needs
    // a stronger, independently verified reset/re-enrollment protocol.
    reset_detected: Mutex<bool>,
    history: Mutex<TrustHistory>,
}
impl Default for ModelAnchor {
    fn default() -> Self {
        Self {
            value: Mutex::new(None),
            reachable: Mutex::new(true),
            reset_detected: Mutex::new(false),
            history: Mutex::new(TrustHistory::VerifiedNeverEnrolled),
        }
    }
}
impl ModelAnchor {
    fn present(&self) -> bool {
        self.value.lock().unwrap().is_some()
    }
    fn provision_for_test(&self, next: Commitment) -> Result<(), ActorAttestationError> {
        if !*self.reachable.lock().unwrap()
            || *self.reset_detected.lock().unwrap()
            || *self.history.lock().unwrap() != TrustHistory::VerifiedNeverEnrolled
            || next.generation == 0
            || next.device_domain != DEVICE_DOMAIN
        {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        let mut guard = self.value.lock().unwrap();
        if guard.is_some() {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        *guard = Some(next);
        *self.history.lock().unwrap() = TrustHistory::PreviouslyEnrolled;
        Ok(())
    }
    fn set_reachable(&self, reachable: bool) {
        *self.reachable.lock().unwrap() = reachable;
    }
    fn clear_for_fault_injection(&self) {
        *self.reset_detected.lock().unwrap() = true;
        *self.value.lock().unwrap() = None;
    }
    fn lose_anchor_without_reset_evidence(&self) {
        // A restored disk can omit a formerly committed anchor but cannot
        // rewrite the modeled independent history.
        *self.value.lock().unwrap() = None;
    }
    fn lose_independent_provenance(&self) {
        *self.value.lock().unwrap() = None;
        *self.history.lock().unwrap() = TrustHistory::Unverifiable;
    }
}
impl TrustedOwnerPolicyStore for ModelAnchor {
    fn read_committed(&self) -> Result<TrustedOwnerPolicyState, ActorAttestationError> {
        if !*self.reachable.lock().unwrap() || *self.reset_detected.lock().unwrap() {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        let bound = self
            .value
            .lock()
            .unwrap()
            .ok_or(ActorAttestationError::StorageUnavailable)?;
        if bound.device_domain != DEVICE_DOMAIN {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        Ok(TrustedOwnerPolicyState {
            root: bound.root,
            committed_generation: bound.generation,
            committed_manifest_sha256: bound.signed_manifest_sha256,
        })
    }
    fn compare_and_commit(
        &self,
        root: &VerifyingKey,
        expected_generation: u64,
        expected_digest: &[u8; 32],
        next_generation: u64,
        next_digest: &[u8; 32],
    ) -> Result<(), ActorAttestationError> {
        if !*self.reachable.lock().unwrap() || *self.reset_detected.lock().unwrap() {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        let mut guard = self.value.lock().unwrap();
        let current = guard
            .as_mut()
            .ok_or(ActorAttestationError::StorageUnavailable)?;
        if current.device_domain != DEVICE_DOMAIN
            || &current.root != root
            || current.generation != expected_generation
            || &current.signed_manifest_sha256 != expected_digest
            || next_generation <= current.generation
        {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        current.generation = next_generation;
        current.signed_manifest_sha256 = *next_digest;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PowerCut {
    BeforePrepare,
    AfterPrepare,
    BeforeCommit,
    AfterCommit,
    None,
}
#[derive(Debug, PartialEq, Eq)]
enum ModelResult {
    CommittedButNotActivated,
    Interrupted,
    Denied,
}

// Untrusted disk is deliberately separate from the model independent anchor.
// Even a signed policy on disk cannot authorize without the pinned commitment.
struct ProvisioningModel {
    qualified_provider: bool,
    anchor: Arc<ModelAnchor>,
    disk_manifest: Option<Vec<u8>>,
}
impl ProvisioningModel {
    fn new(qualified_provider: bool) -> Self {
        Self {
            qualified_provider,
            anchor: Arc::new(ModelAnchor::default()),
            disk_manifest: None,
        }
    }
    fn enroll(
        &mut self,
        approval: Option<&ModelOwnerApproval>,
        signed: &[u8],
        cut: PowerCut,
    ) -> ModelResult {
        if !self.qualified_provider
            || self.anchor.present()
            || *self.anchor.reset_detected.lock().unwrap()
            || *self.anchor.history.lock().unwrap() != TrustHistory::VerifiedNeverEnrolled
        {
            return ModelResult::Denied;
        }
        let Some(approval) = approval else {
            return ModelResult::Denied;
        };
        if approval.purpose != CeremonyPurpose::FirstEnrollment
            || approval.device_domain != DEVICE_DOMAIN
            || approval.reviewed_manifest_sha256 != digest(signed)
        {
            return ModelResult::Denied;
        }
        let Ok(valid) = verify_owner_signed_issuer_manifest(signed, &approval.root, 0, NOW) else {
            return ModelResult::Denied;
        };
        // No disk mutation or trusted commit before signature + local approval.
        if matches!(cut, PowerCut::BeforePrepare) {
            return ModelResult::Interrupted;
        }
        self.disk_manifest = Some(signed.to_vec());
        if matches!(cut, PowerCut::AfterPrepare | PowerCut::BeforeCommit) {
            return ModelResult::Interrupted;
        }
        let outcome = self.anchor.provision_for_test(Commitment {
            root: approval.root,
            generation: valid.generation,
            signed_manifest_sha256: digest(signed),
            device_domain: DEVICE_DOMAIN,
        });
        if outcome.is_err() {
            return ModelResult::Denied;
        }
        if matches!(cut, PowerCut::AfterCommit) {
            return ModelResult::Interrupted; // result ambiguous until independently re-read
        }
        // Intentionally NO actor activation after enrollment. Restart is a
        // separate reconciliation and still does not authorize remote tools.
        ModelResult::CommittedButNotActivated
    }
    fn restart_verified_generation(&self) -> Result<u64, ActorAttestationError> {
        if !self.qualified_provider {
            return Err(ActorAttestationError::StorageUnavailable);
        }
        let signed = self
            .disk_manifest
            .as_ref()
            .ok_or(ActorAttestationError::StorageUnavailable)?;
        OwnerPolicyAuthority::from_trusted_store(self.anchor.clone(), signed, NOW)?
            .active_generation()
    }
}

#[test]
fn no_trust_on_first_use_or_unqualified_platform_provisioning() {
    let signer = owner(78);
    let manifest = signed_manifest(&signer, 7, "active");
    let approval = owner_test_ceremony(&signer, &manifest);
    let mut device = ProvisioningModel::new(true);
    assert_eq!(
        device.enroll(None, &manifest, PowerCut::None),
        ModelResult::Denied
    );
    assert!(device.restart_verified_generation().is_err());
    assert!(!device.anchor.present());

    let mut unqualified = ProvisioningModel::new(false);
    assert_eq!(
        unqualified.enroll(Some(&approval), &manifest, PowerCut::None),
        ModelResult::Denied
    );
    assert!(unqualified.restart_verified_generation().is_err());
    assert!(!unqualified.anchor.present());
}

#[test]
fn owner_must_review_exact_signed_manifest_and_correct_device() {
    let signer = owner(78);
    let first = signed_manifest(&signer, 7, "active");
    let alternative = signed_manifest(&signer, 7, "revoked");
    let approval = owner_test_ceremony(&signer, &first);
    let mut device = ProvisioningModel::new(true);
    assert_eq!(
        device.enroll(Some(&approval), &alternative, PowerCut::None),
        ModelResult::Denied
    );
    let forged = signed_manifest(&owner(79), 7, "active");
    assert_eq!(
        device.enroll(Some(&approval), &forged, PowerCut::None),
        ModelResult::Denied
    );
    let wrong_domain = ModelOwnerApproval {
        device_domain: "offline-test-device-b",
        ..approval
    };
    assert_eq!(
        device.enroll(Some(&wrong_domain), &first, PowerCut::None),
        ModelResult::Denied
    );
    assert!(!device.anchor.present());
    assert!(device.disk_manifest.is_none());
}

#[test]
fn interrupted_enrollment_has_only_explicit_recovery_outcomes() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let approval = owner_test_ceremony(&signer, &signed);
    for cut in [
        PowerCut::BeforePrepare,
        PowerCut::AfterPrepare,
        PowerCut::BeforeCommit,
        PowerCut::AfterCommit,
        PowerCut::None,
    ] {
        let mut device = ProvisioningModel::new(true);
        let result = device.enroll(Some(&approval), &signed, cut);
        match cut {
            PowerCut::BeforePrepare | PowerCut::AfterPrepare | PowerCut::BeforeCommit => {
                assert_eq!(result, ModelResult::Interrupted);
                assert!(!device.anchor.present());
                assert!(device.restart_verified_generation().is_err());
            }
            PowerCut::AfterCommit => {
                assert_eq!(result, ModelResult::Interrupted);
                assert!(device.anchor.present());
                assert_eq!(device.restart_verified_generation(), Ok(7));
            }
            PowerCut::None => {
                assert_eq!(result, ModelResult::CommittedButNotActivated);
                assert_eq!(device.restart_verified_generation(), Ok(7));
            }
        }
    }
}

#[test]
fn stale_backup_different_same_generation_policy_and_missing_blob_deny() {
    let signer = owner(78);
    let initial = signed_manifest(&signer, 7, "active");
    let approval = owner_test_ceremony(&signer, &initial);
    let mut device = ProvisioningModel::new(true);
    assert_eq!(
        device.enroll(Some(&approval), &initial, PowerCut::None),
        ModelResult::CommittedButNotActivated
    );
    let old_backup = device.disk_manifest.clone();
    let policy =
        OwnerPolicyAuthority::from_trusted_store(device.anchor.clone(), &initial, NOW).unwrap();
    let next = signed_manifest(&signer, 8, "revoked");
    assert_eq!(
        policy.verify_candidate_commit_and_activate(&next, NOW),
        Ok(8)
    );
    device.disk_manifest = Some(next);
    assert_eq!(device.restart_verified_generation(), Ok(8));

    device.disk_manifest = old_backup; // restore entire untrusted policy data
    assert!(device.restart_verified_generation().is_err());
    device.disk_manifest = Some(signed_manifest(&signer, 8, "active"));
    assert!(device.restart_verified_generation().is_err()); // same generation, wrong bytes
    device.disk_manifest = None;
    assert!(device.restart_verified_generation().is_err());
}

#[test]
fn anchor_outage_reset_and_silent_reenrollment_never_recover_authority() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let approval = owner_test_ceremony(&signer, &signed);
    let mut device = ProvisioningModel::new(true);
    assert_eq!(
        device.enroll(Some(&approval), &signed, PowerCut::None),
        ModelResult::CommittedButNotActivated
    );
    assert_eq!(
        device.enroll(Some(&approval), &signed, PowerCut::None),
        ModelResult::Denied
    );
    device.anchor.set_reachable(false);
    assert!(device.restart_verified_generation().is_err());
    device.anchor.set_reachable(true);
    device.anchor.clear_for_fault_injection();
    assert!(device.restart_verified_generation().is_err());
    assert_eq!(
        device.enroll(Some(&approval), &signed, PowerCut::None),
        ModelResult::Denied,
        "a detected reset is not a fresh device and must not auto-reenroll"
    );
    // The reset latch is simulated. Actual hardware reset detection needs
    // independent owner recovery evidence; these tests do NOT prove it.
}

#[test]
fn conflicting_process_compare_and_commit_is_rejected_by_exact_snapshot_cas() {
    let signer = owner(78);
    let initial = signed_manifest(&signer, 7, "active");
    let next = signed_manifest(&signer, 8, "revoked");
    let alt = signed_manifest(&signer, 8, "active");
    let approval = owner_test_ceremony(&signer, &initial);
    let mut device = ProvisioningModel::new(true);
    assert_eq!(
        device.enroll(Some(&approval), &initial, PowerCut::None),
        ModelResult::CommittedButNotActivated
    );
    let anchor = Arc::clone(&device.anchor);
    let root = signer.verifying_key();
    let old_digest = digest(&initial);
    let first = std::thread::spawn(move || {
        anchor.compare_and_commit(&root, 7, &old_digest, 8, &digest(&next))
    });
    let second = device
        .anchor
        .compare_and_commit(&root, 7, &old_digest, 8, &digest(&alt));
    let a = first.join().unwrap();
    assert_ne!(
        a.is_ok(),
        second.is_ok(),
        "one of two stale contenders must lose"
    );
    // A caller does not get to choose the winning policy by restoring disk:
    // only the current trusted digest can reconstruct a valid authority.
    let valid = if a.is_ok() {
        signed_manifest(&signer, 8, "revoked")
    } else {
        signed_manifest(&signer, 8, "active")
    };
    device.disk_manifest = Some(valid);
    assert_eq!(device.restart_verified_generation(), Ok(8));
}

// Simulated LOCAL ceremony boundary. The test owns the pending record and
// simulates independently authenticated human review. In production a real
// platform authenticator must prove owner presence and verifier binding;
// none of these in-process fields or fixed challenge bytes are credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CeremonyPurpose {
    FirstEnrollment,
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CeremonyBinding {
    session_nonce: [u8; 32],
    challenge: [u8; 32],
    device_domain: &'static str,
    owner_root: [u8; 32],
    signed_manifest_sha256: [u8; 32],
    purpose: CeremonyPurpose,
}

#[derive(Clone, Copy)]
struct PendingCeremony {
    binding: CeremonyBinding,
    opened_at: i64,
    expires_at: i64,
}

#[derive(Default)]
struct TestOwnerCeremony {
    pending: Mutex<Option<PendingCeremony>>,
}

impl TestOwnerCeremony {
    fn begin_with_simulated_owner_auth(
        &self,
        human_owner_authenticated_for_test: bool,
        binding: CeremonyBinding,
        opened_at: i64,
        expires_at: i64,
    ) -> bool {
        // A Boolean deliberately cannot prove owner presence; this is a
        // controlled model fixture, not a public or production API.
        if !human_owner_authenticated_for_test
            || opened_at <= 0
            || expires_at <= opened_at
            || expires_at - opened_at > 60
            || binding.challenge == [0; 32]
            || binding.session_nonce == [0; 32]
        {
            return false;
        }
        let mut guard = self.pending.lock().unwrap();
        if guard.is_some() {
            return false;
        }
        *guard = Some(PendingCeremony {
            binding,
            opened_at,
            expires_at,
        });
        true
    }

    fn cancel(&self) {
        *self.pending.lock().unwrap() = None;
    }

    fn spend(
        &self,
        presented: CeremonyBinding,
        expected_purpose: CeremonyPurpose,
        independently_trusted_now: i64,
    ) -> Option<ModelOwnerApproval> {
        // Atomically consume the pending record even on an invalid attempt.
        // A failed check must never fall back to using the same approval.
        let current = self.pending.lock().unwrap().take()?;
        if current.binding != presented
            || presented.purpose != expected_purpose
            || independently_trusted_now < current.opened_at
            || independently_trusted_now > current.expires_at
            || independently_trusted_now <= 0
        {
            return None;
        }
        let root = VerifyingKey::from_bytes(&presented.owner_root).ok()?;
        Some(ModelOwnerApproval {
            root,
            reviewed_manifest_sha256: presented.signed_manifest_sha256,
            device_domain: presented.device_domain,
            purpose: presented.purpose,
        })
    }
}

fn test_binding(signer: &SigningKey, signed: &[u8], purpose: CeremonyPurpose) -> CeremonyBinding {
    CeremonyBinding {
        session_nonce: [3; 32], // deterministic in tests ONLY
        challenge: [7; 32],     // deterministic in tests ONLY
        device_domain: DEVICE_DOMAIN,
        owner_root: signer.verifying_key().to_bytes(),
        signed_manifest_sha256: digest(signed),
        purpose,
    }
}

#[test]
fn ceremony_is_single_use_and_binds_owner_device_manifest_session_challenge() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let binding = test_binding(&signer, &signed, CeremonyPurpose::FirstEnrollment);
    let gate = TestOwnerCeremony::default();
    assert!(!gate.begin_with_simulated_owner_auth(false, binding, NOW, NOW + 30));
    assert!(gate
        .spend(binding, CeremonyPurpose::FirstEnrollment, NOW)
        .is_none());
    assert!(gate.begin_with_simulated_owner_auth(true, binding, NOW, NOW + 30));
    assert!(!gate.begin_with_simulated_owner_auth(true, binding, NOW, NOW + 30));
    let approved = gate
        .spend(binding, CeremonyPurpose::FirstEnrollment, NOW + 1)
        .unwrap();
    let mut device = ProvisioningModel::new(true);
    assert_eq!(
        device.enroll(Some(&approved), &signed, PowerCut::None),
        ModelResult::CommittedButNotActivated
    );
    assert_eq!(device.restart_verified_generation(), Ok(7));
    assert!(gate
        .spend(binding, CeremonyPurpose::FirstEnrollment, NOW + 2)
        .is_none());
    assert_eq!(
        device.enroll(Some(&approved), &signed, PowerCut::None),
        ModelResult::Denied,
        "a copied grant cannot enroll a previously enrolled device"
    );
}

#[test]
fn mismatched_challenge_session_digest_device_root_and_purpose_burn_ceremony() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let valid = test_binding(&signer, &signed, CeremonyPurpose::FirstEnrollment);
    for wrong in [
        CeremonyBinding {
            challenge: [8; 32],
            ..valid
        },
        CeremonyBinding {
            session_nonce: [4; 32],
            ..valid
        },
        CeremonyBinding {
            signed_manifest_sha256: digest(b"different"),
            ..valid
        },
        CeremonyBinding {
            device_domain: "offline-test-device-b",
            ..valid
        },
        CeremonyBinding {
            owner_root: owner(79).verifying_key().to_bytes(),
            ..valid
        },
        CeremonyBinding {
            purpose: CeremonyPurpose::Recovery,
            ..valid
        },
    ] {
        let gate = TestOwnerCeremony::default();
        assert!(gate.begin_with_simulated_owner_auth(true, valid, NOW, NOW + 30));
        assert!(gate
            .spend(wrong, CeremonyPurpose::FirstEnrollment, NOW)
            .is_none());
        assert!(gate
            .spend(valid, CeremonyPurpose::FirstEnrollment, NOW)
            .is_none());
        let device = ProvisioningModel::new(true);
        assert!(!device.anchor.present());
    }
    let gate = TestOwnerCeremony::default();
    assert!(gate.begin_with_simulated_owner_auth(true, valid, NOW, NOW + 30));
    assert!(gate.spend(valid, CeremonyPurpose::Recovery, NOW).is_none());
    assert!(gate
        .spend(valid, CeremonyPurpose::FirstEnrollment, NOW)
        .is_none());
}

#[test]
fn cancelled_expired_invalid_clock_and_invalid_challenge_never_issue_grant() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let valid = test_binding(&signer, &signed, CeremonyPurpose::FirstEnrollment);
    let gate = TestOwnerCeremony::default();
    assert!(!gate.begin_with_simulated_owner_auth(
        true,
        CeremonyBinding {
            challenge: [0; 32],
            ..valid
        },
        NOW,
        NOW + 30
    ));
    assert!(!gate.begin_with_simulated_owner_auth(true, valid, NOW, NOW + 61));
    assert!(gate.begin_with_simulated_owner_auth(true, valid, NOW, NOW + 30));
    gate.cancel();
    assert!(gate
        .spend(valid, CeremonyPurpose::FirstEnrollment, NOW + 1)
        .is_none());
    for bad_time in [0, NOW - 1, NOW + 31] {
        assert!(gate.begin_with_simulated_owner_auth(true, valid, NOW, NOW + 30));
        assert!(gate
            .spend(valid, CeremonyPurpose::FirstEnrollment, bad_time)
            .is_none());
        assert!(gate
            .spend(valid, CeremonyPurpose::FirstEnrollment, NOW + 1)
            .is_none());
    }
    assert!(gate.begin_with_simulated_owner_auth(true, valid, NOW, NOW + 30));
    assert!(gate
        .spend(valid, CeremonyPurpose::FirstEnrollment, NOW + 30)
        .is_some());
}

#[test]
fn missing_anchor_with_prior_or_unknown_history_cannot_become_fresh_enrollment() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let approved = owner_test_ceremony(&signer, &signed);
    let mut model = ProvisioningModel::new(true);
    assert_eq!(
        model.enroll(Some(&approved), &signed, PowerCut::None),
        ModelResult::CommittedButNotActivated
    );
    model.anchor.lose_anchor_without_reset_evidence();
    assert!(!model.anchor.present());
    assert!(model.restart_verified_generation().is_err());
    assert_eq!(
        model.enroll(Some(&approved), &signed, PowerCut::None),
        ModelResult::Denied,
        "an empty trust anchor after prior enrollment is NOT first-run"
    );

    let mut uncertain = ProvisioningModel::new(true);
    uncertain.anchor.lose_independent_provenance();
    assert_eq!(
        uncertain.enroll(Some(&approved), &signed, PowerCut::None),
        ModelResult::Denied,
        "unknown hardware/witness history must deny"
    );
    assert!(uncertain.restart_verified_generation().is_err());
}

#[test]
fn ambiguous_commit_burns_one_time_ceremony_and_reconciles_exact_state_only() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let binding = test_binding(&signer, &signed, CeremonyPurpose::FirstEnrollment);
    let gate = TestOwnerCeremony::default();
    let mut model = ProvisioningModel::new(true);
    assert!(gate.begin_with_simulated_owner_auth(true, binding, NOW, NOW + 30));
    let approved = gate
        .spend(binding, CeremonyPurpose::FirstEnrollment, NOW + 1)
        .unwrap();
    assert_eq!(
        model.enroll(Some(&approved), &signed, PowerCut::AfterCommit),
        ModelResult::Interrupted
    );
    assert!(gate
        .spend(binding, CeremonyPurpose::FirstEnrollment, NOW + 2)
        .is_none());
    assert!(model.anchor.present());
    assert_eq!(model.restart_verified_generation(), Ok(7));
    model.disk_manifest = Some(signed_manifest(&signer, 7, "revoked"));
    assert!(model.restart_verified_generation().is_err());
    assert_eq!(
        model.enroll(Some(&approved), &signed, PowerCut::None),
        ModelResult::Denied
    );
}

#[test]
fn recovery_scoped_consent_never_becomes_first_enrollment_authority() {
    let signer = owner(78);
    let signed = signed_manifest(&signer, 7, "active");
    let recovery = test_binding(&signer, &signed, CeremonyPurpose::Recovery);
    let gate = TestOwnerCeremony::default();
    assert!(gate.begin_with_simulated_owner_auth(true, recovery, NOW, NOW + 30));
    let approval = gate
        .spend(recovery, CeremonyPurpose::Recovery, NOW + 1)
        .unwrap();
    let mut device = ProvisioningModel::new(true);
    assert_eq!(
        device.enroll(Some(&approval), &signed, PowerCut::None),
        ModelResult::Denied,
        "a recovery purpose must never enroll a purportedly new device"
    );
    assert!(!device.anchor.present());
    assert!(device.disk_manifest.is_none());
}
