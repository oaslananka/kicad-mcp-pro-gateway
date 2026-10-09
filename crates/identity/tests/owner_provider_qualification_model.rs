// Source-only provider-eligibility model. Booleans and deterministic challenges
// are test fixture inputs, NOT verified WebAuthn credentials or trusted OS facts.
// Durable commit, crash/recovery, replay and CAS belong to the separate
// owner_provisioning_model.rs fixture; do not duplicate its trust store here.
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000;
const DEVICE: [u8; 16] = [3; 16];
const ROOT: [u8; 32] = [4; 32];
const CRED: [u8; 16] = [5; 16];
const ORIGIN: &str = "https://owner.example.test";
const RP: &str = "owner.example.test";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose {
    FirstEnrollment,
    Recovery,
}

#[derive(Clone, Copy)]
struct Ceremony {
    session: [u8; 32],
    device: [u8; 16],
    root: [u8; 32],
    manifest_digest: [u8; 32],
    generation: u64,
    reset_epoch: u64,
    purpose: Purpose,
    expires: i64,
}

fn challenge(c: Ceremony) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"kicad-mcp/owner-provider-eligibility-model/v1\n");
    for part in [
        c.session.as_slice(),
        c.device.as_slice(),
        c.root.as_slice(),
        c.manifest_digest.as_slice(),
    ] {
        hash.update(part);
    }
    hash.update(c.generation.to_be_bytes());
    hash.update(c.reset_epoch.to_be_bytes());
    hash.update([match c.purpose {
        Purpose::FirstEnrollment => 1,
        Purpose::Recovery => 2,
    }]);
    hash.update(c.expires.to_be_bytes());
    hash.finalize().into()
}

// These represent fields a REAL conforming verifier and trusted local UI
// would need to validate. A struct supplied by an untrusted caller is not
// an owner proof. Neither signCount nor backup state is a policy counter.
#[derive(Clone, Copy)]
struct AssertionEvidence {
    credential: [u8; 16],
    origin: &'static str,
    rp_id: &'static str,
    challenge: [u8; 32],
    signature_verified: bool,
    user_present: bool,
    user_verified: bool,
    local_review_authenticated: bool,
    time_independently_trusted: bool,
    sign_count: u32,
    backup_eligible: bool,
}
fn owner_proof_eligible(c: Ceremony, e: AssertionEvidence, intent: Purpose, now: i64) -> bool {
    c.purpose == intent
        && c.session != [0; 32]
        && c.device != [0; 16]
        && c.root != [0; 32]
        && c.manifest_digest != [0; 32]
        && c.generation > 0
        && now > 0
        && c.expires
            .checked_sub(now)
            .is_some_and(|remaining| (0..=60).contains(&remaining))
        && e.credential == CRED
        && e.origin == ORIGIN
        && e.rp_id == RP
        && e.challenge == challenge(c)
        && e.signature_verified
        && e.user_present
        && e.user_verified
        && e.local_review_authenticated
        && e.time_independently_trusted
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum History {
    IndependentlyVerifiedVirgin,
    PreviouslyEnrolled,
    Unknown,
}

// A qualification matrix, NOT a witness implementation. Actual reset history,
// anti-rollback CAS and all-writer fencing must be independently proven on an
// approved platform or owner-approved remote witness before any production use.
#[derive(Clone, Copy)]
struct WitnessEvidence {
    qualified_provenance: bool,
    device: [u8; 16],
    reset_epoch: u64,
    reset_detected: bool,
    history: History,
    pinned_root: Option<[u8; 32]>,
    committed_generation: Option<u64>,
    durable_exact_tuple_cas: bool,
    all_writer_fencing: bool,
}
fn operation_eligible(
    c: Ceremony,
    assertion: AssertionEvidence,
    witness: WitnessEvidence,
    candidate_owner_signature_verified: bool,
) -> bool {
    if !owner_proof_eligible(c, assertion, c.purpose, NOW)
        || !candidate_owner_signature_verified
        || !witness.qualified_provenance
        || witness.device != c.device
        || witness.reset_epoch != c.reset_epoch
        || witness.reset_detected
        || !witness.durable_exact_tuple_cas
        || !witness.all_writer_fencing
    {
        return false;
    }
    match c.purpose {
        Purpose::FirstEnrollment => {
            witness.history == History::IndependentlyVerifiedVirgin
                && witness.pinned_root.is_none()
                && witness.committed_generation.is_none()
        }
        Purpose::Recovery => {
            witness.history == History::PreviouslyEnrolled
                && witness.pinned_root == Some(c.root)
                && witness
                    .committed_generation
                    .is_some_and(|old| c.generation > old)
        }
    }
}

fn ceremony(purpose: Purpose) -> Ceremony {
    Ceremony {
        session: [8; 32],
        device: DEVICE,
        root: ROOT,
        manifest_digest: [9; 32],
        generation: 7,
        reset_epoch: 4,
        purpose,
        expires: NOW + 30,
    }
}
fn assertion(c: Ceremony) -> AssertionEvidence {
    AssertionEvidence {
        credential: CRED,
        origin: ORIGIN,
        rp_id: RP,
        challenge: challenge(c),
        signature_verified: true,
        user_present: true,
        user_verified: true,
        local_review_authenticated: true,
        time_independently_trusted: true,
        sign_count: 0,
        backup_eligible: true,
    }
}
fn virgin_witness(c: Ceremony) -> WitnessEvidence {
    WitnessEvidence {
        qualified_provenance: true,
        device: c.device,
        reset_epoch: c.reset_epoch,
        reset_detected: false,
        history: History::IndependentlyVerifiedVirgin,
        pinned_root: None,
        committed_generation: None,
        durable_exact_tuple_cas: true,
        all_writer_fencing: true,
    }
}

#[test]
fn verifier_requires_correct_credential_origin_rp_signature_uv_and_local_review() {
    let c = ceremony(Purpose::FirstEnrollment);
    let good = assertion(c);
    assert!(owner_proof_eligible(c, good, c.purpose, NOW));
    for invalid in [
        AssertionEvidence {
            credential: [1; 16],
            ..good
        },
        AssertionEvidence {
            origin: "https://phish.example.test",
            ..good
        },
        AssertionEvidence {
            rp_id: "phish.example.test",
            ..good
        },
        AssertionEvidence {
            signature_verified: false,
            ..good
        },
        AssertionEvidence {
            user_present: false,
            ..good
        },
        AssertionEvidence {
            user_verified: false,
            ..good
        },
        AssertionEvidence {
            local_review_authenticated: false,
            ..good
        },
        AssertionEvidence {
            time_independently_trusted: false,
            ..good
        },
    ] {
        assert!(!owner_proof_eligible(c, invalid, c.purpose, NOW));
    }
}
#[test]
fn challenge_is_scoped_to_session_device_root_policy_generation_reset_and_purpose() {
    let c = ceremony(Purpose::FirstEnrollment);
    let e = assertion(c);
    for altered in [
        Ceremony {
            session: [1; 32],
            ..c
        },
        Ceremony {
            device: [1; 16],
            ..c
        },
        Ceremony { root: [1; 32], ..c },
        Ceremony {
            manifest_digest: [1; 32],
            ..c
        },
        Ceremony { generation: 8, ..c },
        Ceremony {
            reset_epoch: 5,
            ..c
        },
        Ceremony {
            purpose: Purpose::Recovery,
            ..c
        },
        Ceremony {
            expires: NOW + 31,
            ..c
        },
    ] {
        assert!(!owner_proof_eligible(altered, e, altered.purpose, NOW));
    }
    assert!(!owner_proof_eligible(c, e, Purpose::Recovery, NOW));
}
#[test]
fn expiry_untrusted_time_and_empty_session_fail_closed() {
    let c = ceremony(Purpose::FirstEnrollment);
    for at in [0, NOW - 60, NOW + 31] {
        assert!(!owner_proof_eligible(c, assertion(c), c.purpose, at));
    }
    let zero = Ceremony {
        session: [0; 32],
        ..c
    };
    assert!(!owner_proof_eligible(zero, assertion(zero), c.purpose, NOW));
}
#[test]
fn synchronized_passkey_and_zero_signcount_do_not_qualify_a_device_witness() {
    let c = ceremony(Purpose::FirstEnrollment);
    let e = assertion(c);
    assert!(e.backup_eligible && e.sign_count == 0);
    assert!(owner_proof_eligible(c, e, c.purpose, NOW));
    assert!(!operation_eligible(
        c,
        e,
        WitnessEvidence {
            qualified_provenance: false,
            ..virgin_witness(c)
        },
        true
    ));
}
#[test]
fn absent_history_never_proves_first_enrollment() {
    let c = ceremony(Purpose::FirstEnrollment);
    for history in [History::PreviouslyEnrolled, History::Unknown] {
        assert!(!operation_eligible(
            c,
            assertion(c),
            WitnessEvidence {
                history,
                ..virgin_witness(c)
            },
            true
        ));
    }
    assert!(operation_eligible(c, assertion(c), virgin_witness(c), true));
}
#[test]
fn reset_hardware_mismatch_and_missing_cas_or_fencing_deny() {
    let c = ceremony(Purpose::FirstEnrollment);
    let trusted = virgin_witness(c);
    for invalid in [
        WitnessEvidence {
            device: [1; 16],
            ..trusted
        },
        WitnessEvidence {
            reset_epoch: 5,
            ..trusted
        },
        WitnessEvidence {
            reset_detected: true,
            ..trusted
        },
        WitnessEvidence {
            durable_exact_tuple_cas: false,
            ..trusted
        },
        WitnessEvidence {
            all_writer_fencing: false,
            ..trusted
        },
    ] {
        assert!(!operation_eligible(c, assertion(c), invalid, true));
    }
    assert!(!operation_eligible(c, assertion(c), trusted, false));
}
#[test]
fn recovery_never_becomes_first_enrollment_or_unpinned_root_rotation() {
    let c = ceremony(Purpose::Recovery);
    let prior = WitnessEvidence {
        history: History::PreviouslyEnrolled,
        pinned_root: Some(ROOT),
        committed_generation: Some(6),
        ..virgin_witness(c)
    };
    assert!(operation_eligible(c, assertion(c), prior, true));
    assert!(!operation_eligible(
        c,
        assertion(c),
        WitnessEvidence {
            pinned_root: Some([1; 32]),
            ..prior
        },
        true
    ));
    assert!(!operation_eligible(
        c,
        assertion(c),
        WitnessEvidence {
            committed_generation: Some(7),
            ..prior
        },
        true
    ));
    let virgin = virgin_witness(c);
    assert!(!operation_eligible(c, assertion(c), virgin, true));
    let enroll = ceremony(Purpose::FirstEnrollment);
    assert!(!operation_eligible(enroll, assertion(enroll), prior, true));
}
