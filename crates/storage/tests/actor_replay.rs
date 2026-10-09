use companion_storage::{ActorReplayError, ActorReplayEvidence, Storage};

fn proof(n: u8) -> ActorReplayEvidence<'static> {
    ActorReplayEvidence {
        issuer: "trusted-issuer",
        nonce_hash: [n; 32],
        message_hash: [n + 1; 32],
        challenge_hash: [n + 2; 32],
        correlation_hash: [n + 3; 32],
        expires_at: 1_800_000_030,
    }
}

#[test]
fn all_replay_dimensions_are_unique_and_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let original = proof(10);
    storage.consume_actor_proof(&original).unwrap();
    for dimension in 0..4 {
        let mut altered = proof(20);
        match dimension {
            0 => altered.nonce_hash = original.nonce_hash,
            1 => altered.message_hash = original.message_hash,
            2 => altered.challenge_hash = original.challenge_hash,
            _ => altered.correlation_hash = original.correlation_hash,
        }
        assert_eq!(
            storage.consume_actor_proof(&altered),
            Err(ActorReplayError::Replay)
        );
    }
    // Each conflict rolls back entirely and must not reserve other keys.
    storage.consume_actor_proof(&proof(20)).unwrap();
    drop(storage);
    let reopened = Storage::open(dir.path()).unwrap();
    assert_eq!(
        reopened.consume_actor_proof(&original),
        Err(ActorReplayError::Replay)
    );
    assert_eq!(
        reopened.consume_actor_proof(&proof(20)),
        Err(ActorReplayError::Replay)
    );
}

#[test]
fn broken_storage_and_invalid_inputs_are_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let mut invalid = proof(30);
    invalid.nonce_hash = [0; 32];
    assert_eq!(
        storage.consume_actor_proof(&invalid),
        Err(ActorReplayError::Invalid)
    );
    storage
        .connection()
        .lock()
        .unwrap()
        .execute("DROP TABLE verified_actor_replay", [])
        .unwrap();
    assert_eq!(
        storage.consume_actor_proof(&proof(30)),
        Err(ActorReplayError::Unavailable)
    );
}

fn issued(seed: u8) -> companion_storage::IssuedActorChallenge {
    companion_storage::IssuedActorChallenge {
        challenge_hash: [seed; 32],
        device_hash: [10; 32],
        workspace_hash: [11; 32],
        epoch_hash: [12; 32],
        channel_hash: [13; 32],
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_060,
    }
}

#[test]
fn challenge_claim_and_replay_reservation_are_single_atomic_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let original = issued(20);
    let second = issued(21);
    store.register_actor_challenge(&original).unwrap();
    store.register_actor_challenge(&second).unwrap();

    let replay = proof(40);
    store
        .consume_issued_actor_proof(&replay, &original, 1_800_000_005)
        .unwrap();
    assert_eq!(
        store.consume_issued_actor_proof(&replay, &second, 1_800_000_005),
        Err(ActorReplayError::Replay)
    );
    let distinct = proof(50);
    // Conflict inserting replay must roll back consumption of the second
    // challenge; fresh proof can claim it successfully afterward.
    store
        .consume_issued_actor_proof(&distinct, &second, 1_800_000_005)
        .unwrap();
    assert_eq!(
        store.consume_issued_actor_proof(&distinct, &second, 1_800_000_005),
        Err(ActorReplayError::Replay)
    );
    drop(store);
    let reopened = Storage::open(dir.path()).unwrap();
    assert_eq!(
        reopened.consume_issued_actor_proof(&distinct, &second, 1_800_000_005),
        Err(ActorReplayError::Replay)
    );
}

#[test]
fn challenge_binding_expiry_and_missing_persistence_deny() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let original = issued(70);
    store.register_actor_challenge(&original).unwrap();
    let mut forged = issued(70);
    forged.channel_hash = [99; 32];
    assert_eq!(
        store.consume_issued_actor_proof(&proof(80), &forged, 1_800_000_005),
        Err(ActorReplayError::Replay)
    );
    assert_eq!(
        store.consume_issued_actor_proof(&proof(80), &original, 1_800_000_061),
        Err(ActorReplayError::Invalid)
    );
    store
        .connection()
        .lock()
        .unwrap()
        .execute("DROP TABLE gateway_actor_challenges", [])
        .unwrap();
    assert_eq!(
        store.consume_issued_actor_proof(&proof(80), &original, 1_800_000_005),
        Err(ActorReplayError::Unavailable)
    );
}
