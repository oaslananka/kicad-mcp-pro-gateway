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

fn high_water(store: &Storage) -> i64 {
    store
        .connection()
        .lock()
        .unwrap()
        .query_row(
            "SELECT last_seen_unix FROM actor_clock_high_water WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn persistent_high_water_denies_local_clock_rollback_across_reopen() {
    const START: i64 = 1_800_000_000;
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let first = issued(101);
    let mut old_clock = issued(102);
    old_clock.issued_at = START - 1;
    old_clock.expires_at = START + 59;
    store.register_actor_challenge(&first).unwrap();
    assert_eq!(high_water(&store), START);
    assert_eq!(
        store.register_actor_challenge(&old_clock),
        Err(ActorReplayError::Invalid)
    );
    assert_eq!(high_water(&store), START);

    let second = issued(103);
    store.register_actor_challenge(&second).unwrap();
    store
        .consume_issued_actor_proof(&proof(110), &first, START + 5)
        .unwrap();
    assert_eq!(high_water(&store), START + 5);
    assert_eq!(
        store.consume_issued_actor_proof(&proof(120), &second, START + 4),
        Err(ActorReplayError::Invalid),
        "a valid unconsumed challenge cannot be accepted after clock rollback"
    );
    drop(store);

    let reopened = Storage::open(dir.path()).unwrap();
    assert_eq!(high_water(&reopened), START + 5);
    assert_eq!(
        reopened.consume_issued_actor_proof(&proof(120), &second, START + 4),
        Err(ActorReplayError::Invalid),
        "persisted high-water must survive restart"
    );
    reopened
        .consume_issued_actor_proof(&proof(120), &second, START + 5)
        .unwrap();
    assert_eq!(high_water(&reopened), START + 5);
}

#[test]
fn failed_mid_transaction_never_advances_high_water_or_spends_challenge() {
    const START: i64 = 1_800_000_000;
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let first = issued(131);
    let second = issued(132);
    store.register_actor_challenge(&first).unwrap();
    store.register_actor_challenge(&second).unwrap();
    let duplicate = proof(141);
    store
        .consume_issued_actor_proof(&duplicate, &first, START + 5)
        .unwrap();
    assert_eq!(high_water(&store), START + 5);

    assert_eq!(
        store.consume_issued_actor_proof(&duplicate, &second, START + 20),
        Err(ActorReplayError::Replay),
        "duplicate evidence must roll back both challenge and high-water writes"
    );
    assert_eq!(high_water(&store), START + 5);
    store
        .consume_issued_actor_proof(&proof(151), &second, START + 6)
        .unwrap();
    assert_eq!(high_water(&store), START + 6);
    // Neither expiry nor rollback safeguards permit evidence eviction.
    assert_eq!(
        store
            .connection()
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM gateway_actor_challenges", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        2
    );
}

#[test]
fn missing_or_corrupt_high_water_denies_without_new_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(dir.path()).unwrap();
    let entry = issued(201);
    store.register_actor_challenge(&entry).unwrap();
    let original = high_water(&store);
    store
        .connection()
        .lock()
        .unwrap()
        .execute(
            "UPDATE actor_clock_high_water SET last_seen_unix = ?1 WHERE singleton=1",
            [original + 100],
        )
        .unwrap();
    assert_eq!(
        store.consume_issued_actor_proof(&proof(211), &entry, original + 1),
        Err(ActorReplayError::Invalid)
    );
    store
        .connection()
        .lock()
        .unwrap()
        .execute("DELETE FROM actor_clock_high_water WHERE singleton=1", [])
        .unwrap();
    assert_eq!(
        store.register_actor_challenge(&issued(202)),
        Err(ActorReplayError::Invalid),
        "missing singleton row must never reset the clock to zero"
    );
}

#[test]
fn schema_v8_seeds_high_water_from_oldest_unexpired_evidence_conservatively() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    // Emulate the relevant minimal v7 tables and two kinds of recorded
    // expiration; exercise the *actual* migration SQL, not a duplicate.
    conn.execute_batch(
        "CREATE TABLE gateway_actor_challenges (expires_at INTEGER NOT NULL);
         CREATE TABLE verified_actor_replay (expires_at INTEGER NOT NULL);
         INSERT INTO gateway_actor_challenges VALUES (1800000060);
         INSERT INTO verified_actor_replay VALUES (1800000080);",
    )
    .unwrap();
    conn.execute_batch(include_str!(
        "../migrations/0008_actor_clock_high_water.sql"
    ))
    .unwrap();
    let seeded: i64 = conn
        .query_row(
            "SELECT last_seen_unix FROM actor_clock_high_water WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(seeded, 1_800_000_080);
}
