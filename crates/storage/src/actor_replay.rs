//! Durable, atomic anti-replay reservation for future verified actor proofs.
//! This store is deliberately not an authorization engine or a token signer.

use companion_core::CompanionError;
use rusqlite::{params, Connection, ErrorCode, Transaction, TransactionBehavior};

use crate::Storage;

/// Already-hashed evidence; no raw bearer tokens or credentials are stored.
pub struct ActorReplayEvidence<'a> {
    pub issuer: &'a str,
    pub nonce_hash: [u8; 32],
    pub message_hash: [u8; 32],
    pub challenge_hash: [u8; 32],
    pub correlation_hash: [u8; 32],
    pub expires_at: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActorReplayError {
    #[error("actor proof replay detected")]
    Replay,
    #[error("actor replay store unavailable")]
    Unavailable,
    #[error("invalid actor replay reservation")]
    Invalid,
}

impl CompanionError for ActorReplayError {
    fn code(&self) -> &'static str {
        match self {
            Self::Replay => "ACTOR_REPLAY",
            Self::Unavailable => "ACTOR_REPLAY_UNAVAILABLE",
            Self::Invalid => "ACTOR_REPLAY_INVALID",
        }
    }

    fn retryable(&self) -> bool {
        false
    }
}

impl Storage {
    /// Legacy offline replay reservation only: does NOT grant a verified
    /// principal or replace the Gateway-issued challenge path. It still
    /// requires trusted Gateway-local time and the SAME transactional
    /// high-water protection as all other replay mutation paths.
    /// Records never auto-expire or bypass the bounded capacity gate.
    pub fn consume_actor_proof(
        &self,
        proof: &ActorReplayEvidence<'_>,
        trusted_now_unix: i64,
    ) -> Result<(), ActorReplayError> {
        if proof.issuer.trim().is_empty()
            || proof.issuer.len() > 256
            || trusted_now_unix <= 0
            || proof.expires_at < trusted_now_unix
            || proof.nonce_hash == [0; 32]
            || proof.message_hash == [0; 32]
            || proof.challenge_hash == [0; 32]
            || proof.correlation_hash == [0; 32]
        {
            return Err(ActorReplayError::Invalid);
        }
        let mut conn = self
            .connection()
            .lock()
            .map_err(|_| ActorReplayError::Unavailable)?;
        let tx = begin_limited_write(&mut conn, ReplayTable::VerifiedProofs, trusted_now_unix)?;
        tx.execute(
            "INSERT INTO verified_actor_replay (issuer, nonce_hash, message_hash, challenge_hash, correlation_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                proof.issuer,
                proof.nonce_hash.as_slice(),
                proof.message_hash.as_slice(),
                proof.challenge_hash.as_slice(),
                proof.correlation_hash.as_slice(),
                proof.expires_at
            ],
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(ref e, _)
                if e.code == ErrorCode::ConstraintViolation => ActorReplayError::Replay,
            _ => ActorReplayError::Unavailable,
        })?;
        tx.commit().map_err(|_| ActorReplayError::Unavailable)?;
        Ok(())
    }
}

enum ReplayTable {
    IssuedChallenges,
    VerifiedProofs,
}

/// Advance the Gateway-owned local wall-clock high-water mark INSIDE the
/// transaction which issues or consumes proof evidence. Never trust an
/// assertion-provided timestamp for this purpose. Any rollback, missing
/// sentinel row or broken database denies the operation without weakening
/// replay protection or deleting records.
fn require_nondecreasing_local_clock(
    tx: &Transaction<'_>,
    now_unix: i64,
) -> Result<(), ActorReplayError> {
    if now_unix <= 0 {
        return Err(ActorReplayError::Invalid);
    }
    let updated = tx
        .execute(
            "UPDATE actor_clock_high_water SET last_seen_unix = ?1
             WHERE singleton = 1 AND last_seen_unix <= ?1",
            params![now_unix],
        )
        .map_err(|_| ActorReplayError::Unavailable)?;
    if updated != 1 {
        return Err(ActorReplayError::Invalid);
    }
    Ok(())
}

/// Begin an exclusive writer reservation and check the table-specific fixed
/// fail-closed capacity in the SAME transaction, eliminating divergent caps.
fn begin_limited_write(
    conn: &mut Connection,
    table: ReplayTable,
    trusted_now_unix: i64,
) -> Result<Transaction<'_>, ActorReplayError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ActorReplayError::Unavailable)?;
    require_nondecreasing_local_clock(&tx, trusted_now_unix)?;
    let count_sql = match table {
        ReplayTable::IssuedChallenges => "SELECT count(*) FROM gateway_actor_challenges",
        ReplayTable::VerifiedProofs => "SELECT count(*) FROM verified_actor_replay",
    };
    let count: i64 = tx
        .query_row(count_sql, [], |row| row.get(0))
        .map_err(|_| ActorReplayError::Unavailable)?;
    if count >= 250_000 {
        return Err(ActorReplayError::Unavailable);
    }
    Ok(tx)
}

/// Opaque hashes of the Gateway's own authenticated local channel context.
pub struct IssuedActorChallenge {
    pub challenge_hash: [u8; 32],
    pub device_hash: [u8; 32],
    pub workspace_hash: [u8; 32],
    pub epoch_hash: [u8; 32],
    pub channel_hash: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
}

fn valid_issued_challenge(c: &IssuedActorChallenge) -> bool {
    [
        c.challenge_hash,
        c.device_hash,
        c.workspace_hash,
        c.epoch_hash,
        c.channel_hash,
    ]
    .into_iter()
    .all(|digest| digest != [0; 32])
        && c.issued_at > 0
        && c.expires_at > c.issued_at
        && c.expires_at.saturating_sub(c.issued_at) <= 60
}

impl Storage {
    /// Call ONLY after the local Gateway creates a CSPRNG challenge for a
    /// verified native device connection. Retains issued rows indefinitely:
    /// a full store denies rather than expiring records across clock rollback.
    pub fn register_actor_challenge(
        &self,
        c: &IssuedActorChallenge,
    ) -> Result<(), ActorReplayError> {
        if !valid_issued_challenge(c) {
            return Err(ActorReplayError::Invalid);
        }
        let mut conn = self
            .connection()
            .lock()
            .map_err(|_| ActorReplayError::Unavailable)?;
        let tx = begin_limited_write(&mut conn, ReplayTable::IssuedChallenges, c.issued_at)?;
        tx.execute(
            "INSERT INTO gateway_actor_challenges
             (challenge_hash, device_hash, workspace_hash, epoch_hash, channel_hash, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![c.challenge_hash.as_slice(), c.device_hash.as_slice(),
                c.workspace_hash.as_slice(), c.epoch_hash.as_slice(),
                c.channel_hash.as_slice(), c.issued_at, c.expires_at],
        ).map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _) if err.code == ErrorCode::ConstraintViolation =>
                ActorReplayError::Replay,
            _ => ActorReplayError::Unavailable,
        })?;
        tx.commit().map_err(|_| ActorReplayError::Unavailable)?;
        Ok(())
    }

    /// Challenge claim and all proof replay identifiers commit in ONE SQLite
    /// IMMEDIATE transaction; either both are consumed or neither is.
    pub fn consume_issued_actor_proof(
        &self,
        proof: &ActorReplayEvidence<'_>,
        binding: &IssuedActorChallenge,
        now_unix: i64,
    ) -> Result<(), ActorReplayError> {
        if !valid_issued_challenge(binding)
            || now_unix < binding.issued_at
            || now_unix > binding.expires_at
            || proof.issuer.trim().is_empty()
            || proof.issuer.len() > 256
            || proof.expires_at < now_unix
            || [
                proof.nonce_hash,
                proof.message_hash,
                proof.challenge_hash,
                proof.correlation_hash,
            ]
            .into_iter()
            .any(|digest| digest == [0; 32])
        {
            return Err(ActorReplayError::Invalid);
        }
        let mut conn = self
            .connection()
            .lock()
            .map_err(|_| ActorReplayError::Unavailable)?;
        let tx = begin_limited_write(&mut conn, ReplayTable::VerifiedProofs, now_unix)?;
        let changed = tx
            .execute(
                "UPDATE gateway_actor_challenges SET consumed=1
             WHERE challenge_hash=?1 AND device_hash=?2 AND workspace_hash=?3
               AND epoch_hash=?4 AND channel_hash=?5 AND issued_at=?6 AND expires_at=?7
               AND consumed=0",
                params![
                    binding.challenge_hash.as_slice(),
                    binding.device_hash.as_slice(),
                    binding.workspace_hash.as_slice(),
                    binding.epoch_hash.as_slice(),
                    binding.channel_hash.as_slice(),
                    binding.issued_at,
                    binding.expires_at
                ],
            )
            .map_err(|_| ActorReplayError::Unavailable)?;
        if changed != 1 {
            return Err(ActorReplayError::Replay);
        }
        tx.execute(
            "INSERT INTO verified_actor_replay
             (issuer, nonce_hash, message_hash, challenge_hash, correlation_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                proof.issuer,
                proof.nonce_hash.as_slice(),
                proof.message_hash.as_slice(),
                proof.challenge_hash.as_slice(),
                proof.correlation_hash.as_slice(),
                proof.expires_at
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _)
                if err.code == ErrorCode::ConstraintViolation =>
            {
                ActorReplayError::Replay
            }
            _ => ActorReplayError::Unavailable,
        })?;
        tx.commit().map_err(|_| ActorReplayError::Unavailable)?;
        Ok(())
    }
}
