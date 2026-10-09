//! Durable, atomic anti-replay reservation for future verified actor proofs.
//! This store is deliberately not an authorization engine or a token signer.

use companion_core::CompanionError;
use rusqlite::{params, ErrorCode};

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
    /// Atomically reserves ALL four identifiers or none. Persistence failure
    /// denies verification. Records deliberately do not auto-expire: doing
    /// so without a crash-safe clock high-water mark could resurrect proofs
    /// after system clock rollback. Retention policy is a separate gate.
    pub fn consume_actor_proof(
        &self,
        proof: &ActorReplayEvidence<'_>,
    ) -> Result<(), ActorReplayError> {
        if proof.issuer.is_empty()
            || proof.issuer.len() > 256
            || proof.expires_at <= 0
            || proof.nonce_hash == [0; 32]
            || proof.message_hash == [0; 32]
            || proof.challenge_hash == [0; 32]
            || proof.correlation_hash == [0; 32]
        {
            return Err(ActorReplayError::Invalid);
        }
        let conn = self
            .connection()
            .lock()
            .map_err(|_| ActorReplayError::Unavailable)?;
        // No unsafe clock-based eviction until monotonic high-water tracking
        // has been separately qualified. A bounded store fails closed rather
        // than accepting proofs with discarded replay evidence.
        let count: i64 = conn
            .query_row("SELECT count(*) FROM verified_actor_replay", [], |row| {
                row.get(0)
            })
            .map_err(|_| ActorReplayError::Unavailable)?;
        if count >= 250_000 {
            return Err(ActorReplayError::Unavailable);
        }
        conn.execute(
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
        Ok(())
    }
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
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| ActorReplayError::Unavailable)?;
        let count: i64 = tx
            .query_row("SELECT count(*) FROM gateway_actor_challenges", [], |row| {
                row.get(0)
            })
            .map_err(|_| ActorReplayError::Unavailable)?;
        if count >= 250_000 {
            return Err(ActorReplayError::Unavailable);
        }
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
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| ActorReplayError::Unavailable)?;
        let count: i64 = tx
            .query_row("SELECT count(*) FROM verified_actor_replay", [], |row| {
                row.get(0)
            })
            .map_err(|_| ActorReplayError::Unavailable)?;
        if count >= 250_000 {
            return Err(ActorReplayError::Unavailable);
        }
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
