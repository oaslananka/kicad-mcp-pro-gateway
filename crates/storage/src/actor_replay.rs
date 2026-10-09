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
