/* tsqllint-disable */
-- Future authenticated actor proofs. Never stores raw credentials or token
-- bodies; uniqueness is atomic across the four replay dimensions. The table
-- does not, by itself, enable remote execution or grant any capabilities.
CREATE TABLE verified_actor_replay (
    issuer TEXT NOT NULL,
    nonce_hash BLOB NOT NULL CHECK (length(nonce_hash) = 32),
    message_hash BLOB NOT NULL CHECK (length(message_hash) = 32),
    challenge_hash BLOB NOT NULL CHECK (length(challenge_hash) = 32),
    correlation_hash BLOB NOT NULL CHECK (length(correlation_hash) = 32),
    expires_at INTEGER NOT NULL,
    UNIQUE (issuer, nonce_hash),
    UNIQUE (issuer, message_hash),
    UNIQUE (issuer, challenge_hash),
    UNIQUE (issuer, correlation_hash)
);
