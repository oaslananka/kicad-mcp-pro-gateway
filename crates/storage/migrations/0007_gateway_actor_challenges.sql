/* tsqllint-disable */
-- Local Gateway-generated one-time challenge reservations. Non-secret hashes
-- only: the raw challenge and authenticated channel binding are not stored.
-- Do not reuse or delete rows without a crash-safe monotonic retention policy.
CREATE TABLE gateway_actor_challenges (
    challenge_hash BLOB PRIMARY KEY CHECK(length(challenge_hash) = 32),
    device_hash BLOB NOT NULL CHECK(length(device_hash) = 32),
    workspace_hash BLOB NOT NULL CHECK(length(workspace_hash) = 32),
    epoch_hash BLOB NOT NULL CHECK(length(epoch_hash) = 32),
    channel_hash BLOB NOT NULL CHECK(length(channel_hash) = 32),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
);
