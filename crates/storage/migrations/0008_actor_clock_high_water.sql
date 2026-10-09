/* tsqllint-disable */
-- Persistent high-water mark of locally trusted Gateway wall clock timestamps.
-- This guards against rollback; it is NOT proof the OS clock is trustworthy
-- and does NOT authorize deleting any replay or challenge records.
CREATE TABLE actor_clock_high_water (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    last_seen_unix INTEGER NOT NULL CHECK (last_seen_unix >= 0)
);

-- Conservative upgrade from v7: previously issued challenges/proofs may
-- expire in the future, so do not accept a locally rewound clock earlier
-- than their most recent recorded expiry after migration.
INSERT INTO actor_clock_high_water(singleton, last_seen_unix)
SELECT 1, max(
    coalesce((SELECT max(expires_at) FROM gateway_actor_challenges), 0),
    coalesce((SELECT max(expires_at) FROM verified_actor_replay), 0)
);
