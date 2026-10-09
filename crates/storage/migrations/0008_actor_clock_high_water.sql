/* tsqllint-disable */
-- Persistent high-water mark of locally trusted Gateway wall clock timestamps.
-- This guards against rollback; it is NOT proof the OS clock is trustworthy
-- and does NOT authorize deleting any replay or challenge records.
CREATE TABLE actor_clock_high_water (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    last_seen_unix INTEGER NOT NULL CHECK (last_seen_unix >= 0)
);

-- The initial high-water value is inserted by the pinned rusqlite_migration
-- v1.2 up_with_hook, in the SAME transaction as this DDL + user_version.
-- It conservatively seeds from prior recorded proof/challenge expiration.
-- A failed hook aborts the migration atomically, never leaving an
-- uninitialized singleton row accepted by later operation code.
