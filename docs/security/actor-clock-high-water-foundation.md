# Offline persistent actor clock high-water guard (schema v8)

Status: **library-only, unused by live Gateway/native transport**. This is
not a clock synchronization service, independent trusted time authority,
bounded replay-retention implementation or authorization for remote tools.

The SQLite DDL and the conservative v7 history seed run within the
**same** pinned `rusqlite_migration::M::up_with_hook` transaction.
This ensures a failed migration hook cannot commit an uninitialized
high-water sentinel or falsely advance the schema version. The v8
SQL file contains only SQLite DDL; the nontrivial seed query resides in
Rust migration logic rather than an unrelated SQL dialect checker.

This additive SQLite v8 migration introduces a singleton
`actor_clock_high_water.last_seen_unix`. It is advanced by the
**locally authenticated Gateway clock**, never by assertion-supplied
`issued_at` or `expires_at`, inside the same `BEGIN IMMEDIATE`
transaction that creates a Gateway-owned challenge or consumes one
challenge plus its replay identifiers.

## Security invariants

- The older, offline-only `consume_actor_proof` replay reservation API
  also now requires trusted local time and the same bounded IMMEDIATE
  high-water transaction; it is NOT an actor authentication substitute.
- On each issuance/consumption, reject nonpositive local time, time
  **strictly earlier** than the last committed local time, a missing
  sentinel, or unreadable/locked persistence. Equal timestamps are
  permitted. Subsequent recovery requires local clock correction, not an
  automatic reset of security state.
- For a fresh v8 database the high-water starts at zero. On an upgrade from
  v7, the migration **conservatively seeds** it from the maximum recorded
  challenge or signed actor proof expiration. This can temporarily refuse
  new challenges until local time passes the maximum expiration; it must
  never silently waive older v7 evidence.
- If either the challenge/replay reservation or the high-water write fails,
  the entire transaction rolls back: no partially advanced time and no
  wrongly consumed challenge. SQLite serializes writers at the database
  level (transaction behavior `IMMEDIATE`).
- Challenge/proof history is still **not deleted**, even when the clock
  passes a recorded expiration. Current 250,000-record limits continue
  to **fail closed**. Trusted clock progression does not justify deletion
  without additional recovery/retention and anti-rollback guarantees.
- Locally observed wall-clock time is not cryptographically trusted:
  an unauthorized **forward** clock jump could deny service later by
  advancing the high-water; access to the OS clock remains a local trust
  assumption. Restoring or replacing the **entire SQLite database** from
  an old snapshot can revert both replay records and their high-water.
  v8 does **not** detect this, and does not provide cross-node anti-replay
  or a secure external time anchor. These are future deployment gates.

## Evidence and upgrade/rollback

Offline storage tests cover earlier-time issue/consume denial, reopening
the file after rollback attempts, equal-time acceptance, forward progress,
failure midway through a two-record transaction, an absent sentinel,
manually advanced time and migration SQL seeding from v7 proof history.
Existing actor/identity and audit tests remain the compatibility gates.

Schema v8 is additive to v7. Binaries expecting v7 or older must refuse a
newer database by the existing schema-version guard; **do not manually
downgrade user_version**. A future authorized production migration requires
backup, rollback/forward recovery, provenance, actual clock-source
hardening and old-binary compatibility qualification. No running Gateway
database, VPS relay or daemon service is modified by this PR.

References: SQLite official
[transaction semantics](https://www.sqlite.org/lang_transaction.html),
[isolation](https://www.sqlite.org/isolation.html) and the pinned
`rusqlite` `TransactionBehavior::Immediate` API.
