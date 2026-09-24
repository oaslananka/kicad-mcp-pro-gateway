# Audit Fail-Closed Policy

This is the documented read-vs-write policy for pre-execution audit
persistence. It implements GitHub issue #4 (OASL-4), the V1 trust-boundary
invariant.

## Invariant

A remote-originated operation may never reach `kicad-mcp-pro` unless the
`AuditEvent` authorizing it has been durably committed to SQLite first. If
that write fails for any reason, the daemon refuses the operation instead of
downgrading to best-effort logging. There is no configuration flag, log level
or environment variable that turns this off.

The same rule governs approvals: a high-risk operation approved over local
IPC executes only after its approval decision has been persisted.

There is therefore no "executed but unaudited" success state: either the
operation ran with a durable record already on disk, or it did not run and
the caller received a refusal.

## Read vs write

| Request class | Policy decision | Durable evidence required before `tools/call` | If persistence fails |
|---|---|---|---|
| Remote **write** (`*.write`, `manufacturing.export`, low/normal risk) | `Allow` | pre-execution audit event | refused; `tools/call` is never issued |
| Remote **read** (`*.read`, `erc`/`drc`/`validation` runs, low/normal risk) | `Allow` | pre-execution audit event | refused; `tools/call` is never issued |
| **High/critical risk**, any capability | `RequireApproval` | pre-execution audit event **and** the approval decision | not executed; the operation is re-queued for a retry |
| Any class | `Deny` | the audit write is attempted | the denial still applies (nothing executes); a persistence failure is reported to the local operator |

**Reads fail closed as well as writes.** The issue's minimum bar only demands
it for writes and high-risk operations, but allowing a read to run without its
audit record would create exactly the unaudited-execution state this work
exists to remove. Two further points make a read/write split unnecessary:

- Fail-closed is already how the rest of the pipeline treats storage
  failures: session and workspace lookups treat an unreadable store as
  "not found", which resolves to `Deny`, never to `Allow`.
- One invariant is verifiable with one test family; two behaviors would need
  two separate guarantees and two separate reviews.

The availability cost is bounded and visible: a refused read returns a typed
`AUDIT_STORAGE` response that a caller can show to a human, and the refusal
lasts exactly as long as the store is unwritable.

## What the remote caller sees

A refusal is a normal `operation.result` envelope with `success: false` and a
fixed, typed payload:

```json
{
  "operation_id": "…",
  "success": false,
  "result": {
    "error_class": "AUDIT_STORAGE",
    "error": "durable audit record could not be persisted; operation was not executed",
    "retryable": false,
    "executed": false
  }
}
```

- `error_class` is the stable `CompanionError` code of the audit error
  (`AUDIT_STORAGE`, `AUDIT_NOT_FOUND`) — typed, never a free-form string.
- Nothing derived from the storage error crosses the transport. SQL/OS error
  text (which may name local files or tables) and tool arguments are logged
  locally at best and are never echoed back; a test asserts the refusal
  payload equals the object above exactly.
- The same failure surfaces over local IPC as `DaemonError::AuditPersistence`
  with the audit error code, so the desktop/CLI can distinguish an audit-gate
  refusal from a generic internal error.

## Failures covered

Every failure mode below is exercised by a test that also asserts the
upstream `tools/call` counter stays at zero:

| Failure | How it is produced in tests |
|---|---|
| Disk full (`SQLITE_FULL`) | database capped at its current page count and filled until SQLite reports "database or disk is full" |
| Read-only store (`SQLITE_READONLY`) | `PRAGMA query_only = TRUE` on the daemon's own connection |
| Locked store (`SQLITE_BUSY`) | a second connection holds `BEGIN IMMEDIATE` for the whole test |
| Corrupt/missing audit schema | the `audit_events` table is dropped underneath the daemon |
| Injected persistence failure | `BEFORE INSERT`/`BEFORE UPDATE` trigger raising an abort |
| Replayed operation id | the same `operation_id` submitted twice; the `PRIMARY KEY` rejects the duplicate |
| Approval decision not persistable | read-only store (or injected failure) at approval time |

## Approvals, denials and recovery

- **Approvals are fail-closed and re-queued.** If the approval decision
  cannot be written, nothing executes, the caller gets a typed error, and the
  operation goes back into the pending queue so the decision can be retried
  after storage recovers. It is never executed on a best-effort approval and
  never silently dropped.
- **Denials are fail-safe and never resurrected.** By the time a denial is
  recorded the operation has already left the pending queue, so nothing can
  execute it. A denial that cannot be persisted therefore does *not* re-queue
  the operation — a forgotten denial must never become an executable
  operation — and the local operator receives the typed error instead.
- **No partial rows.** Each audit write is a single statement, so it either
  commits or leaves nothing behind; a failed write is retried against an
  unchanged table, and an enclosing transaction rolls the row back with it.
- **No deadlock path.** The storage mutex is never held across an `await`,
  the refusal path performs no further storage writes, and a blocked store
  delays the daemon by at most one bounded SQLite busy window (5s by
  default) before the refusal is returned.

## Not covered here

- **Post-execution status/duration updates.** The pre-execution record (the
  trust-boundary evidence) is already durable when the tool runs, so a failed
  follow-up update is reported as an operational error carrying the operation
  id for reconciliation instead of blocking work that already happened.
- **Restart/checkpoint recovery** of an interrupted execution is tracked
  separately, per the issue's non-goals.

## Where this lives

- Gate: `apps/daemon/src/remote_processor.rs` (`handle_operation_request`,
  `approve_pending_operation`, `deny_pending_operation`)
- Typed IPC error: `DaemonError::AuditPersistence` in
  `apps/daemon/src/errors.rs`
- Audit write semantics: `crates/audit/src/repository.rs`
- Tests: `audit_fail_closed_tests` in
  `apps/daemon/src/remote_processor.rs` and the failure/rollback tests in
  `crates/audit/src/repository.rs`
