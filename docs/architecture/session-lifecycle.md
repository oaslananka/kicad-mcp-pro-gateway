# Session Lifecycle and Authorization Authority

Two different things in Gateway have two different names, and this document
keeps them apart:

- **Transport connectivity** — is the pipe to the relay up? Modelled as
  [`TransportState`](../../crates/core/src/transport_state.rs) and reported
  as `transport_state` in every API view. It says nothing about access.
- **Authorization authority** — is this principal, on this device, allowed to
  do this, until when? Modelled as an [`AccessGrant`](../../crates/core/src/authorization.rs)
  (and the narrower [`AuthorizationLease`](../../crates/core/src/authorization.rs)
  it can cut), persisted in `access_grants` / `authorization_leases`.

A relay pipe can drop, reconnect, and be replaced while an unexpired,
unrevoked grant keeps its authority. And revoking or expiring a grant does
not disconnect the pipe. Neither direction ever implies the other.

## The rule both directions rest on

> Transport connect/disconnect/reconnect must not mint, extend, refresh,
> widen, or resurrect authorization, and revoking/expiring authorization must
> not disconnect transport.

This is enforced structurally, not by convention:

- [`AuthorizationEvent`](../../crates/sessions/src/grant_machine.rs) has no
  transport variant. There is no `Connected`, `Reconnected`, `Pair`, or
  `RequestAccess` arm, so the machine that owns authority cannot be called
  with a connectivity fact.
- [`companion_sessions::transport_boundary`](../../crates/sessions/src/transport_boundary.rs)
  folds connectivity events into the existing `TransportState` model. Its
  signatures take and return no grant, so it cannot touch one.
- The policy engine ([`evaluate_with_grant`](../../crates/policy/src/engine.rs))
  receives a grant and nothing else. It has no access to transport state.
- A remote access request creates a grant in `PendingApproval`, which carries
  no authority. Only a local user's decision moves it to `Active`.

## Access grant states

```
PendingApproval --Approve--> Active <--Resume-- Suspended <--Suspend-- Active
       |                        |                                    |
   Deny/Revoke            CheckExpiry                          CheckExpiry
       v                        v                                    v
    Revoked                  Expired                             Expired
                            (terminal)                          (terminal)
     (terminal)   Active --ConsumeLease--> Consumed   (one-shot only, terminal)
```

| From | To | Trigger | Guard |
|---|---|---|---|
| — | `PendingApproval` | remote principal requests access over a transport | device id matches the persistent local identity; workspace is authorized; TTL already policy-bounded |
| `PendingApproval` | `Active` | local user approves | `approved_at` stamped; no transport fact required |
| `PendingApproval` | `Revoked` | local user denies | reason recorded |
| `Active` | `Suspended` | user presses pause | `expires_at` unchanged — suspension never extends a TTL |
| `Suspended` | `Active` | user resumes | explicit local action, never automatic |
| `PendingApproval` \| `Active` \| `Suspended` | `Expired` | `now >= expires_at` | checked on every operation and on every `CheckExpiry`; a pending request that outlives its TTL can never be approved afterwards |
| any non-terminal | `Revoked` | user revokes | immediate, irreversible for that grant id, `revoked_at` + reason recorded |
| `Active` (one-shot) | `Consumed` | the single lease is spent | only for `issued_lease_id`; a standing grant is never consumed this way |

`Revoked`, `Expired` and `Consumed` are terminal. Resuming access requires a
new grant — a new `grant_id` and a new local approval.

## What a grant carries

`grant_id`, `subject_session_id` (correlation only), `device_id`,
`principal` + `principal_assurance`, `workspace_ids`, `capability_profile`,
`effective_capabilities`, `task_scope`, `grant_kind`
(`standing` \| `one_shot`), `issued_at`, `approved_at`, `expires_at`,
`revoked_at`, `revocation_reason`, `consumed_at`, `issued_lease_id`,
`risk_policy_version`, `approval_policy`, `status`,
`migrated_from_session_id`, `migration_note`.

`PrincipalAssurance` has exactly one value, `Unverified`: nothing in this
repository performs a remote-principal verification handshake, so no grant
may claim more. A UI must render it as what it is.

## Leases, and why they are not "allow once"

An `AuthorizationLease` is a *narrower* record cut from a grant: same device,
same principal, a subset of the granted workspaces, a subset of the granted
capabilities, and an expiry no later than the grant's own. `validate_against`
re-checks the grant, so revoking, suspending, or expiring the grant
invalidates every lease cut from it.

- A `standing` grant may cut further leases, each bounded by the grant.
- A `one_shot` grant may cut exactly one. It is refused a second time, and it
  becomes `Consumed` when that lease is spent.

A per-operation "allow once" (`IpcRequest::ApproveOperation`) is a **different
mechanism**: it approves one already-pending high-risk operation inside an
existing grant and is applied at the operation layer. It never appears in
`AuthorizationEvent`, and `apply_grant_decision` rejects it with
`AUTHORIZATION_NOT_A_GRANT_LEVEL_DECISION`, so it cannot leave standing
authority behind.

## Mapping from transport-era sessions

The `sessions` table and the `Session`/`SessionEvent` model are retained as a
compatibility and audit surface. `migrate_legacy_sessions`
([`crates/sessions/src/migration.rs`](../../crates/sessions/src/migration.rs))
maps them onto grants deterministically at every daemon start:

| Legacy `SessionStatus` | Mapped grant | Note |
|---|---|---|
| `Unpaired`, `Paired`, `Connected`, `Disconnected` | **none** | these rows never carried authority; nothing is minted. A remote must re-request and a user must approve |
| `PendingApproval` | `PendingApproval` | still awaiting a decision |
| `Active` | `Active` | requires a recorded approval, else refused |
| `Suspended` | `Suspended` | |
| `Expired` | `Expired` | terminal, preserved |
| `Revoked` | `Revoked` | terminal, preserved; `revoked_at` is left empty and `migration_note` says the legacy row never recorded one |

Fail-closed rules, all of them refusals to mint authority:

- An internally inconsistent row — active with no approval, no workspace, or
  a non-positive lifetime — is refused and reported; that subject has no
  authority until a fresh request is approved.
- `grant_id` is derived from the legacy row id, so re-running the migration
  addresses the same grant instead of forking a second copy.
- An existing grant is **never overwritten**. The legacy row predates it, so
  re-deriving a revoked grant from a stale `Active` row would resurrect
  authority this build already took away. A revocation therefore survives any
  number of restarts.

`PolicyEngine::evaluate(&Session, …)` exists only as the same adapter for
callers that still hold a legacy row: it maps the row to a grant and then
decides on the grant.

## Schema version and migration

`companion_storage::SCHEMA_VERSION` is the number of applied migrations
(`2`: `0001_init.sql`, then the additive `0002_authorization.sql`). A database
file written by a newer build is refused with
`STORAGE_SCHEMA_FROM_NEWER_BUILD` *before* anything is applied, rather than
partially interpreted. `0002` only creates `access_grants`,
`authorization_leases`, and their indexes; it drops and rewrites nothing, so
pre-migration rows, revocations, and audit references keep resolving.

## Relationship to policy

The grant state machine answers "is this principal authorized right now".
It does not answer "is this specific operation allowed" — that is the
[policy engine](../../crates/policy)'s job, which additionally checks
workspace authorization, capability mapping, and risk/approval requirements
per `OperationRequest`. Before a grant is created, the same policy layer
bounds its requested lifetime by the local profile/risk TTL ceilings in
[Authorization TTL policy](../security/authorization-ttl.md). That
policy-bounded `expires_at` is what the approver sees and what is persisted.

## References

- [Outbound Relay Security Contract](../security/outbound-relay-contract.md)
- [Trust Boundaries](../security/trust-boundaries.md)
- [Data Flow](data-flow.md)
