# Session Lifecycle

A **session** is the only thing that ever grants a remote principal the
ability to invoke a policy-mediated operation. Pairing establishes device
trust; it does not grant operational access. A transport connection proves
the pipe is authenticated; it does not grant operational access either.

## States

```
Unpaired -> Paired -> Disconnected -> Connected -> PendingApproval -> Active
                                          ^                              |
                                          |                              v
                                     Suspended <--------------------- Active
                                                                          |
                                                              +-----------+-----------+
                                                              v                       v
                                                          Expired                 Revoked
```

`Revoked` is terminal for that `SessionId`. No transition leaves `Revoked`.
`Expired` is terminal for that `SessionId` unless a new session is explicitly
re-approved (a new `SessionId` is minted; the old one is never reused).

## Transition table

| From | To | Trigger | Guard |
|---|---|---|---|
| `Unpaired` | `Paired` | account/device registration succeeds | valid signed device proof consumed exactly once |
| `Paired` | `Disconnected` | initial state after pairing, before any transport | — |
| `Disconnected` | `Connected` | authenticated transport established | transport handshake verified; does **not** imply any workspace/capability grant |
| `Connected` | `PendingApproval` | remote requests access to a workspace/profile/task | request is well-formed, carries the persistent local `device_id`, and references an authorized workspace |
| `PendingApproval` | `Active` | local user approves | approval decision recorded; `issued_at`/`expires_at` set |
| `PendingApproval` | `Revoked` | local user denies, or approval window times out | — |
| `Active` | `Suspended` | user presses Pause, or transport becomes unsafe (e.g. reconnect storm, integrity check failure) | — |
| `Suspended` | `Active` | user explicitly resumes | resume is a distinct local action, never automatic |
| `Suspended` | `Revoked` | user revokes while suspended | — |
| `Active` | `Expired` | `now >= expires_at` | checked on every operation, not only on a timer |
| `Active` \| `PendingApproval` \| `Suspended` \| `Connected` | `Revoked` | user revokes | revocation is immediate and irreversible for that session id |
| `Connected` | `Disconnected` | transport drops | session state (if any) is preserved; reconnect re-enters at `Connected`, never at `Active` |

## Explicit non-transitions (must be tested as regressions)

- Reconnecting a transport **never** moves a session directly to `Active`.
  A dropped-then-restored transport lands in `Connected`; a fresh
  `PendingApproval` → `Active` cycle is required to resume operational access
  unless the prior session is still `Active`/`Suspended` and unexpired, in
  which case the *existing* session record is what continues — no new
  implicit grant is created.
- `Revoked` and `Expired` sessions cannot be mutated back to any other state.
- An `Active` session that fails an expiration check mid-operation is
  downgraded to `Expired` before the operation is evaluated further; the
  operation is denied, not queued.

## What a session carries

`session_id`, `device_id`, `remote_principal`, authorized `workspace_ids`,
`capability_profile`, effective `capabilities`, `task_scope`, `issued_at`,
`approved_at`, `expires_at`, `risk_policy_version`, `approval_policy`,
`status`. See [`crates/core`](../../crates/core) for the typed definitions.

## Relationship to policy

The state machine only answers "is this session usable right now." It does
not answer "is this specific operation allowed" — that is the
[policy engine](../../crates/policy)'s job, which additionally checks
workspace authorization, capability mapping, and risk/approval requirements
for every individual `OperationRequest`. Before a session is created, the same
policy layer also bounds its requested lifetime by the local profile/risk TTL
ceilings documented in [Authorization TTL policy](../security/authorization-ttl.md).
The policy-bounded `expires_at` is what the approver sees and what is durably
persisted.

## References
- [Outbound Relay Security Contract](../../security/outbound-relay-contract.md)
