# Data Flow

## Remote operation, end to end

Every remotely initiated privileged operation passes through this exact
pipeline. No step may be skipped, reordered, or short-circuited.

```
1. Message arrives on transport (untrusted input)
2. Envelope validated (protocol_version, size limits, well-formed payload)
3. Access grant resolved for the request's subject (`session_id`). The
   persisted `access_grants` row is the authority; a pre-migration
   `sessions` row is only ever used through the same deterministic adapter,
   and a subject with neither has no authority at all
4. Grant state machine checked: Active, not expired, not revoked, not a spent
   one-shot. Transport state is not consulted anywhere in this pipeline
5. Operation's target workspace checked against the grant's workspace_ids
6. Tool name + forwarded arguments normalized through the SHA-pinned, reviewed
   tool-effect contract into reads/writes/creates/deletes and absolute path
   effects; `OperationRequest.target_path` is ignored as caller metadata
   -> unknown argument, missing contract, or malformed effect = DENY
7. Workspace boundary enforced for every Gateway-derived effect path
   (canonicalized root, no traversal/symlink escape)
8. Tool capability and static base risk resolved from the same trusted
   source-pinned registry -> unknown tool = DENY, no fallback
9. Capability checked against the grant's effective capabilities
10. Operation risk assessed from the static floor plus explicit reviewed
    rules, using the already-normalized effects and forwarded arguments.
    Effective risk can only stay equal to or rise above base risk; malformed
    risk-relevant arguments = DENY. Policy version 2 currently has one rule:
    `pcb_delete_items.item_ids >= 2 -> High`
11. Approval requirement evaluated from effective risk. A High/Critical
    result becomes `RequireApproval`; the per-operation decision never
    activates, extends, or widens the standing grant (see
    [session-lifecycle.md](session-lifecycle.md))
12. AuditEvent durably recorded for Allow/Deny/RequireApproval, including
    effective risk plus immutable base risk, risk-policy version, and safe
    risk factors. This is a gate, not a log line: if persistence fails, the
    operation is neither executed nor queued for approval (see
    [audit-fail-closed.md](../security/audit-fail-closed.md))
13. If RequireApproval: store the same immutable `RiskAssessment` in the
    PendingApproval queue and stop until a local decision. Approval re-runs
    current policy and requires the assessment to match before execution; the
    original audit assessment is never rewritten
14. If Allow, or after a durably persisted valid local approval:
    OperationRequest forwarded to core-bridge -> kicad-mcp-pro
15. Result (or error) received, correlation id preserved
16. AuditEvent updated with execution status/duration. This post-execution
    update never replaces the pre-execution risk assessment
17. OperationResult returned over transport
```

Steps 3–11 are the policy engine's responsibility and are pure/deterministic
given `(OperationRequest, AccessGrant, WorkspaceAuthorization, reviewed
tool/effect/risk contracts, current time, policy)` — see
[`crates/policy`](../../crates/policy). Step 12 is the durable audit gate and
is the one I/O step in the decision path: nothing downstream of it is executed
or queued for approval without a committed record. Nothing upstream of the
policy engine is trusted.

## What crosses each boundary

| Boundary | Data that crosses | Data that must NOT cross |
|---|---|---|
| Cloud ⇄ Gateway transport | Envelopes: pairing messages, session requests, `OperationRequest`/`OperationResult`, heartbeats | Private key material, raw project file contents beyond what a tool result legitimately returns, unrelated workspace paths |
| Gateway daemon ⇄ Desktop/CLI (local IPC) | Status, session/workspace/audit views, approval decisions, effective/base risk, risk-policy version, safe reviewed factor metadata | Private key material, raw secrets/tokens, raw operation arguments such as item IDs or paths |
| Gateway ⇄ kicad-mcp-pro (loopback MCP) | `initialize`, `tools/list`, `tools/call` for the single authorized operation, with correlation id | Nothing about other sessions/workspaces; the bridge only ever performs the one operation policy allowed |
| Gateway ⇄ SQLite | Device metadata (public), workspaces, transport-era session records, access grants/leases, approvals, audit including immutable risk assessment evidence, checkpoint metadata, settings | Private key material (goes through `SecretStore`, never the DB), raw argument values copied only for risk explanation |

## Local-only data (never leaves the machine by default)

Project files, schematics, board contents, and audit records are not sent to
any remote service for analytics or telemetry. Telemetry is off by default
(see [privacy section of the README](../../README.md#privacy)). The only
data that leaves the machine during a remote session is what the approved
operation's own result legitimately contains, returned to the same session
that requested it.
