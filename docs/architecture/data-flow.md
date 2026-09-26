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
8. Tool/operation capability and risk resolved from the same trusted contract
   -> unknown tool = DENY, no fallback
9. Capability checked against the grant's effective capabilities
10. Approval requirement evaluated (policy + risk); if required and not
    already granted for this operation, the operation moves to the daemon's
    PendingApproval queue and stops here until a local decision is made.
    That per-operation decision is distinct from standing authorization: it
    never activates, extends, or widens a grant (see
    [session-lifecycle.md](session-lifecycle.md))
11. AuditEvent durably recorded for the decision (Allow/Deny/RequireApproval).
    This is a gate, not a log line: if the record cannot be persisted the
    operation is refused here and step 12 never happens — for reads and
    writes alike (see [audit-fail-closed.md](../security/audit-fail-closed.md))
12. If Allow: OperationRequest forwarded to core-bridge -> kicad-mcp-pro
13. Result (or error) received, correlation id preserved
14. AuditEvent updated with execution status/duration (post-execution; the
    pre-execution record from step 11 is already durable, so a failure here
    is an operational error to reconcile, never an unaudited execution)
15. OperationResult returned over transport
```

Steps 3–10 are the policy engine's responsibility and are pure/deterministic
given `(OperationRequest, Session, WorkspaceAuthorization, reviewed tool-effect
contracts, current time, policy)` — see
[`crates/policy`](../../crates/policy). Step 11 is the durable audit gate and
is the one I/O step in the decision path: nothing downstream of it
(core-bridge, kicad-mcp-pro) is reached without both a policy `Allow` and a
committed audit record. Nothing upstream of the policy engine is trusted.

## What crosses each boundary

| Boundary | Data that crosses | Data that must NOT cross |
|---|---|---|
| Cloud ⇄ Gateway transport | Envelopes: pairing messages, session requests, `OperationRequest`/`OperationResult`, heartbeats | Private key material, raw project file contents beyond what a tool result legitimately returns, unrelated workspace paths |
| Gateway daemon ⇄ Desktop/CLI (local IPC) | Status, session/workspace/audit views, approval decisions | Private key material, raw secrets/tokens |
| Gateway ⇄ kicad-mcp-pro (loopback MCP) | `initialize`, `tools/list`, `tools/call` for the single authorized operation, with correlation id | Nothing about other sessions/workspaces; the bridge only ever performs the one operation policy allowed |
| Gateway ⇄ SQLite | Device metadata (public), workspaces, transport-era session records, access grants/leases, approvals, audit, checkpoint metadata, settings | Private key material (goes through `SecretStore`, never the DB) |

## Local-only data (never leaves the machine by default)

Project files, schematics, board contents, and audit records are not sent to
any remote service for analytics or telemetry. Telemetry is off by default
(see [privacy section of the README](../../README.md#privacy)). The only
data that leaves the machine during a remote session is what the approved
operation's own result legitimately contains, returned to the same session
that requested it.
