# Data Flow

## Remote operation, end to end

Every remotely initiated privileged operation passes through this exact
pipeline. No step may be skipped, reordered, or short-circuited.

```
1. Message arrives on transport (untrusted input)
2. Envelope validated (protocol_version, size limits, well-formed payload)
3. Session resolved by session_id
4. Session state machine checked: Active, not expired, not revoked
5. Operation's target workspace checked against session.workspace_ids
6. Workspace path boundary enforced (canonicalized root, no traversal/symlink escape)
7. Tool/operation name resolved to a Capability via ToolCapabilityResolver
   -> unknown tool = DENY, no fallback
8. Capability checked against session's effective capabilities
9. Risk classified for the operation
10. Approval requirement evaluated (policy + risk); if required and not
    already granted for this operation, session moves the operation to
    PendingApproval and stops here until a local decision is made
11. AuditEvent recorded for the decision (Allow/Deny/RequireApproval)
12. If Allow: OperationRequest forwarded to core-bridge -> kicad-mcp-pro
13. Result (or error) received, correlation id preserved
14. AuditEvent updated with execution status/duration
15. OperationResult returned over transport
```

Steps 3–11 are the policy engine's responsibility and are pure/deterministic
given `(OperationRequest, Session, WorkspaceAuthorization, capability
mapping, risk classification, current time, policy)` — see
[`crates/policy`](../../crates/policy). Nothing upstream of the policy engine
is trusted; nothing downstream of it (core-bridge, kicad-mcp-pro) is reached
without a policy `Allow`.

## What crosses each boundary

| Boundary | Data that crosses | Data that must NOT cross |
|---|---|---|
| Cloud ⇄ Gateway transport | Envelopes: pairing messages, session requests, `OperationRequest`/`OperationResult`, heartbeats | Private key material, raw project file contents beyond what a tool result legitimately returns, unrelated workspace paths |
| Gateway daemon ⇄ Desktop/CLI (local IPC) | Status, session/workspace/audit views, approval decisions | Private key material, raw secrets/tokens |
| Gateway ⇄ kicad-mcp-pro (loopback MCP) | `initialize`, `tools/list`, `tools/call` for the single authorized operation, with correlation id | Nothing about other sessions/workspaces; the bridge only ever performs the one operation policy allowed |
| Gateway ⇄ SQLite | Device metadata (public), workspaces, sessions, approvals, audit, checkpoint metadata, settings | Private key material (goes through `SecretStore`, never the DB) |

## Local-only data (never leaves the machine by default)

Project files, schematics, board contents, and audit records are not sent to
any remote service for analytics or telemetry. Telemetry is off by default
(see [privacy section of the README](../../README.md#privacy)). The only
data that leaves the machine during a remote session is what the approved
operation's own result legitimately contains, returned to the same session
that requested it.
