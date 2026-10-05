# Gateway Daemon Instructions

These instructions apply to `apps/daemon/**` and supplement the repository root `AGENTS.md`.

## Boundary

The daemon is the single authoritative local runtime. Desktop and CLI are clients of its local IPC
API; neither may short-circuit policy. Remote/cloud input is untrusted.

Read before material changes:

- `docs/architecture/data-flow.md`
- `docs/architecture/session-lifecycle.md`
- `docs/architecture/component-boundaries.md`
- `docs/security/trust-boundaries.md`
- `docs/security/audit-fail-closed.md`
- `docs/security/authorization-ttl.md`
- `docs/development/daemon-lifecycle.md`

## Authorization pipeline

Preserve the documented remote operation order. Do not skip, reorder, or short-circuit security
steps:

1. validate the inbound envelope and protocol limits;
2. resolve the persisted access grant for the subject;
3. reject inactive, expired, revoked, or spent authority;
4. verify workspace membership;
5. normalize tool arguments through the reviewed source-pinned effect contract;
6. enforce workspace containment on every derived path effect;
7. resolve capability and static risk from trusted policy;
8. evaluate reviewed dynamic risk rules;
9. require local approval when policy says so;
10. persist the required audit/approval evidence;
11. only then call the local core bridge.

Transport connectivity is not authority. A connect/reconnect event must not create, extend, widen,
revive, or migrate authorization by itself.

## Access grants and legacy sessions

Persisted `access_grants` are the authority model. Legacy session rows may be migrated through the
documented deterministic migration path, but do not add a runtime fallback that silently treats an
unmigrated legacy session as authority.

Revoked/expired grants are terminal. One-shot authority stays spent after use. A pending request
never becomes active because the transport flaps or reconnects.

## Approvals, races, and replay

- Revalidate security-sensitive state at approval/execution boundaries so session revocation,
  workspace removal, expiry, or competing state changes fail closed.
- Consumed approval/operation identifiers must not execute twice.
- Unknown session or operation approval requests are rejected.
- Do not turn a failed approval persistence into best-effort execution.
- A transport retry must not become a blind retry of a non-idempotent operation.

Maintain negative-path coverage for revoke-vs-execute, workspace-removal-vs-approval, replay, expiry,
and reconnect races when touching these paths.

## Audit is a gate

For remote-originated operations, durable pre-execution audit is mandatory for reads as well as
writes.

If audit persistence fails:

- do not issue `tools/call`;
- return the stable typed failure surface;
- do not leak SQL, filesystem, tool arguments, credentials, or local path details to the remote
  caller.

Approval persistence is fail-closed. Denials never resurrect because their audit write failed.

## IPC and secrets

Local IPC protocol identity/version checks are compatibility and security boundaries. Do not add a
TCP fallback or alternate privileged endpoint.

Do not expose:

- private keys or tokens;
- pairing secrets;
- raw credentials/proofs;
- operation arguments not explicitly approved for a safe view;
- local sensitive error context.

Keep agent-visible errors typed and bounded.

## Startup and recovery

Startup ordering and recovery checks are security behavior.

- Storage/identity/migrations must succeed before privileged serving begins.
- A second daemon for the same data directory must remain rejected.
- Unreadable required recovery/audit/checkpoint state must not be reported as clean recovery.
- Process restart changes process identity, not authorization history or device identity.

## Verification

Run focused daemon tests first, then:

```bash
cargo test -p kicad-mcp-gateway-daemon
cargo clippy -p kicad-mcp-gateway-daemon --all-targets -- -D warnings
cargo test --workspace
```

Live KiCad/MCP claims require the ignored live suite through the repository's documented
`--include-ignored` path or exact-head CI evidence; a zero-test green command is not live evidence.

## Definition of done

A daemon change is complete only when authorization state, workspace effects, approvals, durable
audit, replay/race behavior, IPC compatibility, recovery, error redaction, and core-bridge execution
remain aligned with the canonical pipeline.
