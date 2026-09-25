# Threat Model

## Assets

- The user's local filesystem, specifically authorized workspace roots.
- KiCad project integrity (schematics, PCB layout, manufacturing artifacts).
- Device private key material.
- Session/approval state (who is allowed to do what, until when).
- Audit history (evidence of what happened).

## Trust levels

| Actor | Trust | Rationale |
|---|---|---|
| Local user (via desktop UI / CLI) | Trusted | Physical/session access to the machine; the only actor who can approve, pause, revoke |
| Gateway daemon | Trusted, authoritative | Owns and enforces the policy boundary |
| kicad-mcp-pro (local) | Trusted for its own domain, not for authorization | It executes what Gateway forwards; it does not decide what's allowed |
| Cloud relay / remote AI agent | **Untrusted input**, always | Everything arriving over the transport is treated as attacker-controlled until proven otherwise by session + policy checks |
| Another local process on the same machine | Partially untrusted | Local IPC must not be reachable by an arbitrary unauthenticated local process with no relationship to the daemon's state directory |

## Primary threats and mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | Cloud-originated input executes without going through policy | Every operation path is required to pass through the pipeline in [data-flow.md](../architecture/data-flow.md); there is no direct route from transport to core-bridge |
| T2 | Session accesses a workspace it wasn't approved for | Policy engine checks `OperationRequest.workspace_id ∈ session.workspace_ids` before anything else workspace-related |
| T3 | Path traversal / symlink escape out of an authorized workspace | Policy derives path effects from the pinned tool contract and caller arguments, then applies canonicalized-root containment to every derived path; explicit tests cover `..`, symlinks, foreign absolute syntax, mixed separators, multi-path values, and Unicode — see [`crates/policy`](../../crates/policy) and [`crates/workspace`](../../crates/workspace) |
| T4 | Expired session still executes an operation | Expiry is checked at evaluation time on every request, not only via a background timer |
| T5 | Revoked session becomes active again after reconnect | Reconnect restores transport only; it never restores or re-derives session status. `Revoked` is a terminal, permanent state for that `SessionId` |
| T6 | Unknown, unregistered, or effect-unmodelled tool is executed | `ToolCapabilityResolver` denies by default, and policy additionally requires a source-pinned reviewed effect contract; unknown arguments and contracts with no normalized effects fail closed |
| T7 | Manufacturing/export capability obtained via generic write access | Manufacturing capabilities are modeled as distinct from `*.write` capabilities; profiles never imply them by default |
| T8 | Secret material (private keys, tokens) leaks via logs, CLI `--verbose`, IPC responses, or Debug output | `SecretStore` abstraction, no plaintext private key in SQLite ever, sensitive types avoid `Debug`/redact it, dedicated tests assert this |
| T9 | Malformed/oversized remote input crashes or resource-exhausts the daemon | Envelope size limits, strict parsing (reject unknown message types rather than best-effort), no unbounded allocation from remote-controlled sizes |
| T10 | Inbound public listener becomes an attack surface | No inbound TCP listener is opened; local IPC binds only to a named pipe / Unix-domain socket, and all cloud connectivity is outbound-initiated |
| T11 | UI or CLI bypasses daemon authorization | Both are thin clients over the same local IPC API; neither embeds policy logic |
| T12 | Multiple daemon instances corrupt shared state | Exclusive OS advisory lock against the state directory before any DB/identity mutation; clients require a matching product/protocol/version identity before forwarding privileged IPC |
| T13 | High-risk operation executes without an extra approval step | Risk is modeled separately from capability; `RequireApproval` results are enforced even when the session already holds the capability |
| T14 | Replay of a captured protocol message | Protocol envelopes carry `message_id`/`correlation_id`/`timestamp`; state-changing message handling is designed for replay detection once a real relay exists (see [protocol/README.md](../protocol/README.md)) |
| T15 | Arbitrary shell / arbitrary filesystem access via a "convenience" tool mapping | Forbidden outright in V1; not modeled as a capability at all |
| T16 | Relay traffic intended for another registered device is accepted locally | `session.request` and `operation.request` envelopes must carry the persistent local `device_id`; operation requests are additionally checked against `session.device_id` before policy evaluation can lead to execution |
| T17 | An operation executes although the audit evidence for it could not be durably recorded | Fail-closed pre-execution audit gate: no `tools/call` and no approval execution without a committed record, reads and writes alike, with approval decisions persisted before execution — see [audit-fail-closed.md](audit-fail-closed.md) |
| T18 | Desktop/CLI starts a stale or substituted local daemon | Launch paths are fixed to the Tauri `externalBin` or packaged CLI sibling; a bounded identity/version handshake runs on the same connection as every privileged request, and an incompatible endpoint never triggers a process/endpoint fallback |

## Explicitly out of scope for V1 (tracked, not solved here)

- Multi-tenant/team collaboration abuse (no multi-human collaboration in V1).
- Supply-chain compromise of kicad-mcp-pro itself (out of this repo's
  boundary; tracked upstream).
- Physical/OS-level compromise of the user's machine (secure storage
  mitigates key exfiltration but cannot defend against a fully compromised
  OS).

## Review checklist

The [security review checklist](../../README.md#security-review-checklist)
in the README is the running acceptance gate for this threat model and is
re-verified before any release claim.
