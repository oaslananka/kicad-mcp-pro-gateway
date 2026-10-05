# Repository Agent Router

This repository is a security boundary. Use this file as a router to the canonical architecture,
security, testing, and release contracts; do not turn it into a duplicate engineering manual.

## Scope and precedence

- This file applies repository-wide.
- Nested `AGENTS.md` files add or narrow instructions for their subtree; the closest applicable
  file wins.
- Nested instructions must not weaken fail-closed authorization, audit, workspace, identity,
  protocol, release, or evidence constraints unless the underlying canonical policy is intentionally
  changed in the same work.
- Executable repository policy and tests remain authoritative if prose drifts.

Nested operational boundaries:

- `apps/daemon/AGENTS.md` — authoritative execution pipeline, authorization state, approvals,
  durable audit, IPC, recovery, and remote request processing.
- `apps/desktop/AGENTS.md` — local-IPC-only desktop, packaged daemon sidecar, lifecycle,
  compatibility, vendored Tauri/GTK security patches, and packaging.
- `crates/AGENTS.md` — crate responsibility matrix and shared security rules.
- `crates/policy/AGENTS.md` — source-pinned tool/effect contracts, capability policy, risk, and
  authorization TTL.
- `crates/core-bridge/AGENTS.md` — loopback-only kicad-mcp-pro client and MCP protocol lanes.
- `.github/AGENTS.md` — required checks, workflow security, live evidence, release engineering,
  signing, provenance, and promotion.

## Start here

- `docs/architecture/system-overview.md`
- `docs/architecture/component-boundaries.md`
- `docs/architecture/data-flow.md`
- `docs/architecture/session-lifecycle.md`
- `docs/security/trust-boundaries.md`
- `docs/security/threat-model.md`
- `docs/security/tool-effect-contracts.md`
- `docs/development/testing.md`
- `docs/architecture/compatibility-matrix.md`
- `docs/development/release.md`

## Non-negotiable invariants

- Transport is not authorization.
- Unknown or unclassified tools/effects/arguments deny by default.
- Caller-supplied `OperationRequest.target_path` is not authorization evidence.
- Gateway-derived filesystem effects must remain inside authorized workspace boundaries.
- No remote `tools/call` may execute before the required durable pre-execution audit record exists.
- Reconnect never resurrects revoked, expired, spent, or never-approved authority.
- Device private keys never fall back to plaintext persistence.
- The core bridge remains loopback-only and must not become a general network proxy.
- Gateway does not implement KiCad domain logic; that belongs in `kicad-mcp-pro`.
- No inbound internet-facing listener is introduced by convenience fallback.
- A green workflow is evidence only when the intended tests actually executed.

## Development contract

Before handoff, run the relevant focused tests and, when the pinned toolchain is available:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Desktop changes also use the commands in `apps/desktop/AGENTS.md`.

Do not add analyzer suppressions merely to clear findings. Do not claim stable-release,
cross-platform live-KiCad, clean-machine, signing, or manufacturing evidence beyond what the
repository's exact artifacts and recorded qualification actually prove.
