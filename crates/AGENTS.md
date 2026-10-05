# Workspace Crate Instructions

These instructions apply to `crates/**` and supplement the repository root `AGENTS.md`. More
specific instructions exist under `crates/policy/**` and `crates/core-bridge/**`.

## Responsibility matrix

Keep each crate single-purpose as defined by
`docs/architecture/component-boundaries.md`.

- `core`: strongly typed domain IDs/models, errors, and clock abstraction; no I/O, KiCad logic,
  or transport state.
- `protocol`: bounded/versioned wire and IPC types; no business policy or I/O.
- `identity`: device key lifecycle and secure-storage adapters; no session/workspace policy.
- `workspace`: authorized workspace records and canonical path containment; no risk/capability
  policy.
- `policy`: deterministic capability/effect/risk/TTL policy; no network, filesystem execution, or
  transport state.
- `sessions`: authorization/session state machines and persistence; consumes policy but does not
  invent policy decisions.
- `storage`: SQLite persistence and migrations for non-secret state only.
- `audit`: append-only/evidence persistence over storage; no policy decisions or risk
  recomputation.
- `transport`: transport abstraction/reconnect only; connectivity is not authority.
- `core-bridge`: local kicad-mcp-pro MCP adapter only; no arbitrary/public network targets and no
  KiCad domain logic.
- `checkpoints`: local conservative workspace snapshots; not a distributed revision system.

If one change gives a crate two unrelated reasons to change, stop and re-check the boundary.

## Fail-closed rules

- Do not add permissive fallbacks for unreadable policy, storage, identity, workspace, or
  authorization state.
- Unknown enum/protocol/policy cases should reject rather than guess when the canonical contract is
  closed.
- No `unwrap()`/`expect()` in request/security-handling paths merely to simplify error handling.
- Preserve bounded message/input sizes and typed error surfaces.
- Security-relevant state transitions need negative-path tests, not only success tests.

## Secret handling

Private signing-key material belongs only behind `SecretStore`.

Production identity must never silently fall back to:

- plaintext files;
- SQLite secret columns;
- mock/in-memory stores;
- logs, `Debug`, CLI output, IPC responses, audit rows, or transport payloads.

If the OS-native secret backend is unavailable, fail with the typed identity error.

Safe metadata such as public keys/fingerprints may be persisted only according to the documented
identity model.

## Workspace and filesystem safety

Canonicalize and enforce workspace boundaries using the workspace crate rather than ad-hoc prefix
checks.

Preserve defenses against traversal, foreign absolute paths, symlink escape, and effects derived
from untrusted arguments. Caller metadata is not a substitute for normalized Gateway-derived
effects.

## Storage and migrations

SQLite migrations are production code.

- Do not put secret key material into migrations or tables.
- Preserve forward migration behavior and startup failure semantics.
- This repository's migrations are SQLite. Do not add SQL Server-only syntax merely to satisfy
  hosted analyzer annotations; see the documented disposition in `CONTRIBUTING.md`.
- Migration fixes need migration tests and failure/compatibility evidence.

## Verification

Run the affected crate tests first, then the normal workspace gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Security/state-machine changes should include property, failure-injection, replay, boundary, or race
tests as appropriate.

## Definition of done

A crate change is complete only when its responsibility remains narrow, fail-closed behavior and
secret boundaries are preserved, tests cover invalid states, and downstream daemon/protocol
contracts still agree.
