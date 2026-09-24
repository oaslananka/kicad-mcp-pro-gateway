# Testing

Gateway is a security boundary, so it is test-heavy by requirement, not by
preference. Prefer TDD: write the failing test first, especially for policy,
session-state, and workspace-boundary code.

## Running tests

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Frontend (once `apps/desktop` has a frontend):

```
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm sidecar:dev
cargo test --manifest-path src-tauri/Cargo.toml --all-targets --locked
```

`sidecar:dev` is required before direct Tauri Cargo commands because
`tauri-build` verifies that the configured `externalBin` resource for the host
target exists. Tauri CLI build/dev commands run the equivalent staging step via
`beforeBuildCommand` / `beforeDevCommand`.

## Deterministic time

Session expiry, approval windows, and reconnect backoff are all driven
through the `Clock` trait in `crates/core`. Tests use `FakeClock`, which is
advanced explicitly (`clock.advance(Duration)`); no test should depend on
`std::thread::sleep` to observe expiry.

## Required unit coverage (minimum)

- device identity lifecycle (create, load, never-plaintext secret)
- session state transitions, including every explicit non-transition in
  [session-lifecycle.md](../architecture/session-lifecycle.md)
- expiration under advanced fake clock
- revocation is terminal and survives reconnect
- capability intersection / profile expansion
- unknown capability denial, unknown tool denial
- risk classification per operation kind
- approval requirement enforcement (including "allow once")
- workspace path escape prevention: `..`, symlink escape, Windows drive
  paths (`C:\project` vs `C:\project-evil`), mixed separators, Unicode
  edge cases — naive `path.starts_with(root_str)` is explicitly forbidden
  and tested against
- audit event creation for allow/deny/require-approval/execute outcomes
- pre-execution audit persistence failure fails closed: disk-full,
  read-only, locked, corrupt and injected storage failures all refuse the
  operation with the upstream `tools/call` count unchanged, and a failed
  approval decision refuses approved execution (see
  [audit-fail-closed.md](../security/audit-fail-closed.md))
- config parsing and precedence (flags > env > file > defaults)
- error redaction (no secret ever appears in a `Display`/`Debug` impl that
  can reach logs, CLI output, or IPC responses)
- transport reconnect state transitions and backoff bounds
- replay protection for any signed/nonce-bearing protocol message

## Integration coverage (minimum)

- CLI ⇄ daemon local IPC (status, workspace, session, audit commands)
- daemon ⇄ explicitly enabled mock transport (session request/approve/revoke and reconnect lifecycle)
- daemon ⇄ mock/fake kicad-mcp-pro endpoint (initialize, tools/list,
  tools/call, timeout, error mapping)
- full pairing flow: unpaired → pending → paired
- full session flow: request → approve → active → operation → audit → revoke
- expiration flow: active → clock advance → operation denied
- workspace escape flow: valid workspace vs malicious target outside it
- high-risk flow: valid session + permitted capability + high-risk operation
  → additional approval required → allow-once → operation runs
- revocation flow: active → revoke → reconnect transport → operation still
  denied

## End-to-end

The full vertical slice described in the top-level design spec
(`docs/superpowers/specs/2026-09-16-companion-v1-design.md`) is automated as
an integration test under `tests/` using the mock relay and mock
kicad-mcp-pro server, not a manual/GUI-only check.

## What CI enforces

See `.github/workflows/ci.yml`. The repository declares Rust 1.88 as its MSRV;
CI runs `cargo check --workspace --all-targets --locked` and the desktop Tauri
crate with Rust 1.88.0 in addition to the stable-toolchain matrix. The native
Rust matrix runs the daemon lifecycle/IPC test on Linux, macOS, and Windows.
A separate desktop matrix builds `.deb`, `.dmg`, and `.msi` packages, verifies
that each contains its target-qualified daemon sidecar, and uploads the
unsigned package as evidence. `cargo clippy --workspace --all-targets -- -D
warnings` must be clean; no `unwrap()`/`expect()` is permitted in
request/security-handling paths without a comment justifying the
impossibility statically (and even then it is discouraged — prefer a typed
error). Live-KiCad tests (which require a real KiCad/kicad-mcp-pro install)
are excluded from the default CI run and gated behind a separate opt-in job.

## Tool-registry reconciliation

`crates/policy/assets/tool_registry.toml` is the authorization allowlist.
Discovery never adds permissions. The separate
`upstream_tool_snapshot.toml` records the public upstream surface at an exact
kicad-mcp-pro commit so CI can detect stale registry entries while leaving
new/unclassified tools fail-closed.

Refresh the snapshot from a checked-out upstream commit:

```bash
UPSTREAM=/path/to/kicad-mcp-pro
SHA=$(git -C "$UPSTREAM" rev-parse HEAD)
cargo run -p companion-policy --bin reconcile-tool-registry -- \
  "$UPSTREAM/docs/tools-reference.generated.md" "$SHA" \
  crates/policy/assets/upstream_tool_snapshot.toml
```

For an optional live comparison, start kicad-mcp-pro on a loopback HTTP
endpoint, then run the ignored probe:

```bash
KICAD_MCP_LIVE_ENDPOINT=http://127.0.0.1:3334/mcp \
  cargo test -p kicad-mcp-gateway-daemon \
  --test tool_reconciliation \
  live_core_can_be_reconciled_without_granting_unknown_tools \
  -- --ignored --nocapture
```

The live report is profile-dependent. `registry_not_live` therefore means
"not exposed by this active server/profile", not automatically "stale".
`live_not_snapshot` detects a live tool absent from the pinned public catalog;
`snapshot_not_live` shows public tools omitted by the active profile. Staleness
is evaluated against the SHA-pinned public-tool snapshot. Any live tool that
is unclassified remains denied by `ToolCapabilityResolver`.
