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

## Property and fuzz testing

The trust-boundary parsers are covered by `proptest` property targets, because
their input space is far larger than any example list: a panic, a hang, an
unbounded allocation, or a fail-open classification at one of these boundaries
is a defect, not a flake. Property coverage does not replace the explicit
security regression tests listed further down — it covers the inputs those
examples cannot.

### Maintained targets

| Boundary | Target | Invariants |
| --- | --- | --- |
| local IPC framing and its size limit | `crates/protocol/tests/property_codec.rs` | a read consumes exactly one newline-delimited frame and agrees with `serde_json` on that line; a payload of exactly `MAX_MESSAGE_BYTES` is writable, the first byte over it is refused, and a refused write emits nothing; oversized input is refused after reading only the limit |
| transport envelope | `crates/protocol/tests/property_codec.rs` | every `MessageType` round-trips through the codec with every field intact; version compatibility is decided by the major component alone |
| local IPC request surface | `crates/protocol/tests/property_codec.rs` | an unknown request tag never decodes; a nested tag is payload data, not a second verb; an id from another domain never decodes as a session id, and every accepted spelling normalizes to one identity |
| workspace path boundary | `crates/workspace/tests/property_tests.rs` | a request resolves exactly when its lexically normalized form is inside the root, and then resolves to that form; a sibling directory sharing the root's name prefix is never inside; a symlink inside the root resolves and one pointing outside is refused (Unix) |
| tool registry and effect manifest | `crates/policy/tests/property_registry.rs` | arbitrary and single-byte-mutated manifest text never panics, and never yields a capability, risk, or effect the source did not declare; a capability, risk, or effect outside its closed set is always a load error; an effect contract loads only when source, arguments, effects, and path arguments are all declared |
| operation-effect normalization | `crates/policy/tests/operation_effects.rs` | every member of a multi-path argument is normalized; generated workspace-relative paths satisfy containment; a non-string member denies normalization |

### Corpora

Two mechanisms, both deliberate:

- Each target carries a `historical_*` corpus: the inputs that have actually
  reached that boundary (traversal and sibling-collision attempts, foreign
  absolute syntax, mixed separators, NUL and Unicode look-alikes, split and
  CRLF frames, lowercase and cross-domain ids, capability and effect
  near-misses, partially declared manifests). They are enumerated in code so
  they run on every run instead of only when the generator happens to produce
  them.
- `proptest` persists a minimized failing input to
  `<test-file>.proptest-regressions` beside the target. Commit that file with
  the fix: it is replayed before any new case is generated, so the finding
  stays a regression.

### Bounded CI lane

`cargo test --workspace` runs every property target with proptest's default 256
cases per property. The size-limit property is pinned to 8 cases by its own
`proptest_config`, because its interesting inputs are the byte counts either
side of the limit rather than 256 random ones, and each case pushes over a
megabyte through the codec. The whole property suite is a few seconds of the
CI test step. Nothing in this lane is time- or thread-dependent, so a failure
replays from its persisted seed.

### Longer lane (manual or scheduled)

Not part of routine CI, and never a release gate — a long run is for finding
new inputs, not for blocking a merge on a timeout. Run it locally, or wire it
into a scheduled (non-required) job:

```bash
PROPTEST_CASES=20000 cargo test -p companion-protocol --release \
  --test property_codec --test property_tests
PROPTEST_CASES=20000 cargo test -p companion-policy --release \
  --test property_registry --test operation_effects
PROPTEST_CASES=20000 cargo test -p companion-workspace --release \
  --test property_tests
```

This widens the generated case count only; a property that pins its own
`proptest_config` keeps that bound.

### Reproducing and minimizing a finding

```bash
# replay the persisted corpus for one target
cargo test -p companion-protocol --test property_codec

# re-run the exact random stream a failure came from
PROPTEST_CASES=1 PROPTEST_RNG_SEED=<seed> \
  cargo test -p companion-protocol --test property_codec -- --nocapture

# shrink harder when the minimized input is still too large to read
PROPTEST_MAX_SHRINK_ITERS=100000 cargo test -p companion-protocol \
  --test property_codec -- --nocapture
```

`--nocapture` prints the minimized input and, when one is generated, the
`cc <hex>` line to paste into the target's `.proptest-regressions` file.

## Required unit coverage (minimum)

- device identity lifecycle (create, load, never-plaintext secret)
- session state transitions, including every explicit non-transition in
  [session-lifecycle.md](../architecture/session-lifecycle.md)
- profile/risk authorization TTL ceilings, integer boundaries, persistence of
  the effective expiry, and fail-closed malformed policy configuration (see
  [authorization-ttl.md](../security/authorization-ttl.md))
- expiration under advanced fake clock
- revocation is terminal and survives reconnect
- capability intersection / profile expansion
- unknown capability denial, unknown tool denial
- trusted operation-effect normalization for read/write/create/delete contracts
- unknown or missing effect-contract denial before capability/risk evaluation
- workspace containment for every argument-derived path, including traversal,
  symlink, mixed-separator, single-path, and multi-path regressions
- proof that `target_path` cannot override or omit argument-derived effects
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
- caller/argument mismatch flow: safe caller `target_path` vs escaping argument
  path is denied and never reaches `tools/call`
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

`crates/policy/assets/tool_registry.toml` is the authorization allowlist and
the reviewed source of operation-effect contracts. Discovery never adds
permissions. The separate `upstream_tool_snapshot.toml` records the public
upstream surface at an exact kicad-mcp-pro commit. Daemon startup rejects a
registry whose repository/ref/SHA metadata differs from that snapshot or whose
allowlist contains a stale tool. Newly unclassified tools remain unknown and
denied. A known tool also remains denied when its effect contract is absent.
See [`docs/security/tool-effect-contracts.md`](../security/tool-effect-contracts.md)
for the reviewed V1 argument surface and refresh procedure.

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
