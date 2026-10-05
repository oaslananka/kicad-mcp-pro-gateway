# Core Bridge Instructions

These instructions apply to `crates/core-bridge/**` and supplement both parent agent instruction files.

## Boundary

The core bridge is the adapter from Gateway to the local `kicad-mcp-pro` MCP endpoint. It is not a
general HTTP/MCP proxy and contains no KiCad domain logic.

Read first:

- `docs/protocol/README.md`
- `docs/architecture/component-boundaries.md`
- `docs/architecture/compatibility-matrix.md`
- `docs/security/trust-boundaries.md`

## Network boundary

The bridge remains loopback-only.

- Reject non-loopback endpoints before making a network request.
- Do not add public/LAN host fallback, discovery, proxying, redirect following, or caller-selected
  arbitrary network targets for convenience.
- Gateway never bypasses `kicad-mcp-pro` to manipulate KiCad directly.
- A successful HTTP connection is not authorization; policy/authorization stays in the daemon and
  policy crates.

## MCP protocol lanes

Preserve the explicit compatibility lanes documented in `docs/protocol/README.md` and
`docs/architecture/compatibility-matrix.md`.

Current contract:

- primary stateless MCP `2026-07-28` lane with direct discovery and required per-request metadata;
- explicit legacy `2025-11-25` initialize/session compatibility lane when deliberately selected;
- no implicit protocol guessing;
- no Tasks/Apps extension exposure or consumption unless canonical compatibility policy is
  intentionally expanded.

Breaking protocol behavior is a compatibility change, not a local implementation detail.

## Bounds and error handling

- Preserve request/response size and timeout bounds.
- Treat malformed protocol/HTTP responses as typed bridge failures.
- Do not leak local response details that violate the caller-facing redaction contract.
- Do not auto-retry non-idempotent tool calls without an explicit idempotency/recovery design.

Mocks are test infrastructure, not production fallback.

## Verification

Run:

```bash
cargo test -p companion-core-bridge
cargo clippy -p companion-core-bridge --all-targets -- -D warnings
cargo test --workspace
```

Compatibility changes also require the relevant daemon reconciliation/live evidence path. Mock
bridge tests do not prove a specific released `kicad-mcp-pro` runtime.

## Definition of done

A bridge change is complete only when loopback confinement, protocol-lane behavior, bounds, typed
failures, compatibility metadata, tests, and live evidence requirements remain aligned.
