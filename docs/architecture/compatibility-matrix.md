# Gateway Canonical Compatibility Matrix

This document is the single authoritative source for Gateway's supported runtime
baseline, protocol lanes, and release artifacts. Detailed protocol message
formats live in [`docs/protocol/README.md`](../protocol/README.md), and the
machine-readable upstream tool catalog lives in
[`crates/policy/assets/upstream_tool_snapshot.toml`](../../crates/policy/assets/upstream_tool_snapshot.toml).
Neither is a second support matrix: both must agree with the declarations here.

## Baseline provenance

Audited on **2026-09-24** against `oaslananka/kicad-mcp-pro` release
`mcp-server-v3.35.0`, pinned to commit
`f641a92596ab7adc1e134287578b1ae5ff9580ad`. The upstream compatibility contract
at that commit declares KiCad 10.0.x primary (10.0.6 latest verified) and KiCad
8.x deprecated, with file-level read/migration support and manual validation
only. KiCad 9.x is dropped; KiCad 11.x is preview-only. Gateway does not turn
those upstream statuses into additional Gateway support claims.

## Platform & Architecture Support

| OS | Architecture | Gateway Status | Automated Validation | Release Artifacts Produced Today |
|---|---|---|---|---|
| **Linux** | `x86_64` (GNU) | **SUPPORTED** | Native CI build, format, Clippy, and tests on `ubuntu-latest` | `.tar.gz` CLI/daemon archive; no installer |
| **Linux** | `aarch64` / ARM64 | **PLANNED** | None | None |
| **macOS** | `aarch64` (Apple Silicon) | **SUPPORTED** | Native CI build, format, Clippy, and tests on `macos-latest`; release target is `aarch64-apple-darwin` | `.tar.gz` CLI/daemon archive; no installer |
| **macOS** | `x86_64` (Intel) | **UNSUPPORTED** | No release target or supported runner combination | None |
| **Windows** | `x86_64` (MSVC) | **SUPPORTED** | Native CI build, format, Clippy, and tests on `windows-latest`; release target is `x86_64-pc-windows-msvc` | `.zip` CLI/daemon archive; no installer |
| **Windows** | `arm64` (ARM64) | **PLANNED** | None | None |

CI validation here means the Rust workspace tests, not a live KiCad or
kicad-mcp-pro session. No installer, desktop bundle, signing, or notarization
job is present in the release workflow.

## Core Protocol Lanes & Component Dependencies

| Component | Target / Version Range | Policy / Notes |
|---|---|---|
| **KiCad** | `10.0.x` primary; `10.0.6` latest verified | Required local EDA environment. `8.x` is deprecated upstream and is **not** a Gateway-supported baseline; `9.x` is dropped; `11.x` is preview-only. |
| **kicad-mcp-pro** | `3.35.0`, `main` @ `f641a92596ab7adc1e134287578b1ae5ff9580ad` | Reviewed upstream tool snapshot and tool-effect contract source: 387 tools. Newly discovered or unclassified tools remain denied. |
| **MCP core-bridge protocol** | `2025-11-25` | Standard MCP Streamable HTTP client lane implemented by `crates/core-bridge`; it does not extend MCP. |
| **Gateway transport protocol** | `0.1.0` | Gateway's versioned transport envelope; incompatible major versions are rejected. |
| **Rust MSRV** | 1.88.0 | Checked in CI in addition to stable-toolchain checks. |
| **Node.js / pnpm** | Node 20 / pnpm 9 | Versions used by the Linux desktop CI job. |
| **Product identity** | Companion → Gateway, pre-1.0 | Renamed before the first release; no installed population to migrate — see [identity-migration.md](../development/identity-migration.md). |

## Live-Core Validation Status

Gateway CI does not install KiCad or start a live kicad-mcp-pro server. The
following baseline needs separate live evidence before it is described as
live-validated.

| Combination | Current Status | Required Evidence |
|---|---|---|
| Linux `x86_64` + KiCad 10.0.x + pinned kicad-mcp-pro | Not live-validated by this repository | Run the ignored live reconciliation test against a real loopback MCP server and retain its output. |
| macOS `aarch64` + KiCad 10.0.x + pinned kicad-mcp-pro | Not live-validated by this repository | Repeat the live probe and archive smoke test on a clean Apple Silicon machine. |
| Windows `x86_64` + KiCad 10.0.x + pinned kicad-mcp-pro | Not live-validated by this repository | Repeat the live probe and archive smoke test on a clean Windows machine. |
| KiCad 8.x, 9.x, or 11.x | Unsupported for Gateway release qualification | Do not promote a support claim; an explicit future compatibility review is required. |
| An unpinned upstream `main` checkout | Not an accepted release baseline | Pin and review a release SHA before changing this document or the policy snapshot. |

The live probe is intentionally opt-in because it needs a real local MCP
endpoint:

```sh
KICAD_MCP_LIVE_ENDPOINT=http://127.0.0.1:3334/mcp \
  cargo test -p kicad-mcp-gateway-daemon --test tool_reconciliation \
  live_core_can_be_reconciled_without_granting_unknown_tools -- --ignored --nocapture
```

## Reviewed Upstream Snapshot Refresh

1. Choose an upstream release and record its immutable commit SHA. Verify the
   release metadata and `compatibility.yaml` at that SHA; do not mirror every
   upstream `main` change.
2. Download that commit's `docs/tools-reference.generated.md`, then regenerate
   the policy snapshot from that exact file:

   ```sh
   cargo run -p companion-policy --bin reconcile-tool-registry -- \
     /path/to/tools-reference.generated.md <upstream-commit-sha> \
     crates/policy/assets/upstream_tool_snapshot.toml
   ```

3. Read the reconciliation report. Unclassified tools are an expected
   fail-closed result, not permission to add a policy grant. Review each new
   tool separately before changing `tool_registry.toml`.
4. Update this document and the README baseline together, then run
   `cargo test -p companion-policy` and the relevant workspace checks.
5. Run and retain the live-core probe above before making a new live-support
   claim. An absent probe remains explicitly unvalidated.

## Architecture Decisions Rationale

1. **macOS Intel (`x86_64`):** Explicitly unsupported. Apple Silicon
   (`aarch64`) represents current and future macOS target hardware.
2. **Linux & Windows ARM64:** **PLANNED**, not supported: cross-compilation and
   native hardware QA remain open.
3. **No Unvalidated Support:** A target is `SUPPORTED` only for the native CI
   scope stated above. Live KiCad/MCP validation, installers, and signing are
   separate release gates.
