# Gateway Canonical Compatibility Matrix

This document is the single authoritative source for Gateway's supported runtime
baseline, protocol lanes, and release artifacts. Detailed protocol message
formats live in [`docs/protocol/README.md`](../protocol/README.md), and the
machine-readable upstream tool catalog lives in
[`crates/policy/assets/upstream_tool_snapshot.toml`](../../crates/policy/assets/upstream_tool_snapshot.toml).
Neither is a second support matrix: both must agree with the declarations here.

## Baseline provenance

Baseline audited on **2026-09-24** against `oaslananka/kicad-mcp-pro` release
`mcp-server-v3.35.0`. On **2026-09-30**, the Gateway live-E2E
workflow's actual test execution was re-audited: its previously green runs
were **not** live validation evidence (0 executed tests, 3 ignored). The upstream baseline is pinned to commit
`f641a92596ab7adc1e134287578b1ae5ff9580ad`. The upstream compatibility contract
at that commit declares KiCad 10.0.x primary (10.0.6 latest verified) and KiCad
8.x deprecated, with file-level read/migration support and manual validation
only. KiCad 9.x is dropped; KiCad 11.x is preview-only. Gateway does not turn
those upstream statuses into additional Gateway support claims.

## Platform & Architecture Support

| OS | Architecture | Gateway Status | Automated Validation | Declared Release-Candidate Artifact |
|---|---|---|---|---|
| **Linux** | `x86_64` (GNU) | **SUPPORTED** | Native workspace tests on `ubuntu-latest`; desktop package build and sidecar verification on `ubuntu-22.04` | `.tar.gz` CLI/daemon archive and `.deb` desktop package; identity is bound by checksum and provenance attestation rather than a portable code signature |
| **Linux** | `aarch64` / ARM64 | **PLANNED** | None | None |
| **macOS** | `aarch64` (Apple Silicon) | **SUPPORTED** | Native workspace tests on `macos-latest`; `aarch64-apple-darwin` desktop package build and sidecar verification on `macos-14` | `.tar.gz` CLI/daemon archive and Developer ID signed/notarized `.dmg` required by the release-candidate workflow |
| **macOS** | `x86_64` (Intel) | **UNSUPPORTED** | No release target or supported runner combination | None |
| **Windows** | `x86_64` (MSVC) | **SUPPORTED** | Native workspace tests on `windows-latest`; `x86_64-pc-windows-msvc` desktop package build and sidecar verification on `windows-2022` | `.zip` CLI/daemon archive and timestamped Authenticode-signed `.msi` required by the release-candidate workflow |
| **Windows** | `arm64` (ARM64) | **PLANNED** | None | None |

The supported desktop rows use the application-managed sidecar lifecycle;
Gateway V1 does not install an OS service. Native IPC/restart tests and
packaged `.deb` / `.dmg` / `.msi` sidecar verification are defined in the
[daemon lifecycle evidence matrix](../development/daemon-lifecycle.md#automated-and-clean-machine-evidence).
The ordinary CI package jobs intentionally build unsigned compile-test
artifacts. A separate `e2e-live.yml` workflow installs KiCad 10.0.6 and the
pinned `kicad-mcp-pro 3.35.0` baseline. **As discovered on 2026-09-30,
prior green workflow runs actually executed zero tests (3 ignored)**, so
those runs are not positive Ubuntu live-E2E qualification evidence. PR #57
corrects the invocation and requires executed tests; retain a passing
post-fix run before citing the lane as validated. Even that evidence does
**not** substitute for
exact-artifact clean-machine qualification, and this repository still has no
equivalent automated live KiCad/MCP lane for macOS or Windows. A version tag
runs the fail-closed release-candidate workflow, which requires and verifies
macOS Developer ID/notarization and Windows Authenticode before creating a
draft prerelease. Exact-artifact clean-machine qualification remains a separate
release gate; see [release.md](../development/release.md).

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

The repository has an Ubuntu live-E2E workflow that installs KiCad 10.0.6,
installs pinned `kicad-mcp-pro 3.35.0`, starts the loopback MCP server, and
invokes the Gateway suite. **Historic success conclusions before the PR #57
repair are not test-passing evidence:** all three live tests were marked
`#[ignore]` and the workflow did not enable them (`0 passed; 3 ignored`).
On 2026-09-30, the first real run executed all 3 tests (2 passed, 1
failed) because the fixture was resolved relative to the Cargo crate
directory. After fixing the fixture path, the next actual run again
executed all 3 (2 passed, 1 failed): the live read and durable audit
passed, but `sch_add_symbol` correctly failed closed with
`UnmodelledToolContract` because no reviewed effect contract exists.
PR #57 now tests this explicit deny/audit invariant and continues to
the already-modelled high-risk approval, revocation, and reconnect
stages. **The revised end-to-end test is not yet verified green**;
retain a 3/3 successful executed run before claiming Ubuntu live qualification.
macOS and Windows have no equivalent automated live KiCad/MCP lanes.
Exact release artifacts still require separate clean-machine qualification
on every supported platform.

| Combination | Current Status | Required Evidence |
|---|---|---|
| Linux `x86_64` + KiCad 10.0.6 + pinned kicad-mcp-pro 3.35.0 | Workflow exists; **positive 3-test live E2E result pending** after correcting historical zero-test green runs. | Require a run with 3 tests executed and no failures/ignores; separately qualify the exact tagged artifact on a clean Ubuntu 24.04 machine before promotion. |
| macOS `aarch64` + KiCad 10.0.x + pinned kicad-mcp-pro | Not live-validated by this repository | Run the live probe and exact-artifact smoke/clean-machine qualification on Apple Silicon and retain the evidence. |
| Windows `x86_64` + KiCad 10.0.x + pinned kicad-mcp-pro | Not live-validated by this repository | Run the live probe and exact-artifact smoke/clean-machine qualification on Windows 11 and retain the evidence. |
| KiCad 8.x, 9.x, or 11.x | Unsupported for Gateway release qualification | Do not promote a support claim; an explicit future compatibility review is required. |
| An unpinned upstream `main` checkout | Not an accepted release baseline | Pin and review a release SHA before changing this document or the policy snapshot. |

The separate reconciliation probe remains useful for manual/live compatibility
evidence when a real local MCP endpoint is available:

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
   scope stated above. Live KiCad/MCP validation, signing, notarization, and
   clean-machine installer qualification remain separate release gates.
