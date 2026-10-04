# Gateway Canonical Compatibility Matrix

This document is the single authoritative source for Gateway's supported runtime
baseline, protocol lanes, and release artifacts. Detailed protocol message
formats live in [`docs/protocol/README.md`](../protocol/README.md), and the
machine-readable upstream tool catalog lives in
[`crates/policy/assets/upstream_tool_snapshot.toml`](../../crates/policy/assets/upstream_tool_snapshot.toml).
Neither is a second support matrix: both must agree with the declarations here.

## Baseline provenance

Gateway keeps the runtime protocol baseline and the reviewed policy snapshot
separately pinned so a protocol upgrade cannot silently widen authorization.

- **Runtime/protocol baseline:** reviewed on **2026-10-05** against released
  `oaslananka/kicad-mcp-pro` `mcp-server-v3.37.0`, immutable commit
  `014cf241480afc15ac2b34bf10c904f5415d376c`. That release publishes final MCP
  `2026-07-28` as primary and retains explicit `2025-11-25` compatibility.
- **Policy/tool-effect snapshot:** remains the separately reviewed
  `mcp-server-v3.35.0` source at
  `f641a92596ab7adc1e134287578b1ae5ff9580ad` (387 tools). This change does not
  refresh or widen Gateway authorization facts; that remains issue #8 scope.

On **2026-09-30**, the Gateway live-E2E workflow's earlier false-green runs were
corrected: run 36736490865 then executed and passed all three tests against the
historical 3.35.0 baseline. The current workflow is being moved to the released
3.37.0 strict final-protocol lane; an exact-head passing run is required before
that newer live-runtime claim is considered verified. KiCad 10.0.x remains the
primary Gateway baseline (10.0.6 latest verified); 9.x is dropped and 11.x is
preview-only.

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
released `kicad-mcp-pro 3.37.0` runtime/protocol baseline in its strict
stateless final-protocol lane. **As discovered on 2026-09-30,
prior green workflow runs actually executed zero tests (3 ignored)**, so
those runs are not positive Ubuntu live-E2E qualification evidence. PR #57
corrects the invocation and requires executed tests. The
[post-fix Ubuntu Live E2E run](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) at `98967a3549701da2e2b596d7cf977aff8689987f`
executed **3 tests: 3 passed, 0 failed, 0 ignored** on 2026-09-30.
This provides bounded Ubuntu CI live test evidence but **not**
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
| **kicad-mcp-pro runtime** | `3.37.0` release @ `014cf241480afc15ac2b34bf10c904f5415d376c` | Released protocol/runtime baseline for final MCP validation. |
| **Gateway policy snapshot** | `3.35.0` source @ `f641a92596ab7adc1e134287578b1ae5ff9580ad` | Reviewed tool/effect facts: 387 tools. Newly discovered or unclassified tools remain denied until #8 separately reconciles a released manifest. |
| **MCP core-bridge protocol** | `2026-07-28` primary; `2025-11-25` explicit legacy | Final lane is stateless `server/discover` + per-request metadata/headers with no MCP session ID; legacy initialize/session behavior is separately selected and tested. No automatic downgrade/fallback. |
| **Gateway transport protocol** | `0.1.0` | Gateway's versioned transport envelope; incompatible major versions are rejected. |
| **Rust MSRV** | 1.88.0 | Checked in CI in addition to stable-toolchain checks. |
| **Node.js / pnpm** | Node 20 / pnpm 9 | Versions used by the Linux desktop CI job. |
| **Product identity** | Companion → Gateway, pre-1.0 | Renamed before the first release; no installed population to migrate — see [identity-migration.md](../development/identity-migration.md). |

## Live-Core Validation Status

The repository has an Ubuntu live-E2E workflow that installs KiCad 10.0.6,
installs released `kicad-mcp-pro 3.37.0` from commit
`014cf241480afc15ac2b34bf10c904f5415d376c`, starts the loopback MCP server in
strict stateless MCP `2026-07-28` conformance mode, and invokes the Gateway
suite. The prior 3.35.0 passing run remains historical evidence rather than
evidence for this newer runtime lane. **Historic success conclusions before the PR #57
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
stages. The [repaired exact-head run](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865)
at `98967a3549701da2e2b596d7cf977aff8689987f` **passed all 3 live tests, with none failed or ignored**.
In the vertical slice, the read and audit succeeded; the unmodelled
write was denied and audited without execution; the reviewed high-risk
PCB tool was approved and returned success, but the fixture had no
schematic symbols to place. Revocation and post-reconnect denial passed.
This validates the scoped policy and RPC path, **not actual PCB
placement, all KiCad features, or signed install packages**.
macOS and Windows have no equivalent automated live KiCad/MCP lanes.
Exact release artifacts still require separate clean-machine qualification
on every supported platform.

| Combination | Current Status | Required Evidence |
|---|---|---|
| Linux `x86_64` + KiCad 10.0.6 + kicad-mcp-pro 3.37.0 final MCP lane | **PENDING exact-head Gateway live-E2E evidence for this compatibility change.** | Require a real nonzero passing Live E2E run before promoting the 3.37.0 final-lane support claim; exact-artifact clean-machine qualification remains separate. |
| Linux `x86_64` + KiCad 10.0.6 + kicad-mcp-pro 3.35.0 legacy historical baseline | **3/3 real live E2E tests passed** in [GitHub Actions run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) on 2026-09-30; prior zero-test green runs remain invalid evidence. | Historical bounded evidence only; it does not qualify the 3.37.0 final lane or a release artifact. |
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
