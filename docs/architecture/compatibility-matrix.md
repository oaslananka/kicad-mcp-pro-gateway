# Gateway Canonical Compatibility Matrix

This document is the single authoritative source for Gateway's supported runtime
baseline, protocol lanes, and release artifacts. Detailed protocol message
formats live in [`docs/protocol/README.md`](../protocol/README.md), and the
machine-readable upstream tool catalog lives in
[`crates/policy/assets/upstream_tool_snapshot.toml`](../../crates/policy/assets/upstream_tool_snapshot.toml).
Neither is a second support matrix: both must agree with the declarations here.

## Baseline provenance

The current runtime/protocol baseline was reconciled on **2026-10-04** against
`oaslananka/kicad-mcp-pro` release `mcp-server-v3.37.0`, immutable commit
`014cf241480afc15ac2b34bf10c904f5415d376c`. That release advertises MCP
`2026-07-28` as primary and retains `2025-11-25` as an explicit
backward-compatible lane. Its compatibility contract continues to declare
KiCad 10.0.x primary (10.0.6 latest verified), KiCad 8.x deprecated,
KiCad 9.x dropped, and KiCad 11.x preview-only.

This runtime promotion does **not** promote policy trust. The reviewed Gateway
tool catalog/effect-policy source remains pinned to
`f641a92596ab7adc1e134287578b1ae5ff9580ad` until the separate upstream
manifest/source-pin review in issue #8 is completed. Tools or argument/effect
facts that are new or drifted relative to that reviewed policy source remain
fail-closed.

Historical live-E2E evidence from **2026-09-30** was produced against the older
3.35.0 runtime after PR #57 corrected a false-green workflow that had executed
zero tests. That evidence remains historical; it does not substitute for a
passing exact-head 3.37.0/final-protocol run.

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
artifacts. A separate `e2e-live.yml` workflow installs KiCad 10.0.6 and
pins `kicad-mcp-pro 3.37.0` / `014cf241480afc15ac2b34bf10c904f5415d376c`,
starting its strict stateless `2026-07-28` conformance lane. The current
3.37.0 lane requires fresh exact-head evidence before it becomes positive
release evidence. Historical [post-fix Ubuntu Live E2E run
36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865)
at `98967a3549701da2e2b596d7cf977aff8689987f` executed **3 tests: 3 passed,
0 failed, 0 ignored** against the older 3.35.0 baseline on 2026-09-30. That
remains bounded historical integration evidence, not proof of the current
runtime/protocol baseline or exact-artifact clean-machine qualification.
This repository still has no equivalent automated live KiCad/MCP lane for
macOS or Windows. A version tag
runs the fail-closed release-candidate workflow, which requires and verifies
macOS Developer ID/notarization and Windows Authenticode before creating a
draft prerelease. Exact-artifact clean-machine qualification remains a separate
release gate; see [release.md](../development/release.md).

## Core Protocol Lanes & Component Dependencies

| Component | Target / Version Range | Policy / Notes |
|---|---|---|
| **KiCad** | `10.0.x` primary; `10.0.6` latest verified | Required local EDA environment. `8.x` is deprecated upstream and is **not** a Gateway-supported baseline; `9.x` is dropped; `11.x` is preview-only. |
| **kicad-mcp-pro runtime** | `3.37.0` @ `014cf241480afc15ac2b34bf10c904f5415d376c` | Immutable released runtime used by the live compatibility lane. |
| **Reviewed policy tool snapshot** | `3.35.0` source @ `f641a92596ab7adc1e134287578b1ae5ff9580ad` | Authorization/effect trust remains pinned independently of runtime: 387 tools in the embedded reviewed snapshot. Newly discovered, changed, or unclassified tools remain denied until separately reviewed under #8. |
| **MCP core-bridge protocol** | `2026-07-28` | Primary stateless Streamable HTTP lane: direct `server/discover`, required per-request metadata/headers, no MCP session IDs. Explicit `2025-11-25` initialize/session compatibility remains available through `ProtocolLane::Legacy2025`. Tasks/Apps are not advertised or consumed. |
| **Gateway transport protocol** | `0.1.0` | Gateway's versioned transport envelope; incompatible major versions are rejected. |
| **Rust MSRV** | 1.88.0 | Checked in CI in addition to stable-toolchain checks. |
| **Node.js / pnpm** | Node 20 / pnpm 9 | Versions used by the Linux desktop CI job. |
| **Product identity** | Companion → Gateway, pre-1.0 | Renamed before the first release; no installed population to migrate — see [identity-migration.md](../development/identity-migration.md). |

## Live-Core Validation Status

The repository has an Ubuntu live-E2E workflow that installs KiCad 10.0.6,
installs pinned `kicad-mcp-pro 3.37.0`, starts the strict stateless final MCP
`2026-07-28` loopback lane, and invokes the Gateway suite. A passing exact-head
run of that current lane is required before this matrix treats 3.37.0/final MCP
as live-validated. **Historic success conclusions before the PR #57 repair are
not test-passing evidence:** all three older live tests were marked `#[ignore]`
and the workflow did not enable them (`0 passed; 3 ignored`).
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
| Linux `x86_64` + KiCad 10.0.6 + pinned kicad-mcp-pro 3.37.0 + MCP 2026-07-28 | **Pending exact-head evidence for this compatibility change.** The workflow is pinned to release commit `014cf241480afc15ac2b34bf10c904f5415d376c` and strict stateless final-protocol mode. | Require a passing live run before claiming this row validated; then separately qualify the exact tagged Gateway artifact on a clean Ubuntu 24.04 machine before promotion. |
| Linux `x86_64` + KiCad 10.0.6 + historical kicad-mcp-pro 3.35.0 | **3/3 real live E2E tests passed** in [GitHub Actions run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) on 2026-09-30; prior zero-test green runs remain invalid evidence. | Retain as historical bounded evidence only; it does not validate the promoted 3.37.0/final-protocol lane. |
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
