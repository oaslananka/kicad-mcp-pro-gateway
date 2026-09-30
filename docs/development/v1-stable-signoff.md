# V1 Stable Release Sign-Off Record

**Issue:** OASL-17 — release: complete the final V1 stable-release sign-off
**Date:** 2026-09-25
**Repository:** oaslananka/kicad-mcp-pro-gateway
**Branch:** agent/fleet-builder-omniroute-v2/05b2c295d279 (from origin/main @ 25a008b)

---

## Live Reconciliation — 2026-09-30

This file is a **dated conditional-release readiness record**, not evidence that
a stable release was published or that all manual qualification gates were
completed.

Live repository verification on 2026-09-30 found:

- `main` had advanced from this record's original snapshot
  (`25a008b`) to `dd4bc3c80fcb8b1e877651e1b773d122e8fd1a34`;
- the workspace version was still `0.1.0`;
- the release-candidate pipeline was implemented, but this record still
  contained no evidence for an actual tagged `1.0.0-rc1` artifact set;
- Ubuntu live KiCad/MCP E2E was automated in `.github/workflows/e2e-live.yml`,
  while macOS and Windows live KiCad/MCP validation remained external/manual;
- clean-machine qualification for Ubuntu, macOS, and Windows remained a
  separate promotion gate;
- human release-owner review/authorization remained required.

Closing the implementation/sign-off issues therefore must not be interpreted as
satisfying these external release gates. Before stable promotion, revalidate
the exact candidate hashes, signing/provenance, clean-machine evidence,
cross-platform live evidence, current security surfaces, and human approval
against the then-current release commit.

---

## 2026-09-30 Live E2E Evidence Correction (Supersedes Prior Green Claims)

A security/release-gate audit during [PR #57](https://github.com/oaslananka/kicad-mcp-pro-gateway/pull/57)
found that the Ubuntu `e2e-live.yml` workflow **reported success without executing
any of its three live tests** (`0 passed; 3 ignored`): the tests were individually
`#[ignore]` but the CI invocation lacked `--include-ignored`.

The corrected workflow invokes ignored tests explicitly and rejects zero-test
success. Its first substantive run on 2026-09-30 executed 3 tests: **2 passed
and 1 failed** due to a relative fixture path. After fixing that path, the
next run again executed **2 passed, 1 failed**: the live read and audit
succeeded, while `sch_add_symbol` correctly failed closed with
`UnmodelledToolContract` (no reviewed effects). PR #57's updated scenario
now asserts that deny/audit behavior instead of requesting a new grant;
the high-risk approval, revocation, and reconnect stages needed
fresh passing test evidence. The [2026-09-30 repaired run](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865)
at `98967a3549701da2e2b596d7cf977aff8689987f` subsequently executed **all 3 tests successfully
(3 passed; 0 failed; 0 ignored)**. The vertical slice verified real
read/audit, unmodelled-write denial and nonexecution audit, a reviewed
high-risk tool call only after approval, revocation, and reconnect denial.
The high-risk tool returned "No schematic symbols were found to place";
this **does not demonstrate actual board component placement**.
Earlier zero-test green workflow statuses remain invalid evidence. This correction applies prospectively
to release authorization; it does not alter the historical fact that
implementation issue #38 closed or waive independent macOS/Windows live,
clean-machine, signing, and human release-owner gates.

---

## Executive Summary

This document records a dated **conditional V1 stable-release readiness assessment** for KiCad MCP Pro Gateway. It is based on release-pipeline implementation, automated verification workflows, and documented security/compatibility baselines; it is not evidence that the external qualification and promotion steps were completed.

**Historical decision (superseded for promotion):** **CONDITIONAL GO** was recorded on 2026-09-25. The 2026-09-30 correction above invalidates prior green Ubuntu live-E2E status as positive test evidence. The Ubuntu execution gate was subsequently satisfied in [run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865); **no stable promotion is authorized** until the remaining release qualification gates are satisfied.

---

## 1. Release Blocker Status (P0 `release-blocker` Issues)

| Blocker Area | Issue Reference | Status | Evidence |
|-------------|----------------|--------|----------|
| Trust Boundary / Authorization TTL | #36 / PR #36 | ✅ **CLOSED** | Policy-bounded TTLs with conservative 1-min Critical defaults; malformed config prevents startup |
| Fail-Closed Audit Persistence | #36 / PR #36 | ✅ **CLOSED** | Durable append-only audit store; `AuditPersistence` error on write failure; zero upstream calls when audit unavailable |
| Release Candidate Pipeline | #41 / PR #41 | ✅ **CLOSED** | Fail-closed tag-triggered pipeline with SBOM, provenance, SBOM attestations, draft-prerelease-only publication |
| Signed Desktop Installers | #40 / PR #40 | ✅ **CLOSED** | `.deb` (Linux, validated via provenance), `.dmg` (macOS Developer ID + notarization), `.msi` (Windows Authenticode + timestamp) |
| Live E2E Release Gate | #38 / PR #38 | ✅ **IMPLEMENTATION CLOSED; UBUNTU EXECUTION VERIFIED** | Historic false-green was corrected in PR #57; [real run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) passed 3/3, including correct denied-write and approved high-risk paths. Separate installer/cross-platform gates remain. |
| Desktop Security-Critical UX | #39 / PR #39 | ✅ **CLOSED** | Comprehensive UI tests for offline/failure states; Vitest + React Testing Library in CI |
| Update/Upgrade/Rollback Strategy | #42 / PR #42 | ✅ **CLOSED** | Documented in `docs/upgrade-v1.md`; tested in CI matrix |
| Compatibility Matrix Baseline | #32 / PR #32 | ✅ **CLOSED** | Canonical matrix in `docs/architecture/compatibility-matrix.md` for Ubuntu 24.04 x86_64, macOS Apple Silicon, Windows 11 x86_64 |
| OSV Security Scanning | `osv-full.yml` | ✅ **CLOSED** | Scheduled + push scans; fail-on-vuln; SARIF upload to code scanning |
| Dependency Review | `security.yml` | ✅ **CLOSED** | PR dependency review (moderate+); zizmor workflow audit |

**All identified P0 implementation/release-blocker issues in this dated tracker set are CLOSED with evidence.** The external qualification and promotion conditions recorded below remain blockers to an actual stable promotion.

---

## 2. RC Pipeline Readiness Snapshot — No Tagged RC Yet

**Snapshot HEAD (2026-09-25):** `25a008b` (Merge PR #42)
**Live verification baseline (2026-09-30):** `dd4bc3c80fcb8b1e877651e1b773d122e8fd1a34`
**Workspace Version:** `0.1.0` (pre-release; RC requires version bump to `1.0.0-rc1`)

| Artifact | Expected Filename Pattern | Status |
|----------|---------------------------|--------|
| Linux CLI/Daemon | `kicad-mcp-gateway-v1.0.0-rc1-x86_64-unknown-linux-gnu.tar.gz` | Pipeline ready; requires version bump + tag |
| macOS CLI/Daemon | `kicad-mcp-gateway-v1.0.0-rc1-aarch64-apple-darwin.tar.gz` | Pipeline ready; requires version bump + tag |
| Windows CLI/Daemon | `kicad-mcp-gateway-v1.0.0-rc1-x86_64-pc-windows-msvc.zip` | Pipeline ready; requires version bump + tag |
| Linux Desktop | `kicad-mcp-gateway-desktop-v1.0.0-rc1-x86_64-unknown-linux-gnu.deb` | Pipeline ready; requires version bump + tag |
| macOS Desktop | `kicad-mcp-gateway-desktop-v1.0.0-rc1-aarch64-apple-darwin.dmg` | Pipeline ready; requires version bump + tag |
| Windows Desktop | `kicad-mcp-gateway-desktop-v1.0.0-rc1-x86_64-pc-windows-msvc.msi` | Pipeline ready; requires version bump + tag |

**Note:** The release candidate workflow (`.github/workflows/release.yml`) is fully implemented and fail-closed. It requires a version tag matching `v<workspace_version>` (e.g., `v1.0.0-rc1`). The current workspace version is `0.1.0`; a version bump to `1.0.0-rc1` is required before tagging the RC.

---

## 3. Compatibility Matrix Evidence

**Document:** `docs/architecture/compatibility-matrix.md` (audited 2026-09-24)

| Platform | Architecture | Status | Automated Validation |
|----------|-------------|--------|---------------------|
| Linux | x86_64 (GNU) | **SUPPORTED** | Native workspace tests on `ubuntu-latest`; desktop build on `ubuntu-22.04` |
| macOS | aarch64 (Apple Silicon) | **SUPPORTED** | Native workspace tests on `macos-latest`; desktop build on `macos-14` |
| Windows | x86_64 (MSVC) | **SUPPORTED** | Native workspace tests on `windows-latest`; desktop build on `windows-2022` |
| Linux | aarch64 | PLANNED | None |
| Windows | arm64 | PLANNED | None |
| macOS | x86_64 (Intel) | UNSUPPORTED | Explicitly unsupported |

**Upstream Baseline:** `kicad-mcp-pro@3.35.0` pinned to commit `f641a92596ab7adc1e134287578b1ae5ff9580ad` (387 tools reviewed)

**Live-Core Validation Status (2026-09-30 correction):** Historical green Ubuntu workflows executed 0 tests. The subsequent [corrected run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) executed and passed 3/3 tests at `98967a3549701da2e2b596d7cf977aff8689987f`. This is bounded live integration evidence, not proof of physical PCB mutations or release artifact qualification. macOS/Windows live evidence and exact-artifact clean-machine qualification remain separately outstanding.

---

## 4. Signing / Provenance Evidence

### Automated Pipeline (Implemented in `release.yml`)

| Check | Status | Details |
|-------|--------|---------|
| CI / E2E / OSV gates | ✅ Implemented | Required before any signing credential access |
| Tag/version matching | ✅ Implemented | Exact `v<workspace_version>` required |
| macOS Developer ID import + notarization | ✅ Implemented | Strict `codesign`, `xcrun stapler validate`, `spctl` Gatekeeper |
| Windows Authenticode + timestamp | ✅ Implemented | `Get-AuthenticodeSignature` Valid, thumbprint match, `signtool verify /pa /all` |
| Linux `.deb` extraction + sidecar | ✅ Implemented | Exact package extraction; 1 desktop + 1 daemon executable |
| SPDX 2 JSON SBOM (Syft v1.51.1) | ✅ Implemented | Validated non-empty, < 16 MiB |
| Artifact manifest + SHA256SUMS | ✅ Implemented | Explicit `pending` clean-machine qualification state |
| SLSA build provenance attestation | ✅ Implemented | `actions/attest-build-provenance` on all subjects |
| SBOM attestation | ✅ Implemented | `actions/attest-sbom` bound to same subjects |
| Draft + prerelease publication | ✅ Implemented | GitHub CLI; verifies tag; `draft=true`, `prerelease=true` |

### Physical Evidence (Requires External Validation)

| Evidence | Status | Notes |
|----------|--------|-------|
| Successful signature/notarization output from actual tagged RC | ⏳ **PENDING** | Requires tagging `v1.0.0-rc1` with signing credentials in `release-signing` environment |
| Clean-machine Ubuntu 24.04 `.deb` validation | ⏳ **PENDING** | Requires fresh machine; see `release-qa.md` template |
| Clean-machine macOS Apple Silicon `.dmg` validation | ⏳ **PENDING** | Requires fresh machine; see `release-qa.md` template |
| Clean-machine Windows 11 `.msi` validation | ⏳ **PENDING** | Requires fresh machine; see `release-qa.md` template |

---

## 5. Clean-Machine Qualification Status

**Document:** `docs/development/release.md` (Evidence Checklist section)

| Qualification Area | Status | Evidence Required |
|-------------------|--------|-------------------|
| Fresh Ubuntu 24.04 LTS `.deb` + headless | ⏳ **NOT STARTED** | Requires physical/virtual clean machine |
| Fresh macOS Apple Silicon `.dmg` + headless | ⏳ **NOT STARTED** | Requires physical clean machine |
| Fresh Windows 11 `.msi` + headless | ⏳ **NOT STARTED** | Requires physical clean machine |
| First-launch, identity, policy, crash/restart, revocation | ⏳ **NOT STARTED** | All three platforms |
| Upgrade, uninstall, data-retention, data-wipe | ⏳ **NOT STARTED** | All three platforms |
| Live KiCad 10.0.x / pinned `kicad-mcp-pro` evidence | ⏳ **NOT STARTED** | Exact candidate hashes; promotion blocked without |

**Automated CI package jobs** (`desktop-package` in `ci.yml`) build unsigned compile-test artifacts only. They do not substitute for clean-machine qualification.

---

## 6. Live E2E Evidence

**Workflow:** `.github/workflows/e2e-live.yml`

| Test | Status | Details |
|------|--------|---------|
| Automated live E2E on Ubuntu | ✅ **3/3 EXECUTED AND PASSED** | PR #57 fixes previous `0 passed; 3 ignored` false-green and explicitly validates denied unmodelled writes; [run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) passed all three. |
| Live reconciliation test | ✅ **EXECUTED AND PASSED** | `cargo test -p kicad-mcp-gateway-daemon --test e2e_live -- --include-ignored --nocapture` on [run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) passed health, reconciliation, and full vertical slice, with 0 ignored. |
| macOS live E2E | ❌ **NOT CONFIGURED** | No macOS runner in matrix (only Ubuntu) |
| Windows live E2E | ❌ **NOT CONFIGURED** | No Windows runner in matrix (only Ubuntu) |

**Note:** The live E2E workflow currently only runs on Ubuntu. Cross-platform live validation requires manual execution on macOS/Windows per the compatibility matrix.

---

## 7. Security Regression Evidence

| Area | Status | Evidence |
|------|--------|----------|
| Authorization TTL ceilings | ✅ **VERIFIED** | `crates/policy/src/authorization_ttl.rs`; tests in `crates/policy/tests/` |
| Fail-closed audit persistence | ✅ **VERIFIED** | `crates/audit/src/`; failure injection tests; `docs/security/audit-fail-closed.md` |
| Trust boundaries | ✅ **VERIFIED** | `docs/security/trust-boundaries.md`; enforced in transport/core-bridge |
| Tool-effect contracts | ✅ **VERIFIED** | `docs/security/tool-effect-contracts.md`; 100% disposition coverage |
| Secure storage (Keychain/Secret Service/DPAPI) | ✅ **VERIFIED** | `crates/identity/`; `docs/security/secure-storage.md` |
| OSV scanning | ✅ **VERIFIED** | `osv-full.yml` (scheduled + push); `security.yml` (PR dependency review) |
| Workflow audit (zizmor) | ✅ **VERIFIED** | `security.yml` workflow-audit job |

**No known security regressions** in the current codebase. All security-critical paths have test coverage.

---

## 8. Upgrade / Rollback Evidence

**Document:** `docs/upgrade-v1.md`

| Aspect | Status | Details |
|--------|--------|---------|
| Upgrade order documented | ✅ **COMPLETE** | Config/Data dir → Media Formats → DB schema → Identity → Daemon binary → Service names |
| Failure detection | ✅ **COMPLETE** | Daemon startup failure retains old daemon |
| Rollback mechanism | ✅ **COMPLETE** | Previous binary/config retained; no data written to new location until success |
| Security invariants | ✅ **COMPLETE** | Revoked/expired grants remain revoked; identity never in plaintext |
| Test coverage | ✅ **IMPLEMENTED** | Tests in `tests/` directory; CI matrix in compatibility matrix |

---

## 9. Advisory Exception State

| Exception | Status | Expiry | Notes |
|-----------|--------|--------|-------|
| Available CI security evidence | ✅ **GREEN IN RECORDED RUNS** | N/A | OSV and other recorded security workflows passed for the reviewed state; this record is not a live inventory of GitHub Security alerts. |

**No release-blocking advisory exception was identified in the recorded workflow evidence.**
Before promotion, inspect the then-current Dependabot/code-scanning/secret-scanning
surfaces directly rather than inferring a zero-alert state from CI alone.

---

## 10. Release Notes & Documentation Consistency

| Document | Status | Consistency Check |
|----------|--------|-------------------|
| `CHANGELOG.md` | ✅ **CONSISTENT** | v1.0.0-rc1 entry matches implemented features; Unreleased section reflects current main |
| `docs/development/release.md` | ✅ **CONSISTENT** | Accurately describes implemented `release.yml` workflow |
| `docs/architecture/compatibility-matrix.md` | ✅ **CONSISTENT** | Matches CI matrix and release workflow targets |
| `docs/upgrade-v1.md` | ✅ **CONSISTENT** | Documents tested upgrade/rollback strategy |
| `SECURITY.md` | ✅ **CONSISTENT FOR THE RECORDED REVIEW** | Points to threat model & trust boundaries; this row does not assert that a stable release was published |
| `docs/security/threat-model.md` | ✅ **CONSISTENT** | Current threat model |
| `docs/security/trust-boundaries.md` | ✅ **CONSISTENT** | Current trust boundaries |

**The recorded documentation review was consistent with the implemented codebase and workflows.** “Implemented” must not be read as “published” or “externally qualified.”

---

## 11. Go/No-Go Decision

### ✅ GO Criteria Met (Automated/Documented Evidence)

- [x] All P0 release-blocker issues closed with evidence
- [x] Release candidate pipeline implemented and fail-closed
- [x] Signed installer pipeline implemented for all three platforms
- [x] Compatibility matrix documented and matches CI/release targets
- [x] Ubuntu live E2E **executed and passing** — historical zero-test runs remain invalid; [run 36736490865](https://github.com/oaslananka/kicad-mcp-pro-gateway/actions/runs/36736490865) passed 3/3
- [x] Security invariants verified (TTL, audit, trust boundaries, tool effects)
- [x] Upgrade/rollback strategy documented and tested
- [x] No expired release-blocking advisory exceptions
- [x] Release notes and security documentation consistent with implementation
- [x] SBOM, provenance, attestations pipeline implemented
- [x] Draft-prerelease publication gate implemented

### ⏳ CONDITIONAL Criteria (Require External Validation)

- [ ] **Clean-machine qualification** on all three platforms (Ubuntu 24.04, macOS Apple Silicon, Windows 11)
- [ ] **Live E2E validation** on macOS and Windows (currently only Ubuntu in CI)
- [ ] **Actual tagged RC artifacts** with verified signatures/notarization (requires version bump to `1.0.0-rc1` and tagging with signing credentials)
- [ ] **Physical hardware validation** of installers (not GitHub-hosted runners)

### 📋 Accepted Non-Blocking Limitations

1. **Clean-machine qualification is manual** — Cannot be automated in CI; requires physical/virtual machines per platform. This is explicitly documented in `release.md` as "Not Produced or Automated."
2. **Live E2E on macOS/Windows not in CI** — Only Ubuntu has automated live E2E. Cross-platform live validation requires manual execution per `compatibility-matrix.md`.
3. **Linux `.deb` has no portable code signature** — Identity bound by SHA-256 + provenance attestation (documented limitation).
4. **Windows SmartScreen reputation** — New publisher may trigger warnings despite valid Authenticode signature (documented in `release.md`).
5. **Version bump required** — Current workspace version is `0.1.0`; RC requires `1.0.0-rc1`; stable requires `1.0.0`.

---

## 12. Sign-Off

**Prepared by:** Fleet Builder Agent (automated evidence collection)
**Reviewed by:** [Pending human release owner]
**Date:** 2026-09-25

### Recommendation

**CONDITIONAL GO FOR V1 STABLE PROMOTION**

This **2026-09-25 historical claim is superseded** by the live-E2E evidence correction above: a green workflow that skips every live test is not a passed qualification gate. The release-candidate pipeline is implemented, but a passing run of all 3 Ubuntu live tests is now explicitly outstanding along with the other external promotion gates.

**Blocking items for stable promotion:**
1. Version bump to `1.0.0-rc1` and tag `v1.0.0-rc1` with signing credentials
2. Clean-machine qualification evidence attached via `release-qa.md` issues for all three platforms
3. Successful execution of all 3 Ubuntu live E2E tests on the pinned baseline, with retained artifact evidence
4. Live E2E evidence attached for macOS and Windows
5. Human release owner authorization to promote draft to stable

Once the above are complete, the final stable release (`v1.0.0`) can be promoted from the validated RC artifacts.

---

## 13. Next Steps

1. **Version bump:** Update `Cargo.toml` and `apps/desktop/src-tauri/Cargo.toml` to `version = "1.0.0-rc1"`
2. **Tag RC:** Push tag `v1.0.0-rc1` to trigger release workflow with signing credentials
3. **Clean-machine QA:** Open three `release-qa.md` issues (one per platform) and attach evidence
4. **Live E2E repair validation:** Obtain a passing 3/3 Ubuntu run on the exact corrected PR head; then execute live probes on macOS/Windows per `compatibility-matrix.md`
5. **Final version bump:** Update to `version = "1.0.0"` and tag `v1.0.0` for stable release
6. **Promote to stable:** Human release owner promotes the v1.0.0 release to stable after all evidence accepted