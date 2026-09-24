# Release Engineering & Code Signing Procedures

This document outlines the automated release pipeline, signing readiness configuration, and manual QA procedures for KiCad MCP Pro Gateway releases.

## Release Pipeline Overview

Releases are triggered automatically when a version tag matching `v*` (e.g., `v0.1.0-rc1` or `v0.1.0`) is pushed to GitHub.

Workflow file: `.github/workflows/release.yml`

### Pipeline Stages

1. **Build headless artifacts**: Compiles the CLI
   (`kicad-mcp-gateway`) and daemon (`kicad-mcp-gateway-daemon`) for Linux
   `x86_64-unknown-linux-gnu`, macOS `aarch64-apple-darwin`, and Windows
   `x86_64-pc-windows-msvc`, then packages the sibling binaries with the
   README and license.
2. **Build desktop packages**: Runs the Tauri packaging path for the same
   targets. `prepare-sidecar.mjs` first proves that the daemon, desktop, and
   Tauri versions match, then stages the target-qualified daemon as
   `externalBin`. The matrix produces `.deb`, `.dmg`, and `.msi` packages.
3. **Verify embedded sidecars**: `verify:sidecar` requires a non-empty,
   executable packaged daemon in every Tauri bundle before publication.
4. **Consolidate and checksum**: Collects archives and desktop packages, then
   computes SHA-256 checksums for every release asset.
5. **Publish release**: Uploads all assets and checksums to a GitHub Release
   with generated release notes.

The authoritative ownership, update, rollback, and uninstall rules are in
[daemon-lifecycle.md](daemon-lifecycle.md). Signing/notarization hooks do not
change the requirement that the packaged sidecar be present and version
matched.

---

## Code Signing & Notarization Readiness

Production releases on macOS and Windows require code signing to prevent OS gatekeeper/smartscreen warnings.

### macOS (Apple Developer ID)

For macOS releases, code signing and Apple notarization require the following GitHub Secrets:

- `APPLE_CERTIFICATE`: Base64-encoded Developer ID Application `.p12` certificate.
- `APPLE_CERTIFICATE_PASSWORD`: Password for the `.p12` certificate.
- `APPLE_NOTARIZATION_USERNAME`: Apple ID email address.
- `APPLE_NOTARIZATION_PASSWORD`: App-specific password generated at appleid.apple.com.
- `APPLE_TEAM_ID`: 10-character Apple Developer Team ID.

When these secrets are provided, the Tauri build and macOS binary steps sign the executables with `codesign` and submit the final app bundle to `xcrun notarytool`.

### Windows (Authenticode)

For Windows releases, code signing requires:

- `WINDOWS_PFX_BASE64`: Base64-encoded Code Signing Certificate (`.pfx`).
- `WINDOWS_PFX_PASSWORD`: Password for the PFX certificate.

Alternatively, Azure Trusted Signing can be configured using `azure/trusted-signing-action`.

*Note: Unsigned release builds produced without these secrets display explicit unsigned notices and must be tested in developer mode.*

---

## Manual QA Verification Matrix

Before promoting a release candidate (`v*`) to a stable production release, run the following verification matrix on clean test machines for each supported OS:

### Linux / macOS / Windows Test Flow

1. **Clean Installation**: Install the platform package and confirm no previous
   config or database exists in `<data_dir>`.
2. **Packaged Sidecar Evidence**: Inspect the package and record the bundled
   daemon path. Run `pnpm verify:sidecar` against the produced bundle when
   reproducing locally; CI uploads the verified package artifact.
3. **First Launch & Readiness**: Launch the desktop with no daemon already
   running. Confirm it starts only the packaged sidecar and reaches Ready with
   product `kicad-mcp-gateway`, the expected daemon version, and a non-empty
   per-process instance ID.
4. **Setup & Core Detection**: Run `kicad-mcp-gateway setup` or
   `kicad-mcp-gateway status`. Verify KiCad MCP Pro core bridge detection.
5. **Workspace Management**: Authorize a KiCad project directory. Attempt
   relative path escape (`../`) to verify fail-closed path boundary
   enforcement.
6. **Pairing & Remote Sessions**: Initiate pairing, approve a session request,
   and verify the session becomes Active.
7. **Read-only Tool Execution**: Execute a classified read-only tool (for
   example `pcb_get_layers`). Confirm success and the audit record.
8. **High-Risk Approval**: Attempt manufacturing export and confirm it remains
   blocked pending explicit approval.
9. **Crash & Revocation Recovery**: Terminate the daemon, confirm desktop
   recovery, revoke a session, restart again, and verify the revoked session
   cannot reactivate.
10. **CLI Ownership Hand-off**: Run `daemon stop` while the desktop is open and
    confirm its watchdog does not restart the daemon; run `daemon start` and
    confirm readiness returns.
11. **Failure Evidence**: Repeat first launch with the packaged sidecar
    temporarily unavailable. Capture the safe UI failure banner and a redacted
    log excerpt; verify no alternate daemon or endpoint is launched.
12. **Update & Uninstall**: Upgrade in place and confirm data/revocation
    continuity, then stop/uninstall and confirm binaries are removed while
    `<data_dir>` remains until the user performs a deliberate data wipe.

---

## Release Blockers & External Verification Checklists

### Issue #4 — Upstream Dependency Exception (glib 0.18.5)
- **Current State:** Tracked in apps/desktop/src-tauri/osv-scanner.toml with expiry 2026-10-31.
- **Constraint:** Constrained by Tauri 2.11 GTK3 stack bindings; no direct VariantStrIter usage in Gateway code.
- **Verification:** osv_expiry_test in Tauri crate enforces exception freshness on every build.
- **Next Step:** Re-check upstream Tauri 2.x/3.x GTK updates prior to 2026-10-31.

### Issue #24 — Real KiCad MCP Pro E2E Integration Checklist
- [x] Mock MCP core bridge protocol client & server tests (crates/core-bridge/tests/client.rs)
- [ ] Checked-out upstream kicad-mcp-pro server execution (http://127.0.0.1:3334/mcp)
- [ ] E2E reconciliation pass against live tool catalog
- [ ] Real KiCad 8.x GUI application driven via Gateway policy boundary

### Issue #26 — Clean-Machine Manual QA Verification Checklist
- [x] Automated installer build workflow in CI
- [ ] Fresh Ubuntu 24.04 LTS clean machine first-launch validation
- [ ] Fresh macOS Apple Silicon clean machine first-launch validation
- [ ] Fresh Windows 11 clean machine first-launch validation
- [ ] Uninstaller and data-directory cleanup verification

### Issue #34 — Production Code Signing & Notarization Checklist
- [x] Workflow parameters and secret integration hooks in .github/workflows/release.yml
- [ ] Apple Developer ID .p12 certificate secret configured (APPLE_CERTIFICATE, APPLE_CERTIFICATE_PASSWORD)
- [ ] Apple Notarization credentials configured (APPLE_NOTARIZATION_USERNAME, APPLE_NOTARIZATION_PASSWORD, APPLE_TEAM_ID)
- [ ] Windows Code Signing Certificate configured (WINDOWS_PFX_BASE64, WINDOWS_PFX_PASSWORD or Azure Trusted Signing)
- [ ] Verification of signed binary signatures via codesign --verify and signtool verify

### Issue #36 — Release Candidate Readiness Checklist
- [x] Verified release gate in .github/workflows/release.yml (validate-release)
- [x] Multi-platform release binary & installer build jobs
- [x] SPDX SBOM generation (generate-sbom)
- [x] GitHub Artifact Attestations (attest-artifacts via actions/attest-build-provenance@v2)
- [ ] Maintainer explicit release tag trigger (e.g. v0.1.0-rc.1)

### Issue #39 — Final Stable V1 Sign-off Checklist
- [x] Security invariants verified and tested
- [x] Fail-closed policy, workspace boundary, and session revocation tests passing
- [ ] Resolution of all open release blockers (#4, #24, #26, #34, #36)
- [ ] Official release tag trigger (v1.0.0) and production release publication
