# Release Engineering and Manual QA

This document describes the release artifacts that the current workflow
actually produces and the manual checks required before a release candidate is
promoted. The supported platform baseline is maintained only in the
[canonical compatibility matrix](../architecture/compatibility-matrix.md).

## Automated Release Pipeline

A tag matching `v*` pushed to GitHub starts
[`.github/workflows/release.yml`](../../.github/workflows/release.yml). The
workflow performs exactly these steps:

### Pipeline Stages

1. **Build headless artifacts**: Compiles the CLI (`kicad-mcp-gateway`) and
   daemon (`kicad-mcp-gateway-daemon`) for Linux
   `x86_64-unknown-linux-gnu`, macOS `aarch64-apple-darwin`, and Windows
   `x86_64-pc-windows-msvc`.
2. **Package headless archives**: Adds the sibling binaries, `README.md`, and
   `LICENSE`; Linux/macOS use `.tar.gz` and Windows uses `.zip`.
3. **Build desktop packages**: Runs the Tauri packaging path for the same
   targets. `prepare-sidecar.mjs` proves that daemon, desktop, and Tauri
   versions match, then stages the target-qualified daemon as `externalBin`.
   The matrix produces `.deb`, `.dmg`, and `.msi` packages.
4. **Verify packaged sidecars**: `verify:sidecar` requires a non-empty,
   executable daemon in each Tauri release tree before publication.
5. **Consolidate and checksum**: Collects headless archives and desktop
   packages, then computes SHA-256 checksums for every release asset.
6. **Publish release**: Uploads all assets and checksums to a GitHub Release
   with generated release notes.

The authoritative ownership, update, rollback, and uninstall rules are in
[daemon-lifecycle.md](daemon-lifecycle.md). The packaged sidecar must remain
present and version matched regardless of future signing work.

### Not produced by the current workflow

The workflow does not currently produce AppImage or NSIS packages. It also has
no macOS code-signing or notarization step, Windows Authenticode/Trusted
Signing step, SBOM generation, artifact attestation, release-validation gate,
or uninstaller. These remain future work that requires reviewed workflow
changes; repository configuration or a checklist item is not evidence that
they are implemented.

The headless archives and desktop packages are unsigned unless a maintainer
adds and verifies a future signing workflow. Users must verify the published
`SHA256SUMS.txt` and must not infer platform trust from artifact production
alone.

## Manual Release-Candidate Verification

Before promoting a tag, verify the following on clean test machines for the
three supported platform targets. These checks validate both headless archives
and desktop packages, not a production hosted relay.

1. **Artifact integrity:** download every published asset and `SHA256SUMS.txt`;
   run `sha256sum -c SHA256SUMS.txt` (or the platform equivalent) and confirm
   the expected archive or installer exists.
2. **Clean install and identity:** install the platform desktop package with no
   prior Gateway data, launch it, and confirm the application starts only its
   packaged daemon. Also verify the Device ID is stored in the platform's
   native secret store (Secret Service, Keychain, or DPAPI).
3. **Core detection:** with the approved KiCad 10.0.x environment from the
   compatibility matrix, run `kicad-mcp-gateway setup` or
   `kicad-mcp-gateway status` and confirm the core-bridge detection result.
4. **Workspace containment:** authorize a KiCad project directory and verify a
   relative `../` path escape is denied.
5. **Policy enforcement:** run a classified read-only operation (for example
   `pcb_get_layers`) and confirm the audit event is recorded. Confirm an
   unclassified tool is denied.
6. **High-risk approval:** start a high-risk operation and confirm it remains
   blocked until explicit local approval.
7. **Session controls:** revoke an active session, restart the daemon and
   desktop, and confirm the session cannot reactivate.
8. **Update and cleanup:** upgrade in place and confirm data/revocation
   continuity. Remove the package, confirm packaged binaries are removed, and
   retain `<data_dir>` until the user performs a deliberate data wipe.

### Platform-specific package checks

| Platform | Headless archive | Desktop package | Required check |
|---|---|---|---|
| Ubuntu / Linux `x86_64` | `.tar.gz` | `.deb` | Verify checksums; test both archive binaries and a clean `.deb` install with Secret Service-backed identity storage. |
| macOS Apple Silicon (`aarch64`) | `.tar.gz` | `.dmg` | Verify checksums; test both archive binaries and a clean DMG install, recording unsigned Gatekeeper behavior and Keychain-backed identity storage. |
| Windows `x86_64` | `.zip` | `.msi` | Verify checksums; test both archive executables and a clean MSI install with DPAPI-backed identity storage. |

## Desktop Lifecycle Evidence

For each supported OS, retain clean-machine evidence for the complete
application-managed lifecycle:

1. **Clean installation:** install the platform package with no previous
   config or database in `<data_dir>`.
2. **Packaged sidecar:** inspect the package and record the bundled daemon
   path. When reproducing locally, run `pnpm verify:sidecar` against the
   produced Tauri release tree; CI uploads the verified package artifact.
3. **First launch and readiness:** launch with no daemon already running and
   confirm the desktop starts only the packaged sidecar and reaches Ready with
   product `kicad-mcp-gateway`, the expected version, and a non-empty
   per-process instance ID.
4. **Setup and core detection:** run `kicad-mcp-gateway setup` or
   `kicad-mcp-gateway status` against the supported KiCad 10.0.x baseline and
   verify core-bridge detection.
5. **Workspace and policy:** authorize a KiCad project, reject `../` escapes,
   execute a classified read-only tool, confirm its audit record, and confirm
   an unclassified tool is denied.
6. **High-risk approval:** attempt manufacturing export and confirm it remains
   blocked pending explicit approval.
7. **Crash and revocation recovery:** terminate the daemon, confirm desktop
   recovery, revoke a session, restart again, and verify the revoked session
   cannot reactivate.
8. **CLI ownership hand-off:** run `daemon stop` while the desktop is open and
   confirm its watchdog does not restart the daemon; run `daemon start` and
   confirm readiness returns.
9. **Failure evidence:** repeat first launch with the packaged sidecar
   temporarily unavailable. Capture the safe UI failure banner and a redacted
   log excerpt; verify no alternate daemon or endpoint is launched.
10. **Update and uninstall:** upgrade in place and confirm data/revocation
    continuity, then remove the package and confirm binaries are deleted while
    `<data_dir>` remains until a deliberate user data wipe.

## Release Blockers and External Verification Checklists

### Issue #4 — Upstream Dependency Exception (glib 0.18.5)
- **Current State:** Tracked in `apps/desktop/src-tauri/osv-scanner.toml` with expiry 2026-10-31.
- **Constraint:** Constrained by Tauri 2.11 GTK3 stack bindings; no direct VariantStrIter usage in Gateway code.
- **Verification:** `osv_expiry_test` in the Tauri crate enforces exception freshness on every build.
- **Next Step:** Re-check upstream Tauri 2.x/3.x GTK updates prior to 2026-10-31.

### Issue #24 — Real KiCad MCP Pro E2E Integration Checklist
- [x] Mock MCP core bridge protocol client and server tests (`crates/core-bridge/tests/client.rs`).
- [ ] Checked-out upstream kicad-mcp-pro server execution (`http://127.0.0.1:3334/mcp`).
- [ ] E2E reconciliation pass against the live tool catalog.
- [ ] Real KiCad 10.0.x GUI application driven through the Gateway policy boundary.

### Issue #26 — Clean-Machine Package QA Verification Checklist
- [x] Automated CLI/daemon archive and desktop package release workflows.
- [x] CI sidecar presence, size, and executable-bit verification for every Tauri target.
- [ ] Fresh Ubuntu 24.04 LTS `.deb` and headless archive validation.
- [ ] Fresh macOS Apple Silicon `.dmg` and headless archive validation.
- [ ] Fresh Windows `.msi` and headless archive validation.
- [ ] Manual update, uninstall, and data-directory continuity verification.
- [ ] Automated uninstaller workflow (not implemented).

### Issue #34 — Production Signing and Notarization Checklist
- [ ] Add a reviewed macOS `codesign` and `notarytool` workflow.
- [ ] Add a reviewed Windows Authenticode or Trusted Signing workflow.
- [ ] Verify signatures in release QA once those workflows exist.

### Issue #36 — Release Candidate Readiness Checklist
- [x] Tag-triggered release workflow in `.github/workflows/release.yml`.
- [x] Multi-platform CLI/daemon archive and desktop package jobs.
- [x] Packaged-sidecar verification before desktop artifact upload.
- [x] SHA-256 checksum generation.
- [ ] Add SBOM generation and artifact attestations if required for release.
- [ ] Maintainer explicit release tag trigger (for example `v0.1.0-rc.1`).

### Issue #39 — Final Stable V1 Sign-off Checklist
- [x] Security invariants verified and tested.
- [x] Fail-closed policy, workspace boundary, and session-revocation tests passing.
- [ ] Resolution of all open release blockers (#4, #24, #26, #34, #36).
- [ ] Official release tag trigger (`v1.0.0`) and production release publication.
