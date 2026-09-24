# Release Engineering and Manual QA

This document describes the release artifacts that the current workflow
actually produces and the manual checks required before a release candidate is
promoted. The supported platform baseline is maintained only in the
[canonical compatibility matrix](../architecture/compatibility-matrix.md).

## Automated Release Pipeline

A tag matching `v*` pushed to GitHub starts
[`.github/workflows/release.yml`](../../.github/workflows/release.yml). The
workflow performs exactly these steps:

1. **Build binaries:** release builds of the CLI (`kicad-mcp-gateway`) and
   daemon (`kicad-mcp-gateway-daemon`) for:
   - Linux `x86_64-unknown-linux-gnu`
   - macOS `aarch64-apple-darwin`
   - Windows `x86_64-pc-windows-msvc`
2. **Package archives:** each archive contains the two binaries, `README.md`,
   and `LICENSE`. Linux/macOS use `.tar.gz`; Windows uses `.zip`.
3. **Consolidate and checksum:** the workflow copies the archives to `dist/` and
   writes `SHA256SUMS.txt`.
4. **Publish:** GitHub CLI creates a GitHub Release for the tag, uploads the
   archives and checksum file, and generates release notes.

### Not produced by the current workflow

There is currently **no** automated desktop/app bundle, AppImage, `.deb`, DMG,
`.app`, MSI, or NSIS installer. There is also no macOS code-signing or
notarization step, Windows Authenticode signing, SBOM generation, artifact
attestation, release validation gate, or uninstaller. These are future work
that requires reviewed workflow changes; repository configuration or a
checklist item is not evidence that they are implemented.

The release archives are unsigned. Users must verify the published
`SHA256SUMS.txt`; they must not expect platform trust prompts or an installer
to be resolved by this workflow.

## Manual Release-Candidate Verification

Before promoting a tag, verify the following on clean test machines for the
three supported platform targets. These checks validate the archives, not an
installer or a production hosted relay.

1. **Artifact integrity:** download the release archives and `SHA256SUMS.txt`;
   run `sha256sum -c SHA256SUMS.txt` (or the platform equivalent) and confirm
   the expected CLI and daemon files are present.
2. **First launch and identity:** extract the archive, start
   `kicad-mcp-gateway-daemon` or the CLI, and confirm the Device ID is stored
   in the platform's native secret store (Secret Service, Keychain, or DPAPI).
   There is no installer or service auto-start to verify.
3. **Core detection:** with the approved local environment from the
   compatibility matrix, run `kicad-mcp-gateway setup` or
   `kicad-mcp-gateway status` and confirm the core-bridge detection result.
4. **Workspace containment:** authorize a KiCad project directory and verify a
   relative `../` path escape is denied.
5. **Policy enforcement:** run a classified read-only operation (for example
   `pcb_get_layers`) and confirm the audit event is recorded. Confirm an
   unclassified tool is denied.
6. **High-risk approval:** start a high-risk operation and confirm it remains
   blocked until explicit local approval.
7. **Session controls:** exercise revocation using the in-process test
   transport. A production hosted relay is not part of this repository.
8. **Data cleanup:** remove the test data directory using the documented
   platform path and confirm the expected files are removed. There is no
   automated uninstaller to test.

### Platform-specific archive checks

| Platform | Archive | Required check |
|---|---|---|
| Ubuntu / Linux `x86_64` | `.tar.gz` | Extract outside any prior data directory, launch both binaries, and verify Secret Service-backed identity storage. |
| macOS Apple Silicon (`aarch64`) | `.tar.gz` | Extract and launch both binaries; record the expected unsigned-binary Gatekeeper behavior and verify Keychain-backed identity storage. Do not require a notarization ticket. |
| Windows `x86_64` | `.zip` | Extract and launch both `.exe` files; verify DPAPI-backed identity storage. Do not require an Authenticode signature. |

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

### Issue #26 — Clean-Machine Archive QA Verification Checklist
- [x] Automated CLI/daemon archive release workflow.
- [ ] Fresh Ubuntu 24.04 LTS clean-machine archive validation.
- [ ] Fresh macOS Apple Silicon clean-machine archive validation.
- [ ] Fresh Windows clean-machine archive validation.
- [ ] Manual data-directory cleanup verification.
- [ ] Installer and uninstaller workflows (not implemented).

### Issue #34 — Production Signing and Notarization Checklist
- [ ] Add a reviewed macOS `codesign` and `notarytool` workflow.
- [ ] Add a reviewed Windows Authenticode or Trusted Signing workflow.
- [ ] Verify signatures in release QA once those workflows exist.

### Issue #36 — Release Candidate Readiness Checklist
- [x] Tag-triggered release workflow in `.github/workflows/release.yml`.
- [x] Multi-platform CLI/daemon binary archive jobs.
- [x] SHA-256 checksum generation.
- [ ] Add installer/app-bundle jobs if they become a release requirement.
- [ ] Add SBOM generation and artifact attestations if required for release.
- [ ] Maintainer explicit release tag trigger (for example `v0.1.0-rc.1`).

### Issue #39 — Final Stable V1 Sign-off Checklist
- [x] Security invariants verified and tested.
- [x] Fail-closed policy, workspace boundary, and session-revocation tests passing.
- [ ] Resolution of all open release blockers (#4, #24, #26, #34, #36).
- [ ] Official release tag trigger (`v1.0.0`) and production release publication.
