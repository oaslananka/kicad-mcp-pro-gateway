---
name: Release QA Checklist
about: Standard template for release candidate CLI/daemon archive and desktop package QA
title: 'qa: Release QA sign-off for vX.Y.Z'
labels: qa, release
assignees: ''
---

## Release Candidate Details
- **Version Tag:** `vX.Y.Z`
- **Target SHA:**
- **Release Branch:** `main`
- **SHA256SUMS.txt verified:** [ ] Yes

## Artifact Scope
The current release workflow produces unsigned CLI/daemon archives and unsigned
`.deb`, `.dmg`, and `.msi` desktop packages. It does not produce AppImage,
NSIS, signed or notarized artifacts, SBOMs, attestations, or an automated
uninstaller.

## Platform Package QA Checklist

### Ubuntu / Linux x86_64
- [ ] Verify `SHA256SUMS.txt`, extract the `.tar.gz` archive, and launch both binaries.
- [ ] Install the `.deb` on a clean machine and record the packaged daemon path.
- [ ] Launch the desktop with no external daemon; verify it starts only the packaged sidecar and reaches IPC Ready.
- [ ] Local KiCad 10.0.x detection and pinned `kicad-mcp-pro` status check green.
- [ ] High-risk operation approval flow tested.
- [ ] Secret Service identity storage, revocation across restart, update, uninstall, and data-retention behavior verified.

### macOS Apple Silicon (aarch64)
- [ ] Verify `SHA256SUMS.txt`, extract the `.tar.gz` archive, and launch both binaries.
- [ ] Install the `.dmg` on a clean Apple Silicon machine and record the packaged daemon path.
- [ ] Launch the desktop with no external daemon; record unsigned Gatekeeper behavior and verify packaged-sidecar readiness.
- [ ] Local KiCad 10.0.x detection and pinned `kicad-mcp-pro` status check green.
- [ ] High-risk operation approval flow tested.
- [ ] Keychain identity storage, revocation across restart, update, uninstall, and data-retention behavior verified.

### Windows x86_64
- [ ] Verify `SHA256SUMS.txt`, extract the `.zip` archive, and launch both `.exe` files.
- [ ] Install the `.msi` on a clean machine and record the packaged daemon path.
- [ ] Launch the desktop with no external daemon; verify packaged-sidecar IPC readiness.
- [ ] Local KiCad 10.0.x detection and pinned `kicad-mcp-pro` status check green.
- [ ] High-risk operation approval flow tested.
- [ ] DPAPI identity storage, revocation across restart, update, uninstall, and data-retention behavior verified.

## Sign-Off Decision
- [ ] ALL SUPPORTED PACKAGE PLATFORMS PASSED - Ready for stable promotion.
- [ ] Required live KiCad/MCP evidence is attached, or promotion remains blocked.
