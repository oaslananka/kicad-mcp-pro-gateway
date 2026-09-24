---
name: Release QA Checklist
about: Standard template for release candidate multi-platform QA verification
title: 'qa: Release QA sign-off for vX.Y.Z'
labels: qa, release
assignees: ''
---

## Release Candidate Details
- **Version Tag:** `vX.Y.Z`
- **Target SHA:**
- **Release Branch:** `main`

## Platform QA Checklist

### Ubuntu / Linux x86_64
- [ ] Install AppImage / `.deb` on fresh machine.
- [ ] Daemon auto-start and IPC socket binding verified.
- [ ] Local KiCad 8.x detection and `kicad-mcp-pro` status check green.
- [ ] High-risk operation prompt rendering and approval flow tested.
- [ ] Uninstall and data retention policy verified.

### macOS Apple Silicon (aarch64)
- [ ] Install DMG / `.app` on fresh macOS machine.
- [ ] Gatekeeper & notarization ticket verification.
- [ ] Native Keychain integration for device identity & session tokens.
- [ ] High-risk operation prompt rendering and approval flow tested.
- [ ] Uninstall and data retention policy verified.

### Windows x86_64
- [ ] Install MSI / NSIS installer on clean Windows 11 machine.
- [ ] Authenticode code signing signature verified.
- [ ] Windows Credential Manager integration verified.
- [ ] High-risk operation prompt rendering and approval flow tested.
- [ ] Uninstall and data retention policy verified.

## Sign-Off Decision
- [ ] ALL PLATFORMS PASSED - Ready for stable promotion.
