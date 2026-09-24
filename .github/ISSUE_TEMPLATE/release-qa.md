---
name: Release QA Checklist
about: Standard template for release candidate multi-platform CLI/daemon archive QA verification
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
The current release workflow produces unsigned CLI/daemon archives, not
installers, desktop bundles, signed binaries, SBOMs, or attestations. Record
those as separate future work if they are required for promotion.

## Platform Archive QA Checklist

### Ubuntu / Linux x86_64
- [ ] Verify `SHA256SUMS.txt` and extract the `.tar.gz` archive.
- [ ] Launch the extracted CLI and daemon; verify local IPC binding.
- [ ] Local KiCad 10.0.x detection and pinned `kicad-mcp-pro` status check green.
- [ ] High-risk operation approval flow tested.
- [ ] Secret Service identity storage and manual data-directory cleanup verified.

### macOS Apple Silicon (aarch64)
- [ ] Verify `SHA256SUMS.txt` and extract the `.tar.gz` archive.
- [ ] Launch the extracted CLI and daemon; record unsigned-binary Gatekeeper behavior.
- [ ] Local KiCad 10.0.x detection and pinned `kicad-mcp-pro` status check green.
- [ ] High-risk operation approval flow tested.
- [ ] Keychain identity storage and manual data-directory cleanup verified.

### Windows x86_64
- [ ] Verify `SHA256SUMS.txt` and extract the `.zip` archive.
- [ ] Launch the extracted CLI and daemon `.exe` files; record unsigned-binary behavior.
- [ ] Local KiCad 10.0.x detection and pinned `kicad-mcp-pro` status check green.
- [ ] High-risk operation approval flow tested.
- [ ] DPAPI identity storage and manual data-directory cleanup verified.

## Sign-Off Decision
- [ ] ALL SUPPORTED ARCHIVE PLATFORMS PASSED - Ready for stable promotion.
- [ ] Required live KiCad/MCP evidence is attached, or promotion remains blocked.
