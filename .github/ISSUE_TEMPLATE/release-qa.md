---
name: Release QA Checklist
about: Evidence-gated clean-machine qualification for an exact Gateway release candidate
title: 'qa: Release QA sign-off for vX.Y.Z'
labels: qa, release
assignees: ''
---

## Candidate Identity

- **Draft release URL:**
- **Release workflow run URL:**
- **Version tag:** `vX.Y.Z`
- **Source commit SHA:**
- **`artifact-manifest.json` SHA-256:**
- **`SHA256SUMS.txt` SHA-256:**
- **`gateway-source.spdx.json` SHA-256:**
- **Build-provenance attestation URL / ID:**
- **SBOM attestation URL / ID:**

Do not continue unless the tag, source commit, workflow run, draft release, and
all three manifest hashes refer to the same candidate. Record the exact expected
installer hashes below from the draft's `artifact-manifest.json`.

## Exact Artifact Hashes

| Platform | Installer filename | SHA-256 | Headless archive filename | SHA-256 |
|---|---|---|---|---|
| Ubuntu / Linux x86_64 | `kicad-mcp-gateway-desktop-vX.Y.Z-x86_64-unknown-linux-gnu.deb` | | `kicad-mcp-gateway-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` | |
| macOS Apple Silicon | `kicad-mcp-gateway-desktop-vX.Y.Z-aarch64-apple-darwin.dmg` | | `kicad-mcp-gateway-vX.Y.Z-aarch64-apple-darwin.tar.gz` | |
| Windows 11 x86-64 | `kicad-mcp-gateway-desktop-vX.Y.Z-x86_64-pc-windows-msvc.msi` | | `kicad-mcp-gateway-vX.Y.Z-x86_64-pc-windows-msvc.zip` | |

- [ ] `SHA256SUMS.txt` passes on a clean download.
- [ ] `gh attestation verify <installer>` passes for build provenance.
- [ ] `gh attestation verify <installer>` passes for the source SBOM.

## Clean-Machine Inventory

Record the machine image/build, architecture, date/time in UTC, operator, and
proof that Gateway, its data directory, and its native identity entry were not
present before the test.

| Platform | Clean image/build | Architecture | Operator | UTC start/end |
|---|---|---|---|---|
| Ubuntu 24.04 LTS | | x86_64 | | |
| macOS Apple Silicon | | arm64 | | |
| Windows 11 | | x86-64 | | |

## Per-Platform Qualification

Repeat every applicable section. Attach command output and screenshots from the
same download whose hashes are recorded above.

### Ubuntu / Linux x86_64

- [ ] The `.deb` and `.tar.gz` hashes match the table.
- [ ] `dpkg-deb --info` / package inspection succeeds and the package contains
      exactly one desktop executable and one daemon sidecar.
- [ ] Install the `.deb` with no manual daemon setup; record the installed
      desktop and packaged daemon paths.
- [ ] First launch starts only the packaged daemon and reaches local IPC Ready.
- [ ] Device identity is created/loaded through Secret Service; no private key is
      written to the data directory or logs.
- [ ] `codesign` is not applicable; artifact identity is the exact manifest hash
      plus verified build/SBOM attestations.

### macOS Apple Silicon

- [ ] The `.dmg` and `.tar.gz` hashes match the table.
- [ ] `codesign --verify --deep --strict` passes for the app and packaged daemon;
      `codesign --verify --strict` passes for the DMG.
- [ ] Signature authority is `Developer ID Application`; the Apple Team ID is
      recorded in the public verification evidence.
- [ ] `xcrun stapler validate` and `spctl --assess --type execute` pass for the
      app inside this exact DMG.
- [ ] Mount/install the DMG with no manual daemon setup; record the app and
      packaged daemon paths.
- [ ] First launch starts only the packaged daemon and reaches local IPC Ready.
- [ ] Device identity is created/loaded through Keychain; no private key is
      written to the app container or logs.

### Windows 11 x86-64

- [ ] The `.msi` and `.zip` hashes match the table.
- [ ] `Get-AuthenticodeSignature` reports `Valid`, the signer thumbprint matches
      the approved certificate, and a timestamp certificate is present.
- [ ] `signtool verify /pa /all` passes for this exact MSI.
- [ ] Administrative extraction proves the MSI contains exactly one desktop
      executable and one daemon sidecar.
- [ ] Install the MSI with no manual daemon setup; record the installed desktop
      and packaged daemon paths.
- [ ] First launch starts only the packaged daemon and reaches local IPC Ready.
- [ ] Device identity is created/loaded through DPAPI; no private key is written
      to the install directory or logs.
- [ ] Record any SmartScreen result. A valid signature does not guarantee an
      immediate reputation bypass for a new publisher/file.

## Lifecycle Qualification

Run these checks on every platform and attach redacted evidence.

- [ ] Local KiCad 10.0.x detection and pinned `kicad-mcp-pro` status are green,
      or the exact blocker is recorded and promotion remains blocked.
- [ ] A workspace `../` escape is denied and a classified read operation creates
      an audit record.
- [ ] An unclassified tool is denied; a high-risk operation remains blocked until
      explicit local approval.
- [ ] Daemon termination is recovered by the desktop watchdog; a revoked session
      remains revoked after daemon and desktop restart.
- [ ] CLI `daemon stop` is not raced by the desktop watchdog; `daemon start`
      returns to Ready.
- [ ] Packaged-sidecar failure shows the safe UI failure state and starts no
      alternate daemon or endpoint.
- [ ] One Ready-state screenshot, one safe-failure screenshot, and one redacted
      lifecycle log are attached for each platform.

## Upgrade, Uninstall, and Data Retention

| Check | Ubuntu | macOS | Windows |
|---|---|---|---|
| Install the next candidate in place | [ ] | [ ] | [ ] |
| Identity, database, workspace, approvals, audit, and revocations persist | [ ] | [ ] | [ ] |
| Old daemon is replaced without two owners | [ ] | [ ] | [ ] |
| Uninstall removes desktop and packaged daemon binaries | [ ] | [ ] | [ ] |
| Stable data directory remains after uninstall | [ ] | [ ] | [ ] |
| Deliberate data wipe removes the data directory | [ ] | [ ] | [ ] |
| Deliberate data wipe removes the native-key-store entry | [ ] | [ ] | [ ] |

- [ ] Update evidence records both old and new package hashes and versions.
- [ ] Uninstall/reinstall proves that normal uninstall is not a data wipe.
- [ ] A separate, deliberate wipe removes both stable data and native identity;
      no result is inferred from deleting application files alone.

## Redaction and Sign-Off

- [ ] Attachments contain no pairing codes, device fingerprints, tokens,
      passwords, private keys, configuration secrets, usernames, or unredacted
      user paths.
- [ ] All three platform records point to the exact hashes in this issue.
- [ ] Failed checks are retained as evidence and block promotion.
- [ ] All supported packages and lifecycle checks passed.
- [ ] Required live KiCad/MCP evidence is attached, or promotion remains blocked.
- [ ] A separately authorized release owner may consider draft promotion. This
      QA issue does not itself publish a stable release.
