# Release Candidate Engineering and Manual QA

This document describes the release-candidate workflow that actually exists in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) and the
manual evidence required before any candidate can be promoted. The supported
platform baseline is maintained only in the
[canonical compatibility matrix](../architecture/compatibility-matrix.md).

A tag matching `v*` starts the workflow. The workflow is fail-closed: missing
signing credentials, a tag/version mismatch, a package without its packaged
sidecar, a failed platform signature check, a malformed SBOM, or a missing
attestation prevents creation of the draft release. It creates a **draft and
prerelease only**. Compilation, CI success, or artifact upload is not a support
or promotion decision.

## Automated Release-Candidate Pipeline

### 1. Version, CI, and build gates

Before any signing credential is made available, the workflow requires
successful `push` runs for the exact tagged commit from `ci.yml`,
`e2e-live.yml`, and `osv-full.yml`. Every matrix job then requires the tag to be
exactly `v<workspace version>`. The desktop job also requires the daemon,
desktop Cargo package, and `tauri.conf.json` versions to match. Builds use locked
Rust dependencies and the frozen pnpm lockfile.

### 2. Headless artifacts

The workflow packages the CLI and daemon for:

- Linux `x86_64-unknown-linux-gnu` in `.tar.gz`;
- macOS Apple Silicon `aarch64-apple-darwin` in `.tar.gz`; and
- Windows x86-64 MSVC in `.zip`.

These archives are covered by the release checksum manifest and provenance
attestation. They are not represented as signed installers.

### 3. Signed desktop artifacts

The desktop matrix produces the canonical installer format for every supported
row in the compatibility matrix:

| Platform | Installer | Required release trust check |
|---|---|---|
| Ubuntu / Linux `x86_64` | `.deb` | Exact package extraction, checksum, and provenance attestation |
| macOS Apple Silicon | `.dmg` | Developer ID signature, notarized/stapled app, and Gatekeeper assessment |
| Windows 11 / x86-64 | `.msi` | Timestamped Authenticode signature and `signtool verify /pa` |

#### macOS signing and notarization

The macOS job requires a **Developer ID Application** certificate (not a
development or ad-hoc identity) and App Store Connect API credentials. It
imports the certificate into an ephemeral keychain, requires exactly one valid
Developer ID identity, builds the `aarch64-apple-darwin` DMG, and then verifies
all of the following against the exact DMG contents:

1. the application, packaged daemon sidecar, and DMG pass strict `codesign`
   verification;
2. the application authority is `Developer ID Application` and has a non-empty
   Apple Team ID;
3. `xcrun stapler validate` accepts the notarization ticket; and
4. `spctl --assess --type execute` accepts the application.

A missing certificate, wrong identity class, failed notarization, missing
stapled ticket, or Gatekeeper rejection fails the release build.

#### Windows Authenticode signing

The Windows job imports a code-signing PFX into the ephemeral user certificate
store, requires the configured SHA-1 certificate thumbprint to match, requires a
private key and Code Signing EKU, and generates a temporary Tauri configuration
containing the thumbprint, SHA-256 digest algorithm, and an RFC 3161 timestamp
URL. The private key and generated configuration are removed after the build.

The exact MSI is then administratively extracted to prove that it contains one
desktop executable and one daemon sidecar. The job requires:

- `Get-AuthenticodeSignature` status `Valid`;
- the expected signer thumbprint;
- a trusted timestamp certificate; and
- successful `signtool verify /pa /all` output.

Authenticode makes the artifact eligible for normal Windows trust and
SmartScreen reputation evaluation. A newly signed file can still receive a
SmartScreen warning until Microsoft has reputation for the publisher/file; the
workflow does not claim that compilation or a valid signature guarantees an
immediate warning bypass.

#### Linux package identity

Ubuntu `.deb` packages do not have a portable Microsoft/Apple-style code
signature. Their release identity is instead bound by the exact SHA-256 in
`artifact-manifest.json` / `SHA256SUMS.txt` and the signed GitHub build
provenance attestation. The job also extracts the `.deb` and requires exactly
one desktop executable and one packaged daemon.

### 4. SBOM, manifest, checksums, and provenance

After all six build artifacts pass their platform jobs, the workflow:

1. generates `gateway-source.spdx.json` with pinned Syft v1.51.1 from the locked
   source tree;
2. validates that it is non-empty SPDX 2 JSON below the 16 MiB attestation
   limit;
3. writes `artifact-manifest.json` with the tag, source commit, exact payload
   filenames, sizes, SHA-256 values, and an explicit **pending** clean-machine
   qualification state;
4. creates `SHA256SUMS.txt` for every payload, installer, verification record,
   the manifest, and the SBOM; and
5. verifies that checksum file before upload.

`actions/attest-build-provenance` then creates SLSA build provenance for every
subject in `SHA256SUMS.txt`. `actions/attest-sbom` binds the SPDX document to
those same subjects. Both actions use GitHub OIDC and store verifiable Sigstore
attestations for the repository. The generated JSONL bundles and an attestation
ID/URL index are retained as workflow artifacts and draft-release assets.

Users can verify a downloaded file with both integrity and provenance:

```bash
sha256sum --check SHA256SUMS.txt
gh attestation verify <downloaded-file> \
  --repo oaslananka/kicad-mcp-pro-gateway
```

### 5. Draft publication

Only after all build, platform-verification, SBOM, checksum, and attestation
jobs pass does the workflow use GitHub CLI to create a release. It verifies the
existing tag and creates the release with both `draft` and `prerelease` set.
Failure at any earlier stage leaves the failed workflow logs and artifacts as
release evidence and creates no draft.

This repository change does not publish a stable release. Public promotion is a
separate, explicitly authorized operation after the clean-machine evidence below
is complete.

## Release Signing Configuration

Signing values must be stored in the protected GitHub Actions environment named
`release-signing`, not committed to the repository or written to logs. Configure
required reviewers for that environment so an ordinary tag cannot silently
consume production signing credentials.

| Secret / variable | Purpose |
|---|---|
| `APPLE_CERTIFICATE` | Base64-encoded Developer ID Application PFX |
| `APPLE_CERTIFICATE_PASSWORD` | PFX export password |
| `APPLE_API_ISSUER` | App Store Connect API issuer UUID |
| `APPLE_API_KEY` | App Store Connect API key ID |
| `APPLE_API_PRIVATE_KEY` | Contents of the downloaded App Store Connect `.p8` key |
| `WINDOWS_CERTIFICATE` | Base64-encoded code-signing PFX |
| `WINDOWS_CERTIFICATE_PASSWORD` | PFX export password |
| `WINDOWS_CERTIFICATE_THUMBPRINT` | Expected SHA-1 thumbprint of the code-signing certificate |
| `WINDOWS_TIMESTAMP_URL` | Optional repository variable containing the approved HTTP(S) timestamp URL; defaults to DigiCert's timestamp service |

Never paste a certificate, private key, PFX password, Apple app-specific
password, API key, or Windows credential into an issue, workflow log, release
note, or QA attachment. The workflow only records public certificate identity,
verification status, timestamps, package hashes, and command output.

## Clean-Machine Qualification

GitHub-hosted builders are reproducible build and verification runners; they
are not evidence that a user-visible installer works on a clean supported
machine. Open one issue from
[`.github/ISSUE_TEMPLATE/release-qa.md`](../../.github/ISSUE_TEMPLATE/release-qa.md)
for each candidate and attach its records. Every record must identify the exact
installer filename and SHA-256 from the draft's `artifact-manifest.json`; a
result for different bytes is not valid evidence.

The required clean environments are:

- a fresh Ubuntu 24.04 LTS x86-64 machine with no prior Gateway files or
  packages;
- a fresh Apple Silicon macOS machine; and
- a fresh Windows 11 x86-64 machine.

For each platform, retain the following evidence against the exact candidate
hashes:

1. `SHA256SUMS.txt` and both GitHub attestations verified;
2. the platform signature/notarization verification record downloaded from the
   draft;
3. clean install and packaged-sidecar path;
4. first launch with no pre-existing daemon, reaching the intended local IPC
   Ready state without a manual shell daemon;
5. device identity creation/load in Secret Service, Keychain, or DPAPI, with
   secrets and fingerprints redacted;
6. daemon crash/restart, CLI ownership hand-off, and revoked-session
   persistence;
7. in-place upgrade with identity, database, workspace, approval, audit, and
   revocation continuity;
8. uninstall with binaries removed while stable user data remains; and
9. a separate deliberate data wipe, including removal of the native-key-store
   entry, with redacted before/after paths.

Retain one Ready-state screenshot, one safe-failure screenshot, and one redacted
lifecycle log per platform. Remove pairing codes, device fingerprints, tokens,
usernames, private paths, configuration values, and process arguments before
attaching them.

Compilation, a valid package signature, or three successful installers without
these lifecycle checks is insufficient evidence. A failed check is retained
and blocks promotion; it is not converted into a support claim or removed from
the release record.

## Not Produced or Automated

The current workflow does **not** produce AppImage or NSIS packages, run the
required operating systems on physical clean machines, automate the complete
GUI/update/uninstall scenario, or publish a stable release. Those are explicit
remaining qualification/promotion activities, not implied capabilities.

## Evidence Checklist

### Signing and artifact identity

- [x] Exact-commit CI, live KiCad/MCP E2E, and OSV success gate.
- [x] Tag/version and daemon/desktop/Tauri version gate.
- [x] Developer ID import, signing, notarization, stapling, strict signature,
  and Gatekeeper verification in the macOS release job.
- [x] Authenticode certificate validation, timestamping, package extraction,
  and `signtool` verification in the Windows release job.
- [x] Exact `.deb` extraction and packaged-sidecar verification.
- [x] SPDX JSON SBOM, artifact manifest, SHA-256 manifest, build provenance,
  and SBOM attestation.
- [x] Draft-and-prerelease publication gate.
- [ ] Retain successful signature/notarization output from an actual tagged
  release candidate.

### Clean-machine release qualification

- [ ] Fresh Ubuntu 24.04 LTS `.deb` and headless archive validation.
- [ ] Fresh macOS Apple Silicon `.dmg` and headless archive validation.
- [ ] Fresh Windows 11 `.msi` and headless archive validation.
- [ ] First-launch, identity, policy, crash/restart, and revocation evidence on
  all three platforms.
- [ ] Upgrade, uninstall, data-retention, and deliberate data-wipe evidence on
  all three platforms.
- [ ] Required live KiCad 10.0.x / pinned `kicad-mcp-pro` evidence attached for
  the exact candidate, or promotion remains blocked.

### Promotion

- [ ] All candidate hashes match the draft manifest and qualification records.
- [ ] All required evidence is attached, redacted, and accepted.
- [ ] A separately authorized release owner promotes the draft; this issue
  itself does not publish a stable release.
