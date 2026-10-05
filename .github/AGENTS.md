# CI, Security, and Release Automation Instructions

These instructions apply to `.github/**` and supplement the repository root `AGENTS.md`.

## Boundary

Workflow changes are security and supply-chain policy changes. They may affect branch protection,
required checks, untrusted-code isolation, signing credentials, provenance, live-evidence claims,
and release promotion.

Read first:

- `docs/development/security-automation.md`
- `docs/development/testing.md`
- `docs/development/release.md`
- `docs/development/v1-stable-signoff.md`
- `docs/architecture/compatibility-matrix.md`
- `SECURITY.md`

## Required-check integrity

The live GitHub ruleset is authoritative. The checked-in inventory in
`docs/development/security-automation.md` is a dated record and must be revalidated against the
live repository before changing required contexts.

- Do not rename/delete/path-filter a required job without migrating and verifying branch
  protection in the same work.
- Do not add a required context until its producer/integration has been observed.
- Do not use `continue-on-error`, trigger narrowing, exclusions, or fake success steps to conceal a
  repository-owned failure.
- Keep review-thread resolution and force-push/deletion protections intact unless governance is
  intentionally changed.

## Workflow security

- Keep third-party Actions pinned to full commit SHAs.
- Keep checkout credentials disabled in ordinary CI.
- Default workflow permissions to none or read-only; add write scopes only to the smallest reviewed
  job that needs them.
- Do not expose signing/publishing secrets to pull-request code.
- Preserve Dependency Review, cargo audit, OSV, zizmor, Semgrep/GitGuardian integration assumptions,
  and other repository security gates.
- Do not add analyzer-suppression configuration merely to clear a finding; fix the issue or preserve
  the documented evidence-based disposition.

## Live E2E evidence

This repository has historical false-green evidence where the workflow succeeded with zero live
tests executed. Do not regress that gate.

A green workflow is valid live evidence only when the intended ignored live tests were explicitly
executed and the workflow proves a non-zero expected test count with no failures/ignored tests left
for the required scenario.

Keep the live lane pinned to the declared KiCad, `kicad-mcp-pro`, protocol, and source baseline.
Changing those pins is a compatibility/evidence change and must update the canonical matrix.

Do not claim Ubuntu live evidence proves macOS/Windows live behavior, physical PCB mutation, or
installer qualification.

## Release engineering

The release workflow is privileged supply-chain code.

Preserve:

- exact tag/root-workspace version, daemon workspace-version inheritance, desktop Cargo version, desktop `package.json` version, and `tauri.conf.json` version identity;
- release-version bumps refresh all affected Cargo and package lockfiles before locked CI/package builds;
- CI/live-E2E/OSV gates before signing credential access;
- macOS Developer ID signing, notarization, stapling, and Gatekeeper verification;
- Windows Authenticode identity and timestamp verification;
- exact packaged sidecar checks;
- SPDX SBOM, SHA-256 manifest, provenance, and SBOM attestations;
- draft/prerelease-only publication before manual qualification;
- exact-artifact clean-machine evidence;
- separately authorized human release-owner promotion.

A pipeline-ready repository is not a qualified stable release.

Do not repoint immutable release tags, replace released bytes silently, reuse evidence for different
hashes, or replay a successful publication mutation just to rerun verification.

## Verification

For workflow changes run the repository's security/static checks available for the touched surface,
plus the ordinary Rust/desktop gates as applicable.

A YAML parser passing is not enough. Validate:

- GitHub Actions expression/shell trust boundaries;
- permissions and secret exposure;
- required context production;
- test execution counts;
- artifact identity;
- signing/provenance dependencies;
- promotion semantics.

## Definition of done

A CI/release change is complete only when workflow syntax, required checks, permissions, immutable
pins, security scans, live evidence, artifact identity, signing/provenance, and manual promotion
requirements still agree with live repository governance.
