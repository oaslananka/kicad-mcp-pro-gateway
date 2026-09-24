# Repository security automation

This document records the repository-level security and quality automation baseline as of 2026-09-17.

## Enforced in repository workflows

- GitHub Actions are pinned to full commit SHAs; version comments are kept for Dependabot readability.
- Workflow tokens default to no permissions or `contents: read`. The OSV reusable workflows require `security-events: write` in their caller permission contract; PR SARIF upload remains disabled, while the full scan uses that permission to upload SARIF.
- Checkout credentials are not persisted in ordinary CI jobs.
- `cargo audit` remains part of the normal cross-platform CI workflow.
- `pnpm audit` is part of the desktop CI job and must report no known vulnerabilities.
- Dependency Review blocks pull requests that introduce moderate-or-higher vulnerable dependencies, including development dependencies.
- zizmor audits GitHub Actions workflows as a blocking PR check.
- OSV-Scanner compares PR dependency state against the base branch and rejects newly introduced known vulnerabilities.
- A weekly and main-push OSV full scan checks the complete current dependency baseline and uploads SARIF to GitHub code scanning.

The Tauri lockfile currently requires time-bounded OSV exceptions in `apps/desktop/src-tauri/osv-scanner.toml`. They cover one `glib` unsoundness constrained by the current stable Tauri 2.x GTK3 stack (expiry 2026-10-31) and INFO/unmaintained transitives from GTK/urlpattern (expiry 2026-12-31). OSV prints each exception and its reason during scans; new advisories remain fail-closed.

## GitHub native protections

GitHub secret scanning, secret-scanning push protection, and Dependabot security updates are enabled for this public repository. Generic/non-provider secret patterns and partner validity checks are not enabled because GitHub currently limits those repository-level features to eligible organization-owned repositories with Secret Protection.

## Dependency updates

Dependabot is configured weekly for Cargo, `apps/desktop` npm/pnpm dependencies, and GitHub Actions. Routine minor/patch version updates are grouped into at most one open PR per ecosystem; major version migrations are manual work rather than automated PR churn. Dependabot security updates remain enabled and are not restricted by the version-update policy. Dependabot does not auto-merge changes; every update still goes through the repository's normal review and CI path.

## Mergify

Mergify is already installed for this repository. `.mergify.yml` configures only Merge Protections for `main`: Conventional Commit-style PR titles plus the core Rust, cargo-audit, desktop, Dependency Review, zizmor, and OSV PR checks.

Auto-merge/auto-queue is intentionally not configured. The `auto_merge_conditions` setting is omitted so merging remains an explicit maintainer action.

## SonarQube Cloud

SonarQube Cloud supports Rust, including native Rust analysis and Clippy integration. For GitHub repositories, SonarQube Cloud recommends automatic analysis when the imported project is eligible; that mode requires no repository scanner workflow or `SONAR_TOKEN`.

This repository does not currently have a Sonar project/check. The standard activation path is therefore: bind/import the real GitHub repository into SonarQube Cloud first and use automatic analysis if Sonar marks the project eligible. Only switch to CI-based analysis when automatic analysis is unsuitable (for example, when coverage, monorepo behavior, or other advanced CI-controlled analysis is required); CI-based analysis then needs the real project identifiers and authentication secret.

No placeholder project key, fake token, or workflow that claims Sonar is enabled is committed. Keep the existing `cargo clippy -D warnings` gate regardless of Sonar mode; Sonar's Clippy integration is additive and must not weaken the local compiler/lint gate.

## OpenSSF Scorecard

Scorecard was evaluated but is not enabled in this baseline. As of 2026-09-17, the supported action is v2.4.4 or newer, while an upstream open issue documents that the action's runtime container is referenced by a mutable tag. That weakens the guarantee provided by SHA-pinning the outer action, so the repository does not add that extra supply-chain dependency until the runtime image is immutable/digest-pinned.

## GitHub branch/ruleset enforcement

A repository ruleset named `main quality gate` is staged in GitHub with enforcement set to `disabled` until this baseline is merged to the default branch. It targets `main` and is preconfigured to require pull requests, resolved review threads, the core Rust/desktop/security checks, and `Mergify Merge Protections`; required check sources are pinned to their GitHub App integration IDs. It also blocks force-pushes and deletion when activated. The ruleset intentionally requires zero approving reviews so a single-maintainer repository remains operable, and automatic merging is not enabled by the ruleset. After this baseline is merged and the checks run successfully from `main`, activate the staged ruleset without changing its check set unless a real check name/source has changed.

## Production Branch Protection & Review Policy (#44)

The `main` branch of this repository is protected by GitHub Rulesets and automated quality gates:

### Quality Gates
- **Main Quality Gate Ruleset:** Active and enforced on `main`.
- **Pull Request Requirement:** All changes to `main` must arrive via a pull request.
- **Required Checks:** CI (`cargo test`, `pnpm test`), CodeQL analysis, OSV security scan, and cargo-audit must pass before merging.
- **Resolved Review Threads:** All PR conversation threads must be resolved before merging.
- **Mergify Enforcement:** Auto-merge and queueing are managed via Mergify. PR titles must strictly match Conventional Commit syntax (`type(scope): description`) without slashes in the scope.

### Solo Maintainer Rationale
As a single-maintainer project during the current development phase, mandatory approving reviews are set to zero to avoid self-approval blocking while maintaining automated CI quality gates. Security-critical changes (policy, secret storage, IPC codecs) undergo full automated regression testing in CI before merge.
