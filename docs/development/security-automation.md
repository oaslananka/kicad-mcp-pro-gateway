# Repository security automation

This document records the repository-level security and quality automation baseline. The GitHub-native `main` quality-gate state was last verified against the live API on 2026-09-24; the local glib compatibility patch was reviewed on 2026-09-25.

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

The Tauri lockfile uses a reviewed local backport for the `glib` 0.18 API required by the stable Tauri 2.x GTK3 stack. The backport applies the upstream `VariantStrIter::impl_get` soundness fix (the fix released in glib 0.20.0) without changing the GTK3-facing API; `apps/desktop/src-tauri/vendor/glib/PATCHES.md` records the provenance and exact diff. The remaining time-bounded OSV exceptions cover only INFO/unmaintained transitives from GTK/urlpattern. OSV prints each exception and its reason during scans; new advisories remain fail-closed.

## GitHub native protections

GitHub secret scanning, secret-scanning push protection, and Dependabot security updates are enabled for this public repository. Generic/non-provider secret patterns and partner validity checks are not enabled because GitHub currently limits those repository-level features to eligible organization-owned repositories with Secret Protection.

## Dependency updates

Dependabot is configured weekly for Cargo, `apps/desktop` npm/pnpm dependencies, and GitHub Actions. Routine minor/patch version updates are grouped into at most one open PR per ecosystem; major version migrations are manual work rather than automated PR churn. Dependabot security updates remain enabled and are not restricted by the version-update policy. Dependabot does not auto-merge changes; every update still goes through the repository's normal review and CI path.

## Mergify

Mergify is installed and emits `Mergify Merge Protections`, `Mergify Merge Queue`, and `Summary` check signals. This repository has no checked-in `.mergify.yml`; those signals are informational and none is required by the active `main` ruleset. The repository does not configure Mergify auto-merge or a merge queue in source control, and the quality gate below does not depend on Mergify.

## SonarQube Cloud

SonarQube Cloud supports Rust, including native Rust analysis and Clippy integration. For GitHub repositories, SonarQube Cloud recommends automatic analysis when the imported project is eligible; that mode requires no repository scanner workflow or `SONAR_TOKEN`.

This repository does not currently have a Sonar project/check. The standard activation path is therefore: bind/import the real GitHub repository into SonarQube Cloud first and use automatic analysis if Sonar marks the project eligible. Only switch to CI-based analysis when automatic analysis is unsuitable (for example, when coverage, monorepo behavior, or other advanced CI-controlled analysis is required); CI-based analysis then needs the real project identifiers and authentication secret.

No placeholder project key, fake token, or workflow that claims Sonar is enabled is committed. Keep the existing `cargo clippy -D warnings` gate regardless of Sonar mode; Sonar's Clippy integration is additive and must not weaken the local compiler/lint gate.

## OpenSSF Scorecard

Scorecard was evaluated but is not enabled in this baseline. As of 2026-09-17, the supported action is v2.4.4 or newer, while an upstream open issue documents that the action's runtime container is referenced by a mutable tag. That weakens the guarantee provided by SHA-pinning the outer action, so the repository does not add that extra supply-chain dependency until the runtime image is immutable/digest-pinned.

## GitHub native `main` quality gate

The repository ruleset named `main quality gate` (ID `23952106`) is active and targets the default branch, `main`. Its live policy:

- requires every change to `main` to arrive through a pull request;
- requires zero approving reviews and no named reviewers, so a single maintainer is not forced to self-approve;
- requires all review threads to be resolved;
- requires the 12 contexts listed below;
- blocks force-pushes and branch deletion; and
- permits merge, squash, and rebase merges, but does not enable automatic merging.

### Required-check inventory

| Source | Integration ID | Context | Definition or producer |
|---|---:|---|---|
| GitHub Actions | `15368` | `rust / ubuntu-latest` | `.github/workflows/ci.yml`, `rust` matrix |
| GitHub Actions | `15368` | `rust / windows-latest` | `.github/workflows/ci.yml`, `rust` matrix |
| GitHub Actions | `15368` | `rust / macos-latest` | `.github/workflows/ci.yml`, `rust` matrix |
| GitHub Actions | `15368` | `rust / msrv-1.88` | `.github/workflows/ci.yml`, `msrv` |
| GitHub Actions | `15368` | `frontend (apps/desktop)` | `.github/workflows/ci.yml`, `frontend` |
| GitHub Actions | `15368` | `security / cargo-audit` | `.github/workflows/ci.yml`, `security` |
| GitHub Actions | `15368` | `security / dependency-review` | `.github/workflows/security.yml`, `dependency-review` |
| GitHub Actions | `15368` | `security / osv-pr / osv-scan` | `.github/workflows/security.yml`, `osv-pr` and its reusable workflow |
| GitHub Actions | `15368` | `security / zizmor` | `.github/workflows/security.yml`, `workflow-audit` |
| Semgrep Cloud | `4384945` | `semgrep-cloud-platform/scan` | Semgrep Cloud GitHub App |
| GitGuardian | `46505` | `GitGuardian Security Checks` | GitGuardian GitHub App |
| Commit status | not pinned | `Independent Review` | Required commit status; GitHub's API intentionally omits an integration ID for this context |

The observed CodeQL, full-repository OSV, Socket, Mergify, and Dependabot signals are not part of this required set. CodeQL and full-repository OSV provide additional analysis, Socket supplies informational dependency findings, Mergify supplies coordination signals, and Dependabot is an update actor rather than a pull-request quality gate. Do not add a context to the ruleset until its current workflow or App source has been observed and mapped as above.

### Verification record

Live API state was captured at `2026-09-24T22:42:08Z`:

- The [rulesets index](https://api.github.com/repos/oaslananka/kicad-mcp-pro-gateway/rulesets) returned one ruleset, and [ruleset `23952106`](https://api.github.com/repos/oaslananka/kicad-mcp-pro-gateway/rulesets/23952106) reported `enforcement: active`, the pull-request, required-status-check, deletion, and non-fast-forward rules, and the 12 contexts above.
- Main commit [`7c6a28b`](https://api.github.com/repos/oaslananka/kicad-mcp-pro-gateway/commits/7c6a28bacd41b2d1050a6942dae46b5cfb63f321/check-runs) had 12 check runs, all successful. All six required contexts that run on a push to `main` were present and successful. The other six are pull-request or external gates and therefore do not report on the main-branch push.
- [PR #29](https://github.com/oaslananka/kicad-mcp-pro-gateway/pull/29) head [`4202108`](https://api.github.com/repos/oaslananka/kicad-mcp-pro-gateway/commits/4202108c7128e42dfef617fdee1023d2c265ef79/check-runs) reported all 12 current required contexts as successful and had combined status `success`; its [`Independent Review` status](https://api.github.com/repos/oaslananka/kicad-mcp-pro-gateway/commits/4202108c7128e42dfef617fdee1023d2c265ef79/status) also passed. It required no GitHub approving review and merged as main commit `7c6a28b`.
- The governance verification recorded for this baseline reported that a non-bypass direct-push canary performed earlier on 2026-09-24 was rejected with `GH013` (`Changes must be made through a pull request`) and created no commit. Its message reported the then-current 13-check set; the later live API snapshot above is the source of truth for the present 12-context set.

Revalidate these endpoints before changing the ruleset or this inventory. The live GitHub configuration, not this dated record, remains authoritative.
