# Repository security automation

This document records the repository-level security and quality automation baseline. The GitHub-native `main` quality-gate state was last verified against the live API on 2026-09-26; the GTK3/glib compatibility set was reviewed on 2026-09-25.

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

The Tauri lockfile uses a reviewed GTK3 compatibility set under `apps/desktop/src-tauri/vendor/compat`. It preserves the package versions required by Tauri 2.11.x while rebasing the gtk-rs-core dependencies onto glib 0.20, so the vulnerable glib 0.18 package is absent from `Cargo.lock`. `vendor/compat/README.md` records the provenance and verification contract. The remaining time-bounded OSV exceptions cover only INFO/unmaintained transitives from GTK/urlpattern. OSV prints each exception and its reason during scans; new advisories remain fail-closed.

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
- requires the 11 contexts listed below;
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

The observed CodeQL, full-repository OSV, Socket, Mergify, and Dependabot signals are not part of this required set. CodeQL and full-repository OSV provide additional analysis, Socket supplies informational dependency findings, Mergify supplies coordination signals, and Dependabot is an update actor rather than a pull-request quality gate. Do not add a context to the ruleset until its current workflow or App source has been observed and mapped as above.

### Verification record

Live API state was revalidated on 2026-09-26:

- The [rulesets index](https://api.github.com/repos/oaslananka/kicad-mcp-pro-gateway/rulesets) returns one active repository ruleset, and [ruleset `23952106`](https://api.github.com/repos/oaslananka/kicad-mcp-pro-gateway/rulesets/23952106) currently requires the 11 contexts listed above.
- The legacy `Independent Review` commit-status context was removed from the active required-status-check set on 2026-09-26. It is not produced by a checked-in GitHub Actions workflow in this repository and is not part of the current merge policy.
- Historical commits can still show previously-created `Independent Review` statuses. GitHub's Commit Statuses REST API exposes create/list/read operations for commit statuses but no delete operation, so an old status on an old SHA is historical evidence rather than an active rule.
- The status observed on PR #43's former head `426284d5e87eed19d62dc21a829012e477726493` was created as the `oaslananka` user identity, with context `Independent Review`, state `pending`, description `Waiting for independent review`, and no target URL. After the ruleset change, later PR #43 heads no longer received that status.
- The governance verification recorded for the earlier 2026-09-24 baseline remains useful historical evidence: a non-bypass direct-push canary was rejected with `GH013` (`Changes must be made through a pull request`) and created no commit. Counts in that historical record reflected the then-current policy and must not be treated as the current required-check inventory.

Revalidate these endpoints before changing the ruleset or this inventory. The live GitHub configuration, not any dated record, remains authoritative.
