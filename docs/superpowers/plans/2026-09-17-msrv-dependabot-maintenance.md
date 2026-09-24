# MSRV and Dependabot Maintenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the declared Rust floor match the dependency graph and reduce automated dependency PR churn without weakening security updates.

**Architecture:** Keep stable Rust for ordinary CI, add a dedicated Rust 1.88 compatibility check, and require it through Mergify/ruleset enforcement. Configure Dependabot version updates as grouped minor/patch maintenance while leaving security updates enabled and major migrations manual.

**Tech Stack:** Cargo/Rust, GitHub Actions, Dependabot, Mergify, GitHub rulesets.

**Spec:** GitHub issue #5 and `docs/development/security-automation.md`.

## Global Constraints

- Rust MSRV is 1.88 after this change.
- Security checks remain fail-closed.
- Dependabot security updates remain enabled.
- No automatic merging is introduced.

---

### Task 1: Enforce the actual Rust MSRV

**Files:** `Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml`, `.github/workflows/ci.yml`, `.mergify.yml`, `docs/security/secure-storage.md`

- [x] Reproduce the Rust 1.78 failure with `cargo +1.78.0 check --workspace --all-targets --locked`.
- [x] Verify Rust 1.88 with `cargo +1.88.0 check --workspace --all-targets --locked`.
- [x] Raise both declared Rust floors to 1.88 and add `rust / msrv-1.88` CI enforcement.
- [x] Verify root and Tauri trees at Rust 1.88, then run the normal full gate.

### Task 2: Collapse routine Dependabot PRs

**Files:** `.github/dependabot.yml`, `docs/development/security-automation.md`

- [x] Group routine minor/patch updates per ecosystem and cap version-update PRs at one per ecosystem.
- [x] Exclude automated major migrations while preserving security updates.
- [ ] Validate YAML/Dependabot CI, merge the maintenance PR, then close superseded unmerged version-update PRs.
