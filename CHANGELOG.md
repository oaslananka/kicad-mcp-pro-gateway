# Changelog

All notable changes to this project are documented in this file. Format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Configuration File Support & Precedence**: Implemented `<data_dir>/config.toml` configuration layer with full precedence ordering (`CLI flags > Environment Variables > config.toml > Defaults`).
- **Conservative Tool Registry Classification**: Classified conservative read-only KiCad MCP tools (PCB, schematic, validation, and server metadata) with explicit capability mappings and low risk levels while keeping discovery and destructive tools fail-closed.
- **Desktop Settings V1 Screen**: Built functional V1 Settings UI exposing operational runtime parameters, configuration precedence rules, and privacy/security invariants.
- **Desktop Frontend Test Suite**: Established automated unit testing for React/Tauri frontend components using Vitest and React Testing Library, integrated into GitHub Actions CI pipeline.
- **Release Engineering Workflow**: Created `.github/workflows/release.yml` tag-triggered automated release pipeline generating multi-platform CLI/daemon binary packages and SHA-256 checksums (`SHA256SUMS.txt`).
- **Release Documentation**: Added `docs/development/release.md` detailing code signing (macOS Developer ID, Windows Authenticode), notarization, release engineering, and multi-OS manual QA procedures.
- **Full Catalog Disposition & Snapshot Reconciliation**: Enforced 100% explicit disposition coverage for upstream tool catalog snapshots and automated reconciliation tooling.
- **Trusted Tool-Effect Contracts**: Added source-pinned read/write/create/delete normalization and argument-path containment for reviewed V1 tools; unreviewed effects now fail closed independently of caller `target_path`.

### Changed

- **Companion → Gateway identity migration**: renamed the public product identity from KiCad MCP Pro Companion (`kicad-mcp-pro-companion`) to KiCad MCP Pro Gateway (`kicad-mcp-pro-gateway`) across README, SECURITY, contributing/architecture/protocol/development docs, Cargo repository & package metadata, CLI/daemon/desktop package and binary names, Tauri product title & bundle identifier, release workflow artifact and release titles, data directory, IPC socket/pipe prefix, keyring service label, environment variable prefix, and the MCP `clientInfo.name`. The pre-release compatibility decision and the full old → new mapping are recorded in `docs/development/identity-migration.md`; historical design records under `docs/superpowers/` keep their original names behind an explicit historical-record banner.
- Updated GitHub Actions CI workflow to run frontend tests (`pnpm test`).
- Reconciled documentation maturity and status claims to reflect pre-alpha / unreleased development state.

### Security

- **Policy-Bounded Authorization TTLs**: Remote session lifetimes are clamped by validated local capability-profile and risk-class ceilings, including conservative one-minute Critical defaults. The effective expiry is persisted and shown explicitly in approval surfaces; malformed TTL policy configuration prevents startup rather than falling back.
- **Fail-Closed Audit Persistence**: The daemon now durably persists every approval decision and every request envelope in the append-only audit store *before* any remote `tools/call` to `kicad-mcp-pro` or any other remote write. When the audit store cannot be written (disk full, read-only filesystem, locked or corrupt database, injected persistence failure), the operation is refused with a typed, secret-free `AuditPersistence` error and zero upstream calls — eliminating the "executed but unaudited" state for reads, writes, and high-risk execution alike. Read-vs-write policy, denial non-requeue semantics, and failure-injection coverage are documented in `docs/security/audit-fail-closed.md`.
