# Changelog

All notable changes to this project are documented in this file. Format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/).

> **Release preparation (2026-10-08):** The repository initially planned an
> eventual `1.0.0-rc1` on 2026-09-25. The source manifests now declare
> `1.0.0-rc1` for a future candidate. No tag, signed artifacts, or qualified
> release exists; independent clean-machine, cross-platform, and release-owner
> evidence is still required before any stable promotion.

## [Unreleased]

### Added

- **Explicit Authorization Authority**: New `AccessGrant`/`AuthorizationLease` domain model with its own lifecycle, independent of transport connectivity. Grants bind principal (explicitly `unverified` until remote identity verification exists), device, workspace set, effective capabilities, task scope, standing vs one-shot kind, issue/approval/expiry timestamps, approval policy, and revocation/suspension/consumption state. Local IPC gained `ListAccessGrants` and `ListAuthorizationLeases`; every view now reports authorization state and transport state as separate fields.
- **Configuration File Support & Precedence**: Implemented `<data_dir>/config.toml` configuration layer with full precedence ordering (`CLI flags > Environment Variables > config.toml > Defaults`).
- **Conservative Tool Registry Classification**: Classified conservative read-only KiCad MCP tools (PCB, schematic, validation, and server metadata) with explicit capability mappings and low risk levels while keeping discovery and destructive tools fail-closed.
- **Desktop Settings V1 Screen**: Built functional V1 Settings UI exposing operational runtime parameters, configuration precedence rules, and privacy/security invariants.
- **Desktop Frontend Test Suite**: Established automated unit testing for React/Tauri frontend components using Vitest and React Testing Library, integrated into GitHub Actions CI pipeline.
- **Release Engineering Workflow**: Hardened `.github/workflows/release.yml` into a fail-closed, tag-triggered candidate pipeline with multi-platform CLI/daemon archives, signed desktop installers, exact package/sidecar verification, SPDX SBOM generation, SHA-256 manifests, GitHub provenance/SBOM attestations, and draft-prerelease-only publication.
- **Release Documentation**: Added `docs/development/release.md` detailing code signing (macOS Developer ID, Windows Authenticode), notarization, release engineering, and multi-OS manual QA procedures.
- **Full Catalog Disposition & Snapshot Reconciliation**: Enforced 100% explicit disposition coverage for upstream tool catalog snapshots and automated reconciliation tooling.
- **Trusted Tool-Effect Contracts**: Added source-pinned read/write/create/delete normalization and argument-path containment for reviewed V1 tools; unreviewed effects now fail closed independently of caller `target_path`.
- **Reviewed Argument-Aware Risk Assessment**: Added policy-version-2 `RiskAssessment` evidence with static risk as a non-lowerable floor and typed source-pinned escalation rules. The first bounded rule raises `pcb_delete_items` from Normal to High when `item_ids` contains two or more entries; missing/non-array risk-relevant arguments fail closed, and no generic array/delete heuristic is used.
- **Property/Fuzz Coverage for Trust Boundaries**: Added `proptest` targets for the local IPC framing and its size limit, the transport envelope, the local IPC request surface, the workspace path boundary, and the tool-registry/effect-manifest parsers, with in-code historical corpora for the inputs that have actually reached each boundary; the bounded CI lane and the longer local lane are documented in [`docs/development/testing.md`](docs/development/testing.md#property-and-fuzz-testing).

### Changed

- **Local IPC Contract Version 4**: The current desktop/CLI IPC contract is `4`.
  Version 2 introduced separate authorization/transport views, version 3 separated verified identity
  provenance from caller claims, and version 4 adds base/effective risk, risk-policy version, and safe
  reviewed factor metadata to pending approvals. Older incompatible clients are rejected by the
  readiness handshake; a wrong-protocol endpoint receives no lifecycle or privileged request and no
  alternate endpoint is tried. The version history lives on
  `companion_protocol::LOCAL_IPC_PROTOCOL_VERSION` and is pinned by a test.
- **Authorization Wire Spellings**: `AccessGrantView.authorization_status`,
  `grant_kind`, and `principal_assurance` now report the model's own `snake_case` spellings
  (`pending_approval`, `one_shot`) instead of a lowercased `Debug` rendering
  (`pendingapproval`, `oneshot`), so the reported values are the values the schema persists. A
  test pins every variant against its serde form, so the two cannot drift again.
- **Companion → Gateway identity migration**: renamed the public product identity from KiCad MCP Pro Companion (`kicad-mcp-pro-companion`) to KiCad MCP Pro Gateway (`kicad-mcp-pro-gateway`) across README, SECURITY, contributing/architecture/protocol/development docs, Cargo repository & package metadata, CLI/daemon/desktop package and binary names, Tauri product title & bundle identifier, release workflow artifact and release titles, data directory, IPC socket/pipe prefix, keyring service label, environment variable prefix, and the MCP `clientInfo.name`. The pre-release compatibility decision and the full old → new mapping are recorded in `docs/development/identity-migration.md`; historical design records under `docs/superpowers/` keep their original names behind an explicit historical-record banner.
- Updated GitHub Actions CI workflow to run frontend tests (`pnpm test`).
- Reconciled documentation maturity and status claims to reflect pre-alpha / unreleased development state.

### Security

- **Dynamic-Risk Audit Evidence and Approval UX**: SQLite schema version 5 adds immutable effective/base risk, policy version, and safe factor evidence to audit rows while preserving v4 history without inventing missing facts. Pending approvals reuse the same assessment, approval-time policy revalidation must reproduce it before execution, and IPC/desktop explanations expose counts and reviewed field names without raw item IDs or other argument values.

- **Verified Remote Principal Binding Foundation**: Added a provider-neutral `VerifiedPrincipal` model kept separate from the remote-supplied display claim, atomically couples inbound envelopes to authenticated actor context, persists only safe verification metadata in schema version 3, and refuses a verified grant when the current transport omits or substitutes its binding. The mock transport remains unauthenticated by default and no production credential verifier is claimed yet.

- **Transport/Authorization Separation**: A transport connect, disconnect, reconnect, or replay can no longer mint, extend, refresh, widen, or resurrect access authority — the authorization state machine has no transport event, the connectivity fold has no grant parameter, and a duplicated remote request is deduplicated instead of stacking. Revoking or expiring a grant leaves the transport connected.
- **Additive, Fail-Closed Authorization Migration**: New `access_grants`/`authorization_leases` tables (`SCHEMA_VERSION` 2) with a deterministic, idempotent mapping from persisted transport-era session rows. Legacy revocations and expiries migrate as revocations and expiries, pre-migration audit references stay linked, corrupt or unknown legacy rows are refused rather than interpreted, and an existing grant is never overwritten by a re-run. A database from a newer build is refused before anything is applied.
- **Policy-Bounded Authorization TTLs**: Remote session lifetimes are clamped by validated local capability-profile and risk-class ceilings, including conservative one-minute Critical defaults. The effective expiry is persisted and shown explicitly in approval surfaces; malformed TTL policy configuration prevents startup rather than falling back.
- **Fail-Closed Audit Persistence**: The daemon now durably persists every approval decision and every request envelope in the append-only audit store *before* any remote `tools/call` to `kicad-mcp-pro` or any other remote write. When the audit store cannot be written (disk full, read-only filesystem, locked or corrupt database, injected persistence failure), the operation is refused with a typed, secret-free `AuditPersistence` error and zero upstream calls — eliminating the "executed but unaudited" state for reads, writes, and high-risk execution alike. Read-vs-write policy, denial non-requeue semantics, and failure-injection coverage are documented in `docs/security/audit-fail-closed.md`.
