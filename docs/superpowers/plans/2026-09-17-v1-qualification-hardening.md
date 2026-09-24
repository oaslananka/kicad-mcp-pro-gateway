# Companion V1 Qualification Hardening Implementation Plan

> **Historical record — product naming.** This document was written in
> September 2026 under the project's former name, *KiCad MCP Pro Companion*
> (`kicad-mcp-pro-companion`). The project is now **KiCad MCP Pro Gateway**
> (`kicad-mcp-pro-gateway`). The original text and filenames are preserved
> unchanged as design history: names, paths, and identifiers inside are the
> historical ones, not current ones. Current naming and the compatibility
> decision live in
> [`docs/development/identity-migration.md`](../../development/identity-migration.md).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the critical qualification gaps found during local verification: Linux test portability, MCP tool argument forwarding, and approval-time authorization revalidation.

**Architecture:** Preserve the daemon as the sole authorization boundary. Test-only secret storage is injected explicitly so non-Windows CI can exercise the daemon without weakening production secret-storage policy. Remote tool arguments become part of the immutable operation request, and every pending high-risk operation is re-evaluated immediately before one-time execution.

**Tech Stack:** Rust, Tokio, serde/serde_json, SQLite, existing Companion crates and mock MCP transport.

**Spec:** `docs/superpowers/specs/2026-09-16-companion-v1-design.md`

## Global Constraints

- Production secret keys must never fall back to plaintext storage.
- Unknown tools remain deny-by-default.
- Transport connectivity never grants authorization.
- Expired/revoked sessions must never execute operations.
- High-risk approval grants exactly one operation, not standing access.
- Follow red-green-refactor for every behavior change.

---

### Task 1: Make daemon integration tests portable without weakening production storage

**Files:**
- Modify: `apps/daemon/src/lib.rs`
- Modify: `apps/cli/tests/ipc_integration.rs`
- Modify: `apps/daemon/tests/e2e_vertical_slice.rs`
**Interfaces:**
- Produce: a test-only state/run construction path that accepts `InMemorySecretStore` while production `build_state` still uses the platform backend.

- [ ] **Step 1:** Add a Linux-repro test path that starts the daemon with an injected in-memory secret store.
- [ ] **Step 2:** Run `cargo test -p kicad-mcp-companion-cli --test ipc_integration` and confirm the current production-only constructor fails on Linux.
- [ ] **Step 3:** Add the smallest constructor/run seam needed for tests; do not add an insecure production fallback.
- [ ] **Step 4:** Re-run CLI IPC and daemon E2E tests and confirm green.
- [ ] **Step 5:** Commit as `test: make daemon integration portable across platforms`.

### Task 2: Forward immutable MCP tool arguments end to end

**Files:**
- Modify: `crates/core/src/operation.rs`
- Modify: `crates/core-bridge/src/mock_server.rs`
- Modify: all `OperationRequest` construction sites
- Test: `apps/daemon/tests/e2e_vertical_slice.rs`

**Interfaces:**
- `OperationRequest.arguments: serde_json::Map<String, serde_json::Value>` with `#[serde(default)]`.
- `execute_and_respond` forwards `Value::Object(request.arguments.clone())` to `CoreBridgeClient::call_tool`.

- [ ] **Step 1:** Extend the test-only MCP server to record `tools/call` params.
- [ ] **Step 2:** Add a failing E2E assertion showing a non-empty remote argument object arrives unchanged at the fake MCP server.
- [ ] **Step 3:** Run only the E2E test and verify RED because arguments are currently dropped.
- [ ] **Step 4:** Add the operation arguments field and forward it through the daemon.
- [ ] **Step 5:** Update construction sites with explicit empty maps where appropriate.
- [ ] **Step 6:** Re-run targeted tests and commit as `fix: forward remote tool arguments to core bridge`.
### Task 3: Revalidate pending high-risk operations at approval time

**Files:**
- Modify: `apps/daemon/src/remote_processor.rs`
- Modify: `apps/daemon/src/handlers.rs`
- Test: `apps/daemon/tests/e2e_vertical_slice.rs`

**Interfaces:**
- Produce: approval-time re-evaluation against the current session, workspace, clock, capability and risk policy.
- Produce: revocation removes pending operations belonging to the revoked session.

- [ ] **Step 1:** Add a failing E2E scenario: queue a high-risk operation, revoke its session, then attempt `ApproveOperation`; assert no MCP call occurs.
- [ ] **Step 2:** Run the E2E test and verify RED because the stale operation currently executes.
- [ ] **Step 3:** Re-evaluate the pending request immediately before allow-once execution.
- [ ] **Step 4:** Execute only if the current policy still returns the same `RequireApproval` capability/risk; otherwise record denial and send a denied result.
- [ ] **Step 5:** Purge pending operations for a session when that session is revoked.
- [ ] **Step 6:** Re-run targeted tests and commit as `fix: revalidate high-risk operations before execution`.

### Task 4: Qualification verification

**Files:**
- Modify only documentation if verification exposes stale claims.

- [ ] **Step 1:** Run `cargo fmt --all -- --check`.
- [ ] **Step 2:** Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] **Step 3:** Run `cargo test --workspace` on Linux.
- [ ] **Step 4:** Inspect `git diff`, `git status`, and recent commits.
- [ ] **Step 5:** Push `hardening/v1-qualification` only after all gates are green.
