# Argument- and Effect-Aware Risk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a trusted, versioned operation-risk assessment that raises `pcb_delete_items` from Normal to High when `item_ids` contains two or more entries, preserves static risk as a floor, and carries safe risk factors through audit and local approval surfaces.

**Architecture:** Keep source-pinned tool facts and rule declarations in `companion-policy`, keep the stable risk-assessment result vocabulary in `companion-core`, and evaluate rules only after existing effect normalization/workspace containment/capability checks. Persist the immutable assessment in the pre-execution audit row, reuse it for pending approval, and expose only non-sensitive factor metadata over versioned local IPC.

**Tech Stack:** Rust workspace, serde/serde_json, TOML registry, rusqlite/rusqlite_migration, Tokio daemon, local IPC protocol, React/TypeScript/Tauri, Vitest/React Testing Library.

**Spec:** `docs/superpowers/specs/2026-10-01-argument-effect-aware-risk-design.md`

## Global Constraints

- `effective_risk >= base_risk` for every operation.
- Operation-risk policy version for this tranche is exactly `2`.
- `pcb_delete_items.item_ids`: one ID stays `Normal`; two or more IDs escalate to `High`.
- No generic "array means bulk" or "delete means high" heuristic.
- Risk rules may reference only arguments/effects in the same reviewed source-pinned tool contract.
- Unknown/malformed risk-relevant arguments fail closed; do not coerce scalars to arrays.
- Risk factors must never contain raw item IDs, paths, credentials, source code, or project contents.
- Current production upstream source pin remains `oaslananka/kicad-mcp-pro@f641a92596ab7adc1e134287578b1ae5ff9580ad`; do not refresh it in this work.
- New grants record risk policy version `2`, but operation evaluation always uses the currently running policy; historical grant version never selects a weaker evaluator.
- SQLite schema version becomes `5` through additive `0005_dynamic_risk.sql`; never edit prior migrations.
- Local IPC protocol version becomes `4` because `PendingApprovalView` changes.
- No release, tag, signing, production-relay, or upstream-release action is part of this plan.

## Review Focus

- Missing `item_ids` on a tool with a cardinality rule must deny as malformed instead of silently using base risk. Covered in Task 3 policy tests.
- Non-array `item_ids` must deny as malformed; scalar-to-array coercion is forbidden. Covered in Task 3 policy tests.
- A historical audit row with `risk` but null new assessment columns must remain readable without fabricating policy version/base risk. Covered in Task 4 migration/repository tests.
- Updating `approval_decision` after local approval must not recompute or overwrite the persisted assessment. Covered in Task 5 daemon/audit tests.
- IPC/UI risk-factor rendering must expose counts and reviewed argument name only, never supplied UUID values. Covered in Tasks 5 and 6.

---

## File map

**Core result model**
- Modify: `crates/core/src/risk.rs` — `RiskAssessment`, `RiskFactor`, `RiskFactorCode`.
- Modify: `crates/core/src/lib.rs` — re-export new risk domain types.
- Modify: `crates/core/src/authorization.rs` — make new-grant risk-policy version explicit in `GrantRequest`.

**Trusted policy input and evaluator**
- Modify: `crates/policy/src/tool_registry.rs` — typed risk-rule schema, registry validation, resolver access.
- Create: `crates/policy/src/risk_assessment.rs` — deterministic rule evaluator.
- Modify: `crates/policy/src/lib.rs` — module/exports and `OPERATION_RISK_POLICY_VERSION = 2`.
- Modify: `crates/policy/src/engine.rs` — return structured risk assessment and gate on effective risk.
- Modify: `crates/policy/assets/tool_registry.toml` — first reviewed `pcb_delete_items` rule.
- Modify: `crates/policy/tests/engine.rs` — same-tool different-arguments regression coverage.
- Modify: `crates/policy/tests/property_registry.rs` — fail-closed parser/property coverage.

**Persistence**
- Create: `crates/storage/migrations/0005_dynamic_risk.sql`.
- Modify: `crates/storage/src/migrations.rs` — schema version 5 and migration registration.
- Modify: `crates/storage/tests/migrations.rs` — upgrade/backward-read coverage.
- Modify: `crates/core/src/audit.rs` — assessment fields on `AuditEvent`.
- Modify: `crates/audit/src/repository.rs` — serialize/parse strict assessment evidence.

**Daemon / IPC**
- Modify: `apps/daemon/src/state.rs` — pending operation stores `RiskAssessment`.
- Modify: `apps/daemon/src/remote_processor.rs` — audit, pending queue, approval immutability.
- Modify: `apps/daemon/src/handlers.rs` — map safe assessment into IPC view.
- Modify: `crates/protocol/src/ipc.rs` — IPC v4 and additive pending-approval fields.
- Modify: `crates/protocol/src/lib.rs` as needed for public risk-factor view exports/tests.
- Modify: `apps/daemon/tests/e2e_vertical_slice.rs` — IPC and pre-approval execution gate.
- Modify: `apps/daemon/tests/e2e_live.rs` only if its existing high-risk fixtures require compile/contract updates.

**Desktop**
- Modify: `apps/desktop/src/api/types.ts`.
- Modify: `apps/desktop/src/screens/SessionsScreen.tsx`.
- Modify: `apps/desktop/src/screens/__tests__/SessionsScreen.test.tsx`.

**Docs**
- Modify: `docs/security/tool-effect-contracts.md`.
- Modify: `docs/security/threat-model.md`.
- Modify: `docs/architecture/data-flow.md`.
- Modify: `docs/architecture/component-boundaries.md`.
- Modify: `docs/development/testing.md`.
- Modify: `docs/development/daemon-lifecycle.md` — IPC version 4.
- Modify: `docs/architecture/session-lifecycle.md` — schema version 5.
- Modify: `CHANGELOG.md` — unreleased dynamic-risk hardening entry.

### Task 1: Add the stable risk-assessment domain model and explicit grant policy version

**Files:**
- Modify: `crates/core/src/risk.rs`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/src/authorization.rs`
- Test: unit tests in `crates/core/src/risk.rs` and `crates/core/src/authorization.rs`

**Interfaces:**
- Produces: `RiskFactorCode::BulkArgumentCardinality`.
- Produces: `RiskFactor { code, subject: String, observed_count: u64, threshold: u64, escalated_to: RiskLevel }`.
- Produces: `RiskAssessment { policy_version: u32, base_risk: RiskLevel, effective_risk: RiskLevel, factors: Vec<RiskFactor> }`.
- Produces: `GrantRequest.risk_policy_version: u32`; `AccessGrant::requested` copies it unchanged.
- Consumes: existing `RiskLevel`.

- [ ] **Step 1: Write failing core tests for assessment invariants and grant version copying**

Add tests named:
- `risk_assessment_rejects_effective_risk_below_base`
- `risk_assessment_accepts_equal_or_higher_effective_risk`
- `requested_grant_records_supplied_risk_policy_version`

The constructor API must make `RiskAssessment` impossible to create with `effective_risk < base_risk`; use `RiskAssessment::new(policy_version, base_risk, effective_risk, factors) -> Result<RiskAssessment, RiskAssessmentError>`.

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:
```bash
cargo test -p companion-core risk::tests -- --nocapture
cargo test -p companion-core authorization::tests -- --nocapture
```

Expected: FAIL because the new assessment types/constructor and `GrantRequest.risk_policy_version` do not exist.

- [ ] **Step 3: Implement the domain types and grant request field**

In `crates/core/src/risk.rs`, add the exact types above plus:
```rust
pub enum RiskAssessmentError {
    EffectiveRiskBelowBase,
}
```

Implement `RiskAssessment::new(...) -> Result<Self, RiskAssessmentError>` with the single invariant check. Keep all types serde-serializable and equality-comparable.

In `crates/core/src/authorization.rs`, add `pub risk_policy_version: u32` to `GrantRequest` and copy it in `AccessGrant::requested` instead of hardcoding `1`.

Update all compile-time `GrantRequest` fixtures in the workspace to explicitly pass their intended version; historical/migration fixtures remain `1`.

- [ ] **Step 4: Run core/workspace compile coverage**

Run:
```bash
cargo test -p companion-core
cargo check --workspace
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core
git commit -m "feat(policy): add structured risk assessment model"
```

### Task 2: Add typed reviewed risk rules to the source-pinned registry

**Files:**
- Modify: `crates/policy/src/tool_registry.rs`
- Modify: `crates/policy/src/lib.rs`
- Modify: `crates/policy/assets/tool_registry.toml`
- Modify: `crates/policy/tests/property_registry.rs`

**Interfaces:**
- Produces: `pub const OPERATION_RISK_POLICY_VERSION: u32 = 2`.
- Produces: `RiskRule::ArgumentCardinality { argument: String, minimum_count: u64, requires_effect: OperationEffect, escalate_to: RiskLevel }`.
- Produces: `ToolCapabilityResolver::risk_rules(&self, tool_name: &str) -> &[RiskRule]`, defaulting to an empty slice.
- Consumes: existing `ToolEffectContract` and `OperationEffect`.

- [ ] **Step 1: Write failing registry tests**

Add tests proving:
- valid `argument_cardinality` rule parses;
- unknown rule fields/kinds fail;
- unknown argument reference fails;
- missing required `delete` effect fails;
- `minimum_count < 2` fails;
- `escalate_to <= base_risk` fails;
- duplicate equivalent rules fail;
- any risk rule on a tool without a reviewed effect contract fails.

Extend the property corpus with malformed/near-miss `risk_rules` spellings and assert arbitrary mutation never creates a rule not exactly declared by source text.

- [ ] **Step 2: Run registry tests and confirm failure**

Run:
```bash
cargo test -p companion-policy --test property_registry
cargo test -p companion-policy tool_registry -- --nocapture
```

Expected: FAIL because risk-rule parsing/validation does not exist.

- [ ] **Step 3: Implement closed rule parsing and validation**

Use serde `deny_unknown_fields` and a closed `kind` enum. Store validated rules on each `ToolEntry`.

Validation is performed during `TomlToolRegistry::from_toml_str`; invalid trusted policy returns a `ToolRegistryError` and never falls back to static risk.

Add this exact reviewed rule under `pcb_delete_items` in `tool_registry.toml`:

```toml
[[tool.risk_rules]]
kind = "argument_cardinality"
argument = "item_ids"
minimum_count = 2
requires_effect = "delete"
escalate_to = "high"
```

Do not change the existing source repository/ref/SHA.

- [ ] **Step 4: Run registry/property tests**

Run:
```bash
cargo test -p companion-policy --test property_registry
cargo test -p companion-policy
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/policy/src crates/policy/assets/tool_registry.toml crates/policy/tests/property_registry.rs
git commit -m "feat(policy): add reviewed dynamic risk rules"
```

### Task 3: Evaluate argument cardinality after trusted effect normalization

**Files:**
- Create: `crates/policy/src/risk_assessment.rs`
- Modify: `crates/policy/src/lib.rs`
- Modify: `crates/policy/src/engine.rs`
- Modify: `crates/policy/tests/engine.rs`

**Interfaces:**
- Consumes: `RiskRule`, `RiskAssessment`, `NormalizedOperationEffects`, `OperationRequest.arguments`.
- Produces: `assess_operation_risk(rules: &[RiskRule], arguments: &serde_json::Map<String, serde_json::Value>, normalized_effects: &NormalizedOperationEffects, base_risk: RiskLevel) -> Result<RiskAssessment, RiskAssessmentError>`.
- Produces: `PolicyDecision::{Allow,RequireApproval}.risk: RiskAssessment`.
- Uses: `OPERATION_RISK_POLICY_VERSION = 2`.

- [ ] **Step 1: Write failing same-tool/different-argument policy tests**

In `crates/policy/tests/engine.rs`, add a reviewed `pcb_delete_items` fixture/rule and tests:
- `["a"]` -> `Allow`, base/effective `Normal`, version 2, no escalation factor.
- `["a","b"]` -> `RequireApproval`, base `Normal`, effective `High`, exactly one `BulkArgumentCardinality` factor with subject `item_ids`, count 2, threshold 2.
- 3+ IDs -> still `High` with observed count preserved.
- missing `item_ids` -> `Deny(MalformedToolArguments)`.
- scalar `item_ids = "a"` -> `Deny(MalformedToolArguments)`.
- empty array -> effective `Normal`, never below base.
- a statically `High` tool remains `High`.

- [ ] **Step 2: Run the focused policy tests and confirm failure**

Run:
```bash
cargo test -p companion-policy --test engine -- --nocapture
```

Expected: FAIL because policy decisions still carry bare `RiskLevel` and no argument-cardinality evaluator exists.

- [ ] **Step 3: Implement deterministic assessment**

For each `ArgumentCardinality` rule:
1. confirm `requires_effect` exists in `normalized_effects`;
2. require the named argument to exist and be a JSON array;
3. convert array length to `u64`;
4. when `count >= minimum_count`, append one safe factor and set `effective_risk = max(effective_risk, escalate_to)`;
5. construct through `RiskAssessment::new`.

Do not inspect array elements and do not log/return their values.

Update `PolicyEngine::evaluate_with_grant` so risk assessment happens after capability validation and the approval gate compares `assessment.effective_risk >= RiskLevel::High`.

- [ ] **Step 4: Make new grant creation use policy version 2**

At daemon grant-request call sites that create new authority, pass `risk_policy_version: OPERATION_RISK_POLICY_VERSION`. Keep legacy session/grant migration fixtures at historical version 1.

Run:
```bash
cargo test -p companion-policy
cargo test -p companion-sessions
cargo check --workspace
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/policy apps/daemon/src crates/sessions
git commit -m "feat(policy): escalate bulk destructive operations"
```

### Task 4: Persist immutable risk assessment in schema v5 audit records

**Files:**
- Create: `crates/storage/migrations/0005_dynamic_risk.sql`
- Modify: `crates/storage/src/migrations.rs`
- Modify: `crates/storage/tests/migrations.rs`
- Modify: `crates/core/src/audit.rs`
- Modify: `crates/audit/src/repository.rs`

**Interfaces:**
- Produces DB columns: `risk_policy_version INTEGER NULL`, `base_risk TEXT NULL`, `risk_factors_json TEXT NOT NULL DEFAULT '[]'`.
- Produces `AuditEvent.risk_policy_version: Option<u32>`, `base_risk: Option<RiskLevel>`, `risk_factors: Vec<RiskFactor>`.
- Existing `AuditEvent.risk` remains the effective risk.
- Historical rows with null version/base are readable without inferred values.

- [ ] **Step 1: Write failing migration tests**

Add assertions that:
- `SCHEMA_VERSION == 5`;
- fresh DB exposes all three new audit columns;
- opening an exact v4 DB applies only migration 0005 and preserves its existing audit row;
- the preserved row has null `risk_policy_version`, null `base_risk`, and `risk_factors_json = '[]'`.

- [ ] **Step 2: Run migration tests and confirm failure**

Run:
```bash
cargo test -p companion-storage --test migrations -- --nocapture
```

Expected: FAIL at schema version/columns.

- [ ] **Step 3: Add migration 0005 and schema registration**

`0005_dynamic_risk.sql` must use additive `ALTER TABLE audit_events ADD COLUMN ...` statements only.

Register it after 0004 and bump `SCHEMA_VERSION` to 5.

- [ ] **Step 4: Write failing audit repository tests**

Add tests for:
- new assessment fields round-trip exactly;
- factor JSON contains `item_ids`, count, threshold, enum code, escalation target, but no sample UUID values;
- malformed stored `risk_factors_json` returns the repository's typed deserialize/storage error;
- a historical row with effective `risk` and null assessment columns reads successfully with `None/None/[]`;
- `update_approval_decision` changes only approval decision and leaves risk assessment byte-for-byte/structurally unchanged.

- [ ] **Step 5: Implement audit serialization/deserialization**

Serialize factors only through serde JSON. New daemon writes for `Allow`/`RequireApproval` must supply complete assessment evidence; denied decisions use `None/None/[]`.

Do not fabricate version/base while reading old rows.

Run:
```bash
cargo test -p companion-audit
cargo test -p companion-storage
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/audit.rs crates/audit crates/storage
git commit -m "feat(audit): persist dynamic risk evidence"
```

### Task 5: Carry the assessment through daemon approval and IPC v4

**Files:**
- Modify: `apps/daemon/src/state.rs`
- Modify: `apps/daemon/src/remote_processor.rs`
- Modify: `apps/daemon/src/handlers.rs`
- Modify: `crates/protocol/src/ipc.rs`
- Modify: `crates/protocol/src/lib.rs`
- Modify: `apps/daemon/tests/e2e_vertical_slice.rs`
- Modify as compile requires: `apps/daemon/tests/e2e_live.rs`

**Interfaces:**
- `PendingOperation.risk: RiskAssessment`.
- `PendingSummary.risk: RiskAssessment`.
- `PendingApprovalView` keeps `risk: String` as effective risk and adds:
  - `base_risk: String`
  - `risk_policy_version: u32`
  - `risk_factors: Vec<RiskFactorView>`
- `RiskFactorView { code: String, subject: String, observed_count: u64, threshold: u64, escalated_to: String }`.
- `LOCAL_IPC_PROTOCOL_VERSION = 4`.

- [ ] **Step 1: Write failing daemon E2E test for bulk delete**

Create a request for reviewed `pcb_delete_items` with two distinct fake UUID strings and assert:
- no core-bridge `tools/call` occurs before approval;
- operation appears in pending approvals;
- pending view reports effective `High`, base `Normal`, version 2;
- factor reports only `item_ids`, count 2, threshold 2, target High;
- serialized IPC payload does not contain either supplied UUID string.

- [ ] **Step 2: Run the focused E2E test and confirm failure**

Run:
```bash
cargo test -p kicad-mcp-gateway-daemon --test e2e_vertical_slice -- --nocapture
```

Expected: FAIL because pending state/IPC do not carry structured assessment.

- [ ] **Step 3: Update pending state and audit creation**

Map `PolicyDecision` assessment into the pre-execution `AuditEvent`:
- `risk = Some(effective_risk)`
- `base_risk = Some(base_risk)`
- `risk_policy_version = Some(policy_version)`
- `risk_factors = factors.clone()`

Store the same `RiskAssessment` in `PendingOperation`.

On approval, preserve the current safety re-evaluation against the current policy, but require the re-evaluated assessment to equal the queued assessment before execution. A mismatch is not approval; refuse/keep safe according to the existing stale-policy branch. Never replace the persisted original assessment.

- [ ] **Step 4: Bump and extend local IPC**

Set `LOCAL_IPC_PROTOCOL_VERSION` from 3 to 4 and update its version-history comment/test.

Add `RiskFactorView` and the fields above. Map enum spellings deterministically; do not use arbitrary caller strings.

Run:
```bash
cargo test -p companion-protocol
cargo test -p kicad-mcp-gateway-daemon --test e2e_vertical_slice -- --nocapture
cargo test -p kicad-mcp-gateway-daemon
```

Expected: PASS.

- [ ] **Step 5: Verify approval durability/fail-closed regression**

Run the daemon's audit-failure tests and assert the existing `approval_decision_must_be_durable_before_high_risk_execution` behavior still passes with structured assessment.

Run:
```bash
cargo test -p kicad-mcp-gateway-daemon audit_fail_closed_tests -- --nocapture
```

Expected: PASS with zero upstream execution when audit approval persistence fails.

- [ ] **Step 6: Commit**

```bash
git add apps/daemon crates/protocol
git commit -m "feat(approval): expose dynamic risk evidence"
```

### Task 6: Render safe risk factors in the desktop approval dialog

**Files:**
- Modify: `apps/desktop/src/api/types.ts`
- Modify: `apps/desktop/src/screens/SessionsScreen.tsx`
- Modify: `apps/desktop/src/screens/__tests__/SessionsScreen.test.tsx`

**Interfaces:**
- Consumes the IPC v4 pending-approval fields from Task 5.
- Produces human-readable safe explanation for `BulkArgumentCardinality`.
- Must not render raw operation arguments.

- [ ] **Step 1: Write failing UI tests**

Update `createMockPendingApproval` with base risk/version/factors.

Add tests:
- dynamic escalation dialog shows effective High, base Normal, policy version 2;
- factor renders a message equivalent to "2+ items triggers local approval; this request contains 3 items";
- a static high-risk operation with `risk_factors: []` still renders normally;
- test fixture UUID strings supplied only as sentinel text are absent from rendered DOM.

- [ ] **Step 2: Run UI test and confirm failure**

Run:
```bash
cd apps/desktop
pnpm test -- SessionsScreen.test.tsx
```

Expected: FAIL because TS types/UI do not know the new fields.

- [ ] **Step 3: Implement typed rendering**

Add a small pure renderer/helper for known factor codes. Unknown factor codes must render a conservative generic "Additional reviewed risk factor" message without dumping object JSON.

Keep the operation table's existing `risk` badge as effective risk. Add base/version/factor detail only in the review modal.

- [ ] **Step 4: Run frontend verification**

Run:
```bash
cd apps/desktop
pnpm test
pnpm typecheck
pnpm lint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop/src
git commit -m "feat(desktop): explain dynamic approval risk"
```

### Task 7: Update security/architecture docs and run whole-branch verification

**Files:**
- Modify: `docs/security/tool-effect-contracts.md`
- Modify: `docs/security/threat-model.md`
- Modify: `docs/architecture/data-flow.md`
- Modify: `docs/architecture/component-boundaries.md`
- Modify: `docs/development/testing.md`
- Modify: `docs/development/daemon-lifecycle.md`
- Modify: `docs/architecture/session-lifecycle.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Documents the interfaces established in Tasks 1–6; produces no new runtime API.

- [ ] **Step 1: Update docs with exact landed behavior**

Document:
- static risk is a floor;
- only explicit reviewed rules raise risk;
- first rule is `pcb_delete_items.item_ids >= 2 -> High`;
- risk assessment occurs after normalized effects/workspace containment and before approval;
- audit approval record stores effective/base/version/safe factors;
- SQLite schema is 5 with 0005 dynamic-risk migration;
- local IPC contract is 4;
- #20 remains open for future workspace-context/released-upstream consequence dimensions.

- [ ] **Step 2: Run formatting/lint/unit/integration verification**

Run:
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cd apps/desktop
pnpm test
pnpm typecheck
pnpm lint
pnpm build
```

Expected: all commands PASS.

- [ ] **Step 3: Run repository security/contract checks used by CI**

Inspect `.github/workflows/ci.yml` and any required security workflows on the branch, then run all locally reproducible commands they require. Do not weaken, skip, or reconfigure a gate to make the branch green.

- [ ] **Step 4: Review the diff against the spec**

Confirm:
- only `pcb_delete_items` gains dynamic risk in this tranche;
- no source pin changed;
- no raw IDs are persisted/rendered;
- all effective risks are >= base risk;
- schema/IPC versions match docs/tests;
- no release/tag/signing changes exist.

- [ ] **Step 5: Commit documentation**

```bash
git add docs CHANGELOG.md
git commit -m "docs(policy): document argument-aware risk"
```

- [ ] **Step 6: Push branch and open a dedicated PR referencing #20**

PR title:
```text
feat(policy): make destructive risk argument-aware
```

PR body should summarize the bounded first tranche, security invariants, tests run, schema/IPC compatibility bumps, and explicitly state that #20 remains open for later workspace/upstream-consequence work.

Do not merge until required checks, warnings/annotations, reviews, and security findings have been inspected.
