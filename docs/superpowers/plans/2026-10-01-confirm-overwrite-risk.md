# Confirm-Overwrite Risk Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Escalate `kicad_create_new_project` from Normal to High only when the reviewed `confirm_overwrite` operation fact resolves to true, while preserving policy-v2 audit compatibility and fail-closed behavior.

**Architecture:** Extend the reviewed registry with one closed `boolean_equals` rule kind, evaluate it after normalized effects/workspace containment, and carry the resulting tagged risk factor through the existing immutable `RiskAssessment`. Preserve SQLite schema v5 by keeping the historical bulk-factor JSON shape stable, while deliberately bumping local IPC to v5 because the client-visible factor vocabulary changes.

**Tech Stack:** Rust 1.88+ workspace, serde/serde_json, TOML registry parsing, SQLite/rusqlite audit persistence, Tokio daemon tests, React 18 + TypeScript + Vitest, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-01-confirm-overwrite-risk-design.md`

## Global Constraints

- Production upstream pin remains exactly `oaslananka/kicad-mcp-pro@f641a92596ab7adc1e134287578b1ae5ff9580ad`.
- Operation risk policy version becomes exactly `3`; recorded grant versions remain evidence only and never select an older evaluator.
- SQLite schema remains exactly `5`; do not add a migration unless implementation proves storage shape cannot remain compatible.
- Local IPC protocol version becomes exactly `5`.
- Static risk remains a non-lowerable floor: `effective_risk >= base_risk`.
- Omitted `confirm_overwrite` resolves to the reviewed default `false`; present non-boolean values fail closed.
- Dynamic risk rules remain explicit, typed, source-pinned policy input; no argument-name or truthiness heuristics.
- No raw project path, project name, arbitrary argument JSON, file contents, credentials, or other sensitive values may enter risk factors, audit explanations, IPC summaries, or desktop copy.
- Existing `pcb_delete_items.item_ids >= 2 -> High` behavior and its historical JSON factor shape must remain unchanged.
- No release, tag, signing, production relay, upstream snapshot refresh, or production-host mutation belongs to this plan.

## Review Focus

1. **Explicit null vs omitted boolean** — omitted uses reviewed default false, but explicit `null` must deny as malformed; Task 3 pins both cases.
2. **Multiple risk rules on one tool** — effective risk must remain monotonic and factors append deterministically without one rule masking another; Task 3 adds a synthetic two-rule regression.
3. **Historical bulk-factor JSON** — literal policy-v2 JSON must deserialize after the tagged-enum refactor, not merely round-trip newly serialized values; Task 1 pins the exact legacy object.
4. **IPC omission semantics** — overwrite factors must omit numeric cardinality fields rather than serialize them as misleading zero/null values; Task 5 pins exact JSON.
5. **Sensitive value leakage** — path/name sentinels must stay out of audit factor JSON, pending IPC JSON, and desktop modal text; Tasks 4–6 each pin their own boundary.

---

### Task 1: Make risk factors semantically typed without breaking policy-v2 JSON

**Files:**
- Modify: `crates/core/src/risk.rs`
- Test: `crates/core/src/risk.rs`

**Interfaces:**
- Consumes: existing `RiskLevel`, `RiskAssessment::new(...)`.
- Produces: tagged `RiskFactor` enum with `BulkArgumentCardinality { subject, observed_count, threshold, escalated_to }` and `ConfirmedOverwrite { subject, escalated_to }`; helper access remains read-only through `RiskAssessment::factors() -> &[RiskFactor]`.

- [ ] **Step 1: Write RED core serialization tests**

Add tests:
- `legacy_bulk_factor_json_deserializes_unchanged`: literal JSON `{"code":"bulk_argument_cardinality","subject":"item_ids","observed_count":3,"threshold":2,"escalated_to":"High"}` deserializes to the bulk variant.
- `bulk_factor_serializes_to_legacy_shape`: serialization is byte-for-byte field-compatible as a JSON object with the same five keys/values.
- `confirmed_overwrite_factor_round_trips_without_argument_value`: JSON contains only `code`, `subject`, `escalated_to` and contains neither path/name nor a boolean value field.

- [ ] **Step 2: Run the focused RED test**

Run: `cargo test -p companion-core risk::tests::legacy_bulk_factor_json_deserializes_unchanged -- --exact`  
Expected: FAIL because `RiskFactor` is still the flat cardinality struct and has no `ConfirmedOverwrite` variant.

- [ ] **Step 3: Replace the flat factor struct with the tagged enum**

In `crates/core/src/risk.rs`, define:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum RiskFactor {
    BulkArgumentCardinality {
        subject: String,
        observed_count: u64,
        threshold: u64,
        escalated_to: RiskLevel,
    },
    ConfirmedOverwrite {
        subject: String,
        escalated_to: RiskLevel,
    },
}
```

Remove `RiskFactorCode` if no longer used. Update existing core tests and exports without exposing a constructor path that bypasses `RiskAssessment::new`.

- [ ] **Step 4: Run core tests GREEN**

Run: `cargo test -p companion-core`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/risk.rs
git commit -m "refactor(core): type operation risk factors"
```

### Task 2: Add the reviewed boolean overwrite rule to the trusted registry

**Files:**
- Modify: `crates/policy/src/tool_registry.rs`
- Modify: `crates/policy/src/lib.rs`
- Modify: `crates/policy/assets/tool_registry.toml`
- Test: `crates/policy/src/tool_registry.rs`
- Test: `crates/policy/tests/property_registry.rs`

**Interfaces:**
- Consumes: Task 1 factor vocabulary only as a closed factor code choice.
- Produces: `RiskRule::BooleanEquals { argument: String, expected: bool, default: bool, requires_effect: OperationEffect, escalate_to: RiskLevel, factor: BooleanRiskFactor }`; `OPERATION_RISK_POLICY_VERSION = 3`.

- [ ] **Step 1: Write RED registry tests**

Add tests proving:
- valid `boolean_equals` rule parses exactly for `kicad_create_new_project.confirm_overwrite`;
- unknown rule fields reject;
- unknown argument rejects;
- missing reviewed `write` effect rejects;
- unknown factor code rejects;
- non-escalating target rejects;
- duplicate equivalent boolean rules reject;
- the embedded registry contains exactly the reviewed overwrite rule plus the existing delete-cardinality rule.

- [ ] **Step 2: Run registry/property tests RED**

Run: `cargo test -p companion-policy tool_registry::tests::parses_reviewed_boolean_overwrite_rule -- --exact`  
Expected: FAIL because `boolean_equals` and policy version 3 do not exist.

- [ ] **Step 3: Implement the closed registry schema**

In `tool_registry.rs`:
- bump `OPERATION_RISK_POLICY_VERSION` from 2 to 3;
- add closed raw rule parsing for `boolean_equals`;
- add a closed factor enum containing only `ConfirmedOverwrite` for this rule kind;
- validate reviewed argument membership, reviewed required effect, strict escalation, duplicate equivalence, and unknown fields;
- keep `ArgumentCardinality` parsing behavior unchanged.

In `tool_registry.toml`, add exactly the spec rule under `kicad_create_new_project`; do not change source pin or base risk.

- [ ] **Step 4: Run registry/property tests GREEN**

Run: `cargo test -p companion-policy tool_registry -- --nocapture`  
Run: `cargo test -p companion-policy --test property_registry`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/policy/src/tool_registry.rs crates/policy/src/lib.rs crates/policy/assets/tool_registry.toml crates/policy/tests/property_registry.rs
git commit -m "feat(policy): review project overwrite risk rule"
```

### Task 3: Evaluate the reviewed boolean default and escalate overwrite requests

**Files:**
- Modify: `crates/core/src/risk.rs`
- Modify: `crates/policy/src/risk_assessment.rs`
- Modify: `crates/policy/tests/engine.rs`

**Interfaces:**
- Consumes: Task 2 `RiskRule::BooleanEquals`; Task 1 `RiskFactor::ConfirmedOverwrite`.
- Produces: request-time boolean evaluation returning `RiskAssessment` policy version 3; present non-boolean values map to malformed-tool-arguments.

- [ ] **Step 1: Write RED policy tests**

Add same-tool tests for `kicad_create_new_project`:
- omitted `confirm_overwrite` -> Allow, base/effective Normal, no factors;
- explicit false -> Allow, Normal, no factors;
- explicit true -> RequireApproval, base Normal/effective High, exact `ConfirmedOverwrite { subject: "confirm_overwrite", escalated_to: High }`;
- explicit null/string/number -> Deny `MalformedToolArguments`;
- workspace escape still denies;
- existing `pcb_delete_items` one-vs-many behavior remains identical except policy version is 3;
- synthetic resolver/tool with both supported rule kinds proves effective risk is monotonic and factor ordering is deterministic.

- [ ] **Step 2: Run the focused RED policy test**

Run: `cargo test -p companion-policy --test engine overwrite_true_requires_local_approval -- --exact`  
Expected: FAIL because boolean rules are not evaluated.

- [ ] **Step 3: Implement boolean assessment**

In `risk_assessment.rs`:
- add `ArgumentNotBoolean` to `RiskAssessmentError`;
- for `BooleanEquals`, use the caller boolean when present, otherwise the reviewed default;
- explicit non-boolean values return `ArgumentNotBoolean`;
- verify the required normalized effect before using the rule;
- on match, raise with `max(current, escalate_to)` and append `ConfirmedOverwrite`;
- keep cardinality semantics unchanged.

In `engine.rs`, map `ArgumentNotBoolean` to `DenyReason::MalformedToolArguments`.

- [ ] **Step 4: Run policy tests GREEN**

Run: `cargo test -p companion-policy --test engine`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/risk.rs crates/policy/src/risk_assessment.rs crates/policy/tests/engine.rs
git commit -m "feat(policy): escalate confirmed project overwrite"
```

### Task 4: Preserve audit schema v5 and historical factor compatibility

**Files:**
- Modify: `crates/audit/src/repository.rs`
- Test: `crates/audit/src/repository.rs`
- Verify only: `crates/storage/src/migrations.rs`
- Verify only: `crates/storage/migrations/0005_dynamic_risk.sql`

**Interfaces:**
- Consumes: Task 1 tagged `RiskFactor`.
- Produces: schema-v5 audit round-trip for both factor variants with literal policy-v2 compatibility; no new migration.

- [ ] **Step 1: Write RED/compatibility audit tests**

Add tests:
- literal stored policy-v2 bulk factor JSON parses to the bulk variant;
- policy-v3 confirmed-overwrite factor round-trips;
- overwrite factor JSON does not contain raw path/name sentinel strings or a raw boolean value;
- approval-decision update leaves overwrite assessment evidence byte-equivalent;
- `SCHEMA_VERSION == 5` remains true.

- [ ] **Step 2: Run audit tests**

Run: `cargo test -p companion-audit`  
Expected before adaptation: FAIL where tests/helpers still construct the old flat factor struct.

- [ ] **Step 3: Adapt audit factor construction without changing storage schema**

Update audit tests/helpers and any repository code needed for the tagged enum. Do not add `0006`; keep strict JSON parsing and existing v5 columns.

- [ ] **Step 4: Run audit/storage tests GREEN**

Run: `cargo test -p companion-audit`  
Run: `cargo test -p companion-storage`  
Expected: PASS and schema version remains 5.

- [ ] **Step 5: Commit**

```bash
git add crates/audit/src/repository.rs
git commit -m "test(audit): preserve risk factor compatibility"
```

### Task 5: Propagate overwrite evidence through daemon pending state and IPC v5

**Files:**
- Modify: `apps/daemon/src/handlers.rs`
- Modify: `apps/daemon/tests/e2e_vertical_slice.rs`
- Modify: `crates/protocol/src/ipc.rs`
- Modify: `crates/protocol/src/lib.rs`
- Test: `crates/protocol/src/ipc.rs`
- Test: `apps/daemon/tests/e2e_vertical_slice.rs`

**Interfaces:**
- Consumes: immutable `RiskAssessment` and tagged factors from Tasks 1–3.
- Produces: local IPC v5 `RiskFactorView` with optional `observed_count`/`threshold`; overwrite factor omits cardinality metadata.

- [ ] **Step 1: Write RED protocol and vertical-slice tests**

Protocol tests:
- `LOCAL_IPC_PROTOCOL_VERSION == 5`;
- bulk factor JSON still contains numeric fields;
- confirmed-overwrite factor JSON omits `observed_count` and `threshold`.

Vertical slice:
- send `kicad_create_new_project` with path/name sentinel values and `confirm_overwrite=true`;
- assert operation becomes pending and core call count does not increase before approval;
- pending IPC shows base Normal/effective High/policy v3/code `confirmed_overwrite`;
- serialized IPC does not contain path or name sentinels;
- deny path never calls core;
- existing bulk-delete pending regression remains green.

- [ ] **Step 2: Run focused RED tests**

Run: `cargo test -p companion-protocol a_changed_local_ipc_contract_bumps_the_version_it_is_checked_against -- --exact`  
Run: `cargo test -p kicad-mcp-gateway-daemon --test e2e_vertical_slice`  
Expected: FAIL because IPC is v4 and factor view is cardinality-shaped.

- [ ] **Step 3: Implement IPC v5 mapping**

In `ipc.rs`:
- bump protocol version to 5;
- make `observed_count: Option<u64>` and `threshold: Option<u64>`;
- skip absent numeric fields during serialization.

In daemon handlers:
- map bulk factor to `Some(count/threshold)`;
- map overwrite factor to `None/None`;
- never synthesize raw argument values.

- [ ] **Step 4: Run protocol/daemon tests GREEN**

Run: `cargo test -p companion-protocol`  
Run: `cargo test -p kicad-mcp-gateway-daemon --test e2e_vertical_slice`  
Run: `cargo test -p kicad-mcp-gateway-daemon --test audit_fail_closed`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/protocol/src/ipc.rs crates/protocol/src/lib.rs apps/daemon/src/handlers.rs apps/daemon/tests/e2e_vertical_slice.rs
git commit -m "feat(approval): expose overwrite risk evidence"
```

### Task 6: Render the overwrite consequence safely in desktop approval UX

**Files:**
- Modify: `apps/desktop/src/api/types.ts`
- Modify: `apps/desktop/src/screens/SessionsScreen.tsx`
- Modify: `apps/desktop/src/screens/__tests__/SessionsScreen.test.tsx`

**Interfaces:**
- Consumes: Task 5 IPC v5 factor view.
- Produces: closed desktop summaries for bulk, confirmed-overwrite, and unknown factor codes.

- [ ] **Step 1: Write RED desktop tests**

Add/adjust tests proving:
- bulk count summary still renders;
- `confirmed_overwrite` renders exactly: `Overwrite confirmation is enabled; existing project files may be replaced.`;
- static High/no-factor remains readable;
- unknown factor remains `Additional reviewed risk factor`;
- path/name sentinels supplied by fixtures never appear in modal text;
- overwrite factor does not require numeric fields in TypeScript.

- [ ] **Step 2: Run frontend RED tests**

Run from `apps/desktop`: `pnpm test -- SessionsScreen`  
Expected: FAIL because the TypeScript factor shape requires numeric fields and the UI has no overwrite copy.

- [ ] **Step 3: Update TypeScript contract and summary rendering**

Change `RiskFactorView.observed_count` and `threshold` to optional fields. Update `riskFactorSummary`:
- render bulk copy only when both numeric fields are present;
- render the exact confirmed-overwrite copy;
- use the generic string for malformed/unknown factor metadata rather than interpolating arbitrary fields.

- [ ] **Step 4: Run frontend GREEN gates**

Run from `apps/desktop`:
- `pnpm typecheck`
- `pnpm lint`
- `pnpm test`
- `pnpm build`

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/desktop/src/api/types.ts apps/desktop/src/screens/SessionsScreen.tsx apps/desktop/src/screens/__tests__/SessionsScreen.test.tsx
git commit -m "feat(desktop): explain confirmed overwrite risk"
```

### Task 7: Documentation, compatibility assertions, and final branch verification

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
- Consumes: complete behavior from Tasks 1–6.
- Produces: review-ready branch/PR whose docs match policy v3, IPC v5, schema v5, and the unchanged upstream pin.

- [ ] **Step 1: Update documentation**

Document:
- reviewed boolean default/match semantics;
- overwrite=true as explicit High/local-approval authority;
- policy version 3;
- tagged non-sensitive factors;
- schema remains v5;
- IPC version 5;
- #20 remains open for workspace-context/path-breadth/released-upstream consequence work.

- [ ] **Step 2: Run Rust verification**

Run:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`

Expected: PASS.

- [ ] **Step 3: Run frontend verification**

Run from `apps/desktop`:
- `pnpm audit --audit-level=high`
- `pnpm typecheck`
- `pnpm lint`
- `pnpm test`
- `pnpm build`

Expected: PASS.

- [ ] **Step 4: Run final security/scope audit**

Verify:
- `source_sha` remains `f641a92596ab7adc1e134287578b1ae5ff9580ad`;
- exactly two reviewed dynamic rules exist: existing delete-cardinality and new create-project overwrite;
- no `0006` migration exists;
- `SCHEMA_VERSION == 5`;
- `OPERATION_RISK_POLICY_VERSION == 3`;
- `LOCAL_IPC_PROTOCOL_VERSION == 5`;
- no workflow/release/signing/prod-host files changed;
- raw path/name sentinel values are absent from audit/IPC/UI risk explanations.

- [ ] **Step 5: Commit docs**

```bash
git add docs CHANGELOG.md
git commit -m "docs(policy): document confirmed overwrite risk"
```

- [ ] **Step 6: Open a draft PR referencing #20 and wait for exact-head CI/security review**

PR title: `feat(policy): require approval for confirmed project overwrite`

Keep #20 open after merge unless broader workspace-context/path-breadth/released-upstream consequence scope has independently landed.
