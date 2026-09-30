# Argument- and Effect-Aware Risk Assessment Design

Date: 2026-10-01  
Issue: #20  
Status: Approved design for implementation planning

## 1. Context

Gateway currently resolves a reviewed tool name to a capability and a static `RiskLevel`. The policy engine already derives normalized operation effects from source-pinned tool contracts before authorization, but the final risk classification remains tool-level only.

That means materially different requests for the same tool can receive the same risk classification even when trusted request facts show a larger destructive breadth. Issue #20 requires risk to incorporate trusted argument/effect facts without importing KiCad engineering judgment into Gateway or introducing unstable heuristics.

The first implementation tranche will be intentionally narrow. It will prove the model with `pcb_delete_items.item_ids`, whose pinned upstream implementation at `oaslananka/kicad-mcp-pro@f641a92596ab7adc1e134287578b1ae5ff9580ad` accepts `list[str]` and removes every supplied item ID. The locally reviewed effect contract already classifies the tool as `Normal` risk with `Read` + `Delete` effects.

## 2. Goals

1. Compute an effective operation risk from the existing base tool risk plus explicit, trusted, versioned risk rules.
2. Allow trusted argument cardinality and reviewed effect facts to raise risk deterministically.
3. Never lower the existing base risk.
4. Preserve fail-closed behavior for malformed, unknown, stale, or inconsistent risk-relevant facts.
5. Make the effective risk and the factors that raised it inspectable in approval and audit surfaces.
6. Keep raw caller arguments and project content out of audit and approval metadata.
7. Establish an extensible model for later path-breadth, workspace-context, and upstream consequence annotations without implementing those future dimensions in this tranche.

## 3. Non-goals

- No KiCad electrical, PCB, DFM, release, or manufacturing-domain judgment in Gateway.
- No caller-supplied prose, labels, or untrusted metadata as risk evidence.
- No generic rule such as "all arrays are bulk" or "all deletes are high risk".
- No automatic risk decrease when an operation looks small, reversible, idempotent, or dry-runnable.
- No runtime dependency on unreleased upstream manifests.
- No production refresh of the pinned upstream tool snapshot as part of this work.
- No attempt to close the full #20 epic if remaining acceptance criteria still require workspace or released-upstream consequence facts.

## 4. Security invariants

The following invariants are mandatory:

1. `effective_risk >= base_risk` for every evaluated operation.
2. Risk rules are trusted policy input, never caller input.
3. A rule may reference only arguments and effects present in the same reviewed source-pinned tool contract.
4. A rule whose referenced argument/effect cannot be validated makes the registry invalid and prevents production startup.
5. Unknown tool arguments continue to fail closed before risk assessment.
6. Workspace containment continues to run on normalized paths before an operation can execute.
7. A risk escalation to `High` or `Critical` continues to require local approval under the existing approval gate.
8. Audit persistence remains a pre-execution fail-closed gate.
9. Risk factors never contain raw item IDs, paths, credentials, source code, or other sensitive argument values.
10. Existing static risk remains the conservative floor even when the dynamic assessment cannot derive a lower-risk interpretation.

## 5. Chosen architecture

### 5.1 Separate base classification from effective assessment

The existing registry entry remains the source of the base capability and base risk:

```text
tool_name -> capability + base_risk + reviewed effect contract + optional reviewed risk rules
```

The policy engine produces a structured `RiskAssessment` after operation-effect normalization succeeds:

```rust
pub struct RiskAssessment {
    pub policy_version: u32,
    pub base_risk: RiskLevel,
    pub effective_risk: RiskLevel,
    pub factors: Vec<RiskFactor>,
}
```

`effective_risk` starts at `base_risk`. Rules may only raise it.

The risk-assessment domain type should live in `companion-core` so audit, protocol/IPC, and daemon code can carry the result without creating a dependency from core onto policy. Policy owns rule evaluation; core owns only the stable result vocabulary.

### 5.2 Structured, non-sensitive factors

The first factor code is deliberately specific:

```rust
pub enum RiskFactorCode {
    BulkArgumentCardinality,
}

pub struct RiskFactor {
    pub code: RiskFactorCode,
    pub subject: String,
    pub observed_count: u64,
    pub threshold: u64,
    pub escalated_to: RiskLevel,
}
```

For the first tranche:

- `subject` is the reviewed argument name, e.g. `item_ids`;
- `observed_count` is only the collection cardinality;
- no array elements are persisted or exposed;
- `threshold` and `escalated_to` make the decision reproducible.

Future factor variants may add path breadth, workspace context, or reviewed upstream consequence codes, but they must remain closed, typed, and non-sensitive.

### 5.3 Versioning

Introduce a current operation-risk policy constant in policy code:

```rust
pub const OPERATION_RISK_POLICY_VERSION: u32 = 2;
```

Existing authorization rows already carry `risk_policy_version`. New grants use the current version.

The grant's recorded version is issuance/audit evidence only. It must not select an older permissive evaluator at operation time. Operations are always evaluated using the currently running policy, preserving the rule that a software update cannot silently reactivate weaker historical risk semantics.

The existing version value `1` remains readable for historical rows.

## 6. Trusted registry rule schema

Extend the source-pinned TOML tool entry with optional reviewed risk rules.

The first rule kind is argument-cardinality escalation:

```toml
[[tool]]
name = "pcb_delete_items"
capability = "pcb.write"
risk = "normal"
arguments = ["item_ids"]
effects = ["read", "delete"]

[[tool.risk_rules]]
kind = "argument_cardinality"
argument = "item_ids"
minimum_count = 2
requires_effect = "delete"
escalate_to = "high"
```

Validation requirements:

- `kind` must be a closed enum.
- `argument` must exist in the reviewed tool contract.
- `minimum_count` must be at least 2 for this rule kind.
- `requires_effect` must be present in the reviewed normalized effect contract.
- `escalate_to` must parse as a known `RiskLevel`.
- `escalate_to` must be strictly greater than the tool's base risk.
- duplicate equivalent rules are rejected.
- unsupported rule fields are rejected with `deny_unknown_fields`.
- a rule cannot exist on a tool that lacks a reviewed effect contract.

These validations occur while loading the trusted registry. Invalid embedded policy prevents daemon startup rather than falling back to static risk.

## 7. First tranche behavior

`pcb_delete_items` is the only dynamic-risk rule added in the first implementation PR.

Its pinned upstream contract is:

- argument: `item_ids: list[str]`;
- semantics: every supplied ID is converted to a KiCad ID and passed to `remove_items_by_id`;
- reviewed effects: `Read`, `Delete`;
- current Gateway base risk: `Normal`.

The first policy rule is:

- one supplied item ID: effective risk remains `Normal`;
- two or more supplied item IDs: effective risk becomes `High`;
- empty list remains governed by the upstream/tool argument semantics and existing normalization/validation path; it must not be interpreted as a lower-risk grant;
- non-array or otherwise malformed input fails closed rather than receiving an inferred risk.

This threshold is an explicit Gateway security policy, not a claim about KiCad engineering severity. It establishes a deterministic boundary between a single-object delete and a multi-object destructive request.

## 8. Evaluation order

The policy engine keeps the existing authorization order and inserts risk assessment only after trusted facts are available.

1. Validate request identity and active authorization state.
2. Validate workspace authorization.
3. Resolve the tool from the trusted registry.
4. Load its source-pinned effect contract.
5. Normalize caller arguments using the reviewed contract.
6. Reject malformed/unknown arguments and unmodelled contracts.
7. Enforce workspace containment for all normalized paths.
8. Resolve capability + base risk.
9. Verify the grant contains the required capability.
10. Compute `RiskAssessment` from base risk, normalized effects, and reviewed risk rules.
11. Require local approval when `effective_risk >= High`; otherwise allow.
12. Persist the full safe risk assessment in the pre-execution audit record before execution or queuing.

Dynamic risk does not bypass or precede fail-closed effect normalization.

## 9. Policy API changes

The policy decision should carry the assessment rather than a bare risk:

```rust
pub enum PolicyDecision {
    Allow {
        capability: Capability,
        risk: RiskAssessment,
    },
    Deny {
        reason: DenyReason,
    },
    RequireApproval {
        reason: ApprovalReason,
        capability: Capability,
        risk: RiskAssessment,
    },
}
```

The decision remains deterministic and side-effect free.

A private policy helper evaluates reviewed rules against the already validated request:

```text
assess_operation_risk(tool, request.arguments, normalized_effects, base_risk)
    -> Result<RiskAssessment, DenyReason>
```

A rule mismatch caused by malformed caller input maps to the existing malformed-tool-arguments fail-closed family. A registry inconsistency should be prevented at startup and must not become a runtime permissive branch.

## 10. Audit persistence

The current `AuditEvent.risk` field remains for compatibility and records the effective risk.

Additive fields record the complete assessment:

- `risk_policy_version`;
- `base_risk`;
- `risk_factors`.

Use a new additive SQLite migration, expected to be `0005_dynamic_risk.sql` given the current repository migration sequence.

Recommended storage representation:

- `risk_policy_version INTEGER`;
- `base_risk TEXT`;
- `risk_factors_json TEXT`.

Historical rows default safely:

- old `risk` remains readable as the effective risk;
- missing `base_risk` means "historical/unknown base", not an inferred lower risk;
- missing factors become an empty historical factor list;
- missing version remains historical version 1 where that is already established by surrounding row context, otherwise represented explicitly as absent in the domain adapter rather than fabricated evidence.

The audit repository must serialize/parse factor JSON strictly and fail closed on malformed new writes. It must continue reading legitimate pre-migration rows.

## 11. Pending approval and IPC/UI

`PendingOperation` stores the full `RiskAssessment`, not only a `RiskLevel`.

The existing pending-approval IPC view remains backward readable through its current effective-risk string and gains additive safe fields:

- base risk;
- risk policy version;
- safe factor summaries.

For the first rule, a UI summary can render the equivalent of:

```text
High risk — bulk delete
2+ items triggers local approval; this request contains 3 items.
```

The UI receives only the reviewed argument identifier and counts. It never receives the item IDs through the risk explanation path.

Approval persistence continues to record the effective risk. If approval records gain structured factor metadata, the implementation should reuse the same serialized `RiskAssessment` representation rather than create a divergent explanation format.

## 12. Interaction with upstream reviewed effect manifests

PR #60 added strict parsing/reconciliation for the upstream machine-readable effect manifest, but production authorization still uses the locally reviewed source-pinned fallback until a released upstream artifact includes that manifest.

This design therefore does not consume unreleased upstream runtime data.

When a future released upstream manifest is adopted, its factual annotations such as `destructive`, transaction support, rollback support, or future consequence codes may become validated inputs to additional Gateway risk rules. They must not directly authorize operations and must not automatically lower base risk.

The first `pcb_delete_items` rule remains valid independently because its required argument/effect facts are already part of the pinned reviewed Gateway contract.

## 13. Error handling

### Startup failures

The daemon fails to start when trusted policy contains:

- a risk rule for an unknown argument;
- a required effect absent from the tool contract;
- an unknown risk rule kind;
- an invalid threshold;
- a rule that would lower or preserve rather than escalate risk;
- duplicate or contradictory rules;
- risk rules on an unreviewed tool contract.

### Request-time failures

A request is denied before upstream execution when:

- an argument is unknown;
- a risk-relevant argument has an invalid type;
- effect normalization fails;
- workspace containment fails;
- capability is absent.

The evaluator does not guess a count, coerce scalar values to arrays, or ignore malformed risk-relevant input.

## 14. Testing strategy

### Registry tests

Add tests proving:

- valid `pcb_delete_items` cardinality rule parses;
- unknown rule fields are rejected;
- unknown argument references are rejected;
- missing required `Delete` effect is rejected;
- invalid thresholds are rejected;
- non-escalating target risk is rejected;
- duplicate rules are rejected.

Property/fuzz coverage should continue to assert that arbitrary malformed policy input never creates an authorization path.

### Policy unit tests

For the same tool and grant:

1. `item_ids = ["a"]` -> `Normal`, allow when capability is granted.
2. `item_ids = ["a", "b"]` -> `High`, require approval.
3. larger arrays remain `High`; the rule is threshold-based, not count-sensitive beyond escalation.
4. malformed `item_ids` -> deny.
5. base `High` tools remain at least `High`; no rule may reduce risk.

Assertions include exact `RiskFactor` values and policy version.

### Daemon/audit tests

Verify:

- a multi-item delete is queued and never reaches `kicad-mcp-pro` before approval;
- pre-execution audit records effective `High`, base `Normal`, version 2, and a factor containing only count/threshold metadata;
- the raw supplied item IDs do not appear in the audit row, logs, pending IPC risk explanation, or refusal/approval payload;
- audit-persistence failure still blocks execution;
- approved execution keeps the same immutable pre-execution risk assessment.

### Migration tests

Verify:

- fresh databases include new audit columns;
- existing pre-migration audit rows remain readable;
- new assessment fields round-trip;
- malformed stored factor JSON is surfaced as a typed audit/storage error rather than silently discarded.

### IPC/Desktop tests

Verify pending approval rendering for:

- static high-risk operations with no dynamic factors;
- `pcb_delete_items` escalated from `Normal` to `High`;
- no raw IDs exposed in UI fixtures/snapshots.

## 15. Documentation changes during implementation

Update the following documentation when code lands:

- `docs/security/tool-effect-contracts.md`: explain reviewed risk rules as Gateway-owned policy layered on factual effects.
- `docs/security/threat-model.md`: update the authorization/risk boundary to include deterministic argument/effect-aware escalation.
- `docs/architecture/data-flow.md`: insert risk assessment between normalized effects/capability validation and approval decision.
- `docs/architecture/component-boundaries.md`: keep policy ownership of rule evaluation explicit.
- `docs/development/testing.md`: document dynamic-risk regression and migration coverage.

Do not claim that #20's full workspace-context or upstream-consequence scope is complete unless those dimensions are actually implemented and evidenced.

## 16. Rollout and compatibility

This change is fail-closed and additive:

- no tool becomes newly authorized;
- no base risk is lowered;
- one already reviewed destructive tool becomes more restrictive for multi-object requests;
- old audit rows remain readable;
- current local approval behavior is reused;
- no release, tag, signing, production relay, or upstream snapshot refresh is part of the implementation.

The implementation should land as a dedicated PR referencing #20. The issue should remain open if its broader workspace-context and released-upstream consequence acceptance criteria are still outstanding after this tranche.

## 17. Rejected alternatives

### Generic JSON heuristics

Rejected because array length, object size, or argument naming alone is not trusted semantic evidence. A generic "array means bulk" rule would incorrectly classify arguments such as pins or export layers and would make policy behavior difficult to review.

### Effect-only escalation

Rejected as the only mechanism because `Delete` alone cannot distinguish a single deletion from a multi-object deletion. Effects are necessary validation evidence but insufficient breadth evidence.

### Wait for a future upstream release before any #20 work

Rejected for this tranche because the pinned reviewed fallback already contains enough trusted facts to implement one bounded deterministic rule. Waiting would unnecessarily couple independent Gateway policy work to #8's release-artifact boundary.

## 18. Acceptance for this tranche

The implementation tranche is complete when all of the following are true:

- the trusted registry can express and validate the cardinality escalation rule;
- `pcb_delete_items` with one ID remains `Normal`;
- the same tool with two or more IDs becomes `High` and requires local approval;
- risk cannot fall below the existing static base risk;
- malformed or inconsistent risk facts fail closed;
- audit and pending approval surfaces expose policy version, base/effective risk, and safe factor metadata;
- no raw item IDs leak through those surfaces;
- migration, policy, daemon, audit, IPC, desktop, and security regression tests pass;
- repository-required CI/security checks remain green without weakening any gate.

