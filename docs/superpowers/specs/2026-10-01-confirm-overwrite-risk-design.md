# Confirm-Overwrite Risk Escalation Design

Date: 2026-10-01  
Issue: #20  
Status: Approved design for implementation planning

## 1. Context

The first bounded #20 tranche established reviewed argument-aware risk on top of source-pinned effect contracts. It added policy version 2, made static tool risk a non-lowerable floor, introduced structured `RiskAssessment` evidence, and escalated `pcb_delete_items` from Normal to High when `item_ids` contains two or more entries.

A second independently actionable case exists in the same pinned upstream source without waiting for a new upstream release.

At `oaslananka/kicad-mcp-pro@f641a92596ab7adc1e134287578b1ae5ff9580ad`:

- `kicad_create_new_project(path, name, confirm_overwrite=False)` exposes an explicit boolean overwrite switch.
- The project-creation service refuses an existing non-empty project directory when `confirm_overwrite` is false.
- With `confirm_overwrite=true`, the service proceeds and writes the generated `.kicad_pro`, `.kicad_pcb`, and `.kicad_sch` files into the target project directory.
- The pinned upstream evaluation corpus separately classifies "Create a new project over the existing production directory" as a confirmation/destructive scenario.

Gateway's current reviewed contract for this tool already contains:

- base risk: `Normal`;
- capability: `project.write`;
- arguments: `path`, `name`, `confirm_overwrite`;
- required path facts for `path` and `name`;
- reviewed `read`, `write`, and `create` path effects.

The missing policy fact is that explicitly opting into overwrite materially changes the operation's data-loss consequence.

## 2. Goals

1. Raise `kicad_create_new_project` from Normal to High when the reviewed `confirm_overwrite` argument resolves to true.
2. Preserve Normal risk when the argument is false or omitted and therefore resolves to the reviewed upstream default false.
3. Reject malformed non-boolean overwrite values rather than coercing them.
4. Keep static risk as a floor; the new rule may only raise risk.
5. Make the overwrite escalation visible in audit, pending approval, IPC, and desktop UI using non-sensitive structured evidence.
6. Preserve the existing schema-v5 audit rows and the existing serialized bulk-cardinality factor shape.
7. Keep the production upstream source pin unchanged.
8. Keep #20 open for broader workspace-context, path-breadth, and released-upstream consequence work.

## 3. Non-goals

- No generic rule that every boolean flag raises risk.
- No inference from argument names such as `confirm_*`, `overwrite`, or `force`.
- No filesystem existence probe inside the pure policy evaluator.
- No attempt to determine whether the target directory currently exists or is non-empty.
- No KiCad design-quality judgment.
- No caller-provided prose as risk evidence.
- No risk reduction based on `confirm_overwrite=false`.
- No upstream snapshot refresh, release, tag, signing, or production-host change.
- No SQLite schema migration unless implementation evidence proves one is actually required.

The policy decision is intentionally conservative: `confirm_overwrite=true` means the caller has requested authority to overwrite if a conflicting project exists. Gateway does not need to probe the filesystem to know that the requested operation has crossed the reviewed overwrite boundary.

## 4. Security invariants

1. `effective_risk >= base_risk` remains mandatory.
2. Only reviewed, source-pinned rule configuration may change operation risk.
3. Missing `confirm_overwrite` may resolve to false only because the reviewed rule explicitly carries the pinned upstream default false.
4. A present non-boolean `confirm_overwrite` value fails closed as malformed tool arguments.
5. The rule must reference an argument present in the reviewed tool contract.
6. The rule must require a reviewed write effect present in the same tool contract.
7. A rule target must be strictly higher than base risk.
8. Workspace containment remains enforced before execution and is not weakened by overwrite approval.
9. High effective risk continues to require local approval.
10. The original pre-execution risk assessment remains immutable through approval persistence and approval-time revalidation.
11. Risk factors must not contain raw paths, project names, file contents, credentials, or arbitrary argument values.
12. Historical audit factors written by policy version 2 remain readable exactly.

## 5. Chosen rule model

### 5.1 Policy version

Bump the current operation risk policy version:

```rust
pub const OPERATION_RISK_POLICY_VERSION: u32 = 3;
```

New grants record version 3 as issuance evidence. As before, a grant's historical version never selects an older evaluator; operations always use the currently running policy.

### 5.2 Reviewed boolean-match rule

Add one new closed rule kind to the registry model:

```toml
[[tool]]
name = "kicad_create_new_project"
capability = "project.write"
risk = "normal"
arguments = ["path", "name", "confirm_overwrite"]
effects = []

[[tool.path_arguments]]
argument = "path"
effects = ["read", "write", "create"]
required = true

[[tool.path_arguments]]
argument = "name"
base_argument = "path"
effects = ["read", "write", "create"]
required = true

[[tool.risk_rules]]
kind = "boolean_equals"
argument = "confirm_overwrite"
expected = true
default = false
requires_effect = "write"
escalate_to = "high"
factor = "confirmed_overwrite"
```

The rule remains policy-owned and source-pinned. The `default=false` value is not inferred at runtime; it is part of the reviewed rule because the pinned upstream tool signature defines that default.

The first implementation of `boolean_equals` is intentionally constrained. Registry parsing accepts only closed, typed fields and rejects unsupported factor names.

### 5.3 Registry validation

The registry must reject the rule when any of the following is true:

- the referenced argument is absent from the reviewed contract;
- `expected` or `default` is not a boolean;
- the required effect is absent from the tool's reviewed top-level or path effects;
- `escalate_to` is unknown;
- `escalate_to <= base_risk`;
- the factor code is not one of the closed supported factor codes;
- an equivalent duplicate rule exists;
- the tool has no reviewed effect contract;
- unknown rule fields are present.

For this tranche, `factor = "confirmed_overwrite"` is the only factor accepted for this rule configuration. This avoids turning a generic boolean matcher into an unreviewed generic policy language.

## 6. Request-time semantics

For `kicad_create_new_project`:

| Caller argument | Resolved reviewed value | Effective risk |
| --- | --- | --- |
| omitted | `false` from reviewed default | Normal |
| `false` | false | Normal |
| `true` | true | High → local approval |
| string/number/object/array/null | invalid | deny as malformed tool arguments |

The evaluator does not coerce `"true"`, `1`, or any other truthy value.

The boolean rule runs only after the existing reviewed effect normalization and workspace-containment checks have succeeded.

## 7. Risk factor representation

The current flat `RiskFactor` struct is cardinality-specific. Extending it with unrelated optional fields would make the audit vocabulary ambiguous, so convert it to a closed tagged enum.

Recommended core shape:

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

The new overwrite factor stores only:

- the reviewed argument identifier, `confirm_overwrite`;
- the escalation target, `High`.

It does not store the project path, project name, existing directory contents, or a copy of the caller's raw argument map.

### 7.1 Audit JSON compatibility

The existing policy-v2 bulk factor already serializes as:

```json
{
  "code": "bulk_argument_cardinality",
  "subject": "item_ids",
  "observed_count": 3,
  "threshold": 2,
  "escalated_to": "High"
}
```

A tagged enum with the shape above serializes the bulk variant to the same JSON object shape. Therefore schema v5 can remain unchanged and legitimate historical factor JSON remains readable.

Add a literal legacy-JSON regression test. Do not rely only on round-tripping newly serialized values.

The new overwrite factor serializes as:

```json
{
  "code": "confirmed_overwrite",
  "subject": "confirm_overwrite",
  "escalated_to": "High"
}
```

No database migration is expected.

## 8. Risk assessment behavior

Extend the policy evaluator with the new reviewed rule variant.

Pseudocode:

```text
assessment = base risk
for each reviewed rule:
  verify required normalized effect is present

  cardinality rule:
    require array
    if len >= threshold:
      raise effective risk
      append BulkArgumentCardinality factor

  boolean-equals rule:
    if argument present:
      require JSON boolean
      resolved = argument
    else:
      resolved = reviewed default

    if resolved == expected:
      raise effective risk
      append ConfirmedOverwrite factor
```

Risk remains monotonic via `max(current, escalate_to)`.

Missing data is handled differently only where the reviewed rule explicitly defines a default. An omitted cardinality argument remains malformed because its rule has no reviewed default.

## 9. Approval and revalidation

The existing pending-operation model continues to store the complete immutable `RiskAssessment`.

For `confirm_overwrite=true`:

1. policy yields effective High;
2. pre-execution audit row is persisted with policy version 3, base Normal, effective High, and `ConfirmedOverwrite`;
3. operation enters pending approval and does not reach the core bridge;
4. local IPC/desktop presents the safe overwrite reason;
5. after local approval, policy is re-evaluated;
6. the newly computed assessment must equal the queued assessment before execution.

A changed request or changed policy fact cannot silently reuse an old approval.

## 10. IPC compatibility

The new factor shape is client-visible, so bump local IPC to version 5.

Keep the top-level pending approval fields unchanged:

- effective `risk`;
- `base_risk`;
- `risk_policy_version`;
- `risk_factors`.

The current IPC factor view is cardinality-shaped. Make the numeric fields optional while preserving the existing bulk JSON shape:

```rust
pub struct RiskFactorView {
    pub code: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u64>,
    pub escalated_to: String,
}
```

Mapping:

- `BulkArgumentCardinality`: both numeric fields are present;
- `ConfirmedOverwrite`: numeric fields are absent.

Existing version-4 clients are rejected by the normal readiness handshake rather than being allowed to misread the new factor vocabulary.

## 11. Desktop contract and UX

Mirror the optional numeric fields in TypeScript.

The desktop summary function remains closed and non-sensitive:

- `bulk_argument_cardinality` with valid numeric metadata:
  `2+ items triggers local approval; this request contains 3 items.`
- `confirmed_overwrite`:
  `Overwrite confirmation is enabled; existing project files may be replaced.`
- unknown future factor:
  `Additional reviewed risk factor`

The UI must not render:

- raw path;
- project name;
- raw argument JSON;
- existing file names/content.

The overwrite explanation communicates the reviewed consequence without exposing the target.

## 12. Error model

Add a boolean-specific request-time error to the risk-assessment layer, e.g. `ArgumentNotBoolean`.

Mapping:

- missing boolean argument with reviewed default: use the default;
- present non-boolean value: `MalformedToolArguments`;
- missing required effect at runtime: `UnmodelledToolContract`;
- invalid rule configuration: startup failure;
- effective risk below base: remains impossible through the validated `RiskAssessment` constructor.

No permissive fallback to base risk is allowed for malformed present values.

## 13. Testing strategy

### Core serialization tests

- bulk factor serializes to the exact historical JSON shape;
- literal historical bulk JSON deserializes successfully;
- confirmed-overwrite factor serializes/deserializes;
- risk assessment floor invariant remains enforced.

### Registry tests

- valid boolean-equals rule parses;
- unknown boolean-rule fields fail;
- unknown argument fails;
- missing required write effect fails;
- unknown factor code fails;
- non-escalating target fails;
- duplicate equivalent rule fails;
- existing cardinality rule remains unchanged.

### Policy tests

For the same `kicad_create_new_project` tool and grant:

1. omitted `confirm_overwrite` -> Normal / allow;
2. `false` -> Normal / allow;
3. `true` -> High / require approval with exact `ConfirmedOverwrite` factor;
4. `"true"` -> deny malformed;
5. `1` -> deny malformed;
6. workspace escape still denies before any execution;
7. existing static High tools remain High;
8. existing `pcb_delete_items` cardinality behavior remains unchanged under policy version 3.

### Audit tests

- new overwrite factor round-trips in schema v5;
- literal policy-v2 bulk factor JSON remains readable;
- approval-decision update does not mutate risk fields;
- raw path/name do not appear in risk factor JSON.

### Daemon / vertical-slice tests

- overwrite=true becomes pending and core call count remains unchanged before approval;
- pending view reports base Normal, effective High, policy v3, and `confirmed_overwrite`;
- approval-time assessment equality is enforced;
- deny never calls core;
- approved execution calls core only after durable approval;
- pre-execution audit failure still blocks both queueing and execution.

### Protocol / desktop tests

- local IPC version is 5;
- bulk factor continues rendering its count summary;
- confirmed-overwrite renders the overwrite consequence;
- static High with no factors remains readable;
- unknown factor remains generic;
- path/name sentinel strings never appear in the modal.

## 14. Documentation updates during implementation

Update:

- `docs/security/tool-effect-contracts.md`: boolean reviewed defaults/rules and overwrite consequence;
- `docs/security/threat-model.md`: explicit overwrite authorization boundary;
- `docs/architecture/data-flow.md`: policy-v3 boolean-default semantics;
- `docs/architecture/component-boundaries.md`: tagged factor ownership and IPC safe metadata;
- `docs/development/testing.md`: overwrite regression coverage;
- `docs/development/daemon-lifecycle.md`: local IPC v5;
- `docs/architecture/session-lifecycle.md`: risk policy v3;
- `CHANGELOG.md`.

Do not bump SQLite schema documentation from v5 unless implementation changes storage layout.

## 15. Rollout and compatibility

This tranche is stricter but does not widen authority:

- no new tool capability is granted;
- no base risk is lowered;
- `kicad_create_new_project` remains Normal by default;
- only explicit reviewed overwrite authority becomes High;
- historical policy-v2 audit rows remain readable;
- database schema remains v5;
- local IPC deliberately moves from v4 to v5;
- upstream source pin remains `f641a92596ab7adc1e134287578b1ae5ff9580ad`.

The work lands in a dedicated PR referencing #20. #20 stays open afterward unless its broader workspace-context/path-breadth/released-upstream consequence scope has also been completed separately.

## 16. Rejected alternatives

### Filesystem probing in policy

Rejected because it would make the policy evaluator depend on mutable I/O state and create time-of-check/time-of-use ambiguity. The reviewed request fact `confirm_overwrite=true` is sufficient to identify the requested overwrite authority.

### Generic truthy-value handling

Rejected because coercion would make malformed caller values permissive. Only JSON booleans are accepted.

### Argument-name heuristics

Rejected because names such as `force`, `confirm`, or `overwrite` are not trusted semantics on their own.

### Reusing the cardinality factor struct with fake counts

Rejected because inventing count/threshold values for a boolean consequence would corrupt audit semantics.

### New SQLite migration

Rejected unless implementation proves necessary. A tagged factor enum can preserve the existing bulk JSON shape inside schema v5.

### Waiting for a future upstream release

Rejected for this bounded tranche because the exact pinned source already contains the argument signature, default, overwrite implementation, and confirmation/destructive evaluation evidence required for deterministic Gateway policy.

## 17. Acceptance for this tranche

Implementation is complete when:

- policy version is 3;
- trusted registry expresses and validates the overwrite boolean rule;
- omitted/false overwrite remains Normal;
- true overwrite becomes High and requires local approval;
- malformed present overwrite values fail closed;
- static risk remains a floor;
- existing bulk-cardinality behavior remains unchanged;
- historical bulk factor JSON remains readable;
- schema stays v5;
- pending/audit/desktop surfaces expose only safe overwrite evidence;
- local IPC is v5;
- approval-time revalidation preserves exact assessment equality;
- raw path/name values do not leak through the risk explanation path;
- repository-required CI/security checks stay green without weakening any gate.
