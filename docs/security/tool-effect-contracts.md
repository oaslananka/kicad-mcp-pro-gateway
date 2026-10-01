# Trusted Tool-Effect Contracts

Gateway does not use `OperationRequest.target_path` as authorization evidence.
For every operation it performs this deterministic flow:

```text
tool name + forwarded arguments + SHA-pinned reviewed contract
→ NormalizedOperationEffects
→ workspace containment
→ capability check
→ static base risk + reviewed risk rules → RiskAssessment
→ approval
```

The trusted source is `crates/policy/assets/tool_registry.toml`. Its top-level
`contract_version`, `source_repository`, `source_ref`, and `source_sha` must
match `upstream_tool_snapshot.toml`; daemon startup fails if they do not. A
listed tool without an `effects` block is denied with
`UnmodelledToolContract`. Unknown arguments and malformed path values are also
denied before `tools/call`.

## Reviewed V1 surface

The initial reviewed contracts are pinned to kicad-mcp-pro commit
`f641a92596ab7adc1e134287578b1ae5ff9580ad`. The public names and dispositions
were reconciled against that commit's generated tool catalog; argument
allowlists and effects were reviewed from each FastMCP adapter and the service
it delegates to:

| Tool | Reviewed public arguments | Path arguments | Normalized effects |
|---|---|---|---|
| `sch_get_symbols` | `sheet`, `sheet_file` | `sheet_file` | read workspace and optional sheet path |
| `pcb_auto_place_by_schematic` | `strategy`, `origin_x_mm`, `origin_y_mm`, `scale_x`, `scale_y`, `grid_mm`, `allow_open_board`, `sync_missing` | active board/project state only | read/write/create workspace state |
| `kicad_create_new_project` | `path`, `name`, `confirm_overwrite` | `path`; `name` is also path-bearing because upstream appends it to `path` | read/write/create both normalized components |
| `pcb_delete_items` | `item_ids` | active board state only | read/delete workspace state |
| `lib_create_custom_symbol` | `name`, `pins` | active project state only | read/write/create the custom-symbol library |
| `export_gerber` | `output_subdir`, `layers`, `variant_name` | `output_subdir` (default `gerber`) | read/write workspace; create/write output directory |

The adapter sources are `src/kicad_mcp/tools/schematic_inspection.py`,
`src/kicad_mcp/tools/pcb.py`, `src/kicad_mcp/tools/project_creation.py`,
`src/kicad_mcp/tools/library_local_authoring.py`, and
`src/kicad_mcp/tools/export_gerber.py`. Path semantics were checked in
`src/kicad_mcp/tools/schematic.py`, `src/kicad_mcp/project/creation.py`,
`src/kicad_mcp/library/local_authoring.py`, and `src/kicad_mcp/export/gerber.py`.
The generated catalog's read-only/destructive labels are reconciliation evidence,
not authorization input.

Each contract lists the complete reviewed argument names. A reviewed
`base_argument` makes normalization follow the upstream composition rule rather
than treating independently safe strings as safe after concatenation; this is
required for `kicad_create_new_project` (`name` relative to `path`). This
prevents a caller from adding an unmodelled path-shaped argument. A path value
may be a string or a flat array of strings; every member is normalized and
checked.
Nested arrays, alternate user/environment path syntax, and contracts that
produce no effects fail closed. Relative paths are anchored to the authorized
workspace rather than the daemon process's current directory. Traversal, foreign
absolute syntax, and paths that traverse a symlink outside the workspace are
denied.

`NormalizedOperationEffects` deliberately has read, write, create, and delete
categories. They are security-boundary facts, not a reimplementation of KiCad
domain behavior. Contract review consumes upstream signatures and catalog
metadata; it does not duplicate PCB/schematic semantics in Gateway.

## Reviewed operation-risk rules

The static `risk` on each registry entry is a floor: operation-specific
assessment may raise it but can never lower it. Dynamic risk is policy version
`2` and is driven only by typed `risk_rules` declared on the same
source-pinned reviewed tool contract. Gateway does not infer risk from generic
JSON shape, from a tool name, or from an effect such as `delete` by itself.

The first reviewed rule is intentionally narrow:

```toml
[[tool.risk_rules]]
kind = "argument_cardinality"
argument = "item_ids"
minimum_count = 2
requires_effect = "delete"
escalate_to = "high"
```

It applies only to `pcb_delete_items`. One or zero IDs keep that tool's
static `Normal` risk; two or more IDs raise the effective risk to `High`
and therefore require local approval. The rule is accepted only because
`item_ids` and the `delete` effect are both present in that tool's reviewed
contract. Registry loading rejects rules that reference an unknown argument,
a missing required effect, a threshold below two, a non-escalating target, a
duplicate rule, or a tool without an effect contract.

At evaluation time, risk rules run only after effect normalization, workspace
containment, and capability validation. A risk-relevant argument that is
missing or has the wrong JSON type fails closed as malformed tool arguments;
Gateway never coerces a scalar into an array. The resulting `RiskAssessment`
records policy version, base risk, effective risk, and safe factors containing
only reviewed metadata such as argument name, observed count, threshold, and
escalation target. Raw item IDs, paths, credentials, source text, and project
contents are not risk-factor data and are not persisted or rendered.

This tranche deliberately leaves the production upstream pin at
`oaslananka/kicad-mcp-pro@f641a92596ab7adc1e134287578b1ae5ff9580ad`.
Issue #20 remains open for later workspace-context, path-breadth, and
released-upstream consequence dimensions; those dimensions must enter through
equally explicit reviewed facts rather than heuristics.

## Upstream reviewed-manifest transition

`kicad-mcp-pro` now publishes a versioned machine-readable reviewed effect manifest (upstream PR #1014, merged as `e5065df453a57367cf1ea83437717967d36de77c`).
Gateway treats that document as factual compatibility input, **not** as an
authorization grant. `UpstreamEffectManifest` in `companion-policy` parses the
JSON with closed enums/fields, validates schema/source identity, constructs the
same `ToolEffectContract` domain model used by policy, and can reconcile it
against the embedded fallback without executing upstream Python code.

The production daemon continues to trust only the source-pinned
`tool_registry.toml` fallback until the upstream artifact and
`upstream_tool_snapshot.toml` are reviewed and pinned to the same immutable
upstream revision. Reconciliation rejects locally unclassified manifest tools;
a newly published upstream tool therefore cannot become authorized by
discovery or by manifest presence alone.

The committed test fixture under `crates/policy/tests/fixtures/` is compatibility
evidence only. It deliberately detects source-SHA staleness against the current
production snapshot and exposes contract drift (for example, the current
upstream `export_gerber` surface no longer contains the older reviewed
`variant_name` argument). Stale or malformed evidence must be reviewed before
the fallback is changed.

For a candidate upstream artifact, run:

```sh
cargo run -p companion-policy --bin reconcile-upstream-effect-manifest < \
  /path/to/tool-effect-manifest.json
```

The command accepts manifest JSON only through bounded standard input (max 1 MiB), performs no caller-selected filesystem reads, and exits non-zero when the manifest source pin differs from the
production snapshot or when reviewed tool/effect contracts differ from the
fallback. It reports drift but never writes policy or promotes an upstream
tool into the allowlist.

## Refresh procedure

1. Refresh `upstream_tool_snapshot.toml` with `reconcile-tool-registry` at an
   exact upstream commit.
2. Review upstream input signatures and effect metadata for every newly exposed
   tool. Do not infer authorization from a tool name or MCP annotations alone.
3. Add the exact argument allowlist, implicit effects, path arguments, defaults,
   composition (`base_argument`), and per-path effects to `tool_registry.toml`.
4. Add normalization/property regressions and a core-bridge integration test
   for every path-bearing argument.
5. Run `cargo test -p companion-policy`, then the full Rust fmt/clippy/test
   gates. A new or stale upstream tool remains denied until reviewed.

The reconciliation CLI reports capability classification and effect-contract
coverage separately, making authorization drift and effect-modelling debt
visible rather than silently converting either into an allow.
