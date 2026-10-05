# Policy Engine Instructions

These instructions apply to `crates/policy/**` and supplement both parent agent instruction files.

## Boundary

This crate is the deterministic authorization/effect/risk policy engine. It does not execute KiCad
operations, perform network/filesystem I/O for authorization, or treat transport state as policy.

Read before material changes:

- `docs/security/tool-effect-contracts.md`
- `docs/security/authorization-ttl.md`
- `docs/architecture/data-flow.md`
- `docs/architecture/compatibility-matrix.md`
- `crates/policy/assets/tool_registry.toml`
- `crates/policy/assets/upstream_tool_snapshot.toml`

## Trusted tool/effect contracts

The reviewed local registry is authorization policy. An upstream catalog or machine-readable effect
manifest is factual compatibility input, not an authorization grant.

Preserve these invariants:

- unknown/unclassified tool => deny;
- missing effect contract => deny;
- unknown argument => deny;
- malformed path/effect => deny;
- newly discovered upstream tool remains denied until separately reviewed;
- source identity and pinned snapshot/registry must agree;
- reconciliation reports drift but does not write/promote policy automatically.

Do not authorize a tool because its name, MCP annotation, upstream category, or discovered metadata
looks safe.

## Caller metadata is not authority

`OperationRequest.target_path` is intentionally ignored as authorization evidence.

Derive effects from:

```text
tool name + forwarded arguments + reviewed source-pinned contract
-> NormalizedOperationEffects
```

Then let the daemon/workspace boundary enforce every derived path. Do not replace this with caller
path assertions or generic JSON heuristics.

## Risk policy

Static reviewed risk is a floor. Operation-specific rules may raise effective risk but must not
silently lower it.

Dynamic risk comes only from explicit reviewed rule kinds on trusted contracts. Do not infer risk
from:

- tool-name keywords;
- arbitrary JSON shape;
- generic array length;
- an effect such as `delete` by itself;
- unreviewed path breadth or argument contents.

Risk factors exposed to UI/audit stay non-sensitive and derived from reviewed metadata. Do not
persist raw item IDs, project contents, credentials, or paths as explanation data.

## Authorization TTL

Remote-requested lifetime does not set the maximum authority lifetime. Preserve the local
profile/risk ceilings and validated configuration model.

Malformed/partial/unknown TTL policy configuration is a startup error; do not silently fall back to
defaults after invalid policy input.

TTL is defense in depth. It does not replace explicit revocation or per-operation approval.

## Policy assets and upstream refresh

Changes to `tool_registry.toml`, `upstream_tool_snapshot.toml`, or manifest reconciliation are
security-policy changes.

Follow the reviewed refresh procedure in `docs/security/tool-effect-contracts.md`. New or changed
upstream surfaces require explicit argument/effect/path/risk review and negative tests before
authorization expands.

Use the repository reconciliation binaries; do not hand-edit source pins or counts to make tests
pass.

## Verification

At minimum:

```bash
cargo test -p companion-policy
cargo clippy -p companion-policy --all-targets -- -D warnings
cargo test --workspace
```

For policy refreshes, run the documented registry/effect-manifest reconciliation against the exact
upstream artifact/source and retain the bounded result. Live discovery does not grant authority.

## Definition of done

A policy change is complete only when source identity, capability classification, effect
normalization, workspace-relevant path facts, static/dynamic risk, TTL, tests, and documentation
remain source-pinned and fail closed.
